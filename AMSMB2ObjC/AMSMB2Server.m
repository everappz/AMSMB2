//
//  AMSMB2Server.m
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//
//  Wraps libsmb2's server-side API. libsmb2 parses the SMB2 protocol and hands
//  us decoded request structs through `struct smb2_server_request_handlers`;
//  this file translates those callbacks into AMSMB2ServerDelegate messages and
//  fills the reply structs using host-struct encoders (non-passthrough mode),
//  exactly as the reference examples/smb2-server-sync.c does.
//

#import "AMSMB2Server.h"
#import "SMB2Helpers.h"

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <smb2/smb2-errors.h>
#include <smb2/libsmb2-share-enum.h>      // SRVSVC_SHARE_TYPE_* share-type bits
#include <smb2/libsmb2-srvsvc-server.h>   // smb2_srvsvc_server_netshareenum()

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#define AM_PAD_TO_64BIT(len) (((len) + 0x07) & ~0x07)
#define AM_PAD_TO_32BIT(len) (((len) + 0x03) & ~0x03)

// DEBUG-only trace for the SMB server C core (share enumeration / named-pipe RPC and the
// tree/create/read/write/ioctl plumbing). Prefixed [SMB-SRV] so it filters cleanly in Console
// alongside the app-side [SMB] (controller) and [SMB-FS] (delegate) traces. Compiled out of release.
#if DEBUG
#define SMBSrvLog(fmt, ...) NSLog((@"[SMB-SRV] " fmt), ##__VA_ARGS__)
#else
#define SMBSrvLog(fmt, ...) do {} while (0)
#endif

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Conversions

static uint64_t AMWinTimeFromDate(NSDate *_Nullable date)
{
    if (!date) {
        return 0;
    }
    // Windows FILETIME: 100 ns ticks since 1601-01-01, offset from Unix epoch.
    return (uint64_t)llround(date.timeIntervalSince1970 * 10000000.0) + 116444736000000000ULL;
}

static struct smb2_timeval AMTimevalFromDate(NSDate *_Nullable date)
{
    struct smb2_timeval tv = {0, 0};
    if (date) {
        double s = date.timeIntervalSince1970;
        double whole = floor(s);
        tv.tv_sec = (time_t)whole;
        tv.tv_usec = (long)((s - whole) * 1000000.0);
    }
    return tv;
}

/// Reverse of AMWinTimeFromDate. Returns nil for the "unset"/"don't change"
/// sentinels a client sends (0 and 0xFFFFFFFFFFFFFFFF).
static NSDate *_Nullable AMDateFromWinTime(uint64_t filetime)
{
    if (filetime == 0 || filetime == UINT64_MAX) {
        return nil;
    }
    double seconds = ((double)filetime - 116444736000000000.0) / 10000000.0;
    return [NSDate dateWithTimeIntervalSince1970:seconds];
}

#pragma mark - Little-endian byte access

static uint32_t AMReadLE32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t AMReadLE64(const uint8_t *p)
{
    return (uint64_t)AMReadLE32(p) | ((uint64_t)AMReadLE32(p + 4) << 32);
}

static void AMWriteLE32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void AMWriteLE64(uint8_t *p, uint64_t v)
{
    AMWriteLE32(p, (uint32_t)(v & 0xffffffffULL));
    AMWriteLE32(p + 4, (uint32_t)((v >> 32) & 0xffffffffULL));
}

static uint16_t AMReadLE16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void AMAppendLE16(NSMutableData *d, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)(v & 0xff), (uint8_t)((v >> 8) & 0xff) };
    [d appendBytes:b length:2];
}

static void AMAppendLE32(NSMutableData *d, uint32_t v)
{
    uint8_t b[4];
    AMWriteLE32(b, v);
    [d appendBytes:b length:4];
}

#if DEBUG
// Compact hex preview of a buffer (first `max` bytes) for the [SMB-SRV] pipe traces, so each
// on-device round shows exactly what bytes we received / emitted.
static NSString *AMHexPreview(NSData *data, NSUInteger max)
{
    if (data.length == 0) { return @"<empty>"; }
    NSUInteger n = MIN(data.length, max);
    const uint8_t *b = data.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:n * 3];
    for (NSUInteger i = 0; i < n; i++) { [s appendFormat:@"%02x ", b[i]]; }
    if (n < data.length) { [s appendFormat:@"... (%lu bytes)", (unsigned long)data.length]; }
    return s;
}
#endif

static uint32_t AMAttributesFromInfo(AMSMB2FileInfo *info)
{
    uint32_t attr = 0;
    if (info.isDirectory) {
        attr |= SMB2_FILE_ATTRIBUTE_DIRECTORY;
    }
    if (info.isReadOnly) {
        attr |= SMB2_FILE_ATTRIBUTE_READONLY;
    }
    if (info.isHidden) {
        attr |= SMB2_FILE_ATTRIBUTE_HIDDEN;
    }
    if (info.isSymbolicLink) {
        attr |= SMB2_FILE_ATTRIBUTE_REPARSE_POINT;
    }
    if (attr == 0) {
        attr = SMB2_FILE_ATTRIBUTE_NORMAL;
    }
    return attr;
}

/// A self-relative SECURITY_DESCRIPTOR granting Everyone (S-1-1-0) full control,
/// used to answer QUERY_INFO(SECURITY) so clients treat the share as writable.
/// Layout per MS-DTYP: SD header (20) + Owner SID (12) + Group SID (12) + DACL
/// with one ACCESS_ALLOWED ACE (28) = 72 bytes.
static NSData *AMEveryoneFullControlSecurityDescriptor(void)
{
    static const uint8_t sd[] = {
        // SECURITY_DESCRIPTOR (self-relative)
        0x01, 0x00, 0x04, 0x80,             // Revision, Sbz1, Control = SELF_RELATIVE|DACL_PRESENT
        0x14, 0x00, 0x00, 0x00,             // OffsetOwner = 20
        0x20, 0x00, 0x00, 0x00,             // OffsetGroup = 32
        0x00, 0x00, 0x00, 0x00,             // OffsetSacl  = 0
        0x2C, 0x00, 0x00, 0x00,             // OffsetDacl  = 44
        // Owner SID — Everyone (S-1-1-0)
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // Group SID — Everyone (S-1-1-0)
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // DACL: ACL header (rev=2, size=28, count=1)
        0x02, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00,
        // ACE: ACCESS_ALLOWED, flags=OI|CI, size=20, mask=FILE_ALL_ACCESS (0x001F01FF)
        0x00, 0x03, 0x14, 0x00, 0xFF, 0x01, 0x1F, 0x00,
        // ACE SID — Everyone (S-1-1-0)
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    return [NSData dataWithBytes:sd length:sizeof(sd)];
}

/// SMB delivers share-relative paths with backslash separators; normalize to
/// forward slashes so delegates see conventional POSIX-style paths.
static NSString *AMPathFromCName(const char *_Nullable cname)
{
    if (!cname) {
        return @"";
    }
    NSString *s = [NSString stringWithUTF8String:cname] ?: @"";
    return [s stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
}

#pragma mark - AMSMB2FileInfo

@implementation AMSMB2FileInfo

+ (instancetype)fileInfoWithName:(NSString *)name isDirectory:(BOOL)isDirectory size:(unsigned long long)size
{
    AMSMB2FileInfo *info = [[AMSMB2FileInfo alloc] init];
    info.name = name;
    info.isDirectory = isDirectory;
    info.fileSize = size;
    return info;
}

- (unsigned long long)allocationSize
{
    // Default the allocation size to the logical size when unset.
    return _allocationSize > 0 ? _allocationSize : _fileSize;
}

@end

#pragma mark - Internal state

/// Per-open-handle state, keyed by the 16-byte SMB2 file id we hand the client.
@interface AMSMB2ServerOpenFile : NSObject
@property (nonatomic, strong) id handle;
@property (nonatomic, copy) NSString *path;
@property (nonatomic, strong) AMSMB2FileInfo *info;
@property (nonatomic) BOOL deleteOnClose;
// Directory enumeration cursor state.
@property (nonatomic, nullable, strong) NSArray<AMSMB2FileInfo *> *dirEntries;
@property (nonatomic) NSUInteger dirCursor;
@property (nonatomic) BOOL dirEnumerated;
// Named-pipe (MS-RPC) state: a CREATE of `srvsvc` (etc.) on IPC$ opens a virtual DCE/RPC pipe
// instead of a delegate file. `pipeReadBuffer` holds the response bytes produced by a
// TRANSCEIVE/WRITE until the client READs them (the write-then-read pipe path).
@property (nonatomic) BOOL isPipe;
@property (nonatomic, nullable, copy) NSString *pipeName;
@property (nonatomic, nullable, strong) NSMutableData *pipeReadBuffer;
@end

@implementation AMSMB2ServerOpenFile
@end

/// Per-connection state. libsmb2 serves multiple client contexts from one loop,
/// so state is keyed by the `smb2_context`.
@interface AMSMB2ServerConnection : NSObject {
@public
    uint64_t _counter;
    uint64_t _salt;
    void *_pendingDirBuffer;
    void *_pendingInfoBuffer;
}
@property (nonatomic, strong) NSMutableDictionary<NSData *, AMSMB2ServerOpenFile *> *openFiles;
// The most recently created file id, used to resolve the all-0xFF
// "compound_file_id" sentinel that follow-on commands in a compound request
// (CREATE+SET_INFO+CLOSE, CREATE+QUERY_INFO+CLOSE, …) carry.
@property (nonatomic, nullable, strong) NSData *lastFileId;
// Retains the raw wire buffer handed to libsmb2 in passthrough directory
// listings until the reply is encoded (replaced on the next query).
@property (nonatomic, nullable, strong) NSData *pendingDirData;
// Retains the raw IOCTL reply payload (resume key / copychunk result) until
// libsmb2 copies it into the reply PDU.
@property (nonatomic, nullable, strong) NSData *pendingIoctlData;
@end

@implementation AMSMB2ServerConnection
- (instancetype)init
{
    if ((self = [super init])) {
        _openFiles = [NSMutableDictionary dictionary];
        _counter = 0;
        _salt = (uint64_t)(uintptr_t)self;
    }
    return self;
}
@end

#pragma mark - Forward declarations of C handlers

static int am_authorize_user(struct smb2_server *srvr, struct smb2_context *smb2, const char *user, const char *domain, const char *workstation);
static int am_session_established(struct smb2_server *srvr, struct smb2_context *smb2);
static int am_logoff(struct smb2_server *srvr, struct smb2_context *smb2);
static int am_tree_connect(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_tree_connect_request *req, struct smb2_tree_connect_reply *rep);
static int am_tree_disconnect(struct smb2_server *srvr, struct smb2_context *smb2, const uint32_t tree_id);
static int am_create(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_create_request *req, struct smb2_create_reply *rep);
static int am_close(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_close_request *req, struct smb2_close_reply *rep);
static int am_flush(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_flush_request *req);
static int am_read(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_read_request *req, struct smb2_read_reply *rep);
static int am_write(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_write_request *req, struct smb2_write_reply *rep);
static int am_lock(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_lock_request *req);
static int am_ioctl(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_ioctl_request *req, struct smb2_ioctl_reply *rep);
static int am_cancel(struct smb2_server *srvr, struct smb2_context *smb2);
static int am_echo(struct smb2_server *srvr, struct smb2_context *smb2);
static int am_query_directory(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_query_directory_request *req, struct smb2_query_directory_reply *rep);
static int am_query_info(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_query_info_request *req, struct smb2_query_info_reply *rep);
static int am_set_info(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_set_info_request *req);
static int am_destruction_event(struct smb2_server *srvr, struct smb2_context *smb2);

static void am_on_new_client(struct smb2_context *smb2, void *cb_data);
static void am_on_error(struct smb2_context *smb2, const char *error_string);

#pragma mark - AMSMB2Server

@interface AMSMB2Server ()
- (AMSMB2ServerConnection *)connectionForContext:(struct smb2_context *)smb2 create:(BOOL)create;
- (void)removeConnectionForContext:(struct smb2_context *)smb2;
- (nullable NSString *)resolvedPasswordForUser:(nullable NSString *)user;
@end

@implementation AMSMB2Server {
    struct smb2_server _server;
    struct smb2_server_request_handlers _handlers;
    dispatch_queue_t _serveQueue;
    NSMutableDictionary<NSValue *, AMSMB2ServerConnection *> *_connections;
    NSRecursiveLock *_lock;
    volatile BOOL _serveFinished;
    int _serveError;
    BOOL _stopRequested;
    BOOL _running;
}

- (instancetype)initWithPort:(uint16_t)port shareName:(NSString *)shareName delegate:(nullable id<AMSMB2ServerDelegate>)delegate
{
    if ((self = [super init])) {
        _port = port;
        _shareName = [shareName copy];
        _delegate = delegate;
        _signingEnabled = YES;
        _allowsAnonymousAccess = NO;
        _connections = [NSMutableDictionary dictionary];
        _lock = [[NSRecursiveLock alloc] init];
        _serveQueue = dispatch_queue_create("com.amsmb2.server", DISPATCH_QUEUE_SERIAL);
        _serveFinished = YES;
    }
    return self;
}

- (void)dealloc
{
    [self stop];
}

- (BOOL)isRunning
{
    return _running;
}

#pragma mark Lifecycle

- (BOOL)startAndReturnError:(NSError *_Nullable *_Nullable)error
{
    [_lock lock];
    if (_running) {
        [_lock unlock];
        return YES;
    }

    memset(&_handlers, 0, sizeof(_handlers));
    _handlers.destruction_event = am_destruction_event;
    _handlers.authorize_user = am_authorize_user;
    _handlers.session_established = am_session_established;
    _handlers.logoff_cmd = am_logoff;
    _handlers.tree_connect_cmd = am_tree_connect;
    _handlers.tree_disconnect_cmd = am_tree_disconnect;
    _handlers.create_cmd = am_create;
    _handlers.close_cmd = am_close;
    _handlers.flush_cmd = am_flush;
    _handlers.read_cmd = am_read;
    _handlers.write_cmd = am_write;
    _handlers.lock_cmd = am_lock;
    _handlers.ioctl_cmd = am_ioctl;
    _handlers.cancel_cmd = am_cancel;
    _handlers.echo_cmd = am_echo;
    _handlers.query_directory_cmd = am_query_directory;
    _handlers.query_info_cmd = am_query_info;
    // Only ever invoked when the context is in passthrough mode (fullControl);
    // libsmb2 rejects SET_INFO before the handler otherwise.
    _handlers.set_info_cmd = am_set_info;

    memset(&_server, 0, sizeof(_server));
    _server.handlers = &_handlers;
    _server.port = _port;
    _server.signing_enabled = _signingEnabled ? 1 : 0;
    _server.allow_anonymous = _allowsAnonymousAccess ? 1 : 0;
    _server.auth_data = (__bridge void *)self;
    if (_hostName.length > 0) {
        strncpy(_server.hostname, _hostName.UTF8String, sizeof(_server.hostname) - 1);
    }

    _serveFinished = NO;
    _serveError = 0;
    _stopRequested = NO;
    _running = YES;
    [_lock unlock];

    __weak typeof(self) weakSelf = self;
    dispatch_async(_serveQueue, ^{
        typeof(self) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        // Blocking serve loop; exits on socket shutdown (via -stop) or error.
        int err = smb2_serve_port(&strongSelf->_server, 8, am_on_new_client, (__bridge void *)strongSelf);
        [strongSelf->_lock lock];
        strongSelf->_serveError = err;
        strongSelf->_serveFinished = YES;
        strongSelf->_running = NO;
        [strongSelf->_lock unlock];
    });

    // Wait for the listening socket to bind (or an early bind failure).
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:3.0];
    while (_server.fd <= 0 && !_serveFinished && deadline.timeIntervalSinceNow > 0) {
        usleep(10000);
    }

    if (_server.fd <= 0) {
        [_lock lock];
        _running = NO;
        [_lock unlock];
        if (error) {
            *error = SMB2POSIXError(EADDRINUSE, [NSString stringWithFormat:@"Failed to bind SMB server on port %u.", _port]);
        }
        return NO;
    }
    return YES;
}

- (void)stop
{
    [_lock lock];
    BOOL wasRunning = _running && !_serveFinished;
    _stopRequested = YES;
    [_lock unlock];

    if (!wasRunning) {
        return;
    }

    // libsmb2's smb2_serve_port() has no stop API; its loop only exits when the
    // accept() path returns an error (shutdown() is a no-op on a listening
    // socket, and simply closing the fd races the loop's select()). Reliable
    // fix: atomically replace the listening socket with a readable pipe via
    // dup2(). Every loop iteration then sees the fd readable and calls accept()
    // on a non-socket, which fails with ENOTSOCK and breaks the loop — no race.
    [_lock lock];
    int lfd = _server.fd;
    [_lock unlock];
    if (lfd >= 0) {
        int p[2];
        if (pipe(p) == 0) {
            ssize_t wrote = write(p[1], "x", 1); // keep the read end readable
            (void)wrote;
            dup2(p[0], lfd); // lfd now refers to the pipe read end (a non-socket)
            close(p[0]);
            close(p[1]);
        } else {
            close(lfd);
        }
    }

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:2.0];
    while (!_serveFinished && deadline.timeIntervalSinceNow > 0) {
        usleep(5000);
    }

    [_lock lock];
    _running = NO;
    [_lock unlock];
}

#pragma mark Connection registry

- (AMSMB2ServerConnection *)connectionForContext:(struct smb2_context *)smb2 create:(BOOL)create
{
    NSValue *key = [NSValue valueWithPointer:smb2];
    [_lock lock];
    AMSMB2ServerConnection *conn = _connections[key];
    if (!conn && create) {
        conn = [[AMSMB2ServerConnection alloc] init];
        _connections[key] = conn;
    }
    [_lock unlock];
    return conn;
}

- (void)removeConnectionForContext:(struct smb2_context *)smb2
{
    NSValue *key = [NSValue valueWithPointer:smb2];
    [_lock lock];
    AMSMB2ServerConnection *conn = _connections[key];
    [_connections removeObjectForKey:key];
    [_lock unlock];

    if (!conn) {
        return;
    }
    // Release any handles the client left open and free scratch buffers.
    id<AMSMB2ServerDelegate> delegate = self.delegate;
    for (AMSMB2ServerOpenFile *file in conn.openFiles.allValues) {
        if (file.handle && [delegate respondsToSelector:@selector(server:closeItem:)]) {
            [delegate server:self closeItem:file.handle];
        }
    }
    [conn.openFiles removeAllObjects];
    if (conn->_pendingDirBuffer) {
        free(conn->_pendingDirBuffer);
        conn->_pendingDirBuffer = NULL;
    }
    if (conn->_pendingInfoBuffer) {
        free(conn->_pendingInfoBuffer);
        conn->_pendingInfoBuffer = NULL;
    }
}

- (nullable NSString *)resolvedPasswordForUser:(nullable NSString *)user
{
    id<AMSMB2ServerDelegate> delegate = self.delegate;
    if (user && [delegate respondsToSelector:@selector(server:passwordForUser:)]) {
        return [delegate server:self passwordForUser:user];
    }
    if (user && self.username && [user isEqualToString:self.username]) {
        return self.password;
    }
    return nil;
}

@end

#pragma mark - Handler helpers

static AMSMB2Server *AMServerFromContext(struct smb2_server *srvr)
{
    return srvr ? (__bridge AMSMB2Server *)srvr->auth_data : nil;
}

/// Resolve the wire file id to a storage key, substituting the last-created id
/// for the all-0xFF compound sentinel used by compound requests.
static NSData *_Nullable AMEffectiveKey(AMSMB2ServerConnection *conn, const uint8_t *file_id)
{
    if (!file_id) {
        return nil;
    }
    BOOL sentinel = YES;
    for (int i = 0; i < SMB2_FD_SIZE; i++) {
        if (file_id[i] != 0xff) {
            sentinel = NO;
            break;
        }
    }
    if (sentinel && conn.lastFileId) {
        return conn.lastFileId;
    }
    return [NSData dataWithBytes:file_id length:SMB2_FD_SIZE];
}

static AMSMB2ServerOpenFile *AMFileForId(AMSMB2ServerConnection *conn, const uint8_t *file_id)
{
    if (!conn) {
        return nil;
    }
    NSData *key = AMEffectiveKey(conn, file_id);
    return key ? conn.openFiles[key] : nil;
}

#pragma mark - C handlers: auth & session

static int am_authorize_user(struct smb2_server *srvr, struct smb2_context *smb2, const char *user, const char *domain, const char *workstation)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        if (!server) {
            return -1;
        }
        NSString *userStr = (user && user[0]) ? [NSString stringWithUTF8String:user] : nil;
        NSString *domainStr = (domain && domain[0]) ? [NSString stringWithUTF8String:domain] : nil;
        NSString *wsStr = (workstation && workstation[0]) ? [NSString stringWithUTF8String:workstation] : nil;

        id<AMSMB2ServerDelegate> delegate = server.delegate;
        if ([delegate respondsToSelector:@selector(server:authenticateUser:domain:workstation:)]) {
            if (![delegate server:server authenticateUser:userStr domain:domainStr workstation:wsStr]) {
                return -1;
            }
        }

        // Supply the password so libsmb2 can validate the NTLM response. When no
        // password is available and anonymous access is allowed, the library
        // proceeds anonymously; otherwise it rejects the session.
        NSString *password = [server resolvedPasswordForUser:userStr];
        if (password.length > 0) {
            smb2_set_password(smb2, password.UTF8String);
        }
        return 0;
    }
}

static int am_session_established(struct smb2_server *srvr, struct smb2_context *smb2)
{
    return 0;
}

static int am_logoff(struct smb2_server *srvr, struct smb2_context *smb2)
{
    return 0;
}

#pragma mark - Named-pipe MS-RPC responder (srvsvc share enumeration)

// DCE/RPC PDU types we care about (MS-RPCE 2.2.2.13).
#define AM_DCERPC_PT_REQUEST        0x00
#define AM_DCERPC_PT_RESPONSE       0x02
#define AM_DCERPC_PT_FAULT          0x03
#define AM_DCERPC_PT_BIND           0x0b
#define AM_DCERPC_PT_BIND_ACK       0x0c
#define AM_DCERPC_PT_ALTER_CONTEXT  0x0e
#define AM_DCERPC_PT_ALTER_CTX_RESP 0x0f

// srvsvc opnums (MS-SRVS). Defined locally: libsmb2 keeps these in the non-public dcerpc headers.
#define AM_SRVSVC_NETRSHAREENUM     0x0f
#define AM_SRVSVC_NETRSHAREGETINFO  0x10
#define AM_SRVSVC_NETRSERVERGETINFO 0x15

/// If `path` names a known MS-RPC endpoint served over a named pipe, returns the lowercased pipe
/// name; otherwise nil. Detection is by NAME (leading separators stripped): the CREATE handler has
/// no tree id, so this is how a `\\server\IPC$\srvsvc` open is told apart from a disk-share file.
static NSString *_Nullable AMNamedPipeNameFromPath(NSString *path)
{
    NSString *p = path ?: @"";
    while ([p hasPrefix:@"/"] || [p hasPrefix:@"\\"]) {
        p = [p substringFromIndex:1];
    }
    NSString *lower = p.lowercaseString;
    if ([lower isEqualToString:@"srvsvc"] || [lower isEqualToString:@"wkssvc"] ||
        [lower isEqualToString:@"lsarpc"] || [lower isEqualToString:@"winreg"] ||
        [lower isEqualToString:@"samr"]  || [lower isEqualToString:@"spoolss"]) {
        return lower;
    }
    return nil;
}

/// Build a DCE/RPC BIND_ACK (or ALTER_CONTEXT_RESP) responding to `bind`. We accept a single
/// presentation context using the NDR32 transfer syntax (what macOS/Windows propose for srvsvc),
/// echoing the client's max frag sizes + association group.
static NSData *AMBuildBindAck(NSData *bind, uint32_t callId, BOOL alterContext)
{
    const uint8_t *b = bind.bytes;
    NSInteger len = (NSInteger)bind.length;

    uint16_t maxXmit = (len >= 18) ? AMReadLE16(b + 16) : 4280;
    uint16_t maxRecv = (len >= 20) ? AMReadLE16(b + 18) : 4280;
    uint32_t assoc   = (len >= 24) ? AMReadLE32(b + 20) : 0;
    if (assoc == 0) { assoc = 0x00001063; } // Windows returns a non-zero group id.

    NSMutableData *d = [NSMutableData data];
    uint8_t hdr[16] = { 5, 0, (uint8_t)(alterContext ? AM_DCERPC_PT_ALTER_CTX_RESP : AM_DCERPC_PT_BIND_ACK),
                        0x03 /* FIRST|LAST */, 0x10, 0, 0, 0, /* drep = little-endian */
                        0, 0 /* frag_length, fixed up */, 0, 0 /* auth_length */, 0, 0, 0, 0 /* call_id */ };
    AMWriteLE32(hdr + 12, callId);
    [d appendBytes:hdr length:16];

    AMAppendLE16(d, maxXmit);
    AMAppendLE16(d, maxRecv);
    AMAppendLE32(d, assoc);

    // Secondary address: the pipe name, NUL-terminated ASCII (MS-RPCE 2.2.2.11).
    const char *sec = "\\PIPE\\srvsvc";
    uint16_t secLen = (uint16_t)(strlen(sec) + 1);
    AMAppendLE16(d, secLen);
    [d appendBytes:sec length:secLen];
    // Pad to a 4-byte boundary (relative to the PDU start) before the results list.
    while (d.length & 0x3) { uint8_t z = 0; [d appendBytes:&z length:1]; }

    // p_result_list: num_results(1) + 3 reserved.
    uint8_t nr = 1, zero = 0;
    [d appendBytes:&nr length:1];
    [d appendBytes:&zero length:1];
    [d appendBytes:&zero length:1];
    [d appendBytes:&zero length:1];

    // result[0]: ack_result=acceptance(0), ack_reason=0, transfer syntax = NDR32 v2.
    AMAppendLE16(d, 0);
    AMAppendLE16(d, 0);
    static const uint8_t ndr32[16] = { 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
                                       0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 };
    [d appendBytes:ndr32 length:16];
    AMAppendLE32(d, 2);

    uint8_t *m = (uint8_t *)d.mutableBytes;
    uint16_t frag = (uint16_t)d.length;
    m[8] = (uint8_t)(frag & 0xff);
    m[9] = (uint8_t)((frag >> 8) & 0xff);
    return d;
}

/// Build a DCE/RPC FAULT PDU (for an opnum we do not implement) so the client fails cleanly instead
/// of hanging waiting for a reply.
static NSData *AMBuildFault(uint32_t callId, uint16_t contextId, uint32_t status)
{
    NSMutableData *d = [NSMutableData data];
    uint8_t hdr[16] = { 5, 0, AM_DCERPC_PT_FAULT, 0x03, 0x10, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0 };
    AMWriteLE32(hdr + 12, callId);
    [d appendBytes:hdr length:16];
    AMAppendLE32(d, 0);          // alloc_hint
    AMAppendLE16(d, contextId);  // p_cont_id
    uint8_t cc = 0, fl = 0;
    [d appendBytes:&cc length:1]; // cancel_count
    [d appendBytes:&fl length:1]; // reserved
    AMAppendLE32(d, status);     // status
    AMAppendLE32(d, 0);          // reserved
    uint8_t *m = (uint8_t *)d.mutableBytes;
    uint16_t frag = (uint16_t)d.length;
    m[8] = (uint8_t)(frag & 0xff);
    m[9] = (uint8_t)((frag >> 8) & 0xff);
    return d;
}

/// Build the NetrShareEnum (opnum 0x0f) level-1 response: the single disk share plus IPC$.
/// The NDR marshalling lives inside libsmb2 (smb2_srvsvc_server_netshareenum), which reuses the
/// same coders the client decode path uses; here we just pass the share list.
static NSData *_Nullable AMBuildShareEnumResponse(AMSMB2Server *server, struct smb2_context *smb2,
                                                  uint32_t callId, uint16_t contextId)
{
    NSString *shareName = server.shareName.length ? server.shareName : @"Share";
    const char *names[2] = { shareName.UTF8String, "IPC$" };
    uint32_t types[2] = {
        SRVSVC_SHARE_TYPE_DISKTREE,
        SRVSVC_SHARE_TYPE_IPC | SRVSVC_SHARE_TYPE_HIDDEN,
    };

    uint8_t buf[16384];
    int n = smb2_srvsvc_server_netshareenum(smb2, callId, contextId,
                                            names, types, 2, buf, (int)sizeof(buf));
    if (n <= 0) {
        SMBSrvLog(@"NetrShareEnum encode FAILED (n=%d)", n);
        return nil;
    }
    return [NSData dataWithBytes:buf length:(NSUInteger)n];
}

/// Build the NetrShareGetInfo (opnum 0x10) level-1 response for our disk share.
static NSData *_Nullable AMBuildShareGetInfoResponse(AMSMB2Server *server, struct smb2_context *smb2,
                                                     uint32_t callId, uint16_t contextId)
{
    NSString *shareName = server.shareName.length ? server.shareName : @"Share";
    uint8_t buf[8192];
    int n = smb2_srvsvc_server_netsharegetinfo(smb2, callId, contextId,
                                               shareName.UTF8String, SRVSVC_SHARE_TYPE_DISKTREE,
                                               buf, (int)sizeof(buf));
    if (n <= 0) { SMBSrvLog(@"NetrShareGetInfo encode FAILED (n=%d)", n); return nil; }
    return [NSData dataWithBytes:buf length:(NSUInteger)n];
}

/// Build the NetrServerGetInfo (opnum 0x15) level-101 response describing this server.
static NSData *_Nullable AMBuildServerGetInfoResponse(AMSMB2Server *server, struct smb2_context *smb2,
                                                      uint32_t callId, uint16_t contextId)
{
    NSString *host = server.hostName.length ? server.hostName : @"SMB";
    uint8_t buf[8192];
    int n = smb2_srvsvc_server_netservergetinfo(smb2, callId, contextId,
                                                host.UTF8String, "", buf, (int)sizeof(buf));
    if (n <= 0) { SMBSrvLog(@"NetrServerGetInfo encode FAILED (n=%d)", n); return nil; }
    return [NSData dataWithBytes:buf length:(NSUInteger)n];
}

/// Turn one inbound DCE/RPC pipe PDU into the response bytes (or nil to fail the op). Handles BIND /
/// ALTER_CONTEXT and REQUEST (srvsvc NetrShareEnum / NetrShareGetInfo / NetrServerGetInfo). Other opnums -> FAULT.
static NSData *_Nullable AMHandlePipeInput(AMSMB2Server *server, struct smb2_context *smb2,
                                           AMSMB2ServerOpenFile *file, NSData *input)
{
    const uint8_t *b = input.bytes;
    NSInteger len = (NSInteger)input.length;
    if (len < 16) {
        SMBSrvLog(@"pipe '%@' input too short (%ld bytes)", file.pipeName, (long)len);
        return nil;
    }

    uint8_t rpcVers = b[0];
    uint8_t ptype   = b[2];
    uint8_t drep0   = b[4];
    uint32_t callId = AMReadLE32(b + 12);
#if DEBUG
    SMBSrvLog(@"pipe '%@' <- ptype=%u vers=%u drep=0x%02x call_id=%u len=%ld | %@",
              file.pipeName, ptype, rpcVers, drep0, callId, (long)len, AMHexPreview(input, 64));
#endif
    if (rpcVers != 5) {
        SMBSrvLog(@"pipe '%@' unexpected rpc_vers=%u", file.pipeName, rpcVers);
    }
    if ((drep0 & 0x10) == 0) {
        SMBSrvLog(@"pipe '%@' WARNING big-endian NDR not supported (drep=0x%02x)", file.pipeName, drep0);
    }

    NSData *out = nil;

    if (ptype == AM_DCERPC_PT_BIND || ptype == AM_DCERPC_PT_ALTER_CONTEXT) {
        out = AMBuildBindAck(input, callId, ptype == AM_DCERPC_PT_ALTER_CONTEXT);
        SMBSrvLog(@"pipe '%@' -> %@ (%lu bytes)", file.pipeName,
                  ptype == AM_DCERPC_PT_ALTER_CONTEXT ? @"ALTER_CTX_RESP" : @"BIND_ACK",
                  (unsigned long)out.length);
    } else if (ptype == AM_DCERPC_PT_REQUEST) {
        if (len < 24) {
            SMBSrvLog(@"pipe '%@' REQUEST too short (%ld)", file.pipeName, (long)len);
            return nil;
        }
        uint16_t contextId = AMReadLE16(b + 20);
        uint16_t opnum     = AMReadLE16(b + 22);
        SMBSrvLog(@"pipe '%@' REQUEST opnum=0x%02x context_id=%u", file.pipeName, opnum, contextId);

        if (opnum == AM_SRVSVC_NETRSHAREENUM) {
            out = AMBuildShareEnumResponse(server, smb2, callId, contextId);
        } else if (opnum == AM_SRVSVC_NETRSHAREGETINFO) {
            out = AMBuildShareGetInfoResponse(server, smb2, callId, contextId);
        } else if (opnum == AM_SRVSVC_NETRSERVERGETINFO) {
            out = AMBuildServerGetInfoResponse(server, smb2, callId, contextId);
        } else {
            SMBSrvLog(@"pipe '%@' unsupported opnum 0x%02x -> FAULT", file.pipeName, opnum);
            out = AMBuildFault(callId, contextId, 0x1C010002 /* nca_op_rng_error */);
        }
        if (out) {
            SMBSrvLog(@"pipe '%@' -> RESPONSE opnum=0x%02x (%lu bytes)",
                      file.pipeName, opnum, (unsigned long)out.length);
        }
    } else {
        SMBSrvLog(@"pipe '%@' ignoring ptype=%u", file.pipeName, ptype);
        return nil;
    }

#if DEBUG
    if (out) { SMBSrvLog(@"pipe '%@' -> bytes: %@", file.pipeName, AMHexPreview(out, 96)); }
#endif
    return out;
}

#pragma mark - C handlers: tree

static int am_tree_connect(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_tree_connect_request *req, struct smb2_tree_connect_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        if (!server) {
            return -1;
        }
        NSString *shareName = server.shareName;
        if (req->path && req->path_length) {
            const char *utf8 = smb2_utf16_to_utf8(req->path, req->path_length / 2);
            if (utf8) {
                NSString *full = [NSString stringWithUTF8String:utf8];
                free((void *)utf8);
                // Path is \\server\share — take the trailing component.
                NSArray<NSString *> *parts = [full componentsSeparatedByString:@"\\"];
                shareName = parts.lastObject.length ? parts.lastObject : shareName;
            }
        }

        // IPC$ is the RPC endpoint tree (share enumeration via the srvsvc named pipe). It is not a
        // delegate-backed disk share, so answer it here as a PIPE tree without gating on the app's
        // connectToShare: (which only knows about the real disk share).
        if ([shareName caseInsensitiveCompare:@"IPC$"] == NSOrderedSame) {
            SMBSrvLog(@"tree_connect IPC$ -> SHARE_TYPE_PIPE");
            rep->share_type = SMB2_SHARE_TYPE_PIPE;
            rep->maximal_access = 0x001f00a9; // read/list/execute
            rep->share_flags = 0;
            rep->capabilities = 0;
            return 0;
        }

        id<AMSMB2ServerDelegate> delegate = server.delegate;
        if ([delegate respondsToSelector:@selector(server:connectToShare:)]) {
            if (![delegate server:server connectToShare:shareName]) {
                return -1;
            }
        }

        SMBSrvLog(@"tree_connect '%@' -> SHARE_TYPE_DISK", shareName);
        rep->share_type = SMB2_SHARE_TYPE_DISK;
        rep->maximal_access = 0x001f01ff; // full access
        rep->share_flags = 0;
        rep->capabilities = 0;
        return 0;
    }
}

static int am_tree_disconnect(struct smb2_server *srvr, struct smb2_context *smb2, const uint32_t tree_id)
{
    return 0;
}

#pragma mark - C handlers: create / close

static int am_create(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_create_request *req, struct smb2_create_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        if (!server || !delegate) {
            return -1;
        }
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:YES];

        NSString *path = AMPathFromCName(req->name);

        // A CREATE of a known RPC endpoint name (srvsvc, ...) is a named-pipe open on IPC$, NOT a
        // delegate file. Intercept it here so it is not forwarded to the app delegate (which would
        // try to open a real file called "srvsvc" and fail with ENOENT, blocking share browsing).
        NSString *pipeName = AMNamedPipeNameFromPath(path);
        if (pipeName) {
            AMSMB2ServerOpenFile *pfile = [[AMSMB2ServerOpenFile alloc] init];
            pfile.isPipe = YES;
            pfile.pipeName = pipeName;
            pfile.path = path;
            pfile.pipeReadBuffer = [NSMutableData data];
            pfile.info = [AMSMB2FileInfo fileInfoWithName:pipeName isDirectory:NO size:0];

            NSData *pipeId = nil;
            {
                uint8_t idbuf[SMB2_FD_SIZE];
                memset(idbuf, 0, sizeof(idbuf));
                uint64_t n = ++conn->_counter;
                memcpy(idbuf, &n, sizeof(n));
                memcpy(idbuf + 8, &conn->_salt, sizeof(conn->_salt));
                pipeId = [NSData dataWithBytes:idbuf length:SMB2_FD_SIZE];
            }
            conn.openFiles[pipeId] = pfile;
            conn.lastFileId = pipeId;

            // The generic IOCTL/READ reply encoders only ship raw output when the context is in
            // passthrough mode. On a read-only share passthrough is otherwise off, so enable it for
            // the pipe's lifetime (restored when the pipe closes) or share enumeration silently
            // returns nothing.
            smb2_set_passthrough(smb2, 1);

            memset(rep, 0, sizeof(*rep));
            rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
            rep->create_action = 1; // FILE_OPENED
            rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
            memcpy(rep->file_id, pipeId.bytes, SMB2_FD_SIZE);
            SMBSrvLog(@"create pipe '%@' -> file opened (passthrough on)", pipeName);
            return 0;
        }

        AMSMB2FileInfo *info = nil;
        NSError *err = nil;
        id handle = [delegate server:server
                      openItemAtPath:path
                       desiredAccess:req->desired_access
                         disposition:(AMSMB2CreateDisposition)req->create_disposition
                       createOptions:req->create_options
                          attributes:req->file_attributes
                            fileInfo:&info
                               error:&err];
        if (!handle) {
            // Propagate a POSIX errno so libsmb2 maps it to a specific NT status (e.g. EEXIST ->
            // STATUS_OBJECT_NAME_COLLISION for a create-disposition clash); else generic failure.
            if (err && [err.domain isEqualToString:NSPOSIXErrorDomain] && err.code > 0) {
                return (int)err.code;
            }
            return -1;
        }
        if (!info) {
            BOOL isDir = (req->create_options & SMB2_FILE_DIRECTORY_FILE) != 0;
            info = [AMSMB2FileInfo fileInfoWithName:path.lastPathComponent isDirectory:isDir size:0];
        }

        AMSMB2ServerOpenFile *file = [[AMSMB2ServerOpenFile alloc] init];
        file.handle = handle;
        file.path = path;
        file.info = info;
        file.deleteOnClose = (req->create_options & SMB2_FILE_DELETE_ON_CLOSE) != 0;

        NSData *fileId = nil;
        {
            uint8_t idbuf[SMB2_FD_SIZE];
            memset(idbuf, 0, sizeof(idbuf));
            uint64_t n = ++conn->_counter;
            memcpy(idbuf, &n, sizeof(n));
            memcpy(idbuf + 8, &conn->_salt, sizeof(conn->_salt));
            fileId = [NSData dataWithBytes:idbuf length:SMB2_FD_SIZE];
        }
        conn.openFiles[fileId] = file;
        conn.lastFileId = fileId; // resolves the compound_file_id sentinel

        memset(rep, 0, sizeof(*rep));
        rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        rep->create_action = (req->create_disposition == SMB2_FILE_CREATE) ? 2 /* FILE_CREATED */ : 1 /* FILE_OPENED */;
        rep->creation_time = AMWinTimeFromDate(info.creationDate);
        rep->last_access_time = AMWinTimeFromDate(info.lastAccessDate);
        rep->last_write_time = AMWinTimeFromDate(info.modificationDate);
        rep->change_time = AMWinTimeFromDate(info.modificationDate);
        rep->allocation_size = info.isDirectory ? 0 : info.allocationSize;
        rep->end_of_file = info.isDirectory ? 0 : info.fileSize;
        rep->file_attributes = AMAttributesFromInfo(info);
        memcpy(rep->file_id, fileId.bytes, SMB2_FD_SIZE);
        return 0;
    }
}

static int am_close(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_close_request *req, struct smb2_close_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        AMSMB2ServerOpenFile *file = AMFileForId(conn, req->file_id);

        memset(rep, 0, sizeof(*rep));

        if (file) {
            if (file.isPipe) {
                // Restore the context's passthrough state to the server default now the pipe is
                // done (it was forced on in am_create so the RPC reply could be shipped).
                smb2_set_passthrough(smb2, server.fullControlEnabled ? 1 : 0);
                SMBSrvLog(@"close pipe '%@' (passthrough restored to %@)",
                          file.pipeName, server.fullControlEnabled ? @"on" : @"off");
            }
            if (file.deleteOnClose && [delegate respondsToSelector:@selector(server:deleteItem:error:)]) {
                NSError *err = nil;
                [delegate server:server deleteItem:file.handle error:&err];
            }
            if (file.handle && [delegate respondsToSelector:@selector(server:closeItem:)]) {
                [delegate server:server closeItem:file.handle];
            }
            AMSMB2FileInfo *info = file.info;
            rep->creation_time = AMWinTimeFromDate(info.creationDate);
            rep->last_access_time = AMWinTimeFromDate(info.lastAccessDate);
            rep->last_write_time = AMWinTimeFromDate(info.modificationDate);
            rep->change_time = AMWinTimeFromDate(info.modificationDate);
            rep->allocation_size = info.isDirectory ? 0 : info.allocationSize;
            rep->end_of_file = info.isDirectory ? 0 : info.fileSize;
            rep->file_attributes = AMAttributesFromInfo(info);

            NSData *key = AMEffectiveKey(conn, req->file_id);
            if (key) {
                [conn.openFiles removeObjectForKey:key];
            }
        }
        return 0;
    }
}

static int am_flush(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_flush_request *req)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        AMSMB2ServerOpenFile *file = AMFileForId(conn, req->file_id);
        if (file && [delegate respondsToSelector:@selector(server:flushItem:error:)]) {
            NSError *err = nil;
            [delegate server:server flushItem:file.handle error:&err];
        }
        return 0;
    }
}

#pragma mark - C handlers: read / write

static int am_read(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_read_request *req, struct smb2_read_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        AMSMB2ServerOpenFile *file = AMFileForId(conn, req->file_id);
        if (!file) {
            return -1;
        }

        // Named-pipe READ: hand back the response bytes produced by the preceding TRANSCEIVE/WRITE
        // (the write-then-read RPC path some clients use instead of a single IOCTL).
        if (file.isPipe) {
            NSData *pending = file.pipeReadBuffer ?: [NSData data];
            uint32_t n = (uint32_t)MIN((NSUInteger)req->length, pending.length);
            rep->data_offset = 0;
            rep->data_remaining = 0;
            rep->data_length = n;
            if (n > 0) {
                rep->data = malloc(n);
                if (!rep->data) { return -1; }
                memcpy(rep->data, pending.bytes, n);
            } else {
                rep->data = NULL;
            }
            if (n < pending.length) {
                file.pipeReadBuffer = [[pending subdataWithRange:NSMakeRange(n, pending.length - n)] mutableCopy];
            } else {
                file.pipeReadBuffer = [NSMutableData data];
            }
            SMBSrvLog(@"pipe '%@' READ -> %u bytes (%lu remaining)",
                      file.pipeName, n, (unsigned long)file.pipeReadBuffer.length);
            return 0;
        }

        NSError *err = nil;
        NSData *data = [delegate server:server readFromItem:file.handle offset:req->offset length:req->length error:&err];
        if (!data) {
            return -1;
        }

        rep->data_offset = 0;
        rep->data_remaining = 0;
        rep->data_length = (uint32_t)data.length;
        if (data.length > 0) {
            // libsmb2 frees rep->data (its iovector free callback is free()).
            rep->data = malloc(data.length);
            if (!rep->data) {
                return -1;
            }
            memcpy(rep->data, data.bytes, data.length);
        } else {
            rep->data = NULL;
        }
        return 0;
    }
}

static int am_write(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_write_request *req, struct smb2_write_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        AMSMB2ServerOpenFile *file = AMFileForId(conn, req->file_id);
        if (!file) {
            return -1;
        }

        // Named-pipe WRITE: the client is sending a DCE/RPC request; process it now and stash the
        // response for the follow-up READ. Report the whole request as written.
        if (file.isPipe) {
            NSData *input = [NSData dataWithBytesNoCopy:(void *)req->buf length:req->length freeWhenDone:NO];
            NSData *output = AMHandlePipeInput(server, smb2, file, input);
            file.pipeReadBuffer = output ? [output mutableCopy] : [NSMutableData data];
            rep->count = req->length;
            rep->remaining = 0;
            SMBSrvLog(@"pipe '%@' WRITE %u bytes -> %lu response queued",
                      file.pipeName, req->length, (unsigned long)file.pipeReadBuffer.length);
            return 0;
        }

        NSData *data = [NSData dataWithBytesNoCopy:(void *)req->buf length:req->length freeWhenDone:NO];
        NSError *err = nil;
        NSInteger written = [delegate server:server writeToItem:file.handle offset:req->offset data:data error:&err];
        if (written < 0) {
            return -1;
        }

        // Keep cached size in sync so subsequent QUERY_INFO reflects the write.
        unsigned long long end = req->offset + (unsigned long long)written;
        if (!file.info.isDirectory && end > file.info.fileSize) {
            file.info.fileSize = end;
        }

        rep->count = (uint32_t)written;
        rep->remaining = 0;
        return 0;
    }
}

static int am_lock(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_lock_request *req)
{
    // Advisory byte-range locks are acknowledged but not enforced.
    return 0;
}

/// Build a symlink REPARSE_DATA_BUFFER (MS-FSCC 2.1.2.4) for FSCTL_GET_REPARSE_POINT. Substitute and
/// print names are both `target` (UTF-16LE); flags = SYMLINK_FLAG_RELATIVE. Path buffer starts at 20.
static NSData *AMBuildSymlinkReparseBuffer(NSString *target)
{
    NSData *name = [target dataUsingEncoding:NSUTF16LittleEndianStringEncoding] ?: [NSData data];
    uint16_t nameLen = (uint16_t)name.length;
    NSMutableData *d = [NSMutableData data];
    AMAppendLE32(d, SMB2_REPARSE_TAG_SYMLINK);                 // ReparseTag
    AMAppendLE16(d, (uint16_t)(12 + nameLen + nameLen));       // ReparseDataLength (symlink buffer)
    AMAppendLE16(d, 0);                                        // Reserved
    AMAppendLE16(d, 0);                                        // SubstituteNameOffset
    AMAppendLE16(d, nameLen);                                  // SubstituteNameLength
    AMAppendLE16(d, nameLen);                                  // PrintNameOffset
    AMAppendLE16(d, nameLen);                                  // PrintNameLength
    AMAppendLE32(d, 1);                                        // Flags = SYMLINK_FLAG_RELATIVE
    [d appendData:name];                                      // SubstituteName
    [d appendData:name];                                      // PrintName
    return d;
}

static int am_ioctl(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_ioctl_request *req, struct smb2_ioctl_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);

        // Named-pipe RPC transceive (Finder's share enumeration): input is a DCE/RPC PDU, output is
        // our response. Handled REGARDLESS of fullControlEnabled so read-only share browsing works.
        if (req->ctl_code == SMB2_FSCTL_PIPE_TRANSCEIVE) {
            AMSMB2ServerConnection *pconn = [server connectionForContext:smb2 create:NO];
            AMSMB2ServerOpenFile *pfile = AMFileForId(pconn, req->file_id);
            if (!pfile || !pfile.isPipe) {
                SMBSrvLog(@"ioctl PIPE_TRANSCEIVE on non-pipe handle -> reject");
                return -1;
            }
            NSData *input = [NSData dataWithBytesNoCopy:(void *)req->input length:req->input_count freeWhenDone:NO];
            NSData *output = AMHandlePipeInput(server, smb2, pfile, input);
            if (!output) {
                return -1;
            }
            memset(rep, 0, sizeof(*rep));
            rep->ctl_code = req->ctl_code;
            memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);
            pconn.pendingIoctlData = output; // keep the bytes alive until libsmb2 encodes the reply
            rep->output = (void *)output.bytes;
            rep->output_count = (uint32_t)output.length;
            return 0;
        }

        // VALIDATE_NEGOTIATE_INFO is handled inside libsmb2 before this point.
        // Server-side copy needs passthrough (the generic IOCTL reply encoder
        // only ships raw output in passthrough), so gate on fullControlEnabled.
        // Anything else → NOT_IMPLEMENTED, letting the client fall back.
        if (!server.fullControlEnabled) {
            return -1;
        }

        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        id<AMSMB2ServerDelegate> delegate = server.delegate;

        memset(rep, 0, sizeof(*rep));
        rep->ctl_code = req->ctl_code;
        memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);

        switch (req->ctl_code) {
            case SMB2_FSCTL_SRV_REQUEST_RESUME_KEY: {
                // Response: ResumeKey[24] + ContextLength(4)=0 + Reserved(4).
                // Encode the source file id into the key so COPYCHUNK can find it.
                uint8_t out[32];
                memset(out, 0, sizeof(out));
                memcpy(out, req->file_id, SMB2_FD_SIZE);
                NSData *data = [NSData dataWithBytes:out length:sizeof(out)];
                conn.pendingIoctlData = data;
                rep->output = (void *)data.bytes;
                rep->output_count = (uint32_t)data.length;
                return 0;
            }
            case SMB2_FSCTL_SRV_COPYCHUNK:
            case SMB2_FSCTL_SRV_COPYCHUNK_WRITE: {
                const uint8_t *in = (const uint8_t *)req->input;
                uint32_t inLen = req->input_count;
                if (!in || inLen < 32) {
                    return -1;
                }
                // SourceKey[24] + ChunkCount(4) + Reserved(4) + chunks[].
                AMSMB2ServerOpenFile *source = AMFileForId(conn, in); // key starts with file_id
                AMSMB2ServerOpenFile *dest = AMFileForId(conn, req->file_id);
                if (!source || !dest) {
                    return -1;
                }
                uint32_t chunkCount = AMReadLE32(in + 24);
                if (32 + (uint64_t)chunkCount * 24 > inLen) {
                    return -1;
                }

                BOOL hasCopier = [delegate respondsToSelector:@selector(server:copyChunkFromItem:sourceOffset:toItem:targetOffset:length:error:)];
                uint32_t chunksWritten = 0;
                uint64_t totalWritten = 0;
                for (uint32_t c = 0; c < chunkCount; c++) {
                    const uint8_t *ch = in + 32 + c * 24;
                    uint64_t srcOff = AMReadLE64(ch);
                    uint64_t tgtOff = AMReadLE64(ch + 8);
                    uint32_t length = AMReadLE32(ch + 16);

                    NSInteger written = -1;
                    NSError *err = nil;
                    if (hasCopier) {
                        written = [delegate server:server
                                 copyChunkFromItem:source.handle
                                      sourceOffset:srcOff
                                            toItem:dest.handle
                                      targetOffset:tgtOff
                                            length:length
                                             error:&err];
                    } else {
                        // Fallback: pull the bytes through read + write.
                        NSData *data = [delegate server:server readFromItem:source.handle offset:srcOff length:length error:&err];
                        if (data) {
                            written = [delegate server:server writeToItem:dest.handle offset:tgtOff data:data error:&err];
                        }
                    }
                    if (written < 0) {
                        return -1;
                    }
                    chunksWritten++;
                    totalWritten += (uint64_t)written;
                    uint64_t end = tgtOff + (uint64_t)written;
                    if (!dest.info.isDirectory && end > dest.info.fileSize) {
                        dest.info.fileSize = end;
                    }
                }

                // Response: ChunksWritten(4) + ChunkBytesWritten(4) + TotalBytesWritten(4).
                uint8_t out[12];
                AMWriteLE32(out + 0, chunksWritten);
                AMWriteLE32(out + 4, 0);
                AMWriteLE32(out + 8, (uint32_t)totalWritten);
                NSData *data = [NSData dataWithBytes:out length:sizeof(out)];
                conn.pendingIoctlData = data;
                rep->output = (void *)data.bytes;
                rep->output_count = (uint32_t)data.length;
                return 0;
            }
            case SMB2_FSCTL_SET_REPARSE_POINT: {
                // MS-FSCC 2.1.2.4: tag(4) datalen(2) reserved(2) then the symlink buffer
                // subOff(2) subLen(2) prnOff(2) prnLen(2) flags(4), then the path buffer @20.
                AMSMB2ServerOpenFile *lf = AMFileForId(conn, req->file_id);
                const uint8_t *in = (const uint8_t *)req->input;
                uint32_t inLen = req->input_count;
                if (!lf || !in || inLen < 20) { return -1; }
                if (AMReadLE32(in) != SMB2_REPARSE_TAG_SYMLINK) { return -1; }
                uint16_t subOff = AMReadLE16(in + 8), subLen = AMReadLE16(in + 10);
                if ((uint32_t)20 + subOff + subLen > inLen) { return -1; }
                NSString *target = [[NSString alloc] initWithBytes:in + 20 + subOff length:subLen
                                                          encoding:NSUTF16LittleEndianStringEncoding] ?: @"";
                if (![delegate respondsToSelector:@selector(server:createSymbolicLinkAtItem:withTarget:error:)]) {
                    return -1;
                }
                NSError *serr = nil;
                if (![delegate server:server createSymbolicLinkAtItem:lf.handle withTarget:target error:&serr]) {
                    return -1;
                }
                SMBSrvLog(@"SET_REPARSE '%@' -> symlink target '%@'", lf.path, target);
                lf.info.isSymbolicLink = YES;
                rep->output = NULL;           // SET_REPARSE_POINT has no output
                rep->output_count = 0;
                return 0;
            }
            case SMB2_FSCTL_GET_REPARSE_POINT: {
                AMSMB2ServerOpenFile *lf = AMFileForId(conn, req->file_id);
                if (!lf) { return -1; }
                if (![delegate respondsToSelector:@selector(server:symbolicLinkTargetForItem:error:)]) {
                    return -1;
                }
                NSError *gerr = nil;
                NSString *target = [delegate server:server symbolicLinkTargetForItem:lf.handle error:&gerr];
                if (!target) { return -1; }
                NSData *out = AMBuildSymlinkReparseBuffer(target);
                conn.pendingIoctlData = out;  // keep alive until libsmb2 encodes the reply (passthrough)
                rep->output = (void *)out.bytes;
                rep->output_count = (uint32_t)out.length;
                return 0;
            }
            default:
                return -1;
        }
    }
}

static int am_cancel(struct smb2_server *srvr, struct smb2_context *smb2)
{
    return 0;
}

static int am_echo(struct smb2_server *srvr, struct smb2_context *smb2)
{
    return 0;
}

#pragma mark - C handlers: query directory

/// Build an array of host `smb2_fileidbothdirectoryinformation` records for the
/// non-passthrough encoder. Names are appended after the record array in the
/// same allocation so a single free() releases everything; the encoder only
/// dereferences `fs->name`, which points into that trailing region.
static void *_Nullable AMBuildDirBuffer(NSArray<AMSMB2FileInfo *> *entries, uint32_t *outLength)
{
    const size_t recSize = AM_PAD_TO_64BIT(sizeof(struct smb2_fileidbothdirectoryinformation));
    size_t nameBytes = 0;
    for (AMSMB2FileInfo *info in entries) {
        nameBytes += strlen(info.name.UTF8String) + 1;
    }

    size_t total = entries.count * recSize + nameBytes;
    uint8_t *block = calloc(1, total > 0 ? total : 1);
    if (!block) {
        *outLength = 0;
        return NULL;
    }

    uint8_t *namePtr = block + entries.count * recSize;
    NSUInteger i = 0;
    for (AMSMB2FileInfo *info in entries) {
        struct smb2_fileidbothdirectoryinformation *fs =
            (struct smb2_fileidbothdirectoryinformation *)(void *)(block + i * recSize);
        fs->next_entry_offset = 0; // encoder computes the wire offsets itself
        fs->file_index = (uint32_t)i;
        fs->creation_time = AMTimevalFromDate(info.creationDate);
        fs->last_access_time = AMTimevalFromDate(info.lastAccessDate);
        fs->last_write_time = AMTimevalFromDate(info.modificationDate);
        fs->change_time = AMTimevalFromDate(info.modificationDate);
        fs->end_of_file = info.isDirectory ? 0 : info.fileSize;
        fs->allocation_size = info.isDirectory ? 0 : info.allocationSize;
        fs->file_attributes = AMAttributesFromInfo(info);
        fs->ea_size = 0;
        fs->short_name_length = 0;
        fs->file_id = (uint64_t)(i + 1);

        const char *nm = info.name.UTF8String;
        size_t len = strlen(nm) + 1;
        memcpy(namePtr, nm, len);
        fs->name = (const char *)namePtr;
        namePtr += len;
        i++;
    }

    *outLength = (uint32_t)(entries.count * recSize);
    return block;
}

/// Fixed (name-excluded) size of one directory-info record per info class.
static size_t AMDirFixedSize(uint8_t infoClass)
{
    switch (infoClass) {
        case SMB2_FILE_DIRECTORY_INFORMATION:         return 64;  // 0x01
        case SMB2_FILE_FULL_DIRECTORY_INFORMATION:    return 68;  // 0x02
        case SMB2_FILE_BOTH_DIRECTORY_INFORMATION:    return 94;  // 0x03
        case SMB2_FILE_NAMES_INFORMATION:             return 12;  // 0x0C
        case SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION: return 104; // 0x25
        case SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION: return 80;  // 0x26
        default:                                      return 0;
    }
}

/// Build raw SMB2 directory-listing wire records for passthrough mode. Emits
/// entries starting at *ioCursor, honoring the client's byte budget and 8-byte
/// record alignment with correct NextEntryOffset chaining. Layouts follow
/// MS-FSCC (cross-checked against libsmb2's own client-side decoders and the
/// go-smb-server / SMBLibrary references).
static NSData *_Nullable AMBuildDirWire(uint8_t infoClass, NSArray<AMSMB2FileInfo *> *entries, NSUInteger *ioCursor, uint32_t budget, BOOL singleEntry)
{
    size_t fixed = AMDirFixedSize(infoClass);
    if (fixed == 0) {
        return nil; // unsupported info class
    }

    NSMutableData *out = [NSMutableData data];
    NSMutableArray<NSNumber *> *starts = [NSMutableArray array];
    NSUInteger i = *ioCursor;

    while (i < entries.count) {
        AMSMB2FileInfo *info = entries[i];
        NSData *nameU16 = [info.name dataUsingEncoding:NSUTF16LittleEndianStringEncoding] ?: [NSData data];
        size_t nameLen = nameU16.length;
        size_t recPad = ((fixed + nameLen) + 7) & ~(size_t)7;

        if (out.length > 0 && budget > 0 && out.length + recPad > budget) {
            break;
        }

        size_t start = out.length;
        [starts addObject:@(start)];
        [out increaseLengthBy:recPad];
        uint8_t *p = (uint8_t *)out.mutableBytes + start;

        // FileIndex must be 0 unless the server supports index-based resume;
        // strict clients (macOS) reject non-zero values. (NEO filled below.)
        AMWriteLE32(p + 4, 0);

        if (infoClass == SMB2_FILE_NAMES_INFORMATION) {
            AMWriteLE32(p + 8, (uint32_t)nameLen);
            if (nameLen) {
                memcpy(p + 12, nameU16.bytes, nameLen);
            }
        } else {
            AMWriteLE64(p + 8, AMWinTimeFromDate(info.creationDate));
            AMWriteLE64(p + 16, AMWinTimeFromDate(info.lastAccessDate));
            AMWriteLE64(p + 24, AMWinTimeFromDate(info.modificationDate));
            AMWriteLE64(p + 32, AMWinTimeFromDate(info.modificationDate));
            AMWriteLE64(p + 40, info.isDirectory ? 0 : info.fileSize);
            AMWriteLE64(p + 48, info.isDirectory ? 0 : info.allocationSize);
            AMWriteLE32(p + 56, AMAttributesFromInfo(info));
            AMWriteLE32(p + 60, (uint32_t)nameLen);
            // FileId (file reference number) must be 0 unless it is a stable,
            // per-file identifier; a per-listing index confuses clients' name
            // caches (macOS maps every lookup to the first entry). Match known-
            // good servers and leave it 0 (clients then key on the name).
            uint64_t fileId = 0;
            switch (infoClass) {
                case SMB2_FILE_DIRECTORY_INFORMATION:
                    if (nameLen) memcpy(p + 64, nameU16.bytes, nameLen);
                    break;
                case SMB2_FILE_FULL_DIRECTORY_INFORMATION:
                    // EaSize @64 stays 0.
                    if (nameLen) memcpy(p + 68, nameU16.bytes, nameLen);
                    break;
                case SMB2_FILE_BOTH_DIRECTORY_INFORMATION:
                    // EaSize @64, ShortNameLength @68, ShortName @70..93 stay 0.
                    if (nameLen) memcpy(p + 94, nameU16.bytes, nameLen);
                    break;
                case SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION:
                    AMWriteLE64(p + 96, fileId); // FileId (unique, non-zero)
                    if (nameLen) memcpy(p + 104, nameU16.bytes, nameLen);
                    break;
                case SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION:
                    // EaSize @64, Reserved @68 stay 0.
                    AMWriteLE64(p + 72, fileId);
                    if (nameLen) memcpy(p + 80, nameU16.bytes, nameLen);
                    break;
                default:
                    break;
            }
        }

        i++;
        if (singleEntry) {
            break;
        }
    }

    for (NSUInteger k = 0; k < starts.count; k++) {
        size_t s = starts[k].unsignedLongValue;
        uint32_t neo = (k + 1 < starts.count) ? (uint32_t)(starts[k + 1].unsignedLongValue - s) : 0;
        AMWriteLE32((uint8_t *)out.mutableBytes + s, neo);
    }

    *ioCursor = i;
    return out.length > 0 ? out : nil;
}

static int am_query_directory(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_query_directory_request *req, struct smb2_query_directory_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        AMSMB2ServerOpenFile *file = AMFileForId(conn, req->file_id);
        if (!file) {
            return -1;
        }

        // Enumerate the backing store once per handle; RESTART_SCAN only rewinds
        // the cursor (it must not re-hit the delegate on every call, and some
        // clients set it on each request).
        if (!file.dirEnumerated) {
            NSError *err = nil;
            NSString *pattern = (req->name && req->name[0]) ? AMPathFromCName(req->name) : nil;
            NSArray<AMSMB2FileInfo *> *children = [delegate server:server enumerateItem:file.handle pattern:pattern error:&err];
            if (!children) {
                return -1;
            }
            // Honor the search pattern. Clients (macOS especially) resolve a
            // single path by opening the directory and querying with the leaf
            // name as the pattern; a server that ignores it and returns every
            // entry makes the client take the first entry as the match — so
            // every lookup resolves to the wrong file. Filter here (SMB is
            // case-insensitive; '*' and '?' are wildcards) unless the delegate
            // already narrowed the result.
            if (pattern.length && ![pattern isEqualToString:@"*"]) {
                NSPredicate *pred = [NSPredicate predicateWithFormat:@"name LIKE[c] %@", pattern];
                children = [children filteredArrayUsingPredicate:pred];
            }
            // Note: "." and ".." are intentionally NOT synthesized — clients
            // (macOS kernel VFS, Windows) provide them, and injecting our own
            // can make strict clients reject the whole listing.
            file.dirEntries = children;
            file.dirCursor = 0;
            file.dirEnumerated = YES;
        }
        if ((req->flags & SL_RESTART_SCAN) != 0) {
            file.dirCursor = 0;
        }

        // Free the buffer produced by the previous query on this connection.
        if (conn->_pendingDirBuffer) {
            free(conn->_pendingDirBuffer);
            conn->_pendingDirBuffer = NULL;
        }
        conn.pendingDirData = nil;

        NSArray<AMSMB2FileInfo *> *entries = file.dirEntries;
        if (file.dirCursor >= entries.count) {
            rep->output_buffer = NULL;
            rep->output_buffer_length = 0; // libsmb2 returns STATUS_NO_MORE_FILES
            return 0;
        }

        // Ignore SL_RETURN_SINGLE_ENTRY and fill the buffer (matches known-good
        // servers); the enumerate-once + cursor state terminates the scan.
        BOOL singleEntry = NO;
        uint32_t budget = req->output_buffer_length;

        if (server.fullControlEnabled) {
            // Passthrough mode: libsmb2 ships our bytes verbatim, so emit raw
            // wire records for the exact info class the client requested.
            NSUInteger cursor = file.dirCursor;
            NSData *wire = AMBuildDirWire(req->file_information_class, entries, &cursor, budget, singleEntry);
            file.dirCursor = cursor;
            if (!wire) {
                rep->output_buffer = NULL;
                rep->output_buffer_length = 0;
                return 0;
            }
            conn.pendingDirData = wire;
            rep->output_buffer = (uint8_t *)wire.bytes;
            rep->output_buffer_length = (uint32_t)wire.length;
            return 0;
        }

        // Default mode: hand libsmb2 host structs and let it serialize.
        NSMutableArray<AMSMB2FileInfo *> *chunk = [NSMutableArray array];
        uint32_t used = 0;
        while (file.dirCursor < entries.count) {
            AMSMB2FileInfo *info = entries[file.dirCursor];
            uint32_t utf16len = (uint32_t)([info.name lengthOfBytesUsingEncoding:NSUTF16LittleEndianStringEncoding]);
            uint32_t wireSize = (uint32_t)AM_PAD_TO_32BIT(SMB2_FILEID_BOTH_DIRECTORY_INFORMATION_SIZE + utf16len);
            if (chunk.count > 0 && budget > 0 && used + wireSize > budget) {
                break;
            }
            [chunk addObject:info];
            used += wireSize;
            file.dirCursor++;
            if (singleEntry) {
                break;
            }
        }

        uint32_t length = 0;
        void *buffer = AMBuildDirBuffer(chunk, &length);
        conn->_pendingDirBuffer = buffer;
        rep->output_buffer = buffer;
        rep->output_buffer_length = length;
        return 0;
    }
}

#pragma mark - C handlers: query info

static int am_query_info(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_query_info_request *req, struct smb2_query_info_reply *rep)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        AMSMB2ServerOpenFile *file = AMFileForId(conn, req->file_id);

        AMSMB2FileInfo *info = file.info;
        if (file && [delegate respondsToSelector:@selector(server:infoForItem:error:)]) {
            NSError *err = nil;
            AMSMB2FileInfo *fresh = [delegate server:server infoForItem:file.handle error:&err];
            if (fresh) {
                info = fresh;
            }
        }
        if (!info) {
            // Fallback for compound/unknown ids: treat as the share root.
            info = [AMSMB2FileInfo fileInfoWithName:server.shareName isDirectory:YES size:0];
        }

        if (conn->_pendingInfoBuffer) {
            free(conn->_pendingInfoBuffer);
            conn->_pendingInfoBuffer = NULL;
        }

        void *buffer = NULL;
        int length = 0;

        if (req->info_type == SMB2_0_INFO_FILE) {
            switch (req->file_info_class) {
                case SMB2_FILE_BASIC_INFORMATION: {
                    struct smb2_file_basic_info *fs = calloc(1, sizeof(*fs));
                    fs->creation_time = AMTimevalFromDate(info.creationDate);
                    fs->last_access_time = AMTimevalFromDate(info.lastAccessDate);
                    fs->last_write_time = AMTimevalFromDate(info.modificationDate);
                    fs->change_time = AMTimevalFromDate(info.modificationDate);
                    fs->file_attributes = AMAttributesFromInfo(info);
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_STANDARD_INFORMATION: {
                    struct smb2_file_standard_info *fs = calloc(1, sizeof(*fs));
                    fs->allocation_size = info.isDirectory ? 0 : info.allocationSize;
                    fs->end_of_file = info.isDirectory ? 0 : info.fileSize;
                    fs->number_of_links = 1;
                    fs->delete_pending = file.deleteOnClose ? 1 : 0;
                    fs->directory = info.isDirectory ? 1 : 0;
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_NETWORK_OPEN_INFORMATION: {
                    struct smb2_file_network_open_info *fs = calloc(1, sizeof(*fs));
                    fs->creation_time = AMTimevalFromDate(info.creationDate);
                    fs->last_access_time = AMTimevalFromDate(info.lastAccessDate);
                    fs->last_write_time = AMTimevalFromDate(info.modificationDate);
                    fs->change_time = AMTimevalFromDate(info.modificationDate);
                    fs->allocation_size = info.isDirectory ? 0 : info.allocationSize;
                    fs->end_of_file = info.isDirectory ? 0 : info.fileSize;
                    fs->file_attributes = AMAttributesFromInfo(info);
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_ALL_INFORMATION: {
                    struct smb2_file_all_info *fs = calloc(1, sizeof(*fs));
                    fs->basic.creation_time = AMTimevalFromDate(info.creationDate);
                    fs->basic.last_access_time = AMTimevalFromDate(info.lastAccessDate);
                    fs->basic.last_write_time = AMTimevalFromDate(info.modificationDate);
                    fs->basic.change_time = AMTimevalFromDate(info.modificationDate);
                    fs->basic.file_attributes = AMAttributesFromInfo(info);
                    fs->standard.allocation_size = info.isDirectory ? 0 : info.allocationSize;
                    fs->standard.end_of_file = info.isDirectory ? 0 : info.fileSize;
                    fs->standard.number_of_links = 1;
                    fs->standard.delete_pending = file.deleteOnClose ? 1 : 0;
                    fs->standard.directory = info.isDirectory ? 1 : 0;
                    fs->index_number = 0;
                    fs->ea_size = 0;
                    fs->access_flags = 0x001f01ff;
                    fs->current_byte_offset = 0;
                    fs->mode = 0;
                    fs->alignment_requirement = 0;
                    fs->name = (const uint8_t *)"";
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_ATTRIBUTE_TAG_INFORMATION: {
                    struct smb2_file_attribute_tag_info *fs = calloc(1, sizeof(*fs));
                    fs->file_attributes = AMAttributesFromInfo(info);
                    fs->reparse_tag = info.isSymbolicLink ? SMB2_REPARSE_TAG_SYMLINK : 0;
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                default:
                    break;
            }
        } else if (req->info_type == SMB2_0_INFO_FILESYSTEM) {
            switch (req->file_info_class) {
                case SMB2_FILE_FS_SIZE_INFORMATION: {
                    struct smb2_file_fs_size_info *fs = calloc(1, sizeof(*fs));
                    fs->total_allocation_units = 0x100000;
                    fs->available_allocation_units = 0x80000;
                    fs->sectors_per_allocation_unit = 1;
                    fs->bytes_per_sector = 512;
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_FS_DEVICE_INFORMATION: {
                    struct smb2_file_fs_device_info *fs = calloc(1, sizeof(*fs));
                    fs->device_type = FILE_DEVICE_DISK;
                    fs->characteristics = 0;
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_FS_ATTRIBUTE_INFORMATION: {
                    struct smb2_file_fs_attribute_info *fs = calloc(1, sizeof(*fs));
                    fs->filesystem_attributes = 0x02; // FILE_CASE_PRESERVED_NAMES
                    fs->maximum_component_name_length = 255;
                    fs->filesystem_name = (uint8_t *)"AMSMB2";
                    fs->filesystem_name_length = (uint32_t)strlen((char *)fs->filesystem_name);
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_FS_VOLUME_INFORMATION: {
                    // Provides the volume name Finder shows for the share. The
                    // encoder reads volume_label as a UTF-8 C string and keeps it
                    // alive only until this reply is encoded, so pack the label
                    // into the same allocation and point at it.
                    NSData *label = [server.shareName dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
                    struct smb2_file_fs_volume_info *fs = calloc(1, sizeof(*fs) + label.length + 1);
                    uint8_t *labelBytes = (uint8_t *)fs + sizeof(*fs);
                    if (label.length) {
                        memcpy(labelBytes, label.bytes, label.length);
                    }
                    fs->creation_time = AMTimevalFromDate([NSDate dateWithTimeIntervalSince1970:0]);
                    fs->volume_serial_number = 0x414D5342; // "AMSB"
                    fs->supports_objects = 0;
                    fs->reserved = 0;
                    fs->volume_label = labelBytes;
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_FS_FULL_SIZE_INFORMATION: {
                    // Free/total space for Finder's capacity bar (~512 MB free).
                    struct smb2_file_fs_full_size_info *fs = calloc(1, sizeof(*fs));
                    fs->total_allocation_units = 0x100000;
                    fs->caller_available_allocation_units = 0x80000;
                    fs->actual_available_allocation_units = 0x80000;
                    fs->sectors_per_allocation_unit = 1;
                    fs->bytes_per_sector = 512;
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                case SMB2_FILE_FS_SECTOR_SIZE_INFORMATION: {
                    struct smb2_file_fs_sector_size_info *fs = calloc(1, sizeof(*fs));
                    fs->logical_bytes_per_sector = 512;
                    fs->physical_bytes_per_sector_for_atomicity = 512;
                    fs->physical_bytes_per_sector_for_performance = 512;
                    fs->file_system_effective_physical_bytes_per_sector_for_atomicity = 512;
                    fs->flags = 0;
                    fs->byte_offset_for_sector_alignment = 0;
                    fs->byte_offset_for_partition_alignment = 0;
                    buffer = fs;
                    length = sizeof(*fs);
                    break;
                }
                default:
                    break;
            }
        } else if (req->info_type == SMB2_0_INFO_SECURITY && server.fullControlEnabled) {
            // A minimal self-relative security descriptor granting Everyone full
            // control, so Finder shows the share as writable. Raw bytes are only
            // shippable in passthrough mode (fullControlEnabled).
            NSData *sd = AMEveryoneFullControlSecurityDescriptor();
            void *buf = malloc(sd.length);
            if (buf) {
                memcpy(buf, sd.bytes, sd.length);
                buffer = buf;
                length = (int)sd.length;
            }
        }

        if (!buffer || length <= 0) {
            rep->output_buffer = NULL;
            rep->output_buffer_length = 0; // libsmb2 returns STATUS_NOT_SUPPORTED
            return 0;
        }

        conn->_pendingInfoBuffer = buffer;
        rep->output_buffer = buffer;
        rep->output_buffer_length = length;
        return 0;
    }
}

#pragma mark - C handlers: set info (fullControl / passthrough only)

static int am_set_info(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_set_info_request *req)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        id<AMSMB2ServerDelegate> delegate = server.delegate;
        AMSMB2ServerConnection *conn = [server connectionForContext:smb2 create:NO];
        AMSMB2ServerOpenFile *file = AMFileForId(conn, req->file_id);
        if (!file) {
            return -1;
        }
        if (req->info_type != SMB2_0_INFO_FILE) {
            return 0; // accept filesystem/security sets as no-ops
        }

        const uint8_t *buf = (const uint8_t *)req->input_data;
        uint32_t len = req->buffer_length;
        if (!buf) {
            return -1;
        }

        switch (req->file_info_class) {
            case SMB2_FILE_RENAME_INFORMATION: {
                // ReplaceIfExists(1) Reserved(7) RootDirectory(8) NameLen(4)@16 Name@20 (UTF-16LE)
                if (len < 20) {
                    return -1;
                }
                BOOL replace = buf[0] != 0;
                uint32_t nameLen = AMReadLE32(buf + 16);
                if ((uint64_t)20 + nameLen > len) {
                    return -1;
                }
                NSString *newPath = [[NSString alloc] initWithBytes:buf + 20 length:nameLen encoding:NSUTF16LittleEndianStringEncoding] ?: @"";
                newPath = [newPath stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
                if (![delegate respondsToSelector:@selector(server:renameItem:toPath:replaceExisting:error:)]) {
                    return -1;
                }
                NSError *err = nil;
                if (![delegate server:server renameItem:file.handle toPath:newPath replaceExisting:replace error:&err]) {
                    return -1;
                }
                file.path = newPath;
                file.info.name = newPath.lastPathComponent;
                return 0;
            }
            case SMB2_FILE_DISPOSITION_INFORMATION: {
                // DeletePending(1). Deletion is deferred to close (MS-SMB2).
                if (len < 1) {
                    return -1;
                }
                file.deleteOnClose = buf[0] != 0;
                return 0;
            }
            case SMB2_FILE_END_OF_FILE_INFORMATION: {
                if (len < 8) {
                    return -1;
                }
                uint64_t eof = AMReadLE64(buf);
                if ([delegate respondsToSelector:@selector(server:setEndOfFile:forItem:error:)]) {
                    NSError *err = nil;
                    if (![delegate server:server setEndOfFile:eof forItem:file.handle error:&err]) {
                        return -1;
                    }
                }
                if (!file.info.isDirectory) {
                    file.info.fileSize = eof;
                }
                return 0;
            }
            case SMB2_FILE_ALLOCATION_INFORMATION: {
                // Allocation size is advisory; accept without action.
                return 0;
            }
            case SMB2_FILE_BASIC_INFORMATION: {
                // 4x FILETIME (creation/access/write/change) + FileAttributes.
                if (len < 36) {
                    return -1;
                }
                NSDate *creation = AMDateFromWinTime(AMReadLE64(buf + 0));
                NSDate *access = AMDateFromWinTime(AMReadLE64(buf + 8));
                NSDate *write = AMDateFromWinTime(AMReadLE64(buf + 16));
                uint32_t attrs = AMReadLE32(buf + 32);
                NSNumber *attrsNum = attrs ? @(attrs) : nil;
                if ([delegate respondsToSelector:@selector(server:updateItem:creationDate:modificationDate:accessDate:attributes:error:)]) {
                    NSError *err = nil;
                    if (![delegate server:server updateItem:file.handle creationDate:creation modificationDate:write accessDate:access attributes:attrsNum error:&err]) {
                        return -1;
                    }
                }
                if (creation) file.info.creationDate = creation;
                if (write) file.info.modificationDate = write;
                if (access) file.info.lastAccessDate = access;
                return 0;
            }
            default:
                return 0; // accept unrecognized sets silently
        }
    }
}

#pragma mark - C handlers: lifecycle callbacks

static int am_destruction_event(struct smb2_server *srvr, struct smb2_context *smb2)
{
    @autoreleasepool {
        AMSMB2Server *server = AMServerFromContext(srvr);
        [server removeConnectionForContext:smb2];
        return 0;
    }
}

static void am_on_error(struct smb2_context *smb2, const char *error_string)
{
    // Hook for diagnostics; intentionally quiet.
    (void)smb2;
    (void)error_string;
}

static void am_on_new_client(struct smb2_context *smb2, void *cb_data)
{
    @autoreleasepool {
        AMSMB2Server *server = (__bridge AMSMB2Server *)cb_data;
        smb2_set_version(smb2, SMB2_VERSION_ANY);
        smb2_register_error_callback(smb2, am_on_error);
        if (server.fullControlEnabled) {
            // Required so libsmb2 accepts SET_INFO (rename/disposition/EOF/basic).
            smb2_set_passthrough(smb2, 1);
        }
        [server connectionForContext:smb2 create:YES];
    }
}

NS_ASSUME_NONNULL_END
