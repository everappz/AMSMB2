//
//  SMB2Client.m
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import "SMB2Client.h"
#import "SMB2Helpers.h"
#import "SMB2FileHandle.h"
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <smb2/smb2-errors.h>
#include <smb2/libsmb2-dcerpc-srvsvc.h>
#include <poll.h>

#pragma mark - Callback Data

typedef struct {
    int32_t result;
    BOOL isFinished;
    void (^__unsafe_unretained dataHandler)(void *_Nullable);
} SMB2CBData;

static void smb2_generic_handler(struct smb2_context *smb2, int status, void *command_data, void *cbdata) {
    if (!smb2 || smb2_get_fd(smb2) < 0) return;
    SMB2CBData *cb = (SMB2CBData *)cbdata;
    if (!cb) return;
    if (status != 0) {
        cb->result = status;
    }
    if (cb->dataHandler) {
        cb->dataHandler(command_data);
    }
    cb->isFinished = YES;
}

#pragma mark - SMB2Client

@implementation SMB2Client {
    struct smb2_context *_context;
    NSRecursiveLock *_contextLock;
    // Local storage for properties without public getters in libsmb2.
    NSString *_server;
    NSString *_share;
    NSString *_password;
    uint16_t _securityMode;
    BOOL _seal;
    int32_t _authentication;
}

#pragma mark - Lifecycle

- (nullable instancetype)initWithTimeout:(NSTimeInterval)timeout error:(NSError **)error {
    self = [super init];
    if (!self) return nil;

    _context = smb2_init_context();
    if (!_context) {
        if (error) *error = SMB2POSIXError(ENOMEM, @"Failed to create SMB2 context.");
        return nil;
    }

    _contextLock = [[NSRecursiveLock alloc] init];
    _timeout = timeout;

    return self;
}

- (void)dealloc {
    if (_context) {
        if (self.isConnected) {
            [self disconnectWithError:nil];
        }
        [_contextLock lock];
        struct smb2_context *ctx = _context;
        _context = NULL;
        smb2_destroy_context(ctx);
        [_contextLock unlock];
    }
}

#pragma mark - Properties

- (struct smb2_context *)rawContext {
    return _context;
}

- (BOOL)isConnected {
    return self.fileDescriptor != -1;
}

- (int32_t)fileDescriptor {
    if (!_context) return -1;
    return (int32_t)smb2_get_fd(_context);
}

- (NSString *)server {
    return _server;
}

- (NSString *)share {
    return _share;
}

- (NSInteger)maximumTransactionSize {
    if (!_context) return 65535;
    uint32_t readSize = smb2_get_max_read_size(_context);
    return readSize > 0 ? (NSInteger)readSize : 65535;
}

- (NSString *)workstation {
    if (_context) {
        const char *ws = smb2_get_workstation(_context);
        if (ws) return [NSString stringWithUTF8String:ws];
    }
    return @"";
}

- (void)setWorkstation:(NSString *)workstation {
    [_contextLock lock];
    if (_context) {
        smb2_set_workstation(_context, [workstation UTF8String]);
    }
    [_contextLock unlock];
}

- (NSString *)domain {
    if (_context) {
        const char *d = smb2_get_domain(_context);
        if (d) return [NSString stringWithUTF8String:d];
    }
    return @"";
}

- (void)setDomain:(NSString *)domain {
    [_contextLock lock];
    if (_context) {
        smb2_set_domain(_context, [domain UTF8String]);
    }
    [_contextLock unlock];
}

- (NSString *)user {
    if (_context) {
        const char *u = smb2_get_user(_context);
        if (u) return [NSString stringWithUTF8String:u];
    }
    return @"";
}

- (void)setUser:(NSString *)user {
    [_contextLock lock];
    if (_context) {
        smb2_set_user(_context, [user UTF8String]);
    }
    [_contextLock unlock];
}

- (NSString *)password {
    return _password ?: @"";
}

- (void)setPassword:(NSString *)password {
    [_contextLock lock];
    _password = [password copy];
    if (_context) {
        smb2_set_password(_context, password.length > 0 ? [password UTF8String] : NULL);
    }
    [_contextLock unlock];
}

- (int32_t)authentication {
    return _authentication;
}

- (void)setAuthentication:(int32_t)authentication {
    _authentication = authentication;
    if (_context) {
        smb2_set_authentication(_context, authentication);
    }
}

- (uint16_t)securityMode {
    return _securityMode;
}

- (void)setSecurityMode:(uint16_t)securityMode {
    _securityMode = securityMode;
    if (_context) {
        smb2_set_security_mode(_context, securityMode);
    }
}

- (BOOL)seal {
    return _seal;
}

- (void)setSeal:(BOOL)seal {
    _seal = seal;
    if (_context) {
        smb2_set_seal(_context, seal ? 1 : 0);
    }
}

- (BOOL)passthrough {
    int32_t result = 0;
    if (_context) {
        smb2_get_passthrough(_context, &result);
    }
    return result != 0;
}

- (void)setPassthrough:(BOOL)passthrough {
    if (_context) {
        smb2_set_passthrough(_context, passthrough ? 1 : 0);
    }
}

#pragma mark - Thread-safe Context Access

- (BOOL)withContext:(BOOL (^)(struct smb2_context *))handler error:(NSError **)error {
    [_contextLock lock];
    @try {
        if (!_context) {
            if (error) *error = SMB2POSIXError(ENODATA, @"Invalid/Empty data.");
            return NO;
        }
        return handler(_context);
    } @finally {
        [_contextLock unlock];
    }
}

#pragma mark - Wait for Reply

- (BOOL)waitForReply:(SMB2CBData *)cb error:(NSError **)error {
    NSDate *startDate = [NSDate date];
    while (!cb->isFinished) {
        struct pollfd pfd = {0};
        pfd.fd = self.fileDescriptor;
        pfd.events = (short)smb2_which_events(_context);

        if (pfd.fd < 0 || (poll(&pfd, 1, 1000) < 0 && errno != EAGAIN)) {
            if (error) {
                NSString *desc = smb2_get_error(_context)
                    ? [NSString stringWithUTF8String:smb2_get_error(_context)]
                    : nil;
                *error = SMB2POSIXError(errno, desc);
            }
            return NO;
        }

        if (pfd.revents == 0) {
            if (self.timeout > 0 && [[NSDate date] timeIntervalSinceDate:startDate] > self.timeout) {
                if (error) *error = SMB2POSIXError(ETIMEDOUT, nil);
                return NO;
            }
            continue;
        }

        int32_t serviceResult = smb2_service(_context, (int32_t)pfd.revents);
        if (serviceResult < 0) {
            smb2_destroy_context(_context);
            _context = NULL;
            if (error) {
                *error = SMB2POSIXError((int32_t)(-serviceResult), nil);
            }
            return NO;
        }
    }
    return YES;
}

#pragma mark - Async/Await

- (int32_t)asyncAwait:(int32_t (^)(struct smb2_context *, void *))handler error:(NSError **)error {
    return [self asyncAwaitWithDataHandler:nil execute:handler error:error];
}

- (int32_t)asyncAwaitWithDataHandler:(void (^)(void *))dataHandler
                             execute:(int32_t (^)(struct smb2_context *, void *))handler
                               error:(NSError **)error {
    [_contextLock lock];
    @try {
        if (!_context) {
            if (error) *error = SMB2POSIXError(ENODATA, @"Invalid/Empty data.");
            return -1;
        }

        SMB2CBData cb = {0};
        cb.dataHandler = dataHandler;

        int32_t result = handler(_context, &cb);
        if (result < 0) {
            NSString *errStr = smb2_get_error(_context)
                ? [NSString stringWithUTF8String:smb2_get_error(_context)]
                : nil;
            if (error) *error = SMB2POSIXErrorFromResult(result, errStr);
            return result;
        }

        if (![self waitForReply:&cb error:error]) {
            return -1;
        }

        if (cb.result != 0) {
            uint32_t ntStatus = (uint32_t)cb.result;
            NSError *ntError = SMB2POSIXErrorFromNTStatus(ntStatus);
            if (ntError && error) *error = ntError;
            return cb.result;
        }

        return cb.result;
    } @finally {
        [_contextLock unlock];
    }
}

- (uint32_t)asyncAwaitPDU:(struct smb2_pdu *(^)(struct smb2_context *, void *))handler error:(NSError **)error {
    return [self asyncAwaitPDUWithDataHandler:nil execute:handler error:error];
}

- (uint32_t)asyncAwaitPDUWithDataHandler:(void (^)(void *))dataHandler
                                 execute:(struct smb2_pdu *(^)(struct smb2_context *, void *))handler
                                   error:(NSError **)error {
    [_contextLock lock];
    @try {
        if (!_context) {
            if (error) *error = SMB2POSIXError(ENODATA, @"Invalid/Empty data.");
            return (uint32_t)-1;
        }

        SMB2CBData cb = {0};
        cb.dataHandler = dataHandler;

        struct smb2_pdu *pdu = handler(_context, &cb);
        if (!pdu) {
            if (error) *error = SMB2POSIXError(ENODATA, @"Invalid/Empty data.");
            return (uint32_t)-1;
        }

        smb2_queue_pdu(_context, pdu);

        if (![self waitForReply:&cb error:error]) {
            return (uint32_t)-1;
        }

        uint32_t status = (uint32_t)cb.result;
        if ((status & 0xC0000000) == 0xC0000000) {
            NSError *ntError = SMB2POSIXErrorFromNTStatus(status);
            if (ntError && error) *error = ntError;
        }

        return status;
    } @finally {
        [_contextLock unlock];
    }
}

+ (smb2_command_cb)genericHandler {
    return smb2_generic_handler;
}

#pragma mark - Connectivity

- (BOOL)connectServer:(NSString *)server share:(NSString *)share user:(NSString *)user error:(NSError **)error {
    _server = [server copy];
    _share = [share copy];

    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_connect_share_async(context,
                                        [server UTF8String],
                                        [share UTF8String],
                                        [user UTF8String],
                                        smb2_generic_handler,
                                        cbPtr);
    } error:error];
    return result >= 0;
}

- (BOOL)disconnectWithError:(NSError **)error {
    [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_disconnect_share_async(context, smb2_generic_handler, cbPtr);
    } error:error];
    return YES;
}

- (BOOL)echoWithError:(NSError **)error {
    if (!self.isConnected) {
        if (error) *error = SMB2POSIXError(ENOTCONN, nil);
        return NO;
    }
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_echo_async(context, smb2_generic_handler, cbPtr);
    } error:error];
    return result >= 0;
}

#pragma mark - Share Enum

- (NSArray<NSDictionary *> *)shareEnumWithError:(NSError **)error {
    __block NSMutableArray<NSDictionary *> *shares = nil;
    __block struct smb2_context *capturedContext = nil;
    __block void *capturedData = nil;

    int32_t result = [self asyncAwaitWithDataHandler:^(void *commandData) {
        if (!commandData) return;
        capturedData = commandData;
        struct srvsvc_NetrShareEnum_rep *rep = (struct srvsvc_NetrShareEnum_rep *)commandData;
        struct srvsvc_SHARE_ENUM_STRUCT *ses = &rep->ses;

        if (ses->Level != 1) return;

        struct srvsvc_SHARE_INFO_1_CONTAINER *container = &ses->ShareInfo.Level1;
        if (!container->Buffer || !container->Buffer->share_info_1) return;

        uint32_t count = container->EntriesRead;
        shares = [[NSMutableArray alloc] initWithCapacity:count];

        for (uint32_t i = 0; i < count; i++) {
            struct srvsvc_SHARE_INFO_1 *info = &container->Buffer->share_info_1[i];
            NSString *name = info->netname.utf8
                ? [NSString stringWithUTF8String:info->netname.utf8]
                : @"";
            NSString *comment = info->remark.utf8
                ? [NSString stringWithUTF8String:info->remark.utf8]
                : @"";
            NSNumber *type = @(info->type);

            [shares addObject:@{
                @"name": name,
                @"comment": comment,
                @"type": type,
            }];
        }
    } execute:^int32_t(struct smb2_context *context, void *cbPtr) {
        capturedContext = context;
        return smb2_share_enum_async(context, SHARE_INFO_1, smb2_generic_handler, cbPtr);
    } error:error];

    if (capturedData && capturedContext) {
        smb2_free_data(capturedContext, capturedData);
    }

    if (result < 0) {
        return nil;
    }

    return shares;
}

- (NSArray<NSDictionary *> *)shareEnumSwiftWithError:(NSError **)error {
    SMB2FileHandle *srvsvc = [[SMB2FileHandle alloc] initWithPath:@"srvsvc"
                                                    desiredAccess:0x0012019F // GENERIC_READ | GENERIC_WRITE
                                                      shareAccess:0x00000007
                                                createDisposition:0x00000001 // FILE_OPEN
                                                    createOptions:0
                                                               on:self
                                                            error:error];
    if (!srvsvc) return nil;

    // Write bind data
    NSData *bindData = SMB2MSRPCBuildSrvsvcBindData();
    if ([srvsvc writeData:bindData error:error] < 0) {
        [srvsvc close];
        return nil;
    }

    // Read bind response
    NSData *recvBindData = [srvsvc preadOffset:0 length:(NSInteger)INT16_MAX error:error];
    if (!recvBindData) {
        [srvsvc close];
        return nil;
    }

    if (!SMB2MSRPCValidateBindResponse(recvBindData, error)) {
        [srvsvc close];
        return nil;
    }

    // Write NetShareEnumAll request
    NSString *serverName = self.server ?: @"";
    NSData *enumRequest = SMB2MSRPCBuildNetShareEnumAllRequest(serverName);
    if ([srvsvc pwriteData:enumRequest offset:0 error:error] < 0) {
        [srvsvc close];
        return nil;
    }

    // Read response
    NSData *recvData = [srvsvc preadOffset:0 length:(NSInteger)INT16_MAX error:error];
    [srvsvc close];

    if (!recvData) {
        return nil;
    }

    return SMB2MSRPCParseNetShareEnumAllResponse(recvData, error);
}

#pragma mark - File Information

- (BOOL)stat:(NSString *)path result:(struct smb2_stat_64 *)st error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_stat_async(context, [canonical UTF8String], st, smb2_generic_handler, cbPtr);
    } error:error];
    return result >= 0;
}

- (BOOL)statvfs:(NSString *)path result:(struct smb2_statvfs *)st error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_statvfs_async(context, [canonical UTF8String], st, smb2_generic_handler, cbPtr);
    } error:error];
    return result >= 0;
}

- (NSString *)readlink:(NSString *)path error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    __block NSString *linkTarget = nil;

    int32_t result = [self asyncAwaitWithDataHandler:^(void *commandData) {
        if (commandData) {
            const char *target = (const char *)commandData;
            linkTarget = [NSString stringWithUTF8String:target];
        }
    } execute:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_readlink_async(context, [canonical UTF8String], smb2_generic_handler, cbPtr);
    } error:error];

    if (result < 0) {
        return nil;
    }

    return linkTarget;
}

- (BOOL)symlink:(NSString *)path to:(NSString *)destination error:(NSError **)error {
    // O_RDWR | O_CREAT | O_EXCL | O_SYMLINK | O_SYNC
    int32_t flags = O_RDWR | O_CREAT | O_EXCL | O_SYMLINK | O_SYNC;
    SMB2FileHandle *file = [[SMB2FileHandle alloc] initWithPath:path flags:flags on:self error:error];
    if (!file) return NO;

    NSData *reparseData = SMB2IOCtlBuildSymbolicLinkReparse(destination, YES);
    BOOL success = [file setReparsePoint:reparseData error:error];
    [file close];
    return success;
}

#pragma mark - File Operations

- (BOOL)mkdir:(NSString *)path error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_mkdir_async(context, [canonical UTF8String], smb2_generic_handler, cbPtr);
    } error:error];
    return result >= 0;
}

- (BOOL)rmdir:(NSString *)path error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_rmdir_async(context, [canonical UTF8String], smb2_generic_handler, cbPtr);
    } error:error];
    return result >= 0;
}

- (BOOL)unlink:(NSString *)path error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_unlink_async(context, [canonical UTF8String], smb2_generic_handler, cbPtr);
    } error:error];
    return result >= 0;
}

- (BOOL)unlinkSymlink:(NSString *)path error:(NSError **)error {
    // Open as reparse point: O_RDWR | O_SYMLINK
    int32_t flags = O_RDWR | O_SYMLINK;
    SMB2FileHandle *file = [[SMB2FileHandle alloc] initWithPath:path flags:flags on:self error:error];
    if (!file) return NO;

    BOOL success = [file setDeletePendingWithError:error];
    [file close];
    return success;
}

- (BOOL)rename:(NSString *)path to:(NSString *)newPath error:(NSError **)error {
    NSString *canonicalOld = SMB2CanonicalPath(path);
    NSString *canonicalNew = SMB2CanonicalPath(newPath);
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_rename_async(context,
                                 [canonicalOld UTF8String],
                                 [canonicalNew UTF8String],
                                 smb2_generic_handler,
                                 cbPtr);
    } error:error];
    return result >= 0;
}

- (BOOL)truncate:(NSString *)path toLength:(uint64_t)length error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    int32_t result = [self asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_truncate_async(context, [canonical UTF8String], length, smb2_generic_handler, cbPtr);
    } error:error];
    return result >= 0;
}

@end
