//
//  AMSMB2Server.h
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//
//  Public, Foundation-only interface for hosting an SMB2/3 server backed by
//  libsmb2's server-side API (smb2_serve_port). The backing store is supplied
//  by the app through the AMSMB2ServerDelegate protocol, so the server can
//  expose any content source (local files, a database, a cloud store, an
//  in-memory tree, …) without AMSMB2 imposing a filesystem.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Maps directly to the SMB2 CreateDisposition field of a CREATE request.
typedef NS_ENUM(NSInteger, AMSMB2CreateDisposition) {
    /// Replace the file if it exists, otherwise create it.
    AMSMB2CreateDispositionSupersede = 0,
    /// Open an existing file; fail if it does not exist.
    AMSMB2CreateDispositionOpen = 1,
    /// Create a new file; fail if it already exists.
    AMSMB2CreateDispositionCreate = 2,
    /// Open the file if it exists, otherwise create it.
    AMSMB2CreateDispositionOpenIf = 3,
    /// Open and truncate an existing file; fail if it does not exist.
    AMSMB2CreateDispositionOverwrite = 4,
    /// Open and truncate the file if it exists, otherwise create it.
    AMSMB2CreateDispositionOverwriteIf = 5,
};

#pragma mark - AMSMB2FileInfo

/// Metadata describing a file or directory that the delegate exposes to clients.
///
/// The delegate returns instances of this class from `openItemAtPath:…`,
/// `enumerateItem:…` and `infoForItem:…`. Only `name` and `isDirectory` are
/// required; timestamps and flags are optional and default to sensible values.
@interface AMSMB2FileInfo : NSObject

/// The leaf name of the item (no path separators).
@property (nonatomic, copy) NSString *name;
/// Whether the item is a directory.
@property (nonatomic) BOOL isDirectory;
/// The logical size of the file in bytes. Ignored for directories.
@property (nonatomic) unsigned long long fileSize;
/// Allocation (on-disk) size in bytes. Defaults to `fileSize` when zero.
@property (nonatomic) unsigned long long allocationSize;
/// Creation timestamp. `nil` reports an epoch time to the client.
@property (nonatomic, nullable, copy) NSDate *creationDate;
/// Last modification timestamp.
@property (nonatomic, nullable, copy) NSDate *modificationDate;
/// Last access timestamp.
@property (nonatomic, nullable, copy) NSDate *lastAccessDate;
/// Marks the item read-only (FILE_ATTRIBUTE_READONLY).
@property (nonatomic) BOOL isReadOnly;
/// Marks the item hidden (FILE_ATTRIBUTE_HIDDEN).
@property (nonatomic) BOOL isHidden;
/// Marks the item a symbolic link / reparse point (FILE_ATTRIBUTE_REPARSE_POINT, tag SYMLINK).
@property (nonatomic) BOOL isSymbolicLink;
/// Stable, unique file reference number (the inode on a real filesystem). Emitted as the FileId in
/// directory listings. A non-zero, per-file-stable value lets clients (macOS in particular) cache each
/// entry by reference number instead of re-querying every file individually. 0 = unknown (FileId omitted).
@property (nonatomic) uint64_t fileIdentifier;

+ (instancetype)fileInfoWithName:(NSString *)name
                     isDirectory:(BOOL)isDirectory
                            size:(unsigned long long)size;

@end

#pragma mark - AMSMB2ServerDelegate

@class AMSMB2Server;

/// Backing store for an ``AMSMB2Server``. All callbacks are invoked on the
/// server's private serve queue; implementations must be thread-safe with
/// respect to any state they share with other queues.
///
/// A handle is any non-nil object the delegate returns from
/// `openItemAtPath:…`; AMSMB2 treats it as an opaque token and passes it back
/// on subsequent read/write/enumerate/info/close callbacks for the same open.
@protocol AMSMB2ServerDelegate <NSObject>

@required

#pragma mark Open / close

/// Open or create the item at `path` (share-relative, '/'-separated).
///
/// Return an opaque, non-nil handle on success. On failure return `nil` and
/// optionally populate `*error`; the client receives an access/other error.
/// When `outInfo` is non-NULL, set `*outInfo` to describe the opened item so
/// the client's CREATE response carries correct size/attributes/timestamps.
- (nullable id)server:(AMSMB2Server *)server
       openItemAtPath:(NSString *)path
        desiredAccess:(uint32_t)desiredAccess
          disposition:(AMSMB2CreateDisposition)disposition
        createOptions:(uint32_t)createOptions
           attributes:(uint32_t)attributes
             fileInfo:(AMSMB2FileInfo *_Nullable *_Nullable)outInfo
                error:(NSError *_Nullable *_Nullable)error;

/// Release a handle previously returned from `openItemAtPath:…`.
- (void)server:(AMSMB2Server *)server closeItem:(id)handle;

#pragma mark I/O

/// Read up to `length` bytes at `offset`. Returning fewer bytes signals EOF.
/// Return `nil` and optionally set `*error` on failure.
- (nullable NSData *)server:(AMSMB2Server *)server
               readFromItem:(id)handle
                     offset:(unsigned long long)offset
                     length:(uint32_t)length
                      error:(NSError *_Nullable *_Nullable)error;

/// Write `data` at `offset`. Return the number of bytes written, or a negative
/// value on failure (optionally set `*error`).
- (NSInteger)server:(AMSMB2Server *)server
        writeToItem:(id)handle
             offset:(unsigned long long)offset
               data:(NSData *)data
              error:(NSError *_Nullable *_Nullable)error;

#pragma mark Enumeration & metadata

/// Return the children of the directory `handle`. Do not include "." or ".." —
/// AMSMB2 synthesizes them. `pattern` is the client's search mask (often "*").
/// Return `nil` and optionally set `*error` on failure.
- (nullable NSArray<AMSMB2FileInfo *> *)server:(AMSMB2Server *)server
                                 enumerateItem:(id)handle
                                       pattern:(nullable NSString *)pattern
                                         error:(NSError *_Nullable *_Nullable)error;

/// Return fresh metadata for an open `handle` (used to answer QUERY_INFO).
- (nullable AMSMB2FileInfo *)server:(AMSMB2Server *)server
                        infoForItem:(id)handle
                              error:(NSError *_Nullable *_Nullable)error;

@optional

#pragma mark Connection lifecycle

/// Asked once per new TCP connection, before any protocol exchange, whether to accept the client at
/// `address` (the peer IP, or nil if it can't be determined). Return NO to drop the connection immediately
/// (e.g. a blocked device). If not implemented, all connections are accepted. Called on the serve queue.
/// Optional.
- (BOOL)server:(AMSMB2Server *)server shouldAcceptClientFromAddress:(nullable NSString *)address;

/// A client TCP connection was accepted (before authentication). `address` is the peer IP (IPv4 or IPv6),
/// or nil when it can't be determined. Pairs 1:1 with `server:clientDidDisconnectFromAddress:` (the same
/// address is reported at disconnect). Called on the server's serve queue. Optional.
- (void)server:(AMSMB2Server *)server clientDidConnectFromAddress:(nullable NSString *)address;

/// A client connection was torn down. `address` is the same peer IP reported at connect. Called on the
/// server's serve queue. Optional.
- (void)server:(AMSMB2Server *)server clientDidDisconnectFromAddress:(nullable NSString *)address;

/// A client identified itself during SMB session-setup. `workstation` is the client's computer name from the
/// NTLM authenticate message (SMB has no HTTP-style User-Agent, so this is the best human-readable client
/// label); `user` is the account name (nil/empty for anonymous/guest). `address` is the peer IP. Any may be
/// nil, and it may not be sent at all (e.g. some anonymous connections). Called on the serve queue. Optional.
- (void)server:(AMSMB2Server *)server
    clientDidIdentifyFromAddress:(nullable NSString *)address
                     workstation:(nullable NSString *)workstation
                            user:(nullable NSString *)user;

#pragma mark Authentication

/// Authorize a session. `user` is `nil` for an anonymous attempt. Return `YES`
/// to allow the session to proceed. If not implemented, access is governed by
/// `allowsAnonymousAccess` and the `username`/`password` properties.
///
/// Note: SMB never sends the plaintext password to the server; libsmb2
/// cryptographically validates the client's NTLM response against the password
/// supplied by `server:passwordForUser:` (or the `password` property). This
/// hook therefore authorizes the *user name*, not the password.
- (BOOL)server:(AMSMB2Server *)server
    authenticateUser:(nullable NSString *)user
              domain:(nullable NSString *)domain
         workstation:(nullable NSString *)workstation;

/// Supply the password used to validate `user`'s NTLM response. Return `nil` to
/// reject the user (unless anonymous access is allowed). Overrides the
/// `password` property when implemented.
- (nullable NSString *)server:(AMSMB2Server *)server passwordForUser:(NSString *)user;

/// Called on TREE_CONNECT. Return `YES` if `shareName` should be accessible.
/// If not implemented, a connection to the configured `shareName` is allowed.
- (BOOL)server:(AMSMB2Server *)server connectToShare:(NSString *)shareName;

#pragma mark Mutations

/// Delete the item backing `handle`. Invoked at close time when the client
/// opened the item with FILE_DELETE_ON_CLOSE, or when a client marks the item
/// for deletion via SET_INFO (only in `fullControlEnabled` mode). Return `YES`
/// on success.
- (BOOL)server:(AMSMB2Server *)server
    deleteItem:(id)handle
         error:(NSError *_Nullable *_Nullable)error;

/// Flush buffered writes for `handle`. Return `YES` on success.
- (BOOL)server:(AMSMB2Server *)server
     flushItem:(id)handle
         error:(NSError *_Nullable *_Nullable)error;

#pragma mark Full-control mutations (require fullControlEnabled)

/// Rename/move the item backing `handle` to `newPath` (share-relative,
/// '/'-separated). `replaceExisting` mirrors the client's ReplaceIfExists flag.
/// Only invoked when `fullControlEnabled` is set. Return `YES` on success.
- (BOOL)server:(AMSMB2Server *)server
    renameItem:(id)handle
        toPath:(NSString *)newPath
replaceExisting:(BOOL)replaceExisting
         error:(NSError *_Nullable *_Nullable)error;

/// Truncate or extend the item backing `handle` to `length` bytes (SMB2
/// SetEndOfFile). Only invoked when `fullControlEnabled` is set. Return `YES`
/// on success.
- (BOOL)server:(AMSMB2Server *)server
  setEndOfFile:(unsigned long long)length
       forItem:(id)handle
         error:(NSError *_Nullable *_Nullable)error;

/// Update timestamps and/or attributes of `handle` (SMB2 FileBasicInformation).
/// A `nil` date or `nil` attributes argument means "leave unchanged" (the
/// client sent 0). Only invoked when `fullControlEnabled` is set. Return `YES`
/// on success.
- (BOOL)server:(AMSMB2Server *)server
    updateItem:(id)handle
  creationDate:(nullable NSDate *)creationDate
modificationDate:(nullable NSDate *)modificationDate
    accessDate:(nullable NSDate *)accessDate
    attributes:(nullable NSNumber *)attributes
         error:(NSError *_Nullable *_Nullable)error;

/// Turn `handle` (an already-created placeholder file) into a symbolic link pointing at `target`
/// (a share-relative or absolute path, as the client sent it). Invoked for FSCTL_SET_REPARSE_POINT
/// with a symlink reparse tag. Only invoked when `fullControlEnabled` is set. Return `YES` on success.
- (BOOL)server:(AMSMB2Server *)server
createSymbolicLinkAtItem:(id)handle
    withTarget:(NSString *)target
         error:(NSError *_Nullable *_Nullable)error;

/// Return the target path of the symbolic link `handle` points at (for FSCTL_GET_REPARSE_POINT /
/// destinationOfSymbolicLink), or nil on failure.
- (nullable NSString *)server:(AMSMB2Server *)server
     symbolicLinkTargetForItem:(id)handle
                         error:(NSError *_Nullable *_Nullable)error;

/// Server-side copy of one chunk (SMB2 FSCTL_SRV_COPYCHUNK), letting a backend
/// copy without round-tripping bytes through the client (e.g. APFS clonefile).
/// Return the number of bytes copied, or a negative value on failure. If not
/// implemented, AMSMB2 falls back to `readFromItem:` + `writeToItem:`. Only
/// invoked when `fullControlEnabled` is set.
- (NSInteger)server:(AMSMB2Server *)server
  copyChunkFromItem:(id)sourceHandle
       sourceOffset:(unsigned long long)sourceOffset
             toItem:(id)destinationHandle
       targetOffset:(unsigned long long)targetOffset
             length:(uint32_t)length
              error:(NSError *_Nullable *_Nullable)error;

@end

#pragma mark - AMSMB2Server

/// An SMB2/3 server that listens on a TCP port and dispatches protocol
/// requests to its ``delegate``. Wraps libsmb2's `smb2_serve_port` loop on a
/// private background queue.
///
/// - Note: The standard SMB port is 445, which requires elevated privileges on
///   Apple platforms; use a high port (e.g. 4455) in sandboxed apps and mount
///   with `smb://host:4455/share`.
@interface AMSMB2Server : NSObject

/// TCP port the server listens on.
@property (nonatomic, readonly) uint16_t port;
/// Name of the single share this server exposes.
@property (nonatomic, copy, readonly) NSString *shareName;
/// The backing store. Weak; the caller owns the delegate's lifetime.
@property (nonatomic, weak, nullable) id<AMSMB2ServerDelegate> delegate;

/// Allow unauthenticated (anonymous) sessions. Default `NO`.
@property (nonatomic) BOOL allowsAnonymousAccess;
/// Whether SMB signing is offered/required. Default `YES`.
@property (nonatomic) BOOL signingEnabled;
/// When `YES` the server REQUIRES SMB3 encryption (seal) on every PDU after
/// session setup. Needs an authenticated (non-anonymous) session and a
/// negotiated 3.x dialect, so it cannot be combined with anonymous access.
/// Default `NO`.
@property (nonatomic) BOOL encryptionEnabled;
/// Enables write-side mutation via SMB2 SET_INFO: **rename**, delete-by-
/// disposition, truncate (SetEndOfFile) and timestamp/attribute updates.
///
/// libsmb2 only accepts SET_INFO in "passthrough" mode, which also requires the
/// server to hand-build directory-listing wire records; AMSMB2 handles both
/// when this is set. Default `NO` (the streamlined browse/read/write/create
/// path). Set before calling `startAndReturnError:`. When enabled, implement
/// the "Full-control mutations" delegate methods to back the operations.
@property (nonatomic) BOOL fullControlEnabled;
/// Convenience single-account user name. Used by the default authenticator
/// when the delegate does not implement `server:passwordForUser:`.
@property (nonatomic, nullable, copy) NSString *username;
/// Password for `username`. See `server:passwordForUser:` for the security note.
@property (nonatomic, nullable, copy) NSString *password;
/// Host name announced to clients. Defaults to the device host name.
@property (nonatomic, nullable, copy) NSString *hostName;
/// Whether the serve loop is currently running.
@property (nonatomic, readonly, getter=isRunning) BOOL running;

- (instancetype)initWithPort:(uint16_t)port
                   shareName:(NSString *)shareName
                    delegate:(nullable id<AMSMB2ServerDelegate>)delegate NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

/// Bind, listen and start serving on a background queue. Returns `YES` once the
/// listening socket is up, or `NO` (with `*error`) if the bind/listen fails.
- (BOOL)startAndReturnError:(NSError *_Nullable *_Nullable)error;

/// Stop serving and close the listening socket. Blocks until the serve loop
/// has exited. Safe to call when not running.
- (void)stop;

@end

NS_ASSUME_NONNULL_END
