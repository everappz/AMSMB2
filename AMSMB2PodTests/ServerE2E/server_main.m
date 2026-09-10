#import <Foundation/Foundation.h>
#import "AMSMB2Server.h"
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

// A filesystem-backed delegate over a temp directory — the smallest real
// backing store to prove the wrapper end-to-end.
@interface FSHandle : NSObject
@property (nonatomic, copy) NSString *disk;
@property (nonatomic, copy) NSString *rel;
@property (nonatomic) BOOL isDir;
@property (nonatomic, strong) NSFileHandle *fh;
@end
@implementation FSHandle
@end

@interface FSDelegate : NSObject <AMSMB2ServerDelegate>
@property (nonatomic, copy) NSString *root;
@end

@implementation FSDelegate

- (AMSMB2FileInfo *)infoForDisk:(NSString *)disk name:(NSString *)name
{
    // Detect symlinks with lstat (do NOT follow) so they report as reparse points.
    struct stat lst;
    if (lstat(disk.fileSystemRepresentation, &lst) == 0 && S_ISLNK(lst.st_mode)) {
        AMSMB2FileInfo *fi = [AMSMB2FileInfo fileInfoWithName:(name ?: @"") isDirectory:NO size:0];
        fi.isSymbolicLink = YES;
        fi.modificationDate = [NSDate dateWithTimeIntervalSince1970:lst.st_mtimespec.tv_sec];
        fi.creationDate = fi.modificationDate;
        fi.lastAccessDate = fi.modificationDate;
        return fi;
    }

    NSFileManager *fm = NSFileManager.defaultManager;
    BOOL isDir = NO;
    BOOL exists = [fm fileExistsAtPath:disk isDirectory:&isDir];
    AMSMB2FileInfo *fi = [AMSMB2FileInfo fileInfoWithName:(name ?: @"") isDirectory:isDir size:0];
    if (exists) {
        NSDictionary *a = [fm attributesOfItemAtPath:disk error:nil];
        fi.fileSize = isDir ? 0 : a.fileSize;
        fi.modificationDate = a.fileModificationDate;
        fi.creationDate = a[NSFileCreationDate] ?: a.fileModificationDate;
        fi.lastAccessDate = a.fileModificationDate;
    }
    return fi;
}

- (id)server:(AMSMB2Server *)server openItemAtPath:(NSString *)path desiredAccess:(uint32_t)da
 disposition:(AMSMB2CreateDisposition)disp createOptions:(uint32_t)opts attributes:(uint32_t)attr
    fileInfo:(AMSMB2FileInfo **)outInfo error:(NSError **)error
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *rel = path ?: @"";
    NSString *disk = rel.length ? [self.root stringByAppendingPathComponent:rel] : self.root;

    // Existing symlink: open the LINK itself (lstat, do NOT follow) so it can be read
    // (GET_REPARSE_POINT) or deleted even when dangling. Following it (fileExistsAtPath) would fail
    // for a dangling link and leak it. Exclusive-create over an existing name still collides.
    struct stat lst;
    if (lstat(disk.fileSystemRepresentation, &lst) == 0 && S_ISLNK(lst.st_mode)) {
        if (disp == AMSMB2CreateDispositionCreate) {
            if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EEXIST userInfo:nil];
            return nil;
        }
        FSHandle *sh = [FSHandle new];
        sh.disk = disk; sh.rel = rel; sh.isDir = NO; sh.fh = nil;
        if (outInfo) *outInfo = [self infoForDisk:disk name:rel.lastPathComponent];
        return sh;
    }

    BOOL isDir = NO;
    BOOL exists = [fm fileExistsAtPath:disk isDirectory:&isDir];
    BOOL wantDir = (opts & 0x00000001) != 0; // FILE_DIRECTORY_FILE

    FSHandle *h = [FSHandle new];
    h.disk = disk;
    h.rel = rel;

    if (exists && isDir) {
        h.isDir = YES;
        if (outInfo) *outInfo = [self infoForDisk:disk name:rel.lastPathComponent];
        return h;
    }
    if (wantDir) {
        if (!exists) {
            if (disp == AMSMB2CreateDispositionCreate || disp == AMSMB2CreateDispositionOpenIf ||
                disp == AMSMB2CreateDispositionOverwriteIf || disp == AMSMB2CreateDispositionSupersede) {
                if (![fm createDirectoryAtPath:disk withIntermediateDirectories:NO attributes:nil error:error]) {
                    return nil;
                }
            } else {
                return nil;
            }
        }
        h.isDir = YES;
        if (outInfo) *outInfo = [self infoForDisk:disk name:rel.lastPathComponent];
        return h;
    }

    switch (disp) {
        case AMSMB2CreateDispositionOpen:
            if (!exists) { if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:ENOENT userInfo:nil]; return nil; }
            break;
        case AMSMB2CreateDispositionCreate:
            if (exists)  { if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EEXIST userInfo:nil]; return nil; }
            break;
        case AMSMB2CreateDispositionOverwrite:
            if (!exists) { if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:ENOENT userInfo:nil]; return nil; }
            break;
        default: break;
    }
    if (!exists) {
        [fm createFileAtPath:disk contents:nil attributes:nil];
    } else if (disp == AMSMB2CreateDispositionOverwrite || disp == AMSMB2CreateDispositionOverwriteIf ||
               disp == AMSMB2CreateDispositionSupersede) {
        [[NSData data] writeToFile:disk atomically:NO];
    }
    h.fh = [NSFileHandle fileHandleForUpdatingAtPath:disk];
    if (!h.fh) return nil;
    if (outInfo) *outInfo = [self infoForDisk:disk name:rel.lastPathComponent];
    return h;
}

- (void)server:(AMSMB2Server *)s closeItem:(id)handle
{
    FSHandle *h = handle;
    [h.fh closeFile];
    h.fh = nil;
}

- (NSData *)server:(AMSMB2Server *)s readFromItem:(id)handle offset:(unsigned long long)off length:(uint32_t)len error:(NSError **)e
{
    FSHandle *h = handle;
    if (!h.fh) return [NSData data];
    @try { [h.fh seekToFileOffset:off]; return [h.fh readDataOfLength:len] ?: [NSData data]; }
    @catch (__unused NSException *ex) { return [NSData data]; }
}

- (NSInteger)server:(AMSMB2Server *)s writeToItem:(id)handle offset:(unsigned long long)off data:(NSData *)data error:(NSError **)e
{
    FSHandle *h = handle;
    if (!h.fh) return -1;
    @try { [h.fh seekToFileOffset:off]; [h.fh writeData:data]; return (NSInteger)data.length; }
    @catch (__unused NSException *ex) { return -1; }
}

- (NSArray<AMSMB2FileInfo *> *)server:(AMSMB2Server *)s enumerateItem:(id)handle pattern:(NSString *)pat error:(NSError **)e
{
    FSHandle *h = handle;
    NSArray *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:h.disk error:e];
    if (!names) return nil;
    NSMutableArray *r = [NSMutableArray array];
    for (NSString *n in names) {
        [r addObject:[self infoForDisk:[h.disk stringByAppendingPathComponent:n] name:n]];
    }
    return r;
}

- (AMSMB2FileInfo *)server:(AMSMB2Server *)s infoForItem:(id)handle error:(NSError **)e
{
    FSHandle *h = handle;
    return [self infoForDisk:h.disk name:h.rel.lastPathComponent];
}

- (BOOL)server:(AMSMB2Server *)s deleteItem:(id)handle error:(NSError **)e
{
    FSHandle *h = handle;
    return [NSFileManager.defaultManager removeItemAtPath:h.disk error:e];
}

- (BOOL)server:(AMSMB2Server *)s renameItem:(id)handle toPath:(NSString *)np replaceExisting:(BOOL)rep error:(NSError **)e
{
    FSHandle *h = handle;
    NSString *nd = [self.root stringByAppendingPathComponent:np];
    NSFileManager *fm = NSFileManager.defaultManager;
    if (rep && [fm fileExistsAtPath:nd]) [fm removeItemAtPath:nd error:nil];
    BOOL ok = [fm moveItemAtPath:h.disk toPath:nd error:e];
    if (ok) { h.disk = nd; h.rel = np; }
    return ok;
}

- (BOOL)server:(AMSMB2Server *)s setEndOfFile:(unsigned long long)len forItem:(id)handle error:(NSError **)e
{
    FSHandle *h = handle;
    @try { [h.fh truncateFileAtOffset:len]; return YES; }
    @catch (__unused NSException *ex) { return NO; }
}

- (BOOL)server:(AMSMB2Server *)s flushItem:(id)handle error:(NSError **)e
{
    FSHandle *h = handle;
    @try { [h.fh synchronizeFile]; } @catch (__unused NSException *ex) {}
    return YES;
}

// FSCTL_SET_REPARSE_POINT: replace the just-created placeholder file with a POSIX symlink.
- (BOOL)server:(AMSMB2Server *)s createSymbolicLinkAtItem:(id)handle
    withTarget:(NSString *)target error:(NSError **)e
{
    FSHandle *h = handle;
    [h.fh closeFile]; h.fh = nil;
    [NSFileManager.defaultManager removeItemAtPath:h.disk error:nil]; // drop the CREATE placeholder
    if (symlink(target.fileSystemRepresentation, h.disk.fileSystemRepresentation) != 0) {
        if (e) *e = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return NO;
    }
    return YES;
}

// FSCTL_GET_REPARSE_POINT: read the symlink target (do not follow).
- (NSString *)server:(AMSMB2Server *)s symbolicLinkTargetForItem:(id)handle error:(NSError **)e
{
    FSHandle *h = handle;
    char buf[4096];
    ssize_t n = readlink(h.disk.fileSystemRepresentation, buf, sizeof(buf) - 1);
    if (n < 0) {
        if (e) *e = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return nil;
    }
    buf[n] = '\0';
    return [NSString stringWithUTF8String:buf];
}

// SET_INFO FileBasicInformation: persist the timestamps the client set (nil = leave unchanged).
- (BOOL)server:(AMSMB2Server *)s updateItem:(id)handle
  creationDate:(NSDate *)creationDate modificationDate:(NSDate *)modificationDate
    accessDate:(NSDate *)accessDate attributes:(NSNumber *)attributes error:(NSError **)e
{
    FSHandle *h = handle;
    (void)accessDate; (void)attributes; // no NSFileManager keys for access-date/attributes here
    NSMutableDictionary *attrs = [NSMutableDictionary dictionary];
    if (creationDate) attrs[NSFileCreationDate] = creationDate;
    if (modificationDate) attrs[NSFileModificationDate] = modificationDate;
    if (attrs.count == 0) return YES;
    return [NSFileManager.defaultManager setAttributes:attrs ofItemAtPath:h.disk error:e];
}

@end

int main(int argc, char **argv)
{
    @autoreleasepool {
        NSString *root = argc > 1 ? @(argv[1]) : NSTemporaryDirectory();
        uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 8445;
        FSDelegate *d = [FSDelegate new];
        d.root = root;
        AMSMB2Server *srv = [[AMSMB2Server alloc] initWithPort:port shareName:@"Share" delegate:d];
        srv.fullControlEnabled = (argc > 3 ? atoi(argv[3]) != 0 : YES);
        srv.signingEnabled = (argc > 4 ? atoi(argv[4]) != 0 : YES);
        // Optional argv[5]=user argv[6]=password: when set, require auth (needed to exercise SMB
        // signing/encryption, which derive keys from the authenticated session). Else anonymous.
        if (argc > 6 && argv[5][0]) {
            srv.username = @(argv[5]);
            srv.password = @(argv[6]);
            srv.allowsAnonymousAccess = NO;
        } else {
            srv.allowsAnonymousAccess = YES;
        }
        // Optional argv[7]=encryption: require SMB3 seal on every PDU (needs auth above).
        srv.encryptionEnabled = (argc > 7 ? atoi(argv[7]) != 0 : NO);
        NSError *err = nil;
        if (![srv startAndReturnError:&err]) {
            fprintf(stderr, "SERVER START FAILED: %s\n", err.description.UTF8String);
            return 1;
        }
        fprintf(stderr, "SERVER UP port=%d root=%s\n", port, root.UTF8String);
        [[NSRunLoop currentRunLoop] run];
        (void)srv;
    }
    return 0;
}
