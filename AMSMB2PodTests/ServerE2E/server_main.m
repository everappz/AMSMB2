#import <Foundation/Foundation.h>
#import "AMSMB2Server.h"

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
        case AMSMB2CreateDispositionOpen:      if (!exists) return nil; break;
        case AMSMB2CreateDispositionCreate:    if (exists)  return nil; break;
        case AMSMB2CreateDispositionOverwrite: if (!exists) return nil; break;
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

@end

int main(int argc, char **argv)
{
    @autoreleasepool {
        NSString *root = argc > 1 ? @(argv[1]) : NSTemporaryDirectory();
        uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 8445;
        FSDelegate *d = [FSDelegate new];
        d.root = root;
        AMSMB2Server *srv = [[AMSMB2Server alloc] initWithPort:port shareName:@"Share" delegate:d];
        srv.allowsAnonymousAccess = YES;
        srv.fullControlEnabled = (argc > 3 ? atoi(argv[3]) != 0 : YES);
        srv.signingEnabled = (argc > 4 ? atoi(argv[4]) != 0 : YES);
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
