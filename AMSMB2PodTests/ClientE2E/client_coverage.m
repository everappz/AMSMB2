//
//  client_coverage.m
//  Full-coverage integration tests for the OBJC AMSMB2 client (AMSMB2Manager) against a real server.
//
//  Standalone harness (no CocoaPods/XCTest): links AMSMB2ObjC/*.m + a static libsmb2 and drives the
//  completion-handler API synchronously via semaphores. Mirrors the Swift AMSMB2CoverageTests suite.
//
//  Credentials are NEVER hard-coded: SMB_USER / SMB_PASSWORD come from the environment. Server + share
//  default to the NAS (non-secret) and can be overridden via SMB_SERVER / SMB_SHARE.
//
//  Prints a timed PASS/FAIL table and exits non-zero if any test failed.
//

#import <Foundation/Foundation.h>
#import "AMSMB2Manager.h"

#pragma mark - Config (server address is non-secret; credentials come from the environment)

static NSString *gServerString = @"smb://NAS730C60.local";
static NSString *gShare = @"Public";
static NSString *const kBaseFolder = @"Tests";
static NSURL *gServer;
static NSURLCredential *gCred;

static NSString *EnvOr(const char *key, NSString *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? [NSString stringWithUTF8String:v] : fallback;
}

#pragma mark - Synchronous wrappers around the async AMSMB2Manager API

static const int64_t kTimeoutNs = 120 * NSEC_PER_SEC;
#define WAIT(sem) dispatch_semaphore_wait((sem), dispatch_time(DISPATCH_TIME_NOW, kTimeoutNs))

static AMSMB2Manager *Manager(void) {
    return [[AMSMB2Manager alloc] initWithURL:gServer credential:gCred];
}

static NSError *Connect(AMSMB2Manager *smb) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSError *err = nil;
    [smb connectShareWithName:gShare encrypted:NO completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *Mkdir(AMSMB2Manager *smb, NSString *p) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb createDirectoryAtPath:p completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *WriteData(AMSMB2Manager *smb, NSData *d, NSString *p) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb writeData:d toPath:p progress:nil completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *AppendData(AMSMB2Manager *smb, NSData *d, NSString *p, int64_t off) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb appendData:d toPath:p offset:off progress:nil completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSData *ReadData(AMSMB2Manager *smb, NSString *p, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSData *data = nil; __block NSError *err = nil;
    [smb contentsAtPath:p fromOffset:0 toLength:-1 progress:nil completionHandler:^(NSData *c, NSError *e) { data = c; err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); if (outErr) *outErr = err; return data;
}
static NSData *ReadRange(AMSMB2Manager *smb, NSString *p, int64_t off, NSInteger len, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSData *data = nil; __block NSError *err = nil;
    [smb contentsAtPath:p fromOffset:off toLength:len progress:nil completionHandler:^(NSData *c, NSError *e) { data = c; err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); if (outErr) *outErr = err; return data;
}
static NSError *Move(AMSMB2Manager *smb, NSString *a, NSString *b) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb moveItemAtPath:a toPath:b completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *Copy(AMSMB2Manager *smb, NSString *a, NSString *b, BOOL rec) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb copyItemAtPath:a toPath:b recursive:rec progress:nil completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *RemoveItem(AMSMB2Manager *smb, NSString *p) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb removeItemAtPath:p completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *RemoveFile(AMSMB2Manager *smb, NSString *p) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb removeFileAtPath:p completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *RemoveDir(AMSMB2Manager *smb, NSString *p, BOOL rec) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb removeDirectoryAtPath:p recursive:rec completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSArray<NSDictionary<NSURLResourceKey, id> *> *List(AMSMB2Manager *smb, NSString *p, BOOL rec, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSArray *items = nil; __block NSError *err = nil;
    [smb contentsOfDirectoryAtPath:p recursive:rec completionHandler:^(NSArray *c, NSError *e) { items = c; err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); if (outErr) *outErr = err; return items;
}
static NSError *Truncate(AMSMB2Manager *smb, NSString *p, uint64_t off) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb truncateFileAtPath:p atOffset:off completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSDictionary *Attrs(AMSMB2Manager *smb, NSString *p, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSDictionary *a = nil; __block NSError *err = nil;
    [smb attributesOfItemAtPath:p completionHandler:^(NSDictionary *f, NSError *e) { a = f; err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); if (outErr) *outErr = err; return a;
}
static NSDictionary *FSAttrs(AMSMB2Manager *smb, NSString *p, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSDictionary *a = nil; __block NSError *err = nil;
    [smb attributesOfFileSystemForPath:p completionHandler:^(NSDictionary *f, NSError *e) { a = f; err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); if (outErr) *outErr = err; return a;
}
static NSError *Upload(AMSMB2Manager *smb, NSURL *u, NSString *p) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb uploadItemAtURL:u toPath:p progress:nil completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSError *Download(AMSMB2Manager *smb, NSString *p, NSURL *u) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSError *err = nil;
    [smb downloadItemAtPath:p toURL:u progress:nil completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); return err;
}
static NSArray<NSString *> *ListShares(AMSMB2Manager *smb, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block NSArray *names = nil; __block NSError *err = nil;
    [smb listSharesWithCompletionHandler:^(NSArray<NSString *> *n, NSArray<NSString *> *comments, NSError *e) { (void)comments; names = n; err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); if (outErr) *outErr = err; return names;
}

#pragma mark - Test helpers

static NSData *RandomData(NSInteger size) {
    NSMutableData *d = [NSMutableData dataWithLength:size];
    if (size > 0) arc4random_buf(d.mutableBytes, size);
    return d;
}
static NSURL *TempFile(NSData *d) {
    NSURL *u = [[NSURL fileURLWithPath:NSTemporaryDirectory()] URLByAppendingPathComponent:[NSString stringWithFormat:@"amsmb2-%@.dat", NSUUID.UUID.UUIDString]];
    [d writeToURL:u atomically:YES];
    return u;
}
static NSURL *TempOut(void) {
    return [[NSURL fileURLWithPath:NSTemporaryDirectory()] URLByAppendingPathComponent:[NSString stringWithFormat:@"dl-%@.dat", NSUUID.UUID.UUIDString]];
}
// Create a local temp file of `total` bytes written in chunks (avoids holding it all in memory).
static NSURL *TempFileLarge(NSInteger total) {
    NSURL *u = [[NSURL fileURLWithPath:NSTemporaryDirectory()] URLByAppendingPathComponent:[NSString stringWithFormat:@"big-%@.dat", NSUUID.UUID.UUIDString]];
    [NSFileManager.defaultManager createFileAtPath:u.path contents:nil attributes:nil];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:u.path];
    NSInteger chunk = 8 << 20; NSData *block = RandomData(chunk); NSInteger remaining = total;
    while (remaining > 0) {
        NSInteger n = MIN(chunk, remaining);
        [fh writeData:(n == chunk ? block : [block subdataWithRange:NSMakeRange(0, n)])];
        remaining -= n;
    }
    [fh closeFile];
    return u;
}
// Streaming read via the fetchedData block: accumulate all chunks.
static NSData *StreamRead(AMSMB2Manager *smb, NSString *p, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    NSMutableData *acc = [NSMutableData data]; __block NSError *err = nil;
    [smb contentsAtPath:p fromOffset:0 fetchedData:^BOOL(int64_t offset, int64_t total, NSData *data) {
        (void)offset; (void)total; [acc appendData:data]; return YES;
    } completionHandler:^(NSError *e) { err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); if (outErr) *outErr = err; return acc;
}
static NSArray<NSString *> *Names(NSArray<NSDictionary *> *items) {
    NSMutableArray *n = [NSMutableArray array];
    for (NSDictionary *it in items) { NSString *name = it[NSURLNameKey]; if (name) [n addObject:name]; }
    return n;
}
static BOOL IsDir(NSDictionary *attrs) {
    return [attrs[NSURLFileResourceTypeKey] isEqual:NSURLFileResourceTypeDirectory];
}

// Connect + ensure the base Tests folder, then a fresh per-test workspace under it.
static AMSMB2Manager *ConnectBase(NSString **errMsg) {
    AMSMB2Manager *smb = Manager();
    NSError *e = Connect(smb);
    if (e) { *errMsg = [NSString stringWithFormat:@"connect: %@", e.localizedDescription]; return nil; }
    Mkdir(smb, kBaseFolder); // idempotent
    return smb;
}
static NSString *Workspace(AMSMB2Manager *smb, NSString *name) {
    NSString *dir = [NSString stringWithFormat:@"%@/%@", kBaseFolder, name];
    RemoveItem(smb, dir);
    Mkdir(smb, dir);
    return dir;
}

static NSString *gUmlaut = @"Grüße-Öl-Ärger-Übung";
static NSString *gUmlautFolder = @"Ördnung-Ä";

// Each test returns nil on success, or a human-readable failure reason.
typedef NSString *(^Test)(void);

#define FAIL(fmt, ...) return [NSString stringWithFormat:(fmt), ##__VA_ARGS__]
#define REQUIRE(cond, fmt, ...) do { if (!(cond)) { FAIL((fmt), ##__VA_ARGS__); } } while (0)
#define SETUP(nm) NSString *setupErr = nil; AMSMB2Manager *smb = ConnectBase(&setupErr); if (!smb) return setupErr; NSString *dir = Workspace(smb, (nm))
#define CLEANUP() RemoveItem(smb, dir)

#pragma mark - Tests

static NSString *test_ConnectDisconnectReconnect(void) {
    AMSMB2Manager *smb = Manager();
    NSError *e = Connect(smb); REQUIRE(!e, @"connect1: %@", e);
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    [smb disconnectShareGracefully:YES completionHandler:^(NSError *er){ (void)er; dispatch_semaphore_signal(s); }]; WAIT(s);
    e = Connect(smb); REQUIRE(!e, @"connect2: %@", e);
    return nil;
}
static NSString *test_ListSharesContainsShare(void) {
    AMSMB2Manager *smb = Manager(); NSError *e = nil;
    NSArray<NSString *> *shares = ListShares(smb, &e);
    REQUIRE(!e, @"listShares: %@", e);
    REQUIRE(shares.count > 0, @"no shares returned");
    BOOL found = NO; for (NSString *n in shares) if ([n caseInsensitiveCompare:gShare] == NSOrderedSame) found = YES;
    REQUIRE(found, @"share '%@' not in %@", gShare, shares);
    return nil;
}
static NSString *test_FileSystemAttributes(void) {
    NSString *se=nil; AMSMB2Manager *smb = ConnectBase(&se); if(!smb) return se;
    NSError *e=nil; NSDictionary *a = FSAttrs(smb, kBaseFolder, &e);
    REQUIRE(!e, @"fsattrs: %@", e);
    REQUIRE([a[NSFileSystemSize] longLongValue] > 0, @"system size not positive");
    return nil;
}
static NSString *test_BaseFolderExists(void) {
    NSString *se=nil; AMSMB2Manager *smb = ConnectBase(&se); if(!smb) return se;
    NSError *e=nil; NSDictionary *a = Attrs(smb, kBaseFolder, &e);
    REQUIRE(!e && IsDir(a), @"base folder not a directory: %@", e);
    return nil;
}
static NSString *test_ListRootOfShare(void) {
    NSString *se=nil; AMSMB2Manager *smb = ConnectBase(&se); if(!smb) return se;
    NSError *e=nil; NSArray *items = List(smb, @"/", NO, &e);
    REQUIRE(!e, @"list: %@", e); REQUIRE(items.count > 0, @"root empty");
    return nil;
}

static NSString *test_WriteReadSmall(void) {
    SETUP(@"WriteReadSmall"); NSData *d = RandomData(64);
    NSError *e = WriteData(smb, d, [dir stringByAppendingPathComponent:@"small.dat"]); REQUIRE(!e, @"write: %@", e);
    NSData *back = ReadData(smb, [dir stringByAppendingPathComponent:@"small.dat"], &e); REQUIRE(!e, @"read: %@", e);
    REQUIRE([back isEqualToData:d], @"content mismatch");
    CLEANUP(); return nil;
}
static NSString *test_WriteReadEmpty(void) {
    SETUP(@"WriteReadEmpty");
    NSError *e = WriteData(smb, [NSData data], [dir stringByAppendingPathComponent:@"empty.dat"]); REQUIRE(!e, @"write: %@", e);
    NSData *back = ReadData(smb, [dir stringByAppendingPathComponent:@"empty.dat"], &e); REQUIRE(!e, @"read: %@", e);
    REQUIRE(back.length == 0, @"expected empty, got %lu", (unsigned long)back.length);
    CLEANUP(); return nil;
}
static NSString *test_WriteReadMedium(void) {
    SETUP(@"WriteReadMedium"); NSData *d = RandomData(262144);
    NSError *e = WriteData(smb, d, [dir stringByAppendingPathComponent:@"medium.dat"]); REQUIRE(!e, @"write: %@", e);
    NSData *back = ReadData(smb, [dir stringByAppendingPathComponent:@"medium.dat"], &e);
    REQUIRE(!e && [back isEqualToData:d], @"mismatch: %@", e); CLEANUP(); return nil;
}
static NSString *test_WriteReadLarge1MB(void) {
    SETUP(@"WriteReadLarge1MB"); NSData *d = RandomData(1<<20);
    NSError *e = WriteData(smb, d, [dir stringByAppendingPathComponent:@"large.dat"]); REQUIRE(!e, @"write: %@", e);
    NSData *back = ReadData(smb, [dir stringByAppendingPathComponent:@"large.dat"], &e);
    REQUIRE(!e && [back isEqualToData:d], @"mismatch: %@", e); CLEANUP(); return nil;
}
static NSString *test_OverwriteReplaces(void) {
    SETUP(@"OverwriteReplaces"); NSString *p = [dir stringByAppendingPathComponent:@"o.dat"];
    WriteData(smb, RandomData(4096), p);
    RemoveFile(smb, p); // write() will not overwrite in place
    NSData *small = RandomData(16); NSError *e = WriteData(smb, small, p); REQUIRE(!e, @"write2: %@", e);
    NSData *back = ReadData(smb, p, &e); REQUIRE(!e && [back isEqualToData:small], @"mismatch: %@", e);
    CLEANUP(); return nil;
}
static NSString *test_ModifyFileContent(void) {
    SETUP(@"ModifyFileContent"); NSString *p = [dir stringByAppendingPathComponent:@"m.dat"];
    WriteData(smb, [@"v1" dataUsingEncoding:NSUTF8StringEncoding], p);
    RemoveFile(smb, p);
    NSError *e = WriteData(smb, [@"version-2" dataUsingEncoding:NSUTF8StringEncoding], p); REQUIRE(!e, @"write2: %@", e);
    NSData *back = ReadData(smb, p, &e);
    REQUIRE([back isEqualToData:[@"version-2" dataUsingEncoding:NSUTF8StringEncoding]], @"mismatch");
    CLEANUP(); return nil;
}
static NSString *test_AppendAtOffset(void) {
    SETUP(@"AppendAtOffset"); NSString *p = [dir stringByAppendingPathComponent:@"a.dat"];
    NSData *head = RandomData(100), *tail = RandomData(100);
    NSError *e = WriteData(smb, head, p); REQUIRE(!e, @"write: %@", e);
    e = AppendData(smb, tail, p, (int64_t)head.length); REQUIRE(!e, @"append: %@", e);
    NSMutableData *expect = [head mutableCopy]; [expect appendData:tail];
    NSData *back = ReadData(smb, p, &e);
    REQUIRE([back isEqualToData:expect], @"mismatch len=%lu", (unsigned long)back.length);
    CLEANUP(); return nil;
}
static NSString *test_ReadRange(void) {
    SETUP(@"ReadRange"); NSString *p = [dir stringByAppendingPathComponent:@"r.dat"];
    NSData *d = RandomData(1000); NSError *e = WriteData(smb, d, p); REQUIRE(!e, @"write: %@", e);
    NSData *part = ReadRange(smb, p, 100, 100, &e); REQUIRE(!e, @"read: %@", e);
    REQUIRE([part isEqualToData:[d subdataWithRange:NSMakeRange(100, 100)]], @"range mismatch len=%lu", (unsigned long)part.length);
    CLEANUP(); return nil;
}
static NSString *test_ReadFromOffsetToEnd(void) {
    SETUP(@"ReadFromOffsetToEnd"); NSString *p = [dir stringByAppendingPathComponent:@"roe.dat"];
    NSData *d = RandomData(1000); NSError *e = WriteData(smb, d, p); REQUIRE(!e, @"write: %@", e);
    NSData *tail = ReadRange(smb, p, 600, -1, &e); REQUIRE(!e, @"read: %@", e); // length -1 = to EOF
    REQUIRE([tail isEqualToData:[d subdataWithRange:NSMakeRange(600, 400)]], @"offset-to-end mismatch len=%lu", (unsigned long)tail.length);
    CLEANUP(); return nil;
}
static NSString *test_StreamRead(void) {
    SETUP(@"StreamRead"); NSString *p = [dir stringByAppendingPathComponent:@"sr.dat"];
    NSData *d = RandomData(300000); NSError *e = WriteData(smb, d, p); REQUIRE(!e, @"write: %@", e);
    NSData *acc = StreamRead(smb, p, &e); REQUIRE(!e, @"stream read: %@", e);
    REQUIRE([acc isEqualToData:d], @"stream read mismatch len=%lu", (unsigned long)acc.length);
    CLEANUP(); return nil;
}
static NSString *test_StreamWrite(void) {
    SETUP(@"StreamWrite"); NSData *d = RandomData(400000); NSURL *local = TempFile(d);
    NSString *p = [dir stringByAppendingPathComponent:@"sw.dat"];
    NSError *e = Upload(smb, local, p); // uploadItemAtURL streams the file contents to the server
    [NSFileManager.defaultManager removeItemAtURL:local error:nil]; REQUIRE(!e, @"stream write: %@", e);
    NSData *back = StreamRead(smb, p, &e); REQUIRE([back isEqualToData:d], @"stream write/read mismatch");
    CLEANUP(); return nil;
}
static NSString *test_UploadDownload150MB(void) {
    SETUP(@"UploadDownload150MB");
    NSInteger size = 150 << 20; NSURL *local = TempFileLarge(size);
    NSString *p = [dir stringByAppendingPathComponent:@"big.bin"];
    NSError *e = Upload(smb, local, p);
    if (e) { [NSFileManager.defaultManager removeItemAtURL:local error:nil]; FAIL(@"upload: %@", e); }
    NSError *ae=nil; NSDictionary *a = Attrs(smb, p, &ae);
    if ([a[NSURLFileSizeKey] longLongValue] != size) { [NSFileManager.defaultManager removeItemAtURL:local error:nil]; FAIL(@"server size=%@ expected %ld", a[NSURLFileSizeKey], (long)size); }
    NSURL *out = TempOut(); e = Download(smb, p, out);
    if (e) { [NSFileManager.defaultManager removeItemAtURL:local error:nil]; FAIL(@"download: %@", e); }
    BOOL equal = [NSFileManager.defaultManager contentsEqualAtPath:local.path andPath:out.path];
    [NSFileManager.defaultManager removeItemAtURL:local error:nil];
    [NSFileManager.defaultManager removeItemAtURL:out error:nil];
    REQUIRE(equal, @"150MB round-trip content mismatch");
    CLEANUP(); return nil;
}
static NSString *test_DeleteFile(void) {
    SETUP(@"DeleteFile"); NSString *p = [dir stringByAppendingPathComponent:@"d.dat"];
    WriteData(smb, RandomData(32), p);
    NSError *e = RemoveFile(smb, p); REQUIRE(!e, @"remove: %@", e);
    NSError *ae=nil; Attrs(smb, p, &ae); REQUIRE(ae != nil, @"file still exists");
    CLEANUP(); return nil;
}
static NSString *test_DeleteMissingFileFails(void) {
    SETUP(@"DeleteMissingFileFails");
    NSError *e = RemoveFile(smb, [dir stringByAppendingPathComponent:@"nope.dat"]);
    REQUIRE(e != nil, @"expected failure deleting missing file");
    CLEANUP(); return nil;
}
static NSString *test_FileSizeAttribute(void) {
    SETUP(@"FileSizeAttribute"); NSString *p = [dir stringByAppendingPathComponent:@"s.dat"];
    WriteData(smb, RandomData(4321), p);
    NSError *e=nil; NSDictionary *a = Attrs(smb, p, &e); REQUIRE(!e, @"attrs: %@", e);
    REQUIRE([a[NSURLFileSizeKey] longLongValue] == 4321, @"size=%@", a[NSURLFileSizeKey]);
    CLEANUP(); return nil;
}
static NSString *test_ModificationDatePresent(void) {
    SETUP(@"ModificationDatePresent"); NSString *p = [dir stringByAppendingPathComponent:@"t.dat"];
    WriteData(smb, RandomData(10), p);
    NSError *e=nil; NSDictionary *a = Attrs(smb, p, &e); REQUIRE(!e, @"attrs: %@", e);
    REQUIRE(a[NSURLContentModificationDateKey] != nil, @"no mod date");
    CLEANUP(); return nil;
}
static NSString *test_BinaryRoundtripIntegrity(void) {
    SETUP(@"BinaryRoundtripIntegrity"); NSString *p = [dir stringByAppendingPathComponent:@"b.bin"];
    NSData *d = RandomData(9999); NSError *e = WriteData(smb, d, p); REQUIRE(!e, @"write: %@", e);
    NSData *back = ReadData(smb, p, &e); REQUIRE([back isEqualToData:d], @"mismatch"); CLEANUP(); return nil;
}

static NSString *test_CreateDirectory(void) {
    SETUP(@"CreateDirectory");
    NSError *e = Mkdir(smb, [dir stringByAppendingPathComponent:@"sub"]); REQUIRE(!e, @"mkdir: %@", e);
    NSError *ae=nil; NSDictionary *a = Attrs(smb, [dir stringByAppendingPathComponent:@"sub"], &ae);
    REQUIRE(!ae && IsDir(a), @"not a dir"); CLEANUP(); return nil;
}
static NSString *test_CreateNestedDirectory(void) {
    SETUP(@"CreateNestedDirectory");
    Mkdir(smb, [dir stringByAppendingPathComponent:@"a"]);
    Mkdir(smb, [dir stringByAppendingPathComponent:@"a/b"]);
    NSError *e = Mkdir(smb, [dir stringByAppendingPathComponent:@"a/b/c"]); REQUIRE(!e, @"mkdir: %@", e);
    NSError *ae=nil; NSDictionary *a = Attrs(smb, [dir stringByAppendingPathComponent:@"a/b/c"], &ae);
    REQUIRE(!ae && IsDir(a), @"nested not a dir"); CLEANUP(); return nil;
}
static NSString *test_ListEmptyDirectory(void) {
    SETUP(@"ListEmptyDirectory"); Mkdir(smb, [dir stringByAppendingPathComponent:@"empty"]);
    NSError *e=nil; NSArray *items = List(smb, [dir stringByAppendingPathComponent:@"empty"], NO, &e); REQUIRE(!e, @"list: %@", e);
    NSMutableArray *real = [NSMutableArray array];
    for (NSString *n in Names(items)) if (![n isEqual:@"."] && ![n isEqual:@".."]) [real addObject:n];
    REQUIRE(real.count == 0, @"expected empty, got %@", real); CLEANUP(); return nil;
}
static NSString *test_ListDirectoryWithFiles(void) {
    SETUP(@"ListDirectoryWithFiles");
    for (int i=0;i<5;i++) WriteData(smb, RandomData(8), [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"f%d.dat", i]]);
    NSError *e=nil; NSArray<NSString *> *names = Names(List(smb, dir, NO, &e)); REQUIRE(!e, @"list: %@", e);
    for (int i=0;i<5;i++) REQUIRE([names containsObject:([NSString stringWithFormat:@"f%d.dat", i])], @"missing f%d.dat", i);
    CLEANUP(); return nil;
}
static NSString *test_ListRecursive(void) {
    SETUP(@"ListRecursive"); Mkdir(smb, [dir stringByAppendingPathComponent:@"x"]);
    WriteData(smb, RandomData(8), [dir stringByAppendingPathComponent:@"x/deep.dat"]);
    NSError *e=nil; NSArray<NSString *> *names = Names(List(smb, dir, YES, &e)); REQUIRE(!e, @"list: %@", e);
    REQUIRE([names containsObject:@"deep.dat"], @"deep.dat not listed recursively"); CLEANUP(); return nil;
}
static NSString *test_RemoveEmptyDirectory(void) {
    SETUP(@"RemoveEmptyDirectory"); Mkdir(smb, [dir stringByAppendingPathComponent:@"gone"]);
    NSError *e = RemoveDir(smb, [dir stringByAppendingPathComponent:@"gone"], NO); REQUIRE(!e, @"rmdir: %@", e);
    NSError *ae=nil; Attrs(smb, [dir stringByAppendingPathComponent:@"gone"], &ae); REQUIRE(ae != nil, @"still exists");
    CLEANUP(); return nil;
}
static NSString *test_RemoveDirectoryRecursiveWithFiles(void) {
    SETUP(@"RemoveDirectoryRecursiveWithFiles");
    Mkdir(smb, [dir stringByAppendingPathComponent:@"tree"]);
    Mkdir(smb, [dir stringByAppendingPathComponent:@"tree/inner"]);
    WriteData(smb, RandomData(16), [dir stringByAppendingPathComponent:@"tree/a.dat"]);
    WriteData(smb, RandomData(16), [dir stringByAppendingPathComponent:@"tree/inner/b.dat"]);
    NSError *e = RemoveDir(smb, [dir stringByAppendingPathComponent:@"tree"], YES); REQUIRE(!e, @"rmdir: %@", e);
    NSError *ae=nil; Attrs(smb, [dir stringByAppendingPathComponent:@"tree"], &ae); REQUIRE(ae != nil, @"tree still exists");
    CLEANUP(); return nil;
}
static NSString *test_RemoveMissingDirectoryFails(void) {
    SETUP(@"RemoveMissingDirectoryFails");
    NSError *e = RemoveDir(smb, [dir stringByAppendingPathComponent:@"nope"], NO);
    REQUIRE(e != nil, @"expected failure"); CLEANUP(); return nil;
}
static NSString *test_DirectoryResourceType(void) {
    SETUP(@"DirectoryResourceType");
    NSError *e=nil; NSDictionary *a = Attrs(smb, dir, &e); REQUIRE(!e && IsDir(a), @"not a dir"); CLEANUP(); return nil;
}
static NSString *test_CountFilesInDirectory(void) {
    SETUP(@"CountFilesInDirectory");
    for (int i=0;i<7;i++) WriteData(smb, RandomData(4), [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"c%d.dat", i]]);
    NSError *e=nil; NSArray *items = List(smb, dir, NO, &e); REQUIRE(!e, @"list: %@", e);
    int files = 0; for (NSDictionary *it in items) if (!IsDir(it)) files++;
    REQUIRE(files == 7, @"expected 7 files, got %d", files); CLEANUP(); return nil;
}

static NSString *test_RenameFile(void) {
    SETUP(@"RenameFile");
    WriteData(smb, RandomData(20), [dir stringByAppendingPathComponent:@"old.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"old.dat"], [dir stringByAppendingPathComponent:@"new.dat"]); REQUIRE(!e, @"move: %@", e);
    NSArray<NSString *> *names = Names(List(smb, dir, NO, NULL));
    REQUIRE([names containsObject:@"new.dat"] && ![names containsObject:@"old.dat"], @"rename failed: %@", names);
    CLEANUP(); return nil;
}
static NSString *test_RenamePreservesContent(void) {
    SETUP(@"RenamePreservesContent"); NSData *d = RandomData(500);
    WriteData(smb, d, [dir stringByAppendingPathComponent:@"a.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"a.dat"], [dir stringByAppendingPathComponent:@"b.dat"]); REQUIRE(!e, @"move: %@", e);
    NSData *back = ReadData(smb, [dir stringByAppendingPathComponent:@"b.dat"], &e);
    REQUIRE([back isEqualToData:d], @"content changed"); CLEANUP(); return nil;
}
static NSString *test_MoveFileIntoSubdir(void) {
    SETUP(@"MoveFileIntoSubdir"); Mkdir(smb, [dir stringByAppendingPathComponent:@"sub"]);
    WriteData(smb, RandomData(30), [dir stringByAppendingPathComponent:@"m.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"m.dat"], [dir stringByAppendingPathComponent:@"sub/m.dat"]); REQUIRE(!e, @"move: %@", e);
    REQUIRE([Names(List(smb, [dir stringByAppendingPathComponent:@"sub"], NO, NULL)) containsObject:@"m.dat"], @"not moved");
    CLEANUP(); return nil;
}
static NSString *test_RenameDirectoryWithContents(void) {
    SETUP(@"RenameDirectoryWithContents"); Mkdir(smb, [dir stringByAppendingPathComponent:@"d1"]);
    WriteData(smb, RandomData(12), [dir stringByAppendingPathComponent:@"d1/keep.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"d1"], [dir stringByAppendingPathComponent:@"d2"]); REQUIRE(!e, @"move: %@", e);
    REQUIRE([Names(List(smb, [dir stringByAppendingPathComponent:@"d2"], NO, NULL)) containsObject:@"keep.dat"], @"contents lost");
    CLEANUP(); return nil;
}
static NSString *test_MoveDirectoryIntoDirectory(void) {
    SETUP(@"MoveDirectoryIntoDirectory");
    Mkdir(smb, [dir stringByAppendingPathComponent:@"src"]); Mkdir(smb, [dir stringByAppendingPathComponent:@"dst"]);
    WriteData(smb, RandomData(12), [dir stringByAppendingPathComponent:@"src/x.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"src"], [dir stringByAppendingPathComponent:@"dst/src"]); REQUIRE(!e, @"move: %@", e);
    REQUIRE([Names(List(smb, [dir stringByAppendingPathComponent:@"dst/src"], NO, NULL)) containsObject:@"x.dat"], @"moved dir missing file");
    CLEANUP(); return nil;
}
static NSString *test_RenameOverExisting(void) {
    SETUP(@"RenameOverExisting"); NSData *d = RandomData(40);
    WriteData(smb, d, [dir stringByAppendingPathComponent:@"src.dat"]);
    WriteData(smb, RandomData(10), [dir stringByAppendingPathComponent:@"dst.dat"]);
    RemoveFile(smb, [dir stringByAppendingPathComponent:@"dst.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"src.dat"], [dir stringByAppendingPathComponent:@"dst.dat"]); REQUIRE(!e, @"move: %@", e);
    NSData *back = ReadData(smb, [dir stringByAppendingPathComponent:@"dst.dat"], &e);
    REQUIRE([back isEqualToData:d], @"content mismatch"); CLEANUP(); return nil;
}

static NSString *test_CopyFile(void) {
    SETUP(@"CopyFile");
    WriteData(smb, RandomData(200), [dir stringByAppendingPathComponent:@"c.dat"]);
    NSError *e = Copy(smb, [dir stringByAppendingPathComponent:@"c.dat"], [dir stringByAppendingPathComponent:@"c-copy.dat"], NO); REQUIRE(!e, @"copy: %@", e);
    NSArray<NSString *> *names = Names(List(smb, dir, NO, NULL));
    REQUIRE([names containsObject:@"c.dat"] && [names containsObject:@"c-copy.dat"], @"copy missing: %@", names);
    CLEANUP(); return nil;
}
static NSString *test_CopyFilePreservesContent(void) {
    SETUP(@"CopyFilePreservesContent"); NSData *d = RandomData(1024);
    WriteData(smb, d, [dir stringByAppendingPathComponent:@"orig.dat"]);
    NSError *e = Copy(smb, [dir stringByAppendingPathComponent:@"orig.dat"], [dir stringByAppendingPathComponent:@"dup.dat"], NO); REQUIRE(!e, @"copy: %@", e);
    NSData *back = ReadData(smb, [dir stringByAppendingPathComponent:@"dup.dat"], &e);
    REQUIRE([back isEqualToData:d], @"copy content mismatch"); CLEANUP(); return nil;
}
static NSString *test_CopyDirectoryRecursive(void) {
    SETUP(@"CopyDirectoryRecursive"); Mkdir(smb, [dir stringByAppendingPathComponent:@"from"]);
    WriteData(smb, RandomData(64), [dir stringByAppendingPathComponent:@"from/f.dat"]);
    NSError *e = Copy(smb, [dir stringByAppendingPathComponent:@"from"], [dir stringByAppendingPathComponent:@"to"], YES); REQUIRE(!e, @"copy: %@", e);
    REQUIRE([Names(List(smb, [dir stringByAppendingPathComponent:@"to"], NO, NULL)) containsObject:@"f.dat"], @"recursive copy missing file");
    CLEANUP(); return nil;
}

static NSString *test_UploadFile(void) {
    SETUP(@"UploadFile"); NSURL *local = TempFile(RandomData(4096));
    NSError *e = Upload(smb, local, [dir stringByAppendingPathComponent:@"up.dat"]); [NSFileManager.defaultManager removeItemAtURL:local error:nil];
    REQUIRE(!e, @"upload: %@", e);
    NSError *ae=nil; NSDictionary *a = Attrs(smb, [dir stringByAppendingPathComponent:@"up.dat"], &ae);
    REQUIRE([a[NSURLFileSizeKey] longLongValue] == 4096, @"size=%@", a[NSURLFileSizeKey]); CLEANUP(); return nil;
}
static NSString *test_UploadDownloadRoundtrip(void) {
    SETUP(@"UploadDownloadRoundtrip"); NSData *d = RandomData(50000); NSURL *local = TempFile(d);
    NSError *e = Upload(smb, local, [dir stringByAppendingPathComponent:@"rt.dat"]); [NSFileManager.defaultManager removeItemAtURL:local error:nil];
    REQUIRE(!e, @"upload: %@", e);
    NSURL *out = TempOut(); e = Download(smb, [dir stringByAppendingPathComponent:@"rt.dat"], out); REQUIRE(!e, @"download: %@", e);
    NSData *back = [NSData dataWithContentsOfURL:out]; [NSFileManager.defaultManager removeItemAtURL:out error:nil];
    REQUIRE([back isEqualToData:d], @"roundtrip mismatch"); CLEANUP(); return nil;
}
static NSString *test_DownloadContentMatches(void) {
    SETUP(@"DownloadContentMatches"); NSData *d = RandomData(8192);
    WriteData(smb, d, [dir stringByAppendingPathComponent:@"dc.dat"]);
    NSURL *out = TempOut(); NSError *e = Download(smb, [dir stringByAppendingPathComponent:@"dc.dat"], out); REQUIRE(!e, @"download: %@", e);
    NSData *back = [NSData dataWithContentsOfURL:out]; [NSFileManager.defaultManager removeItemAtURL:out error:nil];
    REQUIRE([back isEqualToData:d], @"download mismatch"); CLEANUP(); return nil;
}
static NSString *test_UploadOverwrite(void) {
    SETUP(@"UploadOverwrite"); NSString *p = [dir stringByAppendingPathComponent:@"ov.dat"];
    WriteData(smb, RandomData(1000), p);
    NSData *d = RandomData(200); NSURL *local = TempFile(d);
    RemoveFile(smb, p);
    NSError *e = Upload(smb, local, p); [NSFileManager.defaultManager removeItemAtURL:local error:nil]; REQUIRE(!e, @"upload: %@", e);
    NSData *back = ReadData(smb, p, &e); REQUIRE([back isEqualToData:d], @"overwrite mismatch"); CLEANUP(); return nil;
}
static NSString *test_UploadProgressReported(void) {
    SETUP(@"UploadProgressReported"); NSURL *local = TempFile(RandomData(120000));
    dispatch_semaphore_t s = dispatch_semaphore_create(0); __block BOOL got = NO; __block NSError *err = nil;
    [smb uploadItemAtURL:local toPath:[dir stringByAppendingPathComponent:@"p.dat"]
                progress:^BOOL(int64_t n){ if (n > 0) got = YES; return YES; }
       completionHandler:^(NSError *e){ err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); [NSFileManager.defaultManager removeItemAtURL:local error:nil];
    REQUIRE(!err, @"upload: %@", err); REQUIRE(got, @"no progress reported"); CLEANUP(); return nil;
}
static NSString *test_DownloadProgressReported(void) {
    SETUP(@"DownloadProgressReported");
    WriteData(smb, RandomData(120000), [dir stringByAppendingPathComponent:@"pd.dat"]);
    NSURL *out = TempOut(); dispatch_semaphore_t s = dispatch_semaphore_create(0); __block BOOL got = NO; __block NSError *err = nil;
    [smb downloadItemAtPath:[dir stringByAppendingPathComponent:@"pd.dat"] toURL:out
                   progress:^BOOL(int64_t n, int64_t t){ if (n > 0) got = YES; return YES; }
          completionHandler:^(NSError *e){ err = e; dispatch_semaphore_signal(s); }];
    WAIT(s); [NSFileManager.defaultManager removeItemAtURL:out error:nil];
    REQUIRE(!err, @"download: %@", err); REQUIRE(got, @"no progress reported"); CLEANUP(); return nil;
}

static NSString *test_TruncateShrink(void) {
    SETUP(@"TruncateShrink"); NSString *p = [dir stringByAppendingPathComponent:@"tr.dat"];
    WriteData(smb, RandomData(2000), p);
    NSError *e = Truncate(smb, p, 500); REQUIRE(!e, @"truncate: %@", e);
    NSData *back = ReadData(smb, p, &e); REQUIRE(back.length == 500, @"len=%lu", (unsigned long)back.length); CLEANUP(); return nil;
}
static NSString *test_TruncateExtend(void) {
    SETUP(@"TruncateExtend"); NSString *p = [dir stringByAppendingPathComponent:@"te.dat"];
    WriteData(smb, RandomData(100), p);
    NSError *e = Truncate(smb, p, 4096); REQUIRE(!e, @"truncate: %@", e);
    NSDictionary *a = Attrs(smb, p, &e); REQUIRE([a[NSURLFileSizeKey] longLongValue] == 4096, @"size=%@", a[NSURLFileSizeKey]); CLEANUP(); return nil;
}
static NSString *test_TruncateToZero(void) {
    SETUP(@"TruncateToZero"); NSString *p = [dir stringByAppendingPathComponent:@"tz.dat"];
    WriteData(smb, RandomData(300), p);
    NSError *e = Truncate(smb, p, 0); REQUIRE(!e, @"truncate: %@", e);
    NSData *back = ReadData(smb, p, &e); REQUIRE(back.length == 0, @"len=%lu", (unsigned long)back.length); CLEANUP(); return nil;
}

static NSString *test_WriteReadUmlautFileName(void) {
    SETUP(@"WriteReadUmlautFileName"); NSData *d = RandomData(256);
    NSString *p = [dir stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@".dat"]];
    NSError *e = WriteData(smb, d, p); REQUIRE(!e, @"write: %@", e);
    NSData *back = ReadData(smb, p, &e); REQUIRE([back isEqualToData:d], @"umlaut file mismatch"); CLEANUP(); return nil;
}
static NSString *test_CreateUmlautFolder(void) {
    SETUP(@"CreateUmlautFolder");
    NSError *e = Mkdir(smb, [dir stringByAppendingPathComponent:gUmlautFolder]); REQUIRE(!e, @"mkdir: %@", e);
    NSError *ae=nil; NSDictionary *a = Attrs(smb, [dir stringByAppendingPathComponent:gUmlautFolder], &ae);
    REQUIRE(!ae && IsDir(a), @"umlaut folder not dir"); CLEANUP(); return nil;
}
static NSString *test_NestedUmlautPath(void) {
    SETUP(@"NestedUmlautPath");
    Mkdir(smb, [dir stringByAppendingPathComponent:@"Ä"]);
    Mkdir(smb, [dir stringByAppendingPathComponent:@"Ä/Ö"]);
    NSError *e = WriteData(smb, RandomData(50), [dir stringByAppendingPathComponent:@"Ä/Ö/Ü.dat"]); REQUIRE(!e, @"write: %@", e);
    NSError *ae=nil; NSDictionary *a = Attrs(smb, [dir stringByAppendingPathComponent:@"Ä/Ö/Ü.dat"], &ae);
    REQUIRE([a[NSURLFileSizeKey] longLongValue] == 50, @"nested umlaut size=%@", a[NSURLFileSizeKey]); CLEANUP(); return nil;
}
static NSString *test_ListDirContainingUmlautNames(void) {
    SETUP(@"ListDirContainingUmlautNames");
    WriteData(smb, RandomData(8), [dir stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@".dat"]]);
    Mkdir(smb, [dir stringByAppendingPathComponent:gUmlautFolder]);
    NSArray<NSString *> *names = Names(List(smb, dir, NO, NULL));
    REQUIRE([names containsObject:[gUmlaut stringByAppendingString:@".dat"]], @"umlaut file not listed");
    REQUIRE([names containsObject:gUmlautFolder], @"umlaut folder not listed"); CLEANUP(); return nil;
}
static NSString *test_RenameToUmlautName(void) {
    SETUP(@"RenameToUmlautName");
    WriteData(smb, RandomData(20), [dir stringByAppendingPathComponent:@"plain.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"plain.dat"], [dir stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@".dat"]]);
    REQUIRE(!e, @"move: %@", e);
    REQUIRE([Names(List(smb, dir, NO, NULL)) containsObject:[gUmlaut stringByAppendingString:@".dat"]], @"rename to umlaut failed");
    CLEANUP(); return nil;
}
static NSString *test_MoveIntoUmlautFolder(void) {
    SETUP(@"MoveIntoUmlautFolder"); Mkdir(smb, [dir stringByAppendingPathComponent:gUmlautFolder]);
    WriteData(smb, RandomData(20), [dir stringByAppendingPathComponent:@"f.dat"]);
    NSError *e = Move(smb, [dir stringByAppendingPathComponent:@"f.dat"], [[dir stringByAppendingPathComponent:gUmlautFolder] stringByAppendingPathComponent:@"f.dat"]);
    REQUIRE(!e, @"move: %@", e);
    REQUIRE([Names(List(smb, [dir stringByAppendingPathComponent:gUmlautFolder], NO, NULL)) containsObject:@"f.dat"], @"move into umlaut folder failed");
    CLEANUP(); return nil;
}
static NSString *test_DeleteUmlautFile(void) {
    SETUP(@"DeleteUmlautFile");
    NSString *p = [dir stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@".dat"]];
    WriteData(smb, RandomData(16), p);
    NSError *e = RemoveFile(smb, p); REQUIRE(!e, @"remove: %@", e);
    REQUIRE(![Names(List(smb, dir, NO, NULL)) containsObject:[gUmlaut stringByAppendingString:@".dat"]], @"umlaut file still present");
    CLEANUP(); return nil;
}
static NSString *test_DeleteUmlautFolderWithFiles(void) {
    SETUP(@"DeleteUmlautFolderWithFiles"); Mkdir(smb, [dir stringByAppendingPathComponent:gUmlautFolder]);
    WriteData(smb, RandomData(16), [[dir stringByAppendingPathComponent:gUmlautFolder] stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@".dat"]]);
    NSError *e = RemoveDir(smb, [dir stringByAppendingPathComponent:gUmlautFolder], YES); REQUIRE(!e, @"rmdir: %@", e);
    REQUIRE(![Names(List(smb, dir, NO, NULL)) containsObject:gUmlautFolder], @"umlaut folder still present");
    CLEANUP(); return nil;
}
static NSString *test_UploadDownloadUmlautFile(void) {
    SETUP(@"UploadDownloadUmlautFile"); NSData *d = RandomData(3000); NSURL *local = TempFile(d);
    NSString *p = [dir stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@".bin"]];
    NSError *e = Upload(smb, local, p); [NSFileManager.defaultManager removeItemAtURL:local error:nil]; REQUIRE(!e, @"upload: %@", e);
    NSURL *out = TempOut(); e = Download(smb, p, out); REQUIRE(!e, @"download: %@", e);
    NSData *back = [NSData dataWithContentsOfURL:out]; [NSFileManager.defaultManager removeItemAtURL:out error:nil];
    REQUIRE([back isEqualToData:d], @"umlaut roundtrip mismatch"); CLEANUP(); return nil;
}
static NSString *test_CopyUmlautFile(void) {
    SETUP(@"CopyUmlautFile"); NSData *d = RandomData(128);
    NSString *src = [dir stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@".dat"]];
    NSString *dst = [dir stringByAppendingPathComponent:[gUmlaut stringByAppendingString:@"-Kopie.dat"]];
    WriteData(smb, d, src);
    NSError *e = Copy(smb, src, dst, NO); REQUIRE(!e, @"copy: %@", e);
    NSData *back = ReadData(smb, dst, &e); REQUIRE([back isEqualToData:d], @"umlaut copy mismatch"); CLEANUP(); return nil;
}
static NSString *test_UmlautDirectoryListingCount(void) {
    SETUP(@"UmlautDirectoryListingCount"); Mkdir(smb, [dir stringByAppendingPathComponent:gUmlautFolder]);
    NSArray *ns = @[@"Straße.dat", @"Café.dat", @"Piñata.dat"];
    for (NSString *n in ns) WriteData(smb, RandomData(8), [[dir stringByAppendingPathComponent:gUmlautFolder] stringByAppendingPathComponent:n]);
    NSError *e=nil; NSArray *items = List(smb, [dir stringByAppendingPathComponent:gUmlautFolder], NO, &e); REQUIRE(!e, @"list: %@", e);
    int files = 0; for (NSDictionary *it in items) if (!IsDir(it)) files++;
    REQUIRE(files == 3, @"expected 3, got %d", files); CLEANUP(); return nil;
}
static NSString *test_SpecialSymbolsFileName(void) {
    SETUP(@"SpecialSymbolsFileName");
    NSString *name = @"a b + c (1) [2] #3 &4.dat"; NSData *d = RandomData(64);
    NSString *p = [dir stringByAppendingPathComponent:name];
    NSError *e = WriteData(smb, d, p); REQUIRE(!e, @"write: %@", e);
    NSData *back = ReadData(smb, p, &e); REQUIRE([back isEqualToData:d], @"special-symbol file mismatch"); CLEANUP(); return nil;
}

#pragma mark - Runner

typedef struct { const char *name; Test block; } Case;

int main(int argc, char **argv) {
    @autoreleasepool {
        gServerString = EnvOr("SMB_SERVER", gServerString);
        gShare = EnvOr("SMB_SHARE", gShare);
        gServer = [NSURL URLWithString:gServerString];
        const char *u = getenv("SMB_USER"), *pw = getenv("SMB_PASSWORD");
        if (!u || !pw) {
            fprintf(stderr, "SMB_USER / SMB_PASSWORD must be set in the environment.\n");
            return 2;
        }
        gCred = [NSURLCredential credentialWithUser:[NSString stringWithUTF8String:u]
                                           password:[NSString stringWithUTF8String:pw]
                                        persistence:NSURLCredentialPersistenceForSession];

        NSArray<NSValue *> *_ = nil; (void)_;
#define C(fn) {#fn, ^NSString *{ return fn(); }}
        Case cases[] = {
            C(test_ConnectDisconnectReconnect), C(test_ListSharesContainsShare), C(test_FileSystemAttributes),
            C(test_BaseFolderExists), C(test_ListRootOfShare),
            C(test_WriteReadSmall), C(test_WriteReadEmpty), C(test_WriteReadMedium), C(test_WriteReadLarge1MB),
            C(test_OverwriteReplaces), C(test_ModifyFileContent), C(test_AppendAtOffset), C(test_ReadRange),
            C(test_ReadFromOffsetToEnd), C(test_StreamRead), C(test_StreamWrite),
            C(test_DeleteFile), C(test_DeleteMissingFileFails), C(test_FileSizeAttribute),
            C(test_ModificationDatePresent), C(test_BinaryRoundtripIntegrity),
            C(test_CreateDirectory), C(test_CreateNestedDirectory), C(test_ListEmptyDirectory),
            C(test_ListDirectoryWithFiles), C(test_ListRecursive), C(test_RemoveEmptyDirectory),
            C(test_RemoveDirectoryRecursiveWithFiles), C(test_RemoveMissingDirectoryFails),
            C(test_DirectoryResourceType), C(test_CountFilesInDirectory),
            C(test_RenameFile), C(test_RenamePreservesContent), C(test_MoveFileIntoSubdir),
            C(test_RenameDirectoryWithContents), C(test_MoveDirectoryIntoDirectory), C(test_RenameOverExisting),
            C(test_CopyFile), C(test_CopyFilePreservesContent), C(test_CopyDirectoryRecursive),
            C(test_UploadFile), C(test_UploadDownloadRoundtrip), C(test_DownloadContentMatches),
            C(test_UploadOverwrite), C(test_UploadProgressReported), C(test_DownloadProgressReported),
            C(test_UploadDownload150MB),
            C(test_TruncateShrink), C(test_TruncateExtend), C(test_TruncateToZero),
            C(test_WriteReadUmlautFileName), C(test_CreateUmlautFolder), C(test_NestedUmlautPath),
            C(test_ListDirContainingUmlautNames), C(test_RenameToUmlautName), C(test_MoveIntoUmlautFolder),
            C(test_DeleteUmlautFile), C(test_DeleteUmlautFolderWithFiles), C(test_UploadDownloadUmlautFile),
            C(test_CopyUmlautFile), C(test_UmlautDirectoryListingCount), C(test_SpecialSymbolsFileName),
        };
        int n = (int)(sizeof(cases) / sizeof(cases[0]));
        int passed = 0, failed = 0;
        printf("== OBJC AMSMB2 client coverage: %d tests vs %s share '%s' ==\n\n",
               n, gServerString.UTF8String, gShare.UTF8String);
        printf("%-4s %-10s %-42s %s\n", "#", "STATUS", "TEST", "TIME");
        for (int i = 0; i < n; i++) {
            @autoreleasepool {
                NSDate *start = [NSDate date];
                NSString *reason = nil;
                @try { reason = cases[i].block(); }
                @catch (NSException *ex) { reason = [NSString stringWithFormat:@"exception: %@", ex.reason]; }
                double secs = -[start timeIntervalSinceNow];
                NSString *nm = [NSString stringWithUTF8String:cases[i].name];
                if ([nm hasPrefix:@"test_"]) nm = [nm substringFromIndex:5];
                if (reason == nil) { passed++; printf("%-4d %-10s %-42s %6.3fs\n", i+1, "PASS", nm.UTF8String, secs); }
                else { failed++; printf("%-4d %-10s %-42s %6.3fs  <- %s\n", i+1, "FAIL", nm.UTF8String, secs, reason.UTF8String); }
            }
        }
        printf("\n==== ObjC: %d passed, %d failed of %d ====\n", passed, failed, n);
        return failed == 0 ? 0 : 1;
    }
}
