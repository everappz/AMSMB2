//
//  AMSMB2ServerTests.m
//  PodTestsTests
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//
//  Tests for the AMSMB2Server ObjC wrapper. These cover the parts that can run
//  reliably in-process: server lifecycle (start/stop/bind), port-in-use
//  handling, and that the listening socket accepts TCP connections.
//
//  NOTE: A full SMB2 protocol round-trip (browse/read/write/rename/copy) cannot
//  run in this same process, because libsmb2 keeps a *global* list of active
//  contexts — a client context would be serviced by the server's serve loop.
//  That end-to-end coverage lives in ../ServerE2E/run.sh, which drives the
//  server from a separate libsmb2 client process.
//

#import <XCTest/XCTest.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
@import AMSMB2;

#pragma mark - In-memory backing store

/// A minimal in-memory AMSMB2ServerDelegate, enough to make the server fully
/// functional and to demonstrate how an app wires one up.
@interface MemoryStore : NSObject <AMSMB2ServerDelegate>
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMutableData *> *files;
@property (nonatomic, strong) NSMutableSet<NSString *> *dirs;
@end

@implementation MemoryStore

- (instancetype)init {
    if ((self = [super init])) {
        _files = [NSMutableDictionary dictionary];
        _dirs = [NSMutableSet setWithObject:@""]; // share root
    }
    return self;
}

- (id)server:(AMSMB2Server *)server openItemAtPath:(NSString *)path desiredAccess:(uint32_t)da
 disposition:(AMSMB2CreateDisposition)disp createOptions:(uint32_t)opts attributes:(uint32_t)attr
    fileInfo:(AMSMB2FileInfo **)outInfo error:(NSError **)error {
    BOOL wantDir = (opts & 0x00000001) != 0;
    BOOL isDir = [self.dirs containsObject:path];
    BOOL isFile = self.files[path] != nil;

    if (wantDir || isDir) {
        if (!isDir) {
            if (disp == AMSMB2CreateDispositionCreate || disp == AMSMB2CreateDispositionOpenIf) {
                [self.dirs addObject:path];
            } else {
                return nil;
            }
        }
        if (outInfo) *outInfo = [AMSMB2FileInfo fileInfoWithName:path.lastPathComponent isDirectory:YES size:0];
        return @{ @"dir": path };
    }

    switch (disp) {
        case AMSMB2CreateDispositionOpen:      if (!isFile) return nil; break;
        case AMSMB2CreateDispositionCreate:    if (isFile)  return nil; break;
        case AMSMB2CreateDispositionOverwrite: if (!isFile) return nil; break;
        default: break;
    }
    if (!isFile) {
        self.files[path] = [NSMutableData data];
    } else if (disp == AMSMB2CreateDispositionOverwrite || disp == AMSMB2CreateDispositionOverwriteIf ||
               disp == AMSMB2CreateDispositionSupersede) {
        self.files[path] = [NSMutableData data];
    }
    if (outInfo) *outInfo = [AMSMB2FileInfo fileInfoWithName:path.lastPathComponent isDirectory:NO size:self.files[path].length];
    return @{ @"file": path };
}

- (void)server:(AMSMB2Server *)server closeItem:(id)handle {}

- (NSData *)server:(AMSMB2Server *)server readFromItem:(id)handle offset:(unsigned long long)off length:(uint32_t)len error:(NSError **)e {
    NSData *data = self.files[handle[@"file"]];
    if (!data || off >= data.length) return [NSData data];
    NSUInteger n = MIN((NSUInteger)len, data.length - (NSUInteger)off);
    return [data subdataWithRange:NSMakeRange((NSUInteger)off, n)];
}

- (NSInteger)server:(AMSMB2Server *)server writeToItem:(id)handle offset:(unsigned long long)off data:(NSData *)data error:(NSError **)e {
    NSMutableData *file = self.files[handle[@"file"]];
    if (!file) return -1;
    if (off + data.length > file.length) [file setLength:(NSUInteger)(off + data.length)];
    [file replaceBytesInRange:NSMakeRange((NSUInteger)off, data.length) withBytes:data.bytes];
    return (NSInteger)data.length;
}

- (NSArray<AMSMB2FileInfo *> *)server:(AMSMB2Server *)server enumerateItem:(id)handle pattern:(NSString *)pat error:(NSError **)e {
    NSString *dir = handle[@"dir"] ?: @"";
    NSMutableArray<AMSMB2FileInfo *> *out = [NSMutableArray array];
    [self.files enumerateKeysAndObjectsUsingBlock:^(NSString *p, NSMutableData *d, BOOL *stop) {
        if ([p.stringByDeletingLastPathComponent isEqualToString:dir] && p.length) {
            [out addObject:[AMSMB2FileInfo fileInfoWithName:p.lastPathComponent isDirectory:NO size:d.length]];
        }
    }];
    return out;
}

- (AMSMB2FileInfo *)server:(AMSMB2Server *)server infoForItem:(id)handle error:(NSError **)e {
    if (handle[@"dir"]) return [AMSMB2FileInfo fileInfoWithName:@"" isDirectory:YES size:0];
    NSString *p = handle[@"file"];
    return [AMSMB2FileInfo fileInfoWithName:p.lastPathComponent isDirectory:NO size:self.files[p].length];
}

@end

#pragma mark - Tests

@interface AMSMB2ServerTests : XCTestCase
@end

@implementation AMSMB2ServerTests

/// A high, ephemeral-ish port to avoid collisions across runs.
- (uint16_t)freshPort {
    return (uint16_t)(20000 + arc4random_uniform(20000));
}

- (void)testServerStartsAndStops {
    MemoryStore *store = [MemoryStore new];
    AMSMB2Server *server = [[AMSMB2Server alloc] initWithPort:[self freshPort] shareName:@"Share" delegate:store];
    server.allowsAnonymousAccess = YES;

    XCTAssertFalse(server.isRunning, @"server should not be running before start");

    NSError *error = nil;
    XCTAssertTrue([server startAndReturnError:&error], @"start failed: %@", error);
    XCTAssertTrue(server.isRunning, @"server should be running after start");
    XCTAssertNil(error);

    [server stop];
    XCTAssertFalse(server.isRunning, @"server should not be running after stop");
}

- (void)testStartIsIdempotent {
    AMSMB2Server *server = [[AMSMB2Server alloc] initWithPort:[self freshPort] shareName:@"Share" delegate:[MemoryStore new]];
    server.allowsAnonymousAccess = YES;

    XCTAssertTrue([server startAndReturnError:NULL]);
    XCTAssertTrue([server startAndReturnError:NULL], @"second start while running should be a no-op success");
    XCTAssertTrue(server.isRunning);
    [server stop];
}

- (void)testPortInUseFails {
    uint16_t port = [self freshPort];
    AMSMB2Server *first = [[AMSMB2Server alloc] initWithPort:port shareName:@"Share" delegate:[MemoryStore new]];
    first.allowsAnonymousAccess = YES;
    XCTAssertTrue([first startAndReturnError:NULL], @"first server should bind");

    AMSMB2Server *second = [[AMSMB2Server alloc] initWithPort:port shareName:@"Share" delegate:[MemoryStore new]];
    second.allowsAnonymousAccess = YES;
    NSError *error = nil;
    XCTAssertFalse([second startAndReturnError:&error], @"second server on the same port should fail");
    XCTAssertNotNil(error);

    [first stop];
    [second stop];
}

- (void)testListeningSocketAcceptsConnection {
    uint16_t port = [self freshPort];
    AMSMB2Server *server = [[AMSMB2Server alloc] initWithPort:port shareName:@"Share" delegate:[MemoryStore new]];
    server.allowsAnonymousAccess = YES;
    XCTAssertTrue([server startAndReturnError:NULL]);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    XCTAssertGreaterThanOrEqual(fd, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    XCTAssertEqual(rc, 0, @"TCP connection to the SMB server should be accepted (errno %d)", errno);

    close(fd);
    [server stop];
}

- (void)testStopWhenNotRunningIsSafe {
    AMSMB2Server *server = [[AMSMB2Server alloc] initWithPort:[self freshPort] shareName:@"Share" delegate:nil];
    XCTAssertNoThrow([server stop], @"stop() before start must be safe");
    XCTAssertFalse(server.isRunning);
}

@end
