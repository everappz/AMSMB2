//
//  AMSMB2ManagerTests.m
//  PodTestsTests
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import <XCTest/XCTest.h>
@import AMSMB2;

static NSString *FolderName(NSString *function, NSString *postfix) {
    NSString *name = [function stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"()"]];
    return [NSString stringWithFormat:@"%@%@", name, postfix ?: @""];
}

static NSString *FileName(NSString *function, NSString *postfix) {
    NSString *name = [function stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"()"]];
    return [NSString stringWithFormat:@"%@%@.dat", name, postfix ?: @""];
}

static NSData *RandomData(NSInteger size) {
    NSMutableData *data = [NSMutableData dataWithLength:size];
    arc4random_buf(data.mutableBytes, size);
    return data;
}

static uint32_t RandomInt(uint32_t max) {
    return arc4random_uniform(max + 1);
}

static NSString *const kSMBServerAddress = @"smb://192.168.1.131";
static NSString *const kSMBShareName     = @"test";
static NSString *const kSMBUser          = @"testtest";
static NSString *const kSMBPassword      = @"Derparol3";

@interface AMSMB2ManagerTests : XCTestCase
@property (nonatomic, strong) NSURL *server;
@property (nonatomic, copy) NSString *share;
@property (nonatomic, strong) NSURLCredential *credential;
@property (nonatomic) BOOL encrypted;
@end

@implementation AMSMB2ManagerTests

- (void)setUp {
    [super setUp];
    self.server = [NSURL URLWithString:kSMBServerAddress];
    self.share = kSMBShareName;
    self.credential = [NSURLCredential credentialWithUser:kSMBUser
                                                 password:kSMBPassword
                                              persistence:NSURLCredentialPersistenceForSession];
    self.encrypted = NO;
}

#pragma mark - Helpers

- (AMSMB2Manager *)newManager {
    return [[AMSMB2Manager alloc] initWithURL:self.server credential:self.credential];
}

- (void)connectManager:(AMSMB2Manager *)smb completion:(void (^)(NSError *_Nullable))completion {
    [smb connectShareWithName:self.share encrypted:self.encrypted completionHandler:completion];
}

- (void)waitForExpectation:(XCTestExpectation *)exp {
    [self waitForExpectations:@[exp] timeout:120.0];
}

#pragma mark - NSSecureCoding

- (void)testNSCodable {
    NSURL *url = [NSURL URLWithString:@"smb://192.168.1.1/share"];
    NSURLCredential *cred = [NSURLCredential credentialWithUser:@"user"
                                                       password:@"password"
                                                    persistence:NSURLCredentialPersistenceForSession];
    AMSMB2Manager *smb = [[AMSMB2Manager alloc] initWithURL:url credential:cred];
    XCTAssertNotNil(smb);

    NSKeyedArchiver *archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];
    [archiver encodeObject:smb forKey:NSKeyedArchiveRootObjectKey];
    [archiver finishEncoding];
    NSData *data = archiver.encodedData;
    XCTAssertNil(archiver.error);
    XCTAssertTrue(data.length > 0);

    NSError *error = nil;
    NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:data error:&error];
    XCTAssertNil(error);
    unarchiver.decodingFailurePolicy = NSDecodingFailurePolicySetErrorAndReturn;
    unarchiver.requiresSecureCoding = YES;
    AMSMB2Manager *decoded = [unarchiver decodeObjectOfClass:[AMSMB2Manager class]
                                                      forKey:NSKeyedArchiveRootObjectKey];
    XCTAssertNotNil(decoded);
    XCTAssertEqualObjects(smb.url, decoded.url);
    XCTAssertEqual(smb.timeout, decoded.timeout);
    XCTAssertNil(unarchiver.error);
}

#pragma mark - NSCopying

- (void)testNSCopy {
    NSURL *url = [NSURL URLWithString:@"smb://192.168.1.1/share"];
    NSURLCredential *cred = [NSURLCredential credentialWithUser:@"user"
                                                       password:@"password"
                                                    persistence:NSURLCredentialPersistenceForSession];
    AMSMB2Manager *smb = [[AMSMB2Manager alloc] initWithURL:url domain:@"" credential:cred];
    XCTAssertNotNil(smb);
    AMSMB2Manager *copy = [smb copy];
    XCTAssertEqualObjects(smb.url, copy.url);
}

#pragma mark - Connection

- (void)testConnectDisconnect {
    XCTestExpectation *exp = [self expectationWithDescription:@"connect-disconnect"];
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb disconnectShareGracefully:NO completionHandler:^(NSError *error2) {
            XCTAssertNil(error2);
            [self connectManager:smb completion:^(NSError *error3) {
                XCTAssertNil(error3);
                [exp fulfill];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Share Enum

- (void)testShareEnum {
    XCTestExpectation *exp = [self expectationWithDescription:@"share-enum"];
    AMSMB2Manager *smb = [self newManager];

    [smb listSharesWithCompletionHandler:^(NSArray<NSString *> *names, NSArray<NSString *> *comments, NSError *error) {
        XCTAssertNil(error);
        XCTAssertTrue(names.count > 0);
        XCTAssertTrue([names containsObject:self.share]);

        [smb listSharesWithEnumerateHidden:YES completionHandler:^(NSArray<NSString *> *hiddenNames, NSArray<NSString *> *hiddenComments, NSError *error2) {
            XCTAssertNil(error2);
            XCTAssertTrue(hiddenNames.count > 0);
            XCTAssertTrue([hiddenNames containsObject:self.share]);
            XCTAssertGreaterThanOrEqual(hiddenNames.count, names.count);
            [exp fulfill];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - File System Attributes

- (void)testFileSystemAttributes {
    XCTestExpectation *exp = [self expectationWithDescription:@"fs-attribs"];
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb attributesOfFileSystemForPath:@"/" completionHandler:^(NSDictionary<NSFileAttributeKey,id> *attributes, NSError *error2) {
            XCTAssertNil(error2);
            XCTAssertTrue(attributes.count > 0);
            XCTAssertGreaterThanOrEqual([attributes[NSFileSystemSize] longLongValue], 0);
            XCTAssertGreaterThanOrEqual([attributes[NSFileSystemFreeSize] longLongValue], 0);
            XCTAssertGreaterThanOrEqual([attributes[NSFileSystemSize] longLongValue],
                                        [attributes[NSFileSystemFreeSize] longLongValue]);
            [exp fulfill];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - File Attributes

- (void)testFileAttributes {
    XCTestExpectation *exp = [self expectationWithDescription:@"file-attribs"];
    NSString *file = FileName(NSStringFromSelector(_cmd), nil);
    NSInteger size = RandomInt(0x000800);
    NSData *data = RandomData(size);
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb writeData:data toPath:file progress:nil completionHandler:^(NSError *writeErr) {
            XCTAssertNil(writeErr);
            [smb attributesOfItemAtPath:file completionHandler:^(NSDictionary<NSURLResourceKey,id> *attribs, NSError *attrErr) {
                XCTAssertNil(attrErr);
                XCTAssertNotNil(attribs[NSURLNameKey]);
                XCTAssertNotNil(attribs[NSURLContentModificationDateKey]);
                XCTAssertNotNil(attribs[NSURLCreationDateKey]);

                // Cleanup
                [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                    [exp fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - File Rename

- (void)testFileRename {
    XCTestExpectation *exp = [self expectationWithDescription:@"rename"];
    NSString *file = FileName(NSStringFromSelector(_cmd), nil);
    NSString *renamed = FileName(NSStringFromSelector(_cmd), @"Renamed");
    NSInteger size = RandomInt(0x000800);
    NSData *data = RandomData(size);
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb writeData:data toPath:file progress:nil completionHandler:^(NSError *writeErr) {
            XCTAssertNil(writeErr);
            [smb moveItemAtPath:file toPath:renamed completionHandler:^(NSError *moveErr) {
                XCTAssertNil(moveErr);
                [smb contentsAtPath:renamed fromOffset:0 toLength:-1 progress:nil completionHandler:^(NSData *rdata, NSError *readErr) {
                    XCTAssertNil(readErr);
                    XCTAssertEqualObjects(data, rdata);
                    // Cleanup
                    [smb removeFileAtPath:renamed completionHandler:^(NSError *rmErr) {
                        [exp fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Truncate

- (void)testFileTruncate {
    XCTestExpectation *exp = [self expectationWithDescription:@"truncate"];
    NSString *file = FileName(NSStringFromSelector(_cmd), nil);
    NSInteger size = 0x000401 + RandomInt(0x001BFF);
    NSData *data = RandomData(size);
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb writeData:data toPath:file progress:nil completionHandler:^(NSError *writeErr) {
            XCTAssertNil(writeErr);
            [smb truncateFileAtPath:file atOffset:0x000200 completionHandler:^(NSError *truncErr) {
                XCTAssertNil(truncErr);
                [smb contentsAtPath:file fromOffset:0 toLength:-1 progress:nil completionHandler:^(NSData *truncData, NSError *readErr) {
                    XCTAssertNil(readErr);
                    XCTAssertEqual(truncData.length, 0x000200);
                    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(0, truncData.length)], truncData);
                    [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                        [exp fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Directory Listing

- (void)testListing {
    XCTestExpectation *exp = [self expectationWithDescription:@"listing"];
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb contentsOfDirectoryAtPath:@"/" recursive:NO completionHandler:^(NSArray<NSDictionary<NSURLResourceKey,id> *> *contents, NSError *listErr) {
            XCTAssertNil(listErr);
            XCTAssertTrue(contents.count > 0);
            NSDictionary *first = contents.firstObject;
            XCTAssertNotNil(first);
            XCTAssertNotNil(first[NSURLNameKey]);
            XCTAssertNotNil(first[NSURLContentModificationDateKey]);
            XCTAssertNotNil(first[NSURLCreationDateKey]);
            [exp fulfill];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Symlink

- (void)testSymlink {
    XCTestExpectation *exp = [self expectationWithDescription:@"symlink"];
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb contentsOfDirectoryAtPath:@"/" recursive:NO completionHandler:^(NSArray<NSDictionary<NSURLResourceKey,id> *> *contents, NSError *listErr) {
            XCTAssertNil(listErr);

            // Find a symlink if any
            NSDictionary *symlink = nil;
            for (NSDictionary *item in contents) {
                if ([item[NSURLIsSymbolicLinkKey] boolValue]) {
                    symlink = item;
                    break;
                }
            }

            if (symlink) {
                NSString *path = symlink[NSURLPathKey];
                [smb destinationOfSymbolicLinkAtPath:path completionHandler:^(NSString *dest, NSError *destErr) {
                    XCTAssertNil(destErr);
                    XCTAssertTrue(dest.length > 0);
                    [exp fulfill];
                }];
            } else {
                [exp fulfill]; // No symlink to test
            }
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Directory Operations

- (void)testDirectoryOperation {
    XCTestExpectation *exp = [self expectationWithDescription:@"dir-ops"];
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        // Pre-cleanup leftovers
        [smb removeDirectoryAtPath:@"testEmpty" recursive:YES completionHandler:^(NSError *pre1) {
        [smb removeDirectoryAtPath:@"testFull" recursive:YES completionHandler:^(NSError *pre2) {
        usleep(200000); // Wait for server to clear delete-pending state
        [smb createDirectoryAtPath:@"testEmpty" completionHandler:^(NSError *mkErr) {
            XCTAssertNil(mkErr);
            [smb removeDirectoryAtPath:@"testEmpty" recursive:NO completionHandler:^(NSError *rmErr) {
                XCTAssertNil(rmErr);
                [smb createDirectoryAtPath:@"testFull" completionHandler:^(NSError *mkErr2) {
                    XCTAssertNil(mkErr2);
                    [smb createDirectoryAtPath:@"testFull/test" completionHandler:^(NSError *mkErr3) {
                        XCTAssertNil(mkErr3);
                        [smb removeDirectoryAtPath:@"testFull" recursive:YES completionHandler:^(NSError *rmErr2) {
                            XCTAssertNil(rmErr2);
                            [exp fulfill];
                        }];
                    }];
                }];
            }];
        }];
        }]; // pre2
        }]; // pre1
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Write/Read

- (void)testZeroWriteRead {
    [self readWriteWithSize:0 function:NSStringFromSelector(_cmd)];
}

- (void)testSmallWriteRead {
    [self readWriteWithSize:RandomInt(14) function:NSStringFromSelector(_cmd)];
}

- (void)testMediumWriteRead {
    [self readWriteWithSize:15 + RandomInt(1024 * 1024 - 15) function:NSStringFromSelector(_cmd)];
}

- (void)testLargeWriteRead {
    [self readWriteWithSize:4 * 1024 * 1024 * 3 + RandomInt(1024 * 1024) function:NSStringFromSelector(_cmd)];
}

- (void)readWriteWithSize:(NSInteger)size function:(NSString *)function {
    XCTestExpectation *exp = [self expectationWithDescription:function];
    NSString *file = FileName(function, nil);
    NSData *data = RandomData(size);
    AMSMB2Manager *smb = [self newManager];

    NSLog(@"%@ test size: %ld", function, (long)size);

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb writeData:data toPath:file progress:^BOOL(int64_t bytes) {
            XCTAssertGreaterThan(bytes, 0);
            return YES;
        } completionHandler:^(NSError *writeErr) {
            XCTAssertNil(writeErr);
            [smb contentsAtPath:file fromOffset:0 toLength:-1 progress:^BOOL(int64_t bytes, int64_t total) {
                XCTAssertGreaterThan(bytes, 0);
                XCTAssertEqual(total, (int64_t)data.length);
                return YES;
            } completionHandler:^(NSData *rdata, NSError *readErr) {
                XCTAssertNil(readErr);
                XCTAssertEqualObjects(data, rdata);

                // Read first 10 bytes
                [smb contentsAtPath:file fromOffset:0 toLength:10 progress:nil completionHandler:^(NSData *trdata, NSError *treadErr) {
                    XCTAssertNil(treadErr);
                    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(0, MIN(10, data.length))], trdata);
                    // Cleanup
                    [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                        [exp fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Chunked Load

- (void)testChunkedLoad {
    XCTestExpectation *exp = [self expectationWithDescription:@"chunked"];
    NSString *file = FileName(NSStringFromSelector(_cmd), nil);
    NSInteger size = RandomInt(0xf00000);
    NSData *data = RandomData(size);
    AMSMB2Manager *smb = [self newManager];

    NSLog(@"%s test size: %ld", __FUNCTION__, (long)size);

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb writeData:data toPath:file progress:nil completionHandler:^(NSError *writeErr) {
            XCTAssertNil(writeErr);

            __block int64_t cachedOffset = 0;
            [smb contentsAtPath:file fromOffset:0 fetchedData:^BOOL(int64_t offset, int64_t total, NSData *chunk) {
                XCTAssertEqual(offset, cachedOffset);
                cachedOffset += chunk.length;
                NSData *expected = [data subdataWithRange:NSMakeRange((NSUInteger)offset, chunk.length)];
                XCTAssertEqualObjects(expected, chunk);
                return YES;
            } completionHandler:^(NSError *readErr) {
                XCTAssertNil(readErr);
                // Cleanup
                [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                    [exp fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Upload/Download

- (void)testUploadDownload {
    XCTestExpectation *exp = [self expectationWithDescription:@"upload-download"];
    NSString *file = FileName(NSStringFromSelector(_cmd), nil);
    NSInteger size = RandomInt(0xf00000);
    NSURL *url = [self dummyFileWithSize:size name:NSStringFromSelector(_cmd)];
    NSURL *dlURL = [url URLByAppendingPathExtension:@"downloaded"];
    AMSMB2Manager *smb = [self newManager];

    NSLog(@"%s test size: %ld", __FUNCTION__, (long)size);

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb uploadItemAtURL:url toPath:file progress:^BOOL(int64_t bytes) {
            XCTAssertGreaterThan(bytes, 0);
            return YES;
        } completionHandler:^(NSError *upErr) {
            XCTAssertNil(upErr);

            // Upload again should fail (file exists)
            [smb uploadItemAtURL:url toPath:file progress:nil completionHandler:^(NSError *upErr2) {
                XCTAssertNotNil(upErr2);
                XCTAssertEqual(upErr2.code, EEXIST);

                [smb downloadItemAtPath:file toURL:dlURL progress:^BOOL(int64_t bytes, int64_t total) {
                    XCTAssertGreaterThan(bytes, 0);
                    XCTAssertGreaterThan(total, 0);
                    return YES;
                } completionHandler:^(NSError *dlErr) {
                    XCTAssertNil(dlErr);
                    XCTAssertTrue([NSFileManager.defaultManager contentsEqualAtPath:url.path andPath:dlURL.path]);

                    [smb echoWithCompletionHandler:^(NSError *echoErr) {
                        XCTAssertNil(echoErr);
                        // Cleanup
                        [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                            [NSFileManager.defaultManager removeItemAtURL:url error:nil];
                            [NSFileManager.defaultManager removeItemAtURL:dlURL error:nil];
                            [smb disconnectShareGracefully:YES completionHandler:^(NSError *dcErr) {
                                [exp fulfill];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Truncate via Upload

- (void)testTruncate {
    XCTestExpectation *exp = [self expectationWithDescription:@"truncate-upload"];
    NSString *file = FileName(NSStringFromSelector(_cmd), nil);
    NSInteger size = RandomInt(0xf00000);
    NSURL *url = [self dummyFileWithSize:size name:NSStringFromSelector(_cmd)];
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [smb uploadItemAtURL:url toPath:file progress:nil completionHandler:^(NSError *upErr) {
            XCTAssertNil(upErr);
            [smb truncateFileAtPath:file atOffset:0x10000 completionHandler:^(NSError *truncErr) {
                XCTAssertNil(truncErr);
                [smb attributesOfItemAtPath:file completionHandler:^(NSDictionary<NSURLResourceKey,id> *attribs, NSError *attrErr) {
                    XCTAssertNil(attrErr);
                    XCTAssertEqual([attribs[NSURLFileSizeKey] longLongValue], 0x10000);

                    [smb echoWithCompletionHandler:^(NSError *echoErr) {
                        XCTAssertNil(echoErr);
                        [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                            [NSFileManager.defaultManager removeItemAtURL:url error:nil];
                            [smb disconnectShareGracefully:YES completionHandler:^(NSError *dcErr) {
                                [exp fulfill];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Copy

- (void)testCopy {
    XCTestExpectation *exp = [self expectationWithDescription:@"copy"];
    NSString *file = FileName(NSStringFromSelector(_cmd), nil);
    NSString *destFile = FileName(NSStringFromSelector(_cmd), @"Dest");
    NSInteger size = RandomInt(0x400000);
    NSData *data = RandomData(size);
    AMSMB2Manager *smb = [self newManager];

    NSLog(@"%s test size: %ld", __FUNCTION__, (long)size);

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        // Clean up leftover files from previous runs
        [self cleanupFilesOnManager:smb paths:@[file, destFile] completion:^{
            [smb writeData:data toPath:file progress:nil completionHandler:^(NSError *writeErr) {
                XCTAssertNil(writeErr);
                [smb copyItemAtPath:file toPath:destFile recursive:NO progress:^BOOL(int64_t bytes, int64_t total) {
                    XCTAssertGreaterThan(bytes, 0);
                    XCTAssertEqual(total, (int64_t)data.length);
                    return YES;
                } completionHandler:^(NSError *copyErr) {
                    XCTAssertNil(copyErr);
                    [smb attributesOfItemAtPath:destFile completionHandler:^(NSDictionary<NSURLResourceKey,id> *attribs, NSError *attrErr) {
                        XCTAssertNil(attrErr);
                        XCTAssertEqual([attribs[NSURLFileSizeKey] longLongValue], (int64_t)data.length);
                        // Cleanup
                        [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                            [smb removeFileAtPath:destFile completionHandler:^(NSError *rmErr2) {
                                [exp fulfill];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Move

- (void)testMove {
    XCTestExpectation *exp = [self expectationWithDescription:@"move"];
    NSString *folder = FolderName(NSStringFromSelector(_cmd), nil);
    NSString *dest = FolderName(NSStringFromSelector(_cmd), @"Dest");
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        // Pre-cleanup leftovers
        [smb removeDirectoryAtPath:folder recursive:YES completionHandler:^(NSError *pre1) {
        [smb removeDirectoryAtPath:dest recursive:YES completionHandler:^(NSError *pre2) {
        usleep(200000); // Wait for server to clear delete-pending state
        [smb createDirectoryAtPath:folder completionHandler:^(NSError *mkErr) {
            XCTAssertNil(mkErr);
            [smb moveItemAtPath:folder toPath:dest completionHandler:^(NSError *moveErr) {
                XCTAssertNil(moveErr);
                // Cleanup
                [smb removeDirectoryAtPath:dest recursive:NO completionHandler:^(NSError *rmErr) {
                    [exp fulfill];
                }];
            }];
        }];
        }]; // pre2
        }]; // pre1
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Recursive Copy/Remove

- (void)testRecursiveCopyRemove {
    XCTestExpectation *exp = [self expectationWithDescription:@"recursive-copy"];
    NSString *root = FolderName(NSStringFromSelector(_cmd), nil);
    NSString *rootCopy = FolderName(NSStringFromSelector(_cmd), @" Copy");
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        // Clean up leftover directories from previous failed runs
        [smb removeDirectoryAtPath:rootCopy recursive:YES completionHandler:^(NSError *pre1) {
            [smb removeDirectoryAtPath:root recursive:YES completionHandler:^(NSError *pre2) {
                usleep(200000); // Wait for server to clear delete-pending state
                [smb createDirectoryAtPath:root completionHandler:^(NSError *mkErr) {
                    XCTAssertNil(mkErr);
                    NSString *subdir = [NSString stringWithFormat:@"%@/subdir", root];
                    [smb createDirectoryAtPath:subdir completionHandler:^(NSError *mkErr2) {
                        XCTAssertNil(mkErr2);
                        NSString *filePath = [NSString stringWithFormat:@"%@/file", root];
                        NSData *fileData = [NSData dataWithBytes:"\x01\x02\x03" length:3];
                        [smb writeData:fileData toPath:filePath progress:nil completionHandler:^(NSError *writeErr) {
                            XCTAssertNil(writeErr);
                            [smb copyItemAtPath:root toPath:rootCopy recursive:YES progress:nil completionHandler:^(NSError *copyErr) {
                                XCTAssertNil(copyErr);
                                NSString *copiedFile = [NSString stringWithFormat:@"%@/file", rootCopy];
                                [smb attributesOfItemAtPath:copiedFile completionHandler:^(NSDictionary<NSURLResourceKey,id> *attribs, NSError *attrErr) {
                                    XCTAssertNil(attrErr);
                                    XCTAssertEqual([attribs[NSURLFileSizeKey] longLongValue], 3);
                                    // Cleanup
                                    [smb removeDirectoryAtPath:root recursive:YES completionHandler:^(NSError *rmErr) {
                                        [smb removeDirectoryAtPath:rootCopy recursive:YES completionHandler:^(NSError *rmErr2) {
                                            [exp fulfill];
                                        }];
                                    }];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Remove

- (void)testRemove {
    XCTestExpectation *exp = [self expectationWithDescription:@"remove"];
    NSString *folder = FolderName(NSStringFromSelector(_cmd), nil);
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        // Clean up leftover directory from previous failed runs
        [smb removeDirectoryAtPath:folder recursive:YES completionHandler:^(NSError *pre) {
        usleep(200000); // Wait for server to clear delete-pending state
        [smb createDirectoryAtPath:folder completionHandler:^(NSError *mkErr) {
            XCTAssertNil(mkErr);
            NSString *subdir = [NSString stringWithFormat:@"%@/subdir", folder];
            [smb createDirectoryAtPath:subdir completionHandler:^(NSError *mkErr2) {
                XCTAssertNil(mkErr2);
                NSString *filePath = [NSString stringWithFormat:@"%@/file", folder];
                [smb writeData:[NSData data] toPath:filePath progress:nil completionHandler:^(NSError *writeErr) {
                    XCTAssertNil(writeErr);
                    [smb removeDirectoryAtPath:folder recursive:YES completionHandler:^(NSError *rmErr) {
                        XCTAssertNil(rmErr);
                        [exp fulfill];
                    }];
                }];
            }];
        }];
        }]; // pre-cleanup
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Umlauts (Non-ASCII paths)

- (void)testUmlautFileOperations {
    XCTestExpectation *exp = [self expectationWithDescription:@"umlaut-file"];
    NSString *file = @"Ärger_Öffnung_Über.dat";
    NSString *renamed = @"Ünterführung_Ähnlich.dat";
    NSData *data = RandomData(256);
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [self cleanupFilesOnManager:smb paths:@[file, renamed] completion:^{
            // Write file with umlauts in name
            [smb writeData:data toPath:file progress:nil completionHandler:^(NSError *writeErr) {
                XCTAssertNil(writeErr);
                // Read back
                [smb contentsAtPath:file fromOffset:0 toLength:-1 progress:nil completionHandler:^(NSData *rdata, NSError *readErr) {
                    XCTAssertNil(readErr);
                    XCTAssertEqualObjects(data, rdata);
                    // Get attributes
                    [smb attributesOfItemAtPath:file completionHandler:^(NSDictionary *attribs, NSError *attrErr) {
                        XCTAssertNil(attrErr);
                        XCTAssertEqual([attribs[NSURLFileSizeKey] longLongValue], (int64_t)data.length);
                        // Rename to another umlaut name
                        [smb moveItemAtPath:file toPath:renamed completionHandler:^(NSError *moveErr) {
                            XCTAssertNil(moveErr);
                            // Read renamed file
                            [smb contentsAtPath:renamed fromOffset:0 toLength:-1 progress:nil completionHandler:^(NSData *rdata2, NSError *readErr2) {
                                XCTAssertNil(readErr2);
                                XCTAssertEqualObjects(data, rdata2);
                                // Cleanup
                                [smb removeFileAtPath:renamed completionHandler:^(NSError *rmErr) {
                                    XCTAssertNil(rmErr);
                                    [exp fulfill];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

- (void)testUmlautDirectoryOperations {
    XCTestExpectation *exp = [self expectationWithDescription:@"umlaut-dir"];
    NSString *folder = @"Bücher_Wörter";
    NSString *dest = @"Größe_Übung";
    NSString *subFile = [NSString stringWithFormat:@"%@/Prüfung.dat", folder];
    NSData *data = RandomData(128);
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        // Pre-cleanup
        [smb removeDirectoryAtPath:dest recursive:YES completionHandler:^(NSError *pre1) {
        [smb removeDirectoryAtPath:folder recursive:YES completionHandler:^(NSError *pre2) {
        usleep(200000);
        // Create directory with umlauts
        [smb createDirectoryAtPath:folder completionHandler:^(NSError *mkErr) {
            XCTAssertNil(mkErr);
            // Write file inside umlaut directory
            [smb writeData:data toPath:subFile progress:nil completionHandler:^(NSError *writeErr) {
                XCTAssertNil(writeErr);
                // List contents
                [smb contentsOfDirectoryAtPath:folder recursive:NO completionHandler:^(NSArray *contents, NSError *listErr) {
                    XCTAssertNil(listErr);
                    XCTAssertEqual(contents.count, 1);
                    XCTAssertTrue([contents.firstObject[NSURLNameKey] containsString:@"Prüfung"]);
                    // Move directory to another umlaut name
                    [smb removeFileAtPath:subFile completionHandler:^(NSError *rmFileErr) {
                        [smb removeDirectoryAtPath:folder recursive:NO completionHandler:^(NSError *rmDirErr) {
                            XCTAssertNil(rmDirErr);
                            usleep(200000);
                            [smb createDirectoryAtPath:folder completionHandler:^(NSError *mkErr2) {
                                XCTAssertNil(mkErr2);
                                [smb moveItemAtPath:folder toPath:dest completionHandler:^(NSError *moveErr) {
                                    XCTAssertNil(moveErr);
                                    // Cleanup
                                    [smb removeDirectoryAtPath:dest recursive:YES completionHandler:^(NSError *rmErr) {
                                        XCTAssertNil(rmErr);
                                        [exp fulfill];
                                    }];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
        }]; // pre2
        }]; // pre1
    }];

    [self waitForExpectation:exp];
}

- (void)testUmlautUploadDownload {
    XCTestExpectation *exp = [self expectationWithDescription:@"umlaut-upload"];
    NSString *file = @"Äpfel_und_Würstchen.dat";
    NSInteger size = 1024 + RandomInt(4096);
    NSURL *url = [self dummyFileWithSize:size name:@"umlaut_upload"];
    NSURL *dlURL = [url URLByAppendingPathExtension:@"downloaded"];
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [self cleanupFilesOnManager:smb paths:@[file] completion:^{
            [smb uploadItemAtURL:url toPath:file progress:nil completionHandler:^(NSError *upErr) {
                XCTAssertNil(upErr);
                [smb downloadItemAtPath:file toURL:dlURL progress:nil completionHandler:^(NSError *dlErr) {
                    XCTAssertNil(dlErr);
                    XCTAssertTrue([NSFileManager.defaultManager contentsEqualAtPath:url.path andPath:dlURL.path]);
                    // Cleanup
                    [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                        [NSFileManager.defaultManager removeItemAtURL:url error:nil];
                        [NSFileManager.defaultManager removeItemAtURL:dlURL error:nil];
                        [exp fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

- (void)testUmlautCopy {
    XCTestExpectation *exp = [self expectationWithDescription:@"umlaut-copy"];
    NSString *file = @"Lösung_Füße.dat";
    NSString *destFile = @"Größenänderung.dat";
    NSData *data = RandomData(512);
    AMSMB2Manager *smb = [self newManager];

    [self connectManager:smb completion:^(NSError *error) {
        XCTAssertNil(error);
        [self cleanupFilesOnManager:smb paths:@[file, destFile] completion:^{
            [smb writeData:data toPath:file progress:nil completionHandler:^(NSError *writeErr) {
                XCTAssertNil(writeErr);
                [smb copyItemAtPath:file toPath:destFile recursive:NO progress:nil completionHandler:^(NSError *copyErr) {
                    XCTAssertNil(copyErr);
                    [smb contentsAtPath:destFile fromOffset:0 toLength:-1 progress:nil completionHandler:^(NSData *rdata, NSError *readErr) {
                        XCTAssertNil(readErr);
                        XCTAssertEqualObjects(data, rdata);
                        // Cleanup
                        [smb removeFileAtPath:file completionHandler:^(NSError *rmErr) {
                            [smb removeFileAtPath:destFile completionHandler:^(NSError *rmErr2) {
                                [exp fulfill];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectation:exp];
}

#pragma mark - Helpers

- (void)cleanupFilesOnManager:(AMSMB2Manager *)smb paths:(NSArray<NSString *> *)paths completion:(void (^)(void))completion {
    if (paths.count == 0) {
        // Wait for server to finish processing any delete-pending state.
        usleep(200000);
        completion();
        return;
    }
    NSMutableArray *remaining = [paths mutableCopy];
    NSString *path = remaining.firstObject;
    [remaining removeObjectAtIndex:0];
    [smb removeFileAtPath:path completionHandler:^(NSError *err) {
        [self cleanupFilesOnManager:smb paths:remaining completion:completion];
    }];
}

- (NSURL *)dummyFileWithSize:(NSInteger)size name:(NSString *)name {
    NSString *fileName = FileName(name, nil);
    NSURL *url = [[NSURL fileURLWithPath:NSTemporaryDirectory()] URLByAppendingPathComponent:fileName];

    if ([NSFileManager.defaultManager fileExistsAtPath:url.path]) {
        [NSFileManager.defaultManager removeItemAtURL:url error:nil];
    }

    NSData *data = RandomData(size);
    [data writeToURL:url atomically:YES];
    return url;
}

@end
