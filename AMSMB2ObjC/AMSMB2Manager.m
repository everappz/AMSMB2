//
//  AMSMB2Manager.m
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import "AMSMB2Manager.h"
#import "SMB2Client.h"
#import "SMB2FileHandle.h"
#import "SMB2Directory.h"
#import "SMB2Helpers.h"

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/smb2-errors.h>

static NSString *const kCodingKeyURL = @"url";
static NSString *const kCodingKeyDomain = @"domain";
static NSString *const kCodingKeyWorkstation = @"workstation";
static NSString *const kCodingKeyUser = @"user";
static NSString *const kCodingKeyPassword = @"password";
static NSString *const kCodingKeyTimeout = @"timeout";

#pragma mark - Private Interface

@interface AMSMB2Manager ()
@property (nonatomic, strong, nullable) SMB2Client *client;
@property (nonatomic, copy) NSString *smb2Domain;
@property (nonatomic, copy) NSString *smb2Workstation;
@property (nonatomic, copy) NSString *smb2User;
@property (nonatomic, copy) NSString *smb2Password;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic) NSTimeInterval internalTimeout;
@property (nonatomic, strong) NSLock *connectLock;
@property (nonatomic, strong) NSCondition *operationLock;
@property (nonatomic) NSInteger operationCount;
@end

#pragma mark -

@implementation AMSMB2Manager

+ (BOOL)supportsSecureCoding {
    return YES;
}

#pragma mark - Init

- (nullable instancetype)initWithURL:(NSURL *)url credential:(nullable NSURLCredential *)credential {
    return [self initWithURL:url domain:@"" credential:credential];
}

- (nullable instancetype)initWithURL:(NSURL *)url domain:(NSString *)domain credential:(nullable NSURLCredential *)credential {
    if (!url.scheme || ![url.scheme.lowercaseString isEqualToString:@"smb"] || !url.host) {
        return nil;
    }

    self = [super init];
    if (!self) return nil;

    NSString *hostLabel = url.host ? [NSString stringWithFormat:@"_%@", url.host] : @"";
    _queue = dispatch_queue_create(
        [[NSString stringWithFormat:@"smb2_queue%@", hostLabel] UTF8String],
        DISPATCH_QUEUE_CONCURRENT
    );
    _url = url;
    _connectLock = [[NSLock alloc] init];
    _operationLock = [[NSCondition alloc] init];
    _operationCount = 0;

    NSString *currentDomain = domain ?: @"";
    NSString *workstation = @"";
    NSString *user = @"guest";

    NSString *undigestedUser = credential.user ?: url.user;
    if (undigestedUser) {
        // Extract domain from "domain;user" format
        if (currentDomain.length == 0) {
            NSArray<NSString *> *semiParts = [undigestedUser componentsSeparatedByString:@";"];
            if (semiParts.count == 2) {
                currentDomain = semiParts[0];
                undigestedUser = semiParts[1];
            }
        }

        NSArray<NSString *> *userParts = [undigestedUser componentsSeparatedByString:@"\\"];
        if (userParts.count == 1) {
            user = userParts[0];
        } else if (userParts.count == 2) {
            workstation = userParts[0];
            user = userParts[1];
        }
    }

    _smb2Domain = currentDomain;
    _smb2Workstation = workstation;
    _smb2User = user;
    _smb2Password = credential.password ?: @"";
    _internalTimeout = 60.0;

    return self;
}

#pragma mark - NSSecureCoding

- (nullable instancetype)initWithCoder:(NSCoder *)coder {
    NSURL *url = [coder decodeObjectOfClass:[NSURL class] forKey:kCodingKeyURL];
    if (!url || ![url.scheme.lowercaseString isEqualToString:@"smb"] || !url.host) {
        return nil;
    }

    self = [super init];
    if (!self) return nil;

    NSString *hostLabel = url.host ? [NSString stringWithFormat:@"_%@", url.host] : @"";
    _queue = dispatch_queue_create(
        [[NSString stringWithFormat:@"smb2_queue%@", hostLabel] UTF8String],
        DISPATCH_QUEUE_CONCURRENT
    );
    _url = url;
    _connectLock = [[NSLock alloc] init];
    _operationLock = [[NSCondition alloc] init];
    _operationCount = 0;

    _smb2Domain = [coder decodeObjectOfClass:[NSString class] forKey:kCodingKeyDomain] ?: @"";
    _smb2Workstation = [coder decodeObjectOfClass:[NSString class] forKey:kCodingKeyWorkstation] ?: @"";
    _smb2User = [coder decodeObjectOfClass:[NSString class] forKey:kCodingKeyUser] ?: @"";
    _smb2Password = [coder decodeObjectOfClass:[NSString class] forKey:kCodingKeyPassword] ?: @"";
    _internalTimeout = [coder decodeDoubleForKey:kCodingKeyTimeout];
    if (_internalTimeout == 0) _internalTimeout = 60.0;

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:_url forKey:kCodingKeyURL];
    [coder encodeObject:_smb2Domain forKey:kCodingKeyDomain];
    [coder encodeObject:_smb2Workstation forKey:kCodingKeyWorkstation];
    [coder encodeObject:_smb2User forKey:kCodingKeyUser];
    [coder encodeObject:_smb2Password forKey:kCodingKeyPassword];
    [coder encodeDouble:self.timeout forKey:kCodingKeyTimeout];
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    NSURLCredential *credential = [NSURLCredential credentialWithUser:_smb2User
                                                            password:_smb2Password
                                                         persistence:NSURLCredentialPersistenceForSession];
    AMSMB2Manager *copy = [[AMSMB2Manager alloc] initWithURL:_url domain:_smb2Domain credential:credential];
    copy.smb2Workstation = _smb2Workstation;
    copy.timeout = self.timeout;
    return copy;
}

#pragma mark - Properties

- (NSTimeInterval)timeout {
    return _client.timeout > 0 ? _client.timeout : _internalTimeout;
}

- (void)setTimeout:(NSTimeInterval)timeout {
    _internalTimeout = timeout;
    _client.timeout = timeout;
}

#pragma mark - Queue Management

- (void)enqueueOperation:(dispatch_block_t)block {
    [_operationLock lock];
    _operationCount++;
    [_operationLock unlock];

    dispatch_async(_queue, ^{
        block();
        [self->_operationLock lock];
        self->_operationCount--;
        [self->_operationLock broadcast];
        [self->_operationLock unlock];
    });
}

- (void)initClient:(SMB2Client *)client encrypted:(BOOL)encrypted {
    client.authentication = SMB2_SEC_NTLMSSP;
    client.securityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
    client.seal = encrypted;
    client.domain = _smb2Domain;
    client.workstation = _smb2Workstation;
    client.user = _smb2User;
    client.password = _smb2Password;
    client.timeout = _internalTimeout;
}

- (SMB2Client *_Nullable)connectToShare:(NSString *)shareName encrypted:(BOOL)encrypted error:(NSError **)error {
    SMB2Client *client = [[SMB2Client alloc] initWithTimeout:_internalTimeout error:error];
    if (!client) return nil;

    self.client = client;
    [self initClient:client encrypted:encrypted];

    NSString *server = self.url.host ?: @"";
    if (self.url.port) {
        server = [NSString stringWithFormat:@"%@:%@", server, self.url.port];
    }

    if (![client connectServer:server share:shareName user:_smb2User error:error]) {
        return nil;
    }
    return client;
}

- (SMB2Client *_Nullable)ensureClient:(NSError **)error {
    SMB2Client *client = self.client;
    if (!client || !client.isConnected) {
        if (error) *error = SMB2POSIXError(ENOTCONN, @"SMB2 server not connected.");
        return nil;
    }
    return client;
}

#pragma mark - Connection

- (void)connectShareWithName:(NSString *)name completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self connectShareWithName:name encrypted:NO completionHandler:completionHandler];
}

- (void)connectShareWithName:(NSString *)name encrypted:(BOOL)encrypted completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        [self->_connectLock lock];
        @try {
            if (self.client) {
                [self.client disconnectWithError:nil];
            }
            NSError *error = nil;
            [self connectToShare:name encrypted:encrypted error:&error];
            if (completionHandler) completionHandler(error);
        } @finally {
            [self->_connectLock unlock];
        }
    }];
}

- (void)disconnectShare {
    [self disconnectShareGracefully:NO completionHandler:nil];
}

- (void)disconnectShareWithCompletionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self disconnectShareGracefully:NO completionHandler:completionHandler];
}

- (void)disconnectShareGracefully:(BOOL)gracefully completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        if (gracefully) {
            [self->_operationLock lock];
            while (self->_operationCount > 1) {
                [self->_operationLock wait];
            }
            [self->_operationLock unlock];
        }

        [self->_connectLock lock];
        @try {
            NSError *error = nil;
            [self.client disconnectWithError:&error];
            self.client = nil;
            if (completionHandler) completionHandler(error);
        } @finally {
            [self->_connectLock unlock];
        }
    }];
}

#pragma mark - Echo

- (void)echoWithCompletionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (client) {
            [client echoWithError:&error];
        }
        if (completionHandler) completionHandler(error);
    }];
}

#pragma mark - Share Listing

- (void)listSharesWithCompletionHandler:(void (^)(NSArray<NSString *> *, NSArray<NSString *> *, NSError * _Nullable))completionHandler {
    [self listSharesWithEnumerateHidden:NO completionHandler:completionHandler];
}

- (void)listSharesWithEnumerateHidden:(BOOL)enumerateHidden completionHandler:(void (^)(NSArray<NSString *> *, NSArray<NSString *> *, NSError * _Nullable))completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        NSString *shareName = @"IPC$";
        SMB2Client *client = [self connectToShare:shareName encrypted:NO error:&error];
        if (!client) {
            completionHandler(@[], @[], error);
            return;
        }

        @try {
            NSArray<NSDictionary *> *shares = [client shareEnumWithError:&error];
            if (!shares) {
                shares = [client shareEnumSwiftWithError:&error];
            }

            if (!shares) {
                completionHandler(@[], @[], error);
                return;
            }

            NSMutableArray<NSString *> *names = [NSMutableArray array];
            NSMutableArray<NSString *> *comments = [NSMutableArray array];
            for (NSDictionary *share in shares) {
                uint32_t type = [share[@"type"] unsignedIntValue];
                SMB2ShareProperties props = { type };
                if (!SMB2SharePropertiesIsDiskTree(props)) continue;
                if (!enumerateHidden && SMB2SharePropertiesIsHidden(props)) continue;
                [names addObject:share[@"name"] ?: @""];
                [comments addObject:share[@"comment"] ?: @""];
            }
            completionHandler(names, comments, nil);
        } @finally {
            [client disconnectWithError:nil];
        }
    }];
}

#pragma mark - Directory Contents

- (void)contentsOfDirectoryAtPath:(NSString *)path recursive:(BOOL)recursive completionHandler:(void (^)(NSArray<NSDictionary<NSURLResourceKey,id> *> * _Nullable, NSError * _Nullable))completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            completionHandler(nil, error);
            return;
        }
        NSArray *contents = [self listDirectoryWithClient:client path:path recursive:recursive error:&error];
        completionHandler(contents, error);
    }];
}

#pragma mark - Attributes

- (void)attributesOfFileSystemForPath:(NSString *)path completionHandler:(void (^)(NSDictionary<NSFileAttributeKey,id> * _Nullable, NSError * _Nullable))completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            completionHandler(nil, error);
            return;
        }

        struct smb2_statvfs st = {0};
        if ([client statvfs:path result:&st error:&error]) {
            completionHandler(SMB2FileSystemAttributesFromStatVFS(&st), nil);
        } else {
            completionHandler(nil, error);
        }
    }];
}

- (void)attributesOfItemAtPath:(NSString *)path completionHandler:(void (^)(NSDictionary<NSURLResourceKey,id> * _Nullable, NSError * _Nullable))completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            completionHandler(nil, error);
            return;
        }

        struct smb2_stat_64 st = {0};
        if ([client stat:path result:&st error:&error]) {
            NSMutableDictionary *result = [NSMutableDictionary dictionary];
            NSURL *fileURL = SMB2FileURLFromPath(path, st.smb2_type == SMB2_TYPE_DIRECTORY);
            result[NSURLNameKey] = fileURL.lastPathComponent;
            result[NSURLPathKey] = fileURL.path;
            SMB2PopulateResourceValues(result, &st);
            completionHandler(result, nil);
        } else {
            completionHandler(nil, error);
        }
    }];
}

- (void)destinationOfSymbolicLinkAtPath:(NSString *)path completionHandler:(void (^)(NSString * _Nullable, NSError * _Nullable))completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            completionHandler(nil, error);
            return;
        }

        NSString *dest = [client readlink:path error:&error];
        completionHandler(dest, error);
    }];
}

#pragma mark - File/Directory Operations

- (void)createDirectoryAtPath:(NSString *)path completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (client) {
            [client mkdir:path error:&error];
        }
        if (completionHandler) completionHandler(error);
    }];
}

- (void)removeDirectoryAtPath:(NSString *)path recursive:(BOOL)recursive completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (client) {
            [self removeDirectoryWithClient:client path:path recursive:recursive error:&error];
        }
        if (completionHandler) completionHandler(error);
    }];
}

- (void)removeFileAtPath:(NSString *)path completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (client) {
            if (![client unlink:path error:&error]) {
                // Try to remove as symbolic link
                if (error.code == ENOLINK || error.code == ENETRESET) {
                    error = nil;
                    [client unlinkSymlink:path error:&error];
                }
            }
        }
        if (completionHandler) completionHandler(error);
    }];
}

- (void)removeItemAtPath:(NSString *)path completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            if (completionHandler) completionHandler(error);
            return;
        }

        struct smb2_stat_64 st = {0};
        BOOL gotStat = [client stat:path result:&st error:&error];
        if (!gotStat && error.code == ENOLINK) {
            // Try as reparse point
            error = nil;
            SMB2FileHandle *file = [[SMB2FileHandle alloc] initWithPath:path flags:O_RDONLY | O_SYMLINK on:client error:&error];
            if (file) {
                gotStat = [file fstat:&st error:&error];
                [file close];
            }
        }

        if (!gotStat) {
            if (completionHandler) completionHandler(error);
            return;
        }

        error = nil;
        if (st.smb2_type == SMB2_TYPE_DIRECTORY) {
            [self removeDirectoryWithClient:client path:path recursive:YES error:&error];
        } else if (st.smb2_type == SMB2_TYPE_LINK) {
            [client unlinkSymlink:path error:&error];
        } else {
            [client unlink:path error:&error];
        }

        if (completionHandler) completionHandler(error);
    }];
}

- (void)truncateFileAtPath:(NSString *)path atOffset:(uint64_t)offset completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (client) {
            [client truncate:path toLength:offset error:&error];
        }
        if (completionHandler) completionHandler(error);
    }];
}

- (void)moveItemAtPath:(NSString *)path toPath:(NSString *)toPath completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (client) {
            [client rename:path to:toPath error:&error];
        }
        if (completionHandler) completionHandler(error);
    }];
}

#pragma mark - Read

- (void)contentsAtPath:(NSString *)path fromOffset:(int64_t)offset toLength:(NSInteger)length progress:(SMB2ReadProgressHandler)progress completionHandler:(void (^)(NSData * _Nullable, NSError * _Nullable))completionHandler {
    if (offset < 0) {
        completionHandler(nil, SMB2POSIXError(EINVAL, @"Invalid content offset."));
        return;
    }

    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            completionHandler(nil, error);
            return;
        }

        int64_t rangeStart = offset;
        int64_t rangeEnd = length >= 0 ? (offset + (int64_t)length) : INT64_MAX;

        NSOutputStream *stream = [NSOutputStream outputStreamToMemory];
        [self readWithClient:client path:path rangeStart:rangeStart rangeEnd:rangeEnd toStream:stream progress:progress error:&error];

        if (error) {
            completionHandler(nil, error);
        } else {
            NSData *data = [stream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
            completionHandler(data ?: [NSData data], nil);
        }
    }];
}

- (void)contentsAtPath:(NSString *)path fromOffset:(int64_t)offset fetchedData:(BOOL (^)(int64_t, int64_t, NSData *))fetchedData completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            if (completionHandler) completionHandler(error);
            return;
        }

        SMB2FileHandle *file = [[SMB2FileHandle alloc] initForReadingAtPath:path on:client error:&error];
        if (!file) {
            if (completionHandler) completionHandler(error);
            return;
        }

        struct smb2_stat_64 st = {0};
        if (![file fstat:&st error:&error]) {
            if (completionHandler) completionHandler(error);
            return;
        }
        int64_t size = (int64_t)st.smb2_size;

        [file lseekOffset:offset whence:SEEK_SET error:&error];
        if (error) {
            if (completionHandler) completionHandler(error);
            return;
        }

        BOOL shouldContinue = YES;
        while (shouldContinue) {
            int64_t currentOffset = [file lseekOffset:0 whence:SEEK_CUR error:&error];
            if (error) break;

            NSData *data = [file readWithLength:0 error:&error];
            if (error) break;
            if (data.length == 0) break;

            shouldContinue = fetchedData(currentOffset, size, data);
        }

        if (completionHandler) completionHandler(error);
    }];
}

#pragma mark - Write

- (void)writeData:(NSData *)data toPath:(NSString *)path progress:(SMB2WriteProgressHandler)progress completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            if (completionHandler) completionHandler(error);
            return;
        }

        NSInputStream *stream = [NSInputStream inputStreamWithData:data];
        [self writeWithClient:client fromStream:stream toPath:path offset:nil chunkSize:0 progress:progress error:&error];
        if (completionHandler) completionHandler(error);
    }];
}

- (void)appendData:(NSData *)data toPath:(NSString *)path offset:(int64_t)offset progress:(SMB2WriteProgressHandler)progress completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            if (completionHandler) completionHandler(error);
            return;
        }

        NSInputStream *stream = [NSInputStream inputStreamWithData:data];
        NSNumber *offsetNum = @(offset);
        [self writeWithClient:client fromStream:stream toPath:path offset:offsetNum chunkSize:0 progress:progress error:&error];
        if (completionHandler) completionHandler(error);
    }];
}

#pragma mark - Copy

- (void)copyItemAtPath:(NSString *)path toPath:(NSString *)toPath recursive:(BOOL)recursive progress:(SMB2ReadProgressHandler)progress completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            if (completionHandler) completionHandler(error);
            return;
        }

        [self recursiveCopyWithClient:client fromPath:path toPath:toPath recursive:recursive progress:progress error:&error];
        if (completionHandler) completionHandler(error);
    }];
}

#pragma mark - Upload/Download

- (void)uploadItemAtURL:(NSURL *)url toPath:(NSString *)toPath progress:(SMB2WriteProgressHandler)progress completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            if (completionHandler) completionHandler(error);
            return;
        }

        if (!url.isFileURL) {
            error = SMB2POSIXError(EIO, @"Could not create Stream from given URL, or given URL is not a local file.");
            if (completionHandler) completionHandler(error);
            return;
        }

        NSInputStream *stream = [NSInputStream inputStreamWithURL:url];
        if (!stream) {
            error = SMB2POSIXError(EIO, @"Could not create Stream from given URL, or given URL is not a local file.");
            if (completionHandler) completionHandler(error);
            return;
        }

        [self writeWithClient:client fromStream:stream toPath:toPath offset:nil chunkSize:0 progress:progress error:&error];
        if (completionHandler) completionHandler(error);
    }];
}

- (void)downloadItemAtPath:(NSString *)path toURL:(NSURL *)url progress:(SMB2ReadProgressHandler)progress completionHandler:(SMB2SimpleCompletionHandler)completionHandler {
    [self enqueueOperation:^{
        NSError *error = nil;
        SMB2Client *client = [self ensureClient:&error];
        if (!client) {
            if (completionHandler) completionHandler(error);
            return;
        }

        if (!url.isFileURL) {
            error = SMB2POSIXError(EIO, @"Could not create Stream from given URL, or given URL is not a local file.");
            if (completionHandler) completionHandler(error);
            return;
        }

        NSOutputStream *stream = [NSOutputStream outputStreamWithURL:url append:NO];
        if (!stream) {
            error = SMB2POSIXError(EIO, @"Could not create Stream from given URL, or given URL is not a local file.");
            if (completionHandler) completionHandler(error);
            return;
        }

        [self readWithClient:client path:path rangeStart:0 rangeEnd:INT64_MAX toStream:stream progress:progress error:&error];
        if (completionHandler) completionHandler(error);
    }];
}

#pragma mark - Private: Directory Listing

- (NSArray<NSDictionary<NSURLResourceKey, id> *> *_Nullable)listDirectoryWithClient:(SMB2Client *)client
                                                                               path:(NSString *)path
                                                                          recursive:(BOOL)recursive
                                                                              error:(NSError **)error {
    NSString *canonical = SMB2CanonicalPath(path);
    SMB2Directory *dir = [[SMB2Directory alloc] initWithPath:canonical on:client error:error];
    if (!dir) return nil;

    NSMutableArray *contents = [NSMutableArray array];
    [dir enumerateEntriesUsingBlock:^(const char *name, struct smb2_stat_64 st) {
        NSString *entryName = [NSString stringWithUTF8String:name];
        if ([entryName isEqualToString:@"."] || [entryName isEqualToString:@".."]) return;

        BOOL isDir = (st.smb2_type == SMB2_TYPE_DIRECTORY);
        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        NSURL *parentURL = SMB2FileURLFromPath(path, YES);
        NSURL *entryURL = [parentURL URLByAppendingPathComponent:entryName isDirectory:isDir];
        result[NSURLNameKey] = entryName;
        result[NSURLPathKey] = entryURL.path;
        SMB2PopulateResourceValues(result, &st);
        [contents addObject:result];
    }];

    if (recursive) {
        NSArray *snapshot = [contents copy];
        for (NSDictionary *entry in snapshot) {
            if ([entry[NSURLIsDirectoryKey] boolValue]) {
                NSString *subPath = entry[NSURLPathKey];
                if (!subPath) continue;
                NSError *subError = nil;
                NSArray *subContents = [self listDirectoryWithClient:client path:subPath recursive:YES error:&subError];
                if (subContents) {
                    [contents addObjectsFromArray:subContents];
                }
            }
        }
    }

    return contents;
}

#pragma mark - Private: Read

- (void)readWithClient:(SMB2Client *)client
                  path:(NSString *)path
            rangeStart:(int64_t)rangeStart
              rangeEnd:(int64_t)rangeEnd
              toStream:(NSOutputStream *)stream
              progress:(SMB2ReadProgressHandler)progress
                 error:(NSError **)error {
    SMB2FileHandle *file = [[SMB2FileHandle alloc] initForReadingAtPath:path on:client error:error];
    if (!file) return;

    struct smb2_stat_64 st = {0};
    if (![file fstat:&st error:error]) return;

    int64_t filesize = (int64_t)st.smb2_size;
    int64_t length = rangeEnd - rangeStart;
    int64_t size = MIN(length, filesize - rangeStart);
    if (size <= 0) return;

    [stream open];
    @try {
        BOOL shouldContinue = YES;
        int64_t sent = 0;
        [file lseekOffset:rangeStart whence:SEEK_SET error:error];
        if (error && *error) return;

        while (shouldContinue) {
            NSInteger prefCount = (NSInteger)MIN((int64_t)file.optimizedReadSize, size - sent);
            if (prefCount <= 0) break;

            NSData *data = [file readWithLength:prefCount error:error];
            if (error && *error) return;
            if (data.length == 0) break;

            const uint8_t *bytes = data.bytes;
            NSInteger written = [stream write:bytes maxLength:data.length];
            if (written < 0) {
                if (error) *error = stream.streamError ?: SMB2POSIXError(EIO, @"Stream write error.");
                return;
            }
            if (written != (NSInteger)data.length) {
                if (error) *error = SMB2POSIXError(EIO, @"Inconsistency in reading from SMB file handle.");
                return;
            }

            sent += written;
            if (progress) {
                shouldContinue = progress(sent, size);
            }
        }
    } @finally {
        [stream close];
    }
}

#pragma mark - Private: Write

- (void)writeWithClient:(SMB2Client *)client
             fromStream:(NSInputStream *)stream
                 toPath:(NSString *)path
                 offset:(NSNumber *_Nullable)offset
              chunkSize:(NSInteger)chunkSize
               progress:(SMB2WriteProgressHandler)progress
                  error:(NSError **)error {
    SMB2FileHandle *file = nil;

    if (offset) {
        int64_t off = offset.longLongValue;
        [client truncate:path toLength:(uint64_t)off error:error];
        if (error && *error) return;
        file = [[SMB2FileHandle alloc] initForOutputAtPath:path on:client error:error];
        if (!file) return;
        [file lseekOffset:off whence:SEEK_SET error:error];
        if (error && *error) return;
    } else {
        file = [[SMB2FileHandle alloc] initForCreatingIfNotExistsAtPath:path on:client error:error];
        if (!file) return;
    }

    NSInteger writeChunkSize = chunkSize > 0 ? chunkSize : file.optimizedWriteSize;
    uint64_t totalWritten = 0;
    uint64_t baseOffset = offset ? (uint64_t)offset.longLongValue : 0;

    [stream open];
    @try {
        while (YES) {
            NSMutableData *segment = [NSMutableData dataWithLength:writeChunkSize];
            uint8_t *buf = segment.mutableBytes;
            NSInteger bytesRead = [stream read:buf maxLength:writeChunkSize];
            if (bytesRead < 0) {
                if (error) *error = stream.streamError ?: SMB2POSIXError(EIO, @"Unknown stream error.");
                return;
            }
            if (bytesRead == 0) break;

            segment.length = bytesRead;
            NSInteger written = [file pwriteData:segment offset:baseOffset + totalWritten error:error];
            if (error && *error) return;
            if (written != bytesRead) {
                if (error) *error = SMB2POSIXError(EIO, @"Inconsistency in writing to SMB file handle.");
                return;
            }

            totalWritten += (uint64_t)bytesRead;
            if (progress) {
                if (!progress((int64_t)totalWritten)) break;
            }
        }
    } @finally {
        [stream close];
    }

    [file fsyncWithError:error];
}

#pragma mark - Private: Remove Directory

- (void)removeDirectoryWithClient:(SMB2Client *)client path:(NSString *)path recursive:(BOOL)recursive error:(NSError **)error {
    if (recursive) {
        NSArray *list = [self listDirectoryWithClient:client path:path recursive:YES error:error];
        if (!list) return;

        // Sort descending by path so children come before parents
        list = [list sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSString *pathA = a[NSURLPathKey] ?: @"";
            NSString *pathB = b[NSURLPathKey] ?: @"";
            return [pathB localizedStandardCompare:pathA];
        }];

        for (NSDictionary *item in list) {
            NSString *itemPath = item[NSURLPathKey];
            if (!itemPath) continue;
            if ([item[NSURLIsDirectoryKey] boolValue]) {
                [client rmdir:itemPath error:error];
            } else {
                [client unlink:itemPath error:error];
            }
            if (error && *error) return;
        }
    }

    [client rmdir:path error:error];
}

#pragma mark - Private: Copy (Server-side)

- (void)recursiveCopyWithClient:(SMB2Client *)client
                       fromPath:(NSString *)path
                         toPath:(NSString *)toPath
                      recursive:(BOOL)recursive
                       progress:(SMB2ReadProgressHandler)progress
                          error:(NSError **)error {
    struct smb2_stat_64 st = {0};
    if (![client stat:path result:&st error:error]) return;

    if (st.smb2_type == SMB2_TYPE_DIRECTORY) {
        [client mkdir:toPath error:error];
        if (error && *error) return;

        NSArray *list = [self listDirectoryWithClient:client path:path recursive:recursive error:error];
        if (!list) return;

        // Sort ascending by path
        list = [list sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSString *pathA = a[NSURLPathKey] ?: @"";
            NSString *pathB = b[NSURLPathKey] ?: @"";
            return [pathA localizedStandardCompare:pathB];
        }];

        // Calculate overall size for progress
        int64_t overallSize = 0;
        for (NSDictionary *item in list) {
            if (![item[NSURLIsDirectoryKey] boolValue]) {
                overallSize += [item[NSURLFileSizeKey] longLongValue];
            }
        }

        int64_t totalCopied = 0;
        NSString *canonical = SMB2CanonicalPath(path);
        for (NSDictionary *item in list) {
            NSString *itemPath = item[NSURLPathKey];
            if (!itemPath) continue;
            NSString *destPath = [SMB2CanonicalPath(itemPath) stringByReplacingOccurrencesOfString:canonical
                                                                                        withString:SMB2CanonicalPath(toPath)
                                                                                           options:NSAnchoredSearch
                                                                                             range:NSMakeRange(0, SMB2CanonicalPath(itemPath).length)];
            if ([item[NSURLIsDirectoryKey] boolValue]) {
                [client mkdir:destPath error:error];
                if (error && *error) return;
            } else {
                int64_t copied = [self copyFileWithClient:client
                                                fromPath:itemPath
                                                  toPath:destPath
                                           totalCopied:totalCopied
                                            overallSize:overallSize
                                               progress:progress
                                                   error:error];
                if (error && *error) return;
                if (copied < 0) return; // Aborted
                totalCopied += copied;
            }
        }
    } else {
        int64_t fileSize = (int64_t)st.smb2_size;
        [self copyFileWithClient:client fromPath:path toPath:toPath totalCopied:0 overallSize:fileSize progress:progress error:error];
    }
}

- (int64_t)copyFileWithClient:(SMB2Client *)client
                     fromPath:(NSString *)path
                       toPath:(NSString *)toPath
                  totalCopied:(int64_t)totalCopied
                  overallSize:(int64_t)overallSize
                     progress:(SMB2ReadProgressHandler)progress
                        error:(NSError **)error {
    SMB2FileHandle *fileSource = [[SMB2FileHandle alloc] initForReadingAtPath:path on:client error:error];
    if (!fileSource) return -1;

    struct smb2_stat_64 st = {0};
    if (![fileSource fstat:&st error:error]) return -1;
    int64_t size = (int64_t)st.smb2_size;

    NSData *sourceKey = [fileSource requestResumeKeyWithError:error];
    if (!sourceKey) return -1;

    NSInteger chunkSize = fileSource.optimizedWriteSize;

    SMB2FileHandle *fileDest = [[SMB2FileHandle alloc] initForCreatingIfNotExistsAtPath:toPath on:client error:error];
    if (!fileDest) return -1;

    BOOL shouldContinue = YES;
    int64_t bytesCopied = 0;

    for (uint64_t offset = 0; offset < (uint64_t)size && shouldContinue; offset += chunkSize) {
        uint32_t len = (uint32_t)MIN((uint64_t)chunkSize, (uint64_t)size - offset);
        NSData *chunkData = SMB2IOCtlBuildCopyChunkCopy(sourceKey, offset, offset, len);
        [fileDest copyChunk:chunkData error:error];
        if (error && *error) return -1;

        bytesCopied = (int64_t)(offset + len);
        if (progress) {
            shouldContinue = progress(totalCopied + bytesCopied, overallSize);
        }
    }

    return shouldContinue ? size : -1;
}

@end
