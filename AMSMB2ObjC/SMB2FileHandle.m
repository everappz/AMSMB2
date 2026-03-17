//
//  SMB2FileHandle.m
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import "SMB2FileHandle.h"
#import "SMB2Client.h"
#import "SMB2Helpers.h"
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <fcntl.h>
#include <string.h>

#ifndef O_SYMLINK
#define O_SYMLINK O_NOFOLLOW
#endif

/// Wrapper struct so smb2_file_id (a C array) can be captured by ObjC blocks.
typedef struct {
    smb2_file_id value;
} SMB2FileIdWrapper;

@interface SMB2FileHandle ()
/// Returns the SMB2 file_id for IOCTL and set-info operations.
- (smb2_file_id *)fileId;
@end

@implementation SMB2FileHandle {
    SMB2Client *_client;
    struct smb2fh *_handle;
}

#pragma mark - Initialization (flags-based)

- (nullable instancetype)initForReadingAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError **)error {
    return [self initWithPath:path flags:O_RDONLY on:client error:error];
}

- (nullable instancetype)initForWritingAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError **)error {
    return [self initWithPath:path flags:O_WRONLY on:client error:error];
}

- (nullable instancetype)initForOverwritingAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError **)error {
    return [self initWithPath:path flags:(O_WRONLY | O_CREAT | O_TRUNC) on:client error:error];
}

- (nullable instancetype)initForOutputAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError **)error {
    return [self initWithPath:path flags:(O_WRONLY | O_CREAT) on:client error:error];
}

- (nullable instancetype)initForCreatingIfNotExistsAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError **)error {
    return [self initWithPath:path flags:(O_RDWR | O_CREAT | O_EXCL) on:client error:error];
}

- (nullable instancetype)initWithPath:(NSString *)path flags:(int32_t)flags on:(SMB2Client *)client error:(NSError **)error {
    self = [super init];
    if (!self) return nil;

    _client = client;
    NSString *canonical = SMB2CanonicalPath(path);

    __block struct smb2fh *fh = NULL;

    int32_t result = [client asyncAwaitWithDataHandler:^(void *commandData) {
        fh = (struct smb2fh *)commandData;
    } execute:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_open_async(context, [canonical UTF8String], flags,
                               [SMB2Client genericHandler], cbPtr);
    } error:error];

    if (result < 0 || !fh) {
        return nil;
    }

    _handle = fh;
    return self;
}

#pragma mark - Initialization (PDU-based create request)

- (nullable instancetype)initWithPath:(NSString *)path
                        desiredAccess:(uint32_t)desiredAccess
                          shareAccess:(uint32_t)shareAccess
                   createDisposition:(uint32_t)createDisposition
                        createOptions:(uint32_t)createOptions
                                   on:(SMB2Client *)client
                                error:(NSError **)error {
    self = [super init];
    if (!self) return nil;

    _client = client;

    // Convert forward slashes to backslashes and trim leading/trailing slashes.
    NSString *backslashPath = [path stringByReplacingOccurrencesOfString:@"/" withString:@"\\"];
    NSCharacterSet *slashSet = [NSCharacterSet characterSetWithCharactersInString:@"\\/"];
    backslashPath = [backslashPath stringByTrimmingCharactersInSet:slashSet];

    __block SMB2FileIdWrapper fileIdWrapper;
    memset(&fileIdWrapper, 0, sizeof(fileIdWrapper));
    __block BOOL gotFileId = NO;

    uint32_t status = [client asyncAwaitPDUWithDataHandler:^(void *commandData) {
        if (commandData) {
            struct smb2_create_reply *reply = (struct smb2_create_reply *)commandData;
            memcpy(fileIdWrapper.value, reply->file_id, sizeof(fileIdWrapper.value));
            gotFileId = YES;
        }
    } execute:^struct smb2_pdu *(struct smb2_context *context, void *cbPtr) {
        struct smb2_create_request req;
        memset(&req, 0, sizeof(req));
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = desiredAccess;
        req.file_attributes = 0;
        req.share_access = shareAccess;
        req.create_disposition = createDisposition;
        req.create_options = createOptions;
        req.name = [backslashPath UTF8String];
        return smb2_cmd_create_async(context, &req, [SMB2Client genericHandler], cbPtr);
    } error:error];

    (void)status;

    if (!gotFileId) {
        return nil;
    }

    // Convert file_id to smb2fh handle.
    _handle = smb2_fh_from_file_id(client.rawContext, &fileIdWrapper.value);
    if (!_handle) {
        if (error) {
            *error = SMB2POSIXError(ENODATA, @"Failed to create file handle from file ID.");
        }
        return nil;
    }

    return self;
}

#pragma mark - Dealloc & Close

- (void)dealloc {
    if (_handle) {
        struct smb2fh *h = _handle;
        [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
            return smb2_close_async(context, h, [SMB2Client genericHandler], cbPtr);
        } error:nil];
    }
}

- (void)close {
    if (!_handle) return;
    struct smb2fh *h = _handle;
    _handle = NULL;
    [_client withContext:^BOOL(struct smb2_context *context) {
        smb2_close(context, h);
        return YES;
    } error:nil];
}

#pragma mark - File ID

- (smb2_file_id *)fileId {
    if (!_handle) return NULL;
    return smb2_get_file_id(_handle);
}

#pragma mark - Properties

- (NSInteger)maxReadSize {
    struct smb2_context *ctx = _client.rawContext;
    return ctx ? (NSInteger)smb2_get_max_read_size(ctx) : -1;
}

- (NSInteger)optimizedReadSize {
    return self.maxReadSize;
}

- (NSInteger)maxWriteSize {
    struct smb2_context *ctx = _client.rawContext;
    return ctx ? (NSInteger)smb2_get_max_write_size(ctx) : -1;
}

- (NSInteger)optimizedWriteSize {
    return self.maxWriteSize;
}

#pragma mark - File Stat

- (BOOL)fstat:(struct smb2_stat_64 *)st error:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return NO;
    }

    __block struct smb2_stat_64 result;
    memset(&result, 0, sizeof(result));

    int32_t r = [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_fstat_async(context, self->_handle, &result,
                                [SMB2Client genericHandler], cbPtr);
    } error:error];

    if (r < 0) return NO;
    *st = result;
    return YES;
}

#pragma mark - Truncate

- (BOOL)ftruncateToLength:(uint64_t)length error:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return NO;
    }

    int32_t r = [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_ftruncate_async(context, self->_handle, length,
                                    [SMB2Client genericHandler], cbPtr);
    } error:error];

    return r >= 0;
}

#pragma mark - Seek

- (int64_t)lseekOffset:(int64_t)offset whence:(int32_t)whence error:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return -1;
    }

    struct smb2_context *ctx = _client.rawContext;
    if (!ctx) {
        if (error) *error = SMB2POSIXError(ENOTCONN, @"Not connected.");
        return -1;
    }

    int64_t result = smb2_lseek(ctx, _handle, offset, whence, NULL);
    if (result < 0) {
        if (error) {
            const char *errStr = smb2_get_error(ctx);
            NSString *desc = errStr ? [NSString stringWithUTF8String:errStr] : nil;
            *error = SMB2POSIXErrorFromResult((int32_t)result, desc);
        }
        return -1;
    }

    return result;
}

#pragma mark - Read

- (nullable NSData *)readWithLength:(NSInteger)length error:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return nil;
    }

    NSInteger count = length > 0 ? length : self.optimizedReadSize;
    if (count <= 0) {
        if (error) *error = SMB2POSIXError(EINVAL, @"Invalid read size.");
        return nil;
    }

    NSMutableData *buffer = [NSMutableData dataWithLength:(NSUInteger)count];

    int32_t result = [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_read_async(context, self->_handle,
                               (uint8_t *)buffer.mutableBytes, (uint32_t)count,
                               [SMB2Client genericHandler], cbPtr);
    } error:error];

    if (result < 0) return nil;
    buffer.length = (NSUInteger)result;
    return [buffer copy];
}

- (nullable NSData *)preadOffset:(uint64_t)offset length:(NSInteger)length error:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return nil;
    }

    NSInteger count = length > 0 ? length : self.optimizedReadSize;
    if (count <= 0) {
        if (error) *error = SMB2POSIXError(EINVAL, @"Invalid read size.");
        return nil;
    }

    NSMutableData *buffer = [NSMutableData dataWithLength:(NSUInteger)count];

    int32_t result = [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_pread_async(context, self->_handle,
                                (uint8_t *)buffer.mutableBytes, (uint32_t)count, offset,
                                [SMB2Client genericHandler], cbPtr);
    } error:error];

    if (result < 0) return nil;
    buffer.length = (NSUInteger)result;
    return [buffer copy];
}

#pragma mark - Write

- (NSInteger)writeData:(NSData *)data error:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return -1;
    }

    int32_t result = [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_write_async(context, self->_handle,
                                (const uint8_t *)data.bytes, (uint32_t)data.length,
                                [SMB2Client genericHandler], cbPtr);
    } error:error];

    return (NSInteger)result;
}

- (NSInteger)pwriteData:(NSData *)data offset:(uint64_t)offset error:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return -1;
    }

    int32_t result = [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_pwrite_async(context, self->_handle,
                                 (const uint8_t *)data.bytes, (uint32_t)data.length, offset,
                                 [SMB2Client genericHandler], cbPtr);
    } error:error];

    return (NSInteger)result;
}

#pragma mark - Fsync

- (BOOL)fsyncWithError:(NSError **)error {
    if (!_handle) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return NO;
    }

    int32_t r = [_client asyncAwait:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_fsync_async(context, self->_handle,
                                [SMB2Client genericHandler], cbPtr);
    } error:error];

    return r >= 0;
}

#pragma mark - IOCTL

- (nullable NSData *)ioctlCommand:(uint32_t)command inputData:(NSData *)inputData error:(NSError **)error {
    smb2_file_id *fidPtr = [self fileId];
    if (!fidPtr) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return nil;
    }

    SMB2FileIdWrapper fidWrapper;
    memcpy(fidWrapper.value, fidPtr, sizeof(fidWrapper.value));

    __block NSData *outputData = nil;

    [_client asyncAwaitPDUWithDataHandler:^(void *commandData) {
        if (commandData) {
            struct smb2_ioctl_reply *reply = (struct smb2_ioctl_reply *)commandData;
            if (reply->output_count > 0 && reply->output) {
                outputData = [NSData dataWithBytes:reply->output length:reply->output_count];
                smb2_free_data(self->_client.rawContext, reply->output);
            }
        }
    } execute:^struct smb2_pdu *(struct smb2_context *context, void *cbPtr) {
        struct smb2_ioctl_request req;
        memset(&req, 0, sizeof(req));
        req.ctl_code = command;
        memcpy(req.file_id, fidWrapper.value, sizeof(req.file_id));
        req.input_count = inputData ? (uint32_t)inputData.length : 0;
        req.input = inputData ? (void *)inputData.bytes : NULL;
        req.max_output_response = 65535;
        req.output_count = (uint32_t)self->_client.maximumTransactionSize;
        req.flags = SMB2_0_IOCTL_IS_FSCTL;
        return smb2_cmd_ioctl_async(context, &req, [SMB2Client genericHandler], cbPtr);
    } error:error];

    return outputData;
}

#pragma mark - Server-side Copy

- (nullable NSData *)requestResumeKeyWithError:(NSError **)error {
    NSData *result = [self ioctlCommand:SMB2_FSCTL_SRV_REQUEST_RESUME_KEY inputData:nil error:error];
    if (result && result.length >= 24) {
        return [result subdataWithRange:NSMakeRange(0, 24)];
    }
    if (error && !*error) {
        *error = SMB2POSIXError(ENODATA, @"Invalid resume key response.");
    }
    return nil;
}

- (BOOL)copyChunk:(NSData *)chunkData error:(NSError **)error {
    NSData *result = [self ioctlCommand:SMB2_FSCTL_SRV_COPYCHUNK inputData:chunkData error:error];
    if (error && *error) return NO;
    return result != nil;
}

#pragma mark - Reparse Point

- (BOOL)setReparsePoint:(NSData *)reparseData error:(NSError **)error {
    [self ioctlCommand:SMB2_FSCTL_SET_REPARSE_POINT inputData:reparseData error:error];
    return error ? (*error == nil) : YES;
}

#pragma mark - Set Info

- (BOOL)setDeletePendingWithError:(NSError **)error {
    smb2_file_id *fidPtr = [self fileId];
    if (!fidPtr) {
        if (error) *error = SMB2POSIXError(ENODATA, @"Invalid file handle.");
        return NO;
    }

    SMB2FileIdWrapper fidWrapper;
    memcpy(fidWrapper.value, fidPtr, sizeof(fidWrapper.value));

    [_client asyncAwaitPDUWithDataHandler:nil execute:^struct smb2_pdu *(struct smb2_context *context, void *cbPtr) {
        struct smb2_file_disposition_info info;
        memset(&info, 0, sizeof(info));
        info.delete_pending = 1;

        struct smb2_set_info_request req;
        memset(&req, 0, sizeof(req));
        memcpy(req.file_id, fidWrapper.value, sizeof(req.file_id));
        req.info_type = SMB2_0_INFO_FILE;
        req.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
        req.input_data = &info;
        return smb2_cmd_set_info_async(context, &req, [SMB2Client genericHandler], cbPtr);
    } error:error];

    return error ? (*error == nil) : YES;
}

@end
