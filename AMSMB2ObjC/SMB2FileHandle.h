//
//  SMB2FileHandle.h
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SMB2Client.h"

NS_ASSUME_NONNULL_BEGIN

@interface SMB2FileHandle : NSObject

@property (nonatomic, readonly) NSInteger maxReadSize;
@property (nonatomic, readonly) NSInteger optimizedReadSize;
@property (nonatomic, readonly) NSInteger maxWriteSize;
@property (nonatomic, readonly) NSInteger optimizedWriteSize;

- (nullable instancetype)initForReadingAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError *_Nullable *_Nullable)error;
- (nullable instancetype)initForWritingAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError *_Nullable *_Nullable)error;
- (nullable instancetype)initForOverwritingAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError *_Nullable *_Nullable)error;
- (nullable instancetype)initForOutputAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError *_Nullable *_Nullable)error;
- (nullable instancetype)initForCreatingIfNotExistsAtPath:(NSString *)path on:(SMB2Client *)client error:(NSError *_Nullable *_Nullable)error;
- (nullable instancetype)initWithPath:(NSString *)path flags:(int32_t)flags on:(SMB2Client *)client error:(NSError *_Nullable *_Nullable)error;

- (nullable instancetype)initWithPath:(NSString *)path
                        desiredAccess:(uint32_t)desiredAccess
                          shareAccess:(uint32_t)shareAccess
                   createDisposition:(uint32_t)createDisposition
                        createOptions:(uint32_t)createOptions
                                   on:(SMB2Client *)client
                                error:(NSError *_Nullable *_Nullable)error;

- (void)close;

- (BOOL)fstat:(struct smb2_stat_64 *)st error:(NSError *_Nullable *_Nullable)error;
- (BOOL)ftruncateToLength:(uint64_t)length error:(NSError *_Nullable *_Nullable)error;

- (int64_t)lseekOffset:(int64_t)offset whence:(int32_t)whence error:(NSError *_Nullable *_Nullable)error;

- (nullable NSData *)readWithLength:(NSInteger)length error:(NSError *_Nullable *_Nullable)error;
- (nullable NSData *)preadOffset:(uint64_t)offset length:(NSInteger)length error:(NSError *_Nullable *_Nullable)error;

- (NSInteger)writeData:(NSData *)data error:(NSError *_Nullable *_Nullable)error;
- (NSInteger)pwriteData:(NSData *)data offset:(uint64_t)offset error:(NSError *_Nullable *_Nullable)error;

- (BOOL)fsyncWithError:(NSError *_Nullable *_Nullable)error;

/// Server-side copy: get resume key (IOCTL SRV_REQUEST_RESUME_KEY).
- (nullable NSData *)requestResumeKeyWithError:(NSError *_Nullable *_Nullable)error;

/// Server-side copy: execute copy chunk (IOCTL SRV_COPYCHUNK).
- (BOOL)copyChunk:(NSData *)chunkData error:(NSError *_Nullable *_Nullable)error;

/// Set reparse point (IOCTL SET_REPARSE_POINT).
- (BOOL)setReparsePoint:(NSData *)reparseData error:(NSError *_Nullable *_Nullable)error;

/// Set file disposition info (delete pending).
- (BOOL)setDeletePendingWithError:(NSError *_Nullable *_Nullable)error;

/// IOCTL generic command.
- (nullable NSData *)ioctlCommand:(uint32_t)command inputData:(NSData *_Nullable)inputData error:(NSError *_Nullable *_Nullable)error;

@end

NS_ASSUME_NONNULL_END
