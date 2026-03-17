//
//  SMB2Helpers.h
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import <Foundation/Foundation.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/smb2-errors.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Error Helpers

FOUNDATION_EXPORT NSString *const SMB2ErrorDomain;

NSError *_Nullable SMB2POSIXErrorFromResult(int32_t result, NSString *_Nullable description);
NSError *_Nullable SMB2POSIXErrorFromNTStatus(uint32_t status);
NSError *SMB2POSIXError(int code, NSString *_Nullable description);

#pragma mark - String Helpers

/// Trims leading/trailing '/' and '\' characters.
NSString *SMB2CanonicalPath(NSString *path);

/// Makes a file URL from a path string.
NSURL *SMB2FileURLFromPath(NSString *path, BOOL isDirectory);

#pragma mark - Data Helpers

uint16_t SMB2DataScanUInt16(NSData *data, NSUInteger offset);
uint32_t SMB2DataScanUInt32(NSData *data, NSUInteger offset);
uint64_t SMB2DataScanUInt64(NSData *data, NSUInteger offset);
NSInteger SMB2DataScanInt(NSData *data, NSUInteger offset, NSUInteger size);

NSData *SMB2DataFromUInt16(uint16_t value);
NSData *SMB2DataFromUInt32(uint32_t value);
NSData *SMB2DataFromUInt64(uint64_t value);
NSData *SMB2DataFromUUID(NSUUID *uuid);

#pragma mark - Date Helpers

NSDate *_Nullable SMB2DateFromTimespec(int64_t tv_sec, int64_t tv_nsec);

#pragma mark - Stat Helpers

void SMB2PopulateResourceValues(NSMutableDictionary<NSURLResourceKey, id> *dict, struct smb2_stat_64 *st);
NSDictionary<NSFileAttributeKey, id> *SMB2FileSystemAttributesFromStatVFS(struct smb2_statvfs *st);

#pragma mark - Share Type

typedef struct {
    uint32_t rawValue;
} SMB2ShareProperties;

BOOL SMB2SharePropertiesIsHidden(SMB2ShareProperties props);
BOOL SMB2SharePropertiesIsDiskTree(SMB2ShareProperties props);

#pragma mark - MSRPC

/// Parse bind response data (validate).
BOOL SMB2MSRPCValidateBindResponse(NSData *data, NSError *_Nullable *_Nullable error);

/// Build srvsvc bind request data.
NSData *SMB2MSRPCBuildSrvsvcBindData(void);

/// Build NetShareEnumAll request data.
NSData *SMB2MSRPCBuildNetShareEnumAllRequest(NSString *serverName);

/// Parse NetShareEnumAll response. Returns array of dictionaries with @"name", @"comment", @"type" keys.
NSArray<NSDictionary *> *_Nullable SMB2MSRPCParseNetShareEnumAllResponse(NSData *data, NSError *_Nullable *_Nullable error);

#pragma mark - IOCTL Helpers

/// Build SrvCopyChunkCopy data.
NSData *SMB2IOCtlBuildCopyChunkCopy(NSData *sourceKey, uint64_t sourceOffset, uint64_t targetOffset, uint32_t length);

/// Build SymbolicLinkReparse data.
NSData *SMB2IOCtlBuildSymbolicLinkReparse(NSString *path, BOOL isRelative);

NS_ASSUME_NONNULL_END
