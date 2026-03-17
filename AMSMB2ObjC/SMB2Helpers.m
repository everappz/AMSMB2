//
//  SMB2Helpers.m
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import "SMB2Helpers.h"
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/smb2-errors.h>

#pragma mark - Error Helpers

NSString *const SMB2ErrorDomain = @"SMB2ErrorDomain";

NSError *_Nullable SMB2POSIXErrorFromResult(int32_t result, NSString *_Nullable description) {
    if (result >= 0) {
        return nil;
    }
    int code = -result;
    NSString *desc = nil;
    if (description != nil) {
        desc = [NSString stringWithFormat:@"Error code %d: %@", code, description];
    }
    NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
    if (desc != nil) {
        userInfo[NSLocalizedDescriptionKey] = desc;
    }
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:userInfo];
}

NSError *_Nullable SMB2POSIXErrorFromNTStatus(uint32_t status) {
    if (status == SMB2_STATUS_SUCCESS) {
        return nil;
    }
    // Check if severity indicates error (high two bits)
    uint32_t severity = status & SMB2_STATUS_SEVERITY_MASK;
    if (severity != SMB2_STATUS_SEVERITY_ERROR) {
        return nil;
    }
    int code = nterror_to_errno(status);
    const char *str = nterror_to_str(status);
    NSString *description = nil;
    if (str != NULL) {
        description = [NSString stringWithFormat:@"Error 0x%X: %s", status, str];
    } else {
        description = [NSString stringWithFormat:@"Error 0x%X", status];
    }
    NSDictionary *userInfo = @{NSLocalizedDescriptionKey: description};
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:userInfo];
}

NSError *SMB2POSIXError(int code, NSString *_Nullable description) {
    NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
    if (description != nil) {
        userInfo[NSLocalizedDescriptionKey] = description;
    }
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:userInfo];
}

#pragma mark - String Helpers

NSString *SMB2CanonicalPath(NSString *path) {
    NSCharacterSet *trimSet = [NSCharacterSet characterSetWithCharactersInString:@"/\\"];
    return [path stringByTrimmingCharactersInSet:trimSet];
}

NSURL *SMB2FileURLFromPath(NSString *path, BOOL isDirectory) {
    NSURL *rootURL = [NSURL fileURLWithPath:@"/"];
    return [NSURL fileURLWithPath:path isDirectory:isDirectory relativeToURL:rootURL];
}

#pragma mark - Data Helpers

uint16_t SMB2DataScanUInt16(NSData *data, NSUInteger offset) {
    uint16_t value = 0;
    if (data.length >= offset + sizeof(value)) {
        [data getBytes:&value range:NSMakeRange(offset, sizeof(value))];
    }
    return value;
}

uint32_t SMB2DataScanUInt32(NSData *data, NSUInteger offset) {
    uint32_t value = 0;
    if (data.length >= offset + sizeof(value)) {
        [data getBytes:&value range:NSMakeRange(offset, sizeof(value))];
    }
    return value;
}

uint64_t SMB2DataScanUInt64(NSData *data, NSUInteger offset) {
    uint64_t value = 0;
    if (data.length >= offset + sizeof(value)) {
        [data getBytes:&value range:NSMakeRange(offset, sizeof(value))];
    }
    return value;
}

NSInteger SMB2DataScanInt(NSData *data, NSUInteger offset, NSUInteger size) {
    if (size == 2) {
        return (NSInteger)SMB2DataScanUInt16(data, offset);
    } else if (size == 4) {
        return (NSInteger)SMB2DataScanUInt32(data, offset);
    }
    return 0;
}

NSData *SMB2DataFromUInt16(uint16_t value) {
    return [NSData dataWithBytes:&value length:sizeof(value)];
}

NSData *SMB2DataFromUInt32(uint32_t value) {
    return [NSData dataWithBytes:&value length:sizeof(value)];
}

NSData *SMB2DataFromUInt64(uint64_t value) {
    return [NSData dataWithBytes:&value length:sizeof(value)];
}

NSData *SMB2DataFromUUID(NSUUID *uuid) {
    uuid_t uuidBytes;
    [uuid getUUIDBytes:uuidBytes];
    // MS-RPC byte order: first 3 groups are byte-swapped
    uint8_t reordered[16] = {
        uuidBytes[3], uuidBytes[2], uuidBytes[1], uuidBytes[0],
        uuidBytes[5], uuidBytes[4],
        uuidBytes[7], uuidBytes[6],
        uuidBytes[8], uuidBytes[9], uuidBytes[10], uuidBytes[11],
        uuidBytes[12], uuidBytes[13], uuidBytes[14], uuidBytes[15],
    };
    return [NSData dataWithBytes:reordered length:16];
}

#pragma mark - Date Helpers

NSDate *_Nullable SMB2DateFromTimespec(int64_t tv_sec, int64_t tv_nsec) {
    NSTimeInterval interval = (NSTimeInterval)tv_sec + (NSTimeInterval)(tv_nsec / 1000) / 1000000.0;
    return [NSDate dateWithTimeIntervalSince1970:interval];
}

#pragma mark - Stat Helpers

void SMB2PopulateResourceValues(NSMutableDictionary<NSURLResourceKey, id> *dict, struct smb2_stat_64 *st) {
    dict[NSURLFileSizeKey] = @(st->smb2_size);
    dict[NSURLLinkCountKey] = @(st->smb2_nlink);
    dict[NSURLDocumentIdentifierKey] = @(st->smb2_ino);

    NSURLFileResourceType resourceType;
    BOOL isDirectory = NO;
    BOOL isRegularFile = NO;
    BOOL isSymbolicLink = NO;

    switch (st->smb2_type) {
        case SMB2_TYPE_DIRECTORY:
            resourceType = NSURLFileResourceTypeDirectory;
            isDirectory = YES;
            break;
        case SMB2_TYPE_LINK:
            resourceType = NSURLFileResourceTypeSymbolicLink;
            isSymbolicLink = YES;
            break;
        case SMB2_TYPE_FILE:
        default:
            resourceType = NSURLFileResourceTypeRegular;
            isRegularFile = YES;
            break;
    }

    dict[NSURLFileResourceTypeKey] = resourceType;
    dict[NSURLIsDirectoryKey] = @(isDirectory);
    dict[NSURLIsRegularFileKey] = @(isRegularFile);
    dict[NSURLIsSymbolicLinkKey] = @(isSymbolicLink);

    dict[NSURLContentModificationDateKey] = SMB2DateFromTimespec(
        (int64_t)st->smb2_mtime, (int64_t)st->smb2_mtime_nsec);
    dict[NSURLAttributeModificationDateKey] = SMB2DateFromTimespec(
        (int64_t)st->smb2_ctime, (int64_t)st->smb2_ctime_nsec);
    dict[NSURLContentAccessDateKey] = SMB2DateFromTimespec(
        (int64_t)st->smb2_atime, (int64_t)st->smb2_atime_nsec);
    dict[NSURLCreationDateKey] = SMB2DateFromTimespec(
        (int64_t)st->smb2_btime, (int64_t)st->smb2_btime_nsec);
}

NSDictionary<NSFileAttributeKey, id> *SMB2FileSystemAttributesFromStatVFS(struct smb2_statvfs *st) {
    NSMutableDictionary<NSFileAttributeKey, id> *result = [NSMutableDictionary dictionary];
    uint64_t blockSize = (uint64_t)st->f_bsize;

    if (st->f_blocks < UINT64_MAX / blockSize) {
        result[NSFileSystemSize] = @(blockSize * st->f_blocks);
        result[NSFileSystemFreeSize] = @(blockSize * st->f_bfree);
    }
    if (st->f_files > 0) {
        result[NSFileSystemNodes] = @(st->f_files);
    }
    if (st->f_ffree > 0) {
        result[NSFileSystemFreeNodes] = @(st->f_ffree);
    }
    return [result copy];
}

#pragma mark - Share Type

BOOL SMB2SharePropertiesIsHidden(SMB2ShareProperties props) {
    return (props.rawValue & 0x80000000) != 0;
}

BOOL SMB2SharePropertiesIsDiskTree(SMB2ShareProperties props) {
    return (props.rawValue & 0x0FFFFFFF) == 0;
}

#pragma mark - MSRPC

BOOL SMB2MSRPCValidateBindResponse(NSData *data, NSError *_Nullable *_Nullable error) {
    // Bind command result is exactly 68 bytes. 54 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
    if (data.length < 68) {
        if (error != NULL) {
            *error = SMB2POSIXError(EBADMSG, @"Binding failure: Invalid size");
        }
        return NO;
    }

    // Ack result bytes at offset 44 and 45
    uint8_t byte44 = 0;
    uint8_t byte45 = 0;
    [data getBytes:&byte44 range:NSMakeRange(44, 1)];
    [data getBytes:&byte45 range:NSMakeRange(45, 1)];

    if (byte44 > 0 || byte45 > 0) {
        // Ack result is not acceptance (0x0000)
        uint16_t errorCode = (uint16_t)byte44 + ((uint16_t)byte45 << 8);
        NSString *errorCodeString = [NSString stringWithFormat:@"%x", errorCode];
        if (error != NULL) {
            *error = SMB2POSIXError(EBADMSG,
                [NSString stringWithFormat:@"Binding failure: %@", errorCodeString]);
        }
        return NO;
    }

    return YES;
}

NSData *SMB2MSRPCBuildSrvsvcBindData(void) {
    NSUUID *srvsvcUuid = [[NSUUID alloc] initWithUUIDString:@"4B324FC8-1670-01D3-1278-5A47BF6EE188"];
    NSUUID *ndrUuid = [[NSUUID alloc] initWithUUIDString:@"8A885D04-1CEB-11C9-9FE8-08002B104860"];

    // Build payload first to calculate total length
    NSMutableData *payload = [NSMutableData data];

    // Max Xmit size (Int16.max = 0x7FFF)
    uint16_t maxXmit = 0x7FFF;
    [payload appendBytes:&maxXmit length:sizeof(maxXmit)];
    // Max Recv size
    uint16_t maxRecv = 0x7FFF;
    [payload appendBytes:&maxRecv length:sizeof(maxRecv)];
    // Assoc group
    uint32_t assocGroup = 0;
    [payload appendBytes:&assocGroup length:sizeof(assocGroup)];
    // Num Ctx Items
    uint32_t numCtxItems = 1;
    [payload appendBytes:&numCtxItems length:sizeof(numCtxItems)];
    // Context ID
    uint16_t contextId = 0;
    [payload appendBytes:&contextId length:sizeof(contextId)];
    // Num Trans Items
    uint16_t numTransItems = 1;
    [payload appendBytes:&numTransItems length:sizeof(numTransItems)];
    // SRVSVC UUID (MS-RPC byte order)
    NSData *srvsvcData = SMB2DataFromUUID(srvsvcUuid);
    [payload appendData:srvsvcData];
    // SRVSVC Version 3.0
    uint16_t srvsvcVersionMajor = 3;
    uint16_t srvsvcVersionMinor = 0;
    [payload appendBytes:&srvsvcVersionMajor length:sizeof(srvsvcVersionMajor)];
    [payload appendBytes:&srvsvcVersionMinor length:sizeof(srvsvcVersionMinor)];
    // NDR UUID (MS-RPC byte order)
    NSData *ndrData = SMB2DataFromUUID(ndrUuid);
    [payload appendData:ndrData];
    // NDR Version 2.0
    uint16_t ndrVersionMajor = 2;
    uint16_t ndrVersionMinor = 0;
    [payload appendBytes:&ndrVersionMajor length:sizeof(ndrVersionMajor)];
    [payload appendBytes:&ndrVersionMinor length:sizeof(ndrVersionMinor)];

    // DCE header is 16 bytes
    uint16_t totalLength = (uint16_t)(16 + payload.length);

    NSMutableData *result = [NSMutableData data];

    // Version major=5, version minor=0, packet type=bind(0x0b), flags=0x03
    uint8_t header1[] = {0x05, 0x00, 0x0b, 0x03};
    [result appendBytes:header1 length:4];
    // Representation = little endian/ASCII
    uint32_t representation = 0x00000010;
    [result appendBytes:&representation length:sizeof(representation)];
    // Total length
    [result appendBytes:&totalLength length:sizeof(totalLength)];
    // Auth len
    uint16_t authLen = 0;
    [result appendBytes:&authLen length:sizeof(authLen)];
    // Call ID
    uint32_t callId = 1;
    [result appendBytes:&callId length:sizeof(callId)];

    // Payload
    [result appendData:payload];

    return [result copy];
}

NSData *SMB2MSRPCBuildNetShareEnumAllRequest(NSString *serverName) {
    // Encode server name as UTF-16LE with null terminator
    NSData *serverNameData = [serverName dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
    uint32_t serverNameLen = (uint32_t)(serverNameData.length / 2 + 1); // +1 for null terminator

    // Build payload
    NSMutableData *payload = [NSMutableData data];

    // Alloc hint
    uint32_t allocHint = 72;
    [payload appendBytes:&allocHint length:sizeof(allocHint)];
    // Context ID
    uint16_t contextId = 0;
    [payload appendBytes:&contextId length:sizeof(contextId)];
    // OpNum = NetShareEnumAll (0x0F)
    uint16_t opNum = 0x0F;
    [payload appendBytes:&opNum length:sizeof(opNum)];

    // Pointer to server UNC - Referent ID
    uint32_t referentId = 1;
    [payload appendBytes:&referentId length:sizeof(referentId)];
    // Max count
    [payload appendBytes:&serverNameLen length:sizeof(serverNameLen)];
    // Offset
    uint32_t offset = 0;
    [payload appendBytes:&offset length:sizeof(offset)];
    // Actual count
    [payload appendBytes:&serverNameLen length:sizeof(serverNameLen)];

    // Server name data (UTF-16LE)
    [payload appendData:serverNameData];
    // Null terminator + padding: if serverNameLen is odd, 4 bytes (UInt32); if even, 2 bytes (UInt16)
    if (serverNameLen % 2 == 1) {
        uint32_t pad = 0;
        [payload appendBytes:&pad length:sizeof(pad)];
    } else {
        uint16_t pad = 0;
        [payload appendBytes:&pad length:sizeof(pad)];
    }

    // Level 1
    uint32_t level = 1;
    [payload appendBytes:&level length:sizeof(level)];
    // Ctr
    uint32_t ctr = 1;
    [payload appendBytes:&ctr length:sizeof(ctr)];
    // Referent ID
    uint32_t ctrReferentId = 1;
    [payload appendBytes:&ctrReferentId length:sizeof(ctrReferentId)];
    // Count/Null Pointer to NetShareInfo1
    uint32_t count = 0;
    [payload appendBytes:&count length:sizeof(count)];
    // Null Pointer to NetShareInfo1
    uint32_t nullPtr = 0;
    [payload appendBytes:&nullPtr length:sizeof(nullPtr)];
    // Max Buffer
    uint32_t maxBuffer = 0xFFFFFFFF;
    [payload appendBytes:&maxBuffer length:sizeof(maxBuffer)];
    // Resume Referent ID
    uint32_t resumeReferentId = 1;
    [payload appendBytes:&resumeReferentId length:sizeof(resumeReferentId)];
    // Resume
    uint32_t resume = 0;
    [payload appendBytes:&resume length:sizeof(resume)];

    // DCE header is 16 bytes
    uint16_t totalLength = (uint16_t)(16 + payload.length);

    NSMutableData *result = [NSMutableData data];

    // Version major=5, version minor=0, packet type=request(0x00), flags=0x03
    uint8_t header1[] = {0x05, 0x00, 0x00, 0x03};
    [result appendBytes:header1 length:4];
    // Representation = little endian/ASCII
    uint32_t representation = 0x00000010;
    [result appendBytes:&representation length:sizeof(representation)];
    // Total length
    [result appendBytes:&totalLength length:sizeof(totalLength)];
    // Auth len
    uint16_t authLen = 0;
    [result appendBytes:&authLen length:sizeof(authLen)];
    // Call ID
    uint32_t callId = 0;
    [result appendBytes:&callId length:sizeof(callId)];

    // Payload
    [result appendData:payload];

    return [result copy];
}

NSArray<NSDictionary *> *_Nullable SMB2MSRPCParseNetShareEnumAllResponse(NSData *data, NSError *_Nullable *_Nullable error) {
    /*
     Data Layout:

     struct _SHARE_INFO_1 {
         uint32 netname;  // pointer to NameContainer
         uint32 type;
         uint32 remark;   // pointer to NameContainer
     }

     struct NameContainer {
         uint32 maxCount;
         uint32 offset;
         uint32 actualCount;
         char* name; // null-terminated utf16le with (actualCount - 1) characters
     }

     First 48 bytes: header + count fields
     _SHARE_INFO_1 entries start at offset 48, each is 12 bytes
     Type field in each entry is at offset +4
     */

    // Need at least 48 bytes for header + count
    if (data.length < 48) {
        if (error != NULL) {
            *error = SMB2POSIXError(EINVAL, @"Invalid NetShareEnumAll response: too short");
        }
        return nil;
    }

    // Count of shares at offset 44
    uint32_t count = SMB2DataScanUInt32(data, 44);

    NSMutableArray<NSDictionary *> *shares = [NSMutableArray arrayWithCapacity:count];

    // Start of name containers: header (48) + _SHARE_INFO_1 entries (count * 12)
    NSUInteger nameOffset = 48 + (NSUInteger)count * 12;

    for (uint32_t i = 0; i < count; i++) {
        // Type of current share at offset 48 + i*12 + 4
        NSUInteger typeOffset = 48 + (NSUInteger)i * 12 + 4;
        uint32_t type = SMB2DataScanUInt32(data, typeOffset);

        // Parse name part
        if (nameOffset + 12 > data.length) {
            break;
        }
        uint32_t nameActualCount = SMB2DataScanUInt32(data, nameOffset + 8);
        nameOffset += 12;

        if (nameOffset + (NSUInteger)nameActualCount * 2 > data.length) {
            if (error != NULL) {
                *error = SMB2POSIXError(EINVAL, @"Invalid NetShareEnumAll response: name overflow");
            }
            return nil;
        }

        NSString *nameString = @"";
        if (nameActualCount > 1) {
            NSData *nameData = [data subdataWithRange:NSMakeRange(nameOffset, (nameActualCount - 1) * 2)];
            nameString = [[NSString alloc] initWithData:nameData encoding:NSUTF16LittleEndianStringEncoding];
            if (nameString == nil) {
                nameString = @"";
            }
        }

        nameOffset += (NSUInteger)nameActualCount * 2;
        if (nameActualCount % 2 == 1) {
            // Padding for alignment if name length is odd
            nameOffset += 2;
        }

        // Parse comment part
        if (nameOffset + 12 > data.length) {
            break;
        }
        uint32_t commentActualCount = SMB2DataScanUInt32(data, nameOffset + 8);
        nameOffset += 12;

        if (nameOffset + (NSUInteger)commentActualCount * 2 > data.length) {
            if (error != NULL) {
                *error = SMB2POSIXError(EINVAL, @"Invalid NetShareEnumAll response: comment overflow");
            }
            return nil;
        }

        NSString *commentString = @"";
        if (commentActualCount > 1) {
            NSData *commentData = [data subdataWithRange:NSMakeRange(nameOffset, (commentActualCount - 1) * 2)];
            commentString = [[NSString alloc] initWithData:commentData encoding:NSUTF16LittleEndianStringEncoding];
            if (commentString == nil) {
                commentString = @"";
            }
        }

        nameOffset += (NSUInteger)commentActualCount * 2;
        if (commentActualCount % 2 == 1) {
            // Padding for alignment if comment length is odd
            nameOffset += 2;
        }

        NSDictionary *shareInfo = @{
            @"name": nameString,
            @"comment": commentString,
            @"type": @(type),
        };
        [shares addObject:shareInfo];

        if (nameOffset > data.length) {
            break;
        }
    }

    return [shares copy];
}

#pragma mark - IOCTL Helpers

NSData *SMB2IOCtlBuildCopyChunkCopy(NSData *sourceKey, uint64_t sourceOffset, uint64_t targetOffset, uint32_t length) {
    NSMutableData *result = [NSMutableData data];

    // 24 bytes source key
    if (sourceKey.length >= 24) {
        [result appendData:[sourceKey subdataWithRange:NSMakeRange(0, 24)]];
    } else {
        [result appendData:sourceKey];
        // Pad to 24 bytes
        NSUInteger padding = 24 - sourceKey.length;
        uint8_t zeros[24] = {0};
        [result appendBytes:zeros length:padding];
    }

    // Chunk count = 1
    uint32_t chunkCount = 1;
    [result appendBytes:&chunkCount length:sizeof(chunkCount)];
    // Reserved
    uint32_t reserved = 0;
    [result appendBytes:&reserved length:sizeof(reserved)];

    // Single chunk: source offset, target offset, length, reserved
    [result appendBytes:&sourceOffset length:sizeof(sourceOffset)];
    [result appendBytes:&targetOffset length:sizeof(targetOffset)];
    [result appendBytes:&length length:sizeof(length)];
    uint32_t chunkReserved = 0;
    [result appendBytes:&chunkReserved length:sizeof(chunkReserved)];

    return [result copy];
}

NSData *SMB2IOCtlBuildSymbolicLinkReparse(NSString *path, BOOL isRelative) {
    // Replace '/' with '\' for the substitute name
    NSString *substituteName = [path stringByReplacingOccurrencesOfString:@"/" withString:@"\\"];
    NSString *printName = path;

    NSData *substituteData = [substituteName dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
    NSData *printData = [printName dataUsingEncoding:NSUTF16LittleEndianStringEncoding];

    uint32_t reparseTag = SMB2_REPARSE_TAG_SYMLINK;
    uint16_t dataLength = (uint16_t)(substituteData.length + printData.length);
    uint16_t reservedField = 0;
    uint16_t substituteNameOffset = 0;
    uint16_t substituteNameLength = (uint16_t)substituteData.length;
    uint16_t printNameOffset = (uint16_t)substituteData.length;
    uint16_t printNameLength = (uint16_t)printData.length;
    uint32_t flags = isRelative ? 1 : 0;

    NSMutableData *result = [NSMutableData data];

    // Reparse tag
    [result appendBytes:&reparseTag length:sizeof(reparseTag)];
    // Data length (substitute + print data sizes)
    [result appendBytes:&dataLength length:sizeof(dataLength)];
    // Reserved
    [result appendBytes:&reservedField length:sizeof(reservedField)];
    // Substitute name offset
    [result appendBytes:&substituteNameOffset length:sizeof(substituteNameOffset)];
    // Substitute name length
    [result appendBytes:&substituteNameLength length:sizeof(substituteNameLength)];
    // Print name offset
    [result appendBytes:&printNameOffset length:sizeof(printNameOffset)];
    // Print name length
    [result appendBytes:&printNameLength length:sizeof(printNameLength)];
    // Flags
    [result appendBytes:&flags length:sizeof(flags)];
    // Substitute name data (UTF-16LE)
    [result appendData:substituteData];
    // Print name data (UTF-16LE)
    [result appendData:printData];

    return [result copy];
}
