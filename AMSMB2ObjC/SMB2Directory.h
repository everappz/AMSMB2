//
//  SMB2Directory.h
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SMB2Client.h"

NS_ASSUME_NONNULL_BEGIN

@interface SMB2Directory : NSObject

- (nullable instancetype)initWithPath:(NSString *)path on:(SMB2Client *)client error:(NSError *_Nullable *_Nullable)error;

/// Enumerate entries, calling block for each. Returns dirent name and stat.
- (void)enumerateEntriesUsingBlock:(void (^)(const char *name, struct smb2_stat_64 st))block;

@end

NS_ASSUME_NONNULL_END
