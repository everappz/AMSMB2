//
//  SMB2Directory.m
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import "SMB2Directory.h"
#import "SMB2Client.h"
#import "SMB2Helpers.h"
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>

@implementation SMB2Directory {
    NSString *_path;
    SMB2Client *_client;
    struct smb2dir *_handle;
}

- (nullable instancetype)initWithPath:(NSString *)path on:(SMB2Client *)client error:(NSError **)error {
    self = [super init];
    if (!self) return nil;

    _path = path;
    _client = client;

    NSString *canonical = SMB2CanonicalPath(path);
    __block struct smb2dir *dirHandle = NULL;

    int32_t result = [client asyncAwaitWithDataHandler:^(void *commandData) {
        dirHandle = (struct smb2dir *)commandData;
    } execute:^int32_t(struct smb2_context *context, void *cbPtr) {
        return smb2_opendir_async(context, [canonical UTF8String], [SMB2Client genericHandler], cbPtr);
    } error:error];

    if (result < 0 || !dirHandle) {
        return nil;
    }

    _handle = dirHandle;
    return self;
}

- (void)dealloc {
    if (_handle) {
        [_client withContext:^BOOL(struct smb2_context *context) {
            smb2_closedir(context, self->_handle);
            return YES;
        } error:nil];
    }
}

- (void)enumerateEntriesUsingBlock:(void (^)(const char *, struct smb2_stat_64))block {
    struct smb2_context *ctx = _client.rawContext;
    if (!ctx || !_handle) return;

    smb2_rewinddir(ctx, _handle);
    struct smb2dirent *ent;
    while ((ent = smb2_readdir(ctx, _handle)) != NULL) {
        block(ent->name, ent->st);
    }
}

@end
