//
//  SMB2Client.h
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import <Foundation/Foundation.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <smb2/smb2-errors.h>

NS_ASSUME_NONNULL_BEGIN

/// Internal wrapper around smb2_context providing synchronous operations.
@interface SMB2Client : NSObject

@property (nonatomic) NSTimeInterval timeout;
@property (nonatomic, readonly) BOOL isConnected;
@property (nonatomic, readonly) int32_t fileDescriptor;
@property (nonatomic, readonly, nullable) NSString *server;
@property (nonatomic, readonly, nullable) NSString *share;
@property (nonatomic, readonly) NSInteger maximumTransactionSize;

@property (nonatomic, copy) NSString *workstation;
@property (nonatomic, copy) NSString *domain;
@property (nonatomic, copy) NSString *user;
@property (nonatomic, copy) NSString *password;
@property (nonatomic) uint16_t securityMode;
@property (nonatomic) BOOL seal;
@property (nonatomic) int32_t authentication;
@property (nonatomic) BOOL passthrough;

- (nullable instancetype)initWithTimeout:(NSTimeInterval)timeout error:(NSError *_Nullable *_Nullable)error;

/// Thread-safe access to the underlying context.
- (BOOL)withContext:(BOOL (^)(struct smb2_context *context))handler error:(NSError *_Nullable *_Nullable)error;

/// Returns the raw smb2_context pointer. Use withContext: for thread-safe access.
@property (nonatomic, readonly, nullable) struct smb2_context *rawContext;

#pragma mark - Connectivity

- (BOOL)connectServer:(NSString *)server share:(NSString *)share user:(NSString *)user error:(NSError *_Nullable *_Nullable)error;
- (BOOL)disconnectWithError:(NSError *_Nullable *_Nullable)error;
- (BOOL)echoWithError:(NSError *_Nullable *_Nullable)error;

#pragma mark - Share Enum

/// Enumerate shares using DCE-RPC via libsmb2.
- (nullable NSArray<NSDictionary *> *)shareEnumWithError:(NSError *_Nullable *_Nullable)error;

/// Enumerate shares using manual MSRPC (fallback).
- (nullable NSArray<NSDictionary *> *)shareEnumSwiftWithError:(NSError *_Nullable *_Nullable)error;

#pragma mark - File Information

- (BOOL)stat:(NSString *)path result:(struct smb2_stat_64 *)st error:(NSError *_Nullable *_Nullable)error;
- (BOOL)statvfs:(NSString *)path result:(struct smb2_statvfs *)st error:(NSError *_Nullable *_Nullable)error;
- (nullable NSString *)readlink:(NSString *)path error:(NSError *_Nullable *_Nullable)error;
- (BOOL)symlink:(NSString *)path to:(NSString *)destination error:(NSError *_Nullable *_Nullable)error;

#pragma mark - File Operations

- (BOOL)mkdir:(NSString *)path error:(NSError *_Nullable *_Nullable)error;
- (BOOL)rmdir:(NSString *)path error:(NSError *_Nullable *_Nullable)error;
- (BOOL)unlink:(NSString *)path error:(NSError *_Nullable *_Nullable)error;
- (BOOL)unlinkSymlink:(NSString *)path error:(NSError *_Nullable *_Nullable)error;
- (BOOL)rename:(NSString *)path to:(NSString *)newPath error:(NSError *_Nullable *_Nullable)error;
- (BOOL)truncate:(NSString *)path toLength:(uint64_t)length error:(NSError *_Nullable *_Nullable)error;

#pragma mark - Low-level Async

/// Execute an async libsmb2 command and wait for completion.
- (int32_t)asyncAwait:(int32_t (^)(struct smb2_context *context, void *cbPtr))handler error:(NSError *_Nullable *_Nullable)error;

/// Execute an async command with data handler.
- (int32_t)asyncAwaitWithDataHandler:(void (^_Nullable)(void *_Nullable commandData))dataHandler
                             execute:(int32_t (^)(struct smb2_context *context, void *cbPtr))handler
                               error:(NSError *_Nullable *_Nullable)error;

/// Execute a PDU-based async command.
- (uint32_t)asyncAwaitPDU:(struct smb2_pdu *_Nullable (^)(struct smb2_context *context, void *cbPtr))handler
                    error:(NSError *_Nullable *_Nullable)error;

/// Execute a PDU-based async command with data handler.
- (uint32_t)asyncAwaitPDUWithDataHandler:(void (^_Nullable)(void *_Nullable commandData))dataHandler
                                 execute:(struct smb2_pdu *_Nullable (^)(struct smb2_context *context, void *cbPtr))handler
                                   error:(NSError *_Nullable *_Nullable)error;

/// The generic C callback for libsmb2 async operations.
+ (smb2_command_cb)genericHandler;

@end

NS_ASSUME_NONNULL_END
