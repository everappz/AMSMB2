//
//  AMSMB2Manager.h
//  AMSMB2
//
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^_Nullable SMB2SimpleCompletionHandler)(NSError *_Nullable error);
typedef BOOL (^_Nullable SMB2ReadProgressHandler)(int64_t bytes, int64_t total);
typedef BOOL (^_Nullable SMB2WriteProgressHandler)(int64_t bytes);

/// Implements SMB2 File operations.
@interface AMSMB2Manager : NSObject <NSSecureCoding, NSCopying>

/// SMB2 Share URL.
@property (nonatomic, readonly) NSURL *url;

/// The timeout interval to use when doing an operation until getting response.
/// Default value is 60 seconds. Set this to 0 or negative value in order to disable it.
@property (nonatomic) NSTimeInterval timeout;

/**
 Initializes a SMB2 class with given url and credential.

 @param url SMB server's URL.
 @param credential Username and password.
 @note For now, only user/password credential on NTLM servers are supported.
 @important A connection to a share must be established by connectShareWithName:completionHandler: before any operation.
 */
- (nullable instancetype)initWithURL:(NSURL *)url
                          credential:(nullable NSURLCredential *)credential;

/**
 Initializes a SMB2 class with given url and credential.

 @param url SMB server's URL.
 @param domain User's domain, if applicable.
 @param credential Username and password.
 */
- (nullable instancetype)initWithURL:(NSURL *)url
                              domain:(NSString *)domain
                          credential:(nullable NSURLCredential *)credential;

#pragma mark - Connection

/**
 Connects to a share.

 @param name Share name to connect.
 @param completionHandler Closure will be run after connection is completed.
 */
- (void)connectShareWithName:(NSString *)name
           completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Connects to a share.

 @param name Share name to connect.
 @param encrypted Enables SMB3 encryption if YES.
 @param completionHandler Closure will be run after connection is completed.
 */
- (void)connectShareWithName:(NSString *)name
                   encrypted:(BOOL)encrypted
           completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Disconnects from a share.
 */
- (void)disconnectShare;

/**
 Disconnects from a share.

 @param completionHandler Closure will be run after disconnection is completed.
 */
- (void)disconnectShareWithCompletionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Disconnects from a share.

 @param gracefully Waits until all queued operations are done before disconnecting.
 @param completionHandler Closure will be run after disconnection is completed.
 */
- (void)disconnectShareGracefully:(BOOL)gracefully
                completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

#pragma mark - Echo

/**
 Sends echo to server. Use it to prevent timeout or check connectivity.

 @param completionHandler Closure will be run after echoing server is completed.
 */
- (void)echoWithCompletionHandler:(SMB2SimpleCompletionHandler)completionHandler;

#pragma mark - Share Listing

/**
 Enumerates shares' list on server.

 @param completionHandler Closure will be run after enumerating is completed.
 */
- (void)listSharesWithCompletionHandler:(void (^)(NSArray<NSString *> *names,
                                                   NSArray<NSString *> *comments,
                                                   NSError *_Nullable error))completionHandler;

/**
 Enumerates shares' list on server.

 @param enumerateHidden Include hidden/administrative shares.
 @param completionHandler Closure will be run after enumerating is completed.
 */
- (void)listSharesWithEnumerateHidden:(BOOL)enumerateHidden
                    completionHandler:(void (^)(NSArray<NSString *> *names,
                                                NSArray<NSString *> *comments,
                                                NSError *_Nullable error))completionHandler;

#pragma mark - Directory Contents

/**
 Enumerates directory contents in the given path.

 @param path Path of directory to be enumerated.
 @param recursive Subdirectories will be enumerated if YES.
 @param completionHandler Closure will be run after enumerating is completed.
 */
- (void)contentsOfDirectoryAtPath:(NSString *)path
                        recursive:(BOOL)recursive
                completionHandler:(void (^)(NSArray<NSDictionary<NSURLResourceKey, id> *> *_Nullable contents,
                                            NSError *_Nullable error))completionHandler;

#pragma mark - Attributes

/**
 Returns attributes of the mounted file system.

 @param path Any pathname within the mounted file system.
 @param completionHandler Closure will be run after fetching attributes is completed.
 */
- (void)attributesOfFileSystemForPath:(NSString *)path
                    completionHandler:(void (^)(NSDictionary<NSFileAttributeKey, id> *_Nullable attributes,
                                                NSError *_Nullable error))completionHandler;

/**
 Returns the attributes of the item at given path.

 @param path Path of file to be examined.
 @param completionHandler Closure will be run after enumerating is completed.
 */
- (void)attributesOfItemAtPath:(NSString *)path
             completionHandler:(void (^)(NSDictionary<NSURLResourceKey, id> *_Nullable file,
                                         NSError *_Nullable error))completionHandler;

/**
 Returns the path of the item pointed to by a symbolic link.

 @param path The path of a file or directory.
 @param completionHandler Closure will be run after reading link is completed.
 */
- (void)destinationOfSymbolicLinkAtPath:(NSString *)path
                      completionHandler:(void (^)(NSString *_Nullable destinationPath,
                                                  NSError *_Nullable error))completionHandler;

#pragma mark - File/Directory Operations

/**
 Creates a new directory at given path.

 @param path Path of new directory to be created.
 @param completionHandler Closure will be run after operation is completed.
 */
- (void)createDirectoryAtPath:(NSString *)path
            completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Removes an existing directory at given path.

 @param path Path of directory to be removed.
 @param recursive Children items will be deleted if YES.
 @param completionHandler Closure will be run after operation is completed.
 */
- (void)removeDirectoryAtPath:(NSString *)path
                    recursive:(BOOL)recursive
            completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Removes an existing file at given path.

 @param path Path of file to be removed.
 @param completionHandler Closure will be run after operation is completed.
 */
- (void)removeFileAtPath:(NSString *)path
       completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Removes an existing file or directory at given path.

 @param path Path of file or directory to be removed.
 @param completionHandler Closure will be run after operation is completed.
 */
- (void)removeItemAtPath:(NSString *)path
       completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Truncates or extends the file at given path.

 @param path Path of file to be truncated.
 @param offset Final size of truncated file.
 @param completionHandler Closure will be run after operation is completed.
 */
- (void)truncateFileAtPath:(NSString *)path
                  atOffset:(uint64_t)offset
         completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Moves/Renames an existing file at given path to a new location.

 @param path Path of file to be moved.
 @param toPath New location of file.
 @param completionHandler Closure will be run after operation is completed.
 */
- (void)moveItemAtPath:(NSString *)path
                toPath:(NSString *)toPath
     completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

#pragma mark - Read

/**
 Fetches data contents of a file from an offset with specified length.

 @param path Path of file to be fetched.
 @param offset First byte of file to be read, starting from zero.
 @param length Length of bytes should be read from offset. Pass -1 for entire file.
 @param progress Reports progress. Return YES to continue, NO to abort.
 @param completionHandler Closure will be run after reading data is completed.
 */
- (void)contentsAtPath:(NSString *)path
            fromOffset:(int64_t)offset
              toLength:(NSInteger)length
              progress:(SMB2ReadProgressHandler)progress
     completionHandler:(void (^)(NSData *_Nullable contents, NSError *_Nullable error))completionHandler;

/**
 Streams data contents of a file from an offset.

 @param path Path of file to be fetched.
 @param offset First byte of file to be read, starting from zero.
 @param fetchedData Returns data portion fetched. Return YES to continue, NO to abort.
 @param completionHandler Closure will be run after reading data is completed.
 */
- (void)contentsAtPath:(NSString *)path
            fromOffset:(int64_t)offset
           fetchedData:(BOOL (^)(int64_t offset, int64_t total, NSData *data))fetchedData
     completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

#pragma mark - Write

/**
 Creates and writes data to file.

 @param data Data that must be written to file.
 @param path Path of file to be written.
 @param progress Reports progress. Return YES to continue, NO to abort.
 @param completionHandler Closure will be run after writing is completed.
 */
- (void)writeData:(NSData *)data
           toPath:(NSString *)path
         progress:(SMB2WriteProgressHandler)progress
completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Creates/Opens and writes data to file at given offset.

 @param data Data that must be written to file.
 @param path Path of file to be written.
 @param offset The offset that new data will be written to.
 @param progress Reports progress. Return YES to continue, NO to abort.
 @param completionHandler Closure will be run after writing is completed.
 */
- (void)appendData:(NSData *)data
            toPath:(NSString *)path
            offset:(int64_t)offset
          progress:(SMB2WriteProgressHandler)progress
 completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

#pragma mark - Copy

/**
 Copy files to a new location (server-side copy).

 @param path Path of file to be copied from.
 @param toPath Path of new file to be copied to.
 @param recursive Copies directory structure and files if path is directory.
 @param progress Reports progress. Return YES to continue, NO to abort.
 @param completionHandler Closure will be run after copying is completed.
 */
- (void)copyItemAtPath:(NSString *)path
                toPath:(NSString *)toPath
             recursive:(BOOL)recursive
              progress:(SMB2ReadProgressHandler)progress
     completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

#pragma mark - Upload/Download

/**
 Uploads local file contents to a new location.

 @param url URL of a local file to be uploaded from.
 @param toPath Path of new file to be uploaded to.
 @param progress Reports progress. Return YES to continue, NO to abort.
 @param completionHandler Closure will be run after uploading is completed.
 */
- (void)uploadItemAtURL:(NSURL *)url
                 toPath:(NSString *)toPath
               progress:(SMB2WriteProgressHandler)progress
      completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

/**
 Downloads file contents to a local url.

 @param path Path of file to be downloaded from.
 @param url URL of a local file to be written to.
 @param progress Reports progress. Return YES to continue, NO to abort.
 @param completionHandler Closure will be run after downloading is completed.
 */
- (void)downloadItemAtPath:(NSString *)path
                     toURL:(NSURL *)url
                  progress:(SMB2ReadProgressHandler)progress
         completionHandler:(SMB2SimpleCompletionHandler)completionHandler;

@end

NS_ASSUME_NONNULL_END
