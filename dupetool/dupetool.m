//
//  main.m
//  dupetool
//
//  Created by Jonathan Fischer on 1/2/14.
//  Copyright (c) 2014 Jonathan Fischer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "FMDB/FMDatabase.h"

static void printUsage()
{
    printf("Usage: dupe-detector (scan|report) -db <database> -path <path>\n");
}

static void createTables(FMDatabase *db)
{
    [db executeUpdate:@"CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, path STRING, hash_id INTEGER)"];
    [db executeUpdate:@"CREATE TABLE IF NOT EXISTS hashes (id INTEGER PRIMARY KEY AUTOINCREMENT, hash STRING, count INTEGER)"];
}

static NSUInteger insertHash(FMDatabase *db, NSString *hash)
{
    NSUInteger hashId = 0;

    FMResultSet *results = [db executeQuery:@"SELECT id FROM hashes WHERE hash = ?", hash];
    if ([results next]) {
        hashId = [results longForColumnIndex:0];
    } else {
        // New hash
        [db executeUpdate:@"INSERT INTO hashes VALUES (NULL, ?, 0)", hash];
        hashId = db.lastInsertRowId;
    }
    [results close];

    return hashId;
}

static void insertFile(FMDatabase *db, NSString *filePath, NSUInteger hashId)
{
    NSNumber *hashIdObj = [NSNumber numberWithInteger:hashId];
    FMResultSet *results = [db executeQuery:@"SELECT id FROM files WHERE path = ?", filePath];
    if ([results next]) {
        NSNumber *fileId = [NSNumber numberWithInteger:[results longForColumnIndex:0]];
        [db executeUpdate:@"UPDATE files SET hash_id = ? WHERE id = ?", hashIdObj, fileId];
    } else {
        [db executeUpdate:@"INSERT INTO files VALUES (NULL, ?, ?)", filePath, hashIdObj];
    }
    [results close];
}

static void updateHashes(FMDatabase *db)
{
    [db executeUpdate:@"UPDATE hashes SET count = (SELECT COUNT(hash_id) FROM files WHERE files.hash_id = hashes.id)"];
}

static NSString *hashStringForFile(NSURL *fileURL)
{
    NSData *data = [[NSData alloc] initWithContentsOfURL:fileURL options:NSDataReadingUncached error:nil];
    unsigned char outputData[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data.bytes, (CC_LONG)data.length, outputData);
    [data release];

    NSMutableString *hashStr = [[NSMutableString alloc] init];
    int i = 0;
    for (i = 0;i < CC_MD5_DIGEST_LENGTH; i++) {
        [hashStr appendFormat:@"%02x", outputData[i]];
    }

    return hashStr;
}

int main(int argc, const char * argv[])
{
    @autoreleasepool {
        NSArray *arguments = [[NSProcessInfo processInfo] arguments];
        if (arguments.count < 2) {
            printUsage();
            return 0;
        }

        NSString *command = arguments[1];
        BOOL shouldScan = [command caseInsensitiveCompare:@"scan"] == 0;
        BOOL shouldReport = [command caseInsensitiveCompare:@"report"] == 0;

        if (!shouldScan && !shouldReport) {
            printUsage();
            return 0;
        }


        // Either mode needs a database
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *databasePath = [defaults stringForKey:@"db"];
        if (databasePath == nil) {
            printUsage();
            return 0;
        }

        FMDatabase *database = [FMDatabase databaseWithPath:databasePath];
        if (databasePath == nil) {
            fprintf(stderr, "Couldn't open database at path %s\n", [databasePath cStringUsingEncoding:NSUTF8StringEncoding]);
            return 1;
        }
        
        if ([database open] == NO) {
            fprintf(stderr, "Couldn't open database at path %s\n", [databasePath cStringUsingEncoding:NSUTF8StringEncoding]);
            return 1;
        }

        if (shouldScan) {
            NSString *basePath = [defaults stringForKey:@"path"];
            if (basePath == nil) {
                printUsage();
                return 0;
            }
            createTables(database);

            printf("Scanning %s...\n", [basePath cStringUsingEncoding:NSUTF8StringEncoding]);

            NSFileManager *fileManager = [NSFileManager defaultManager];

            @autoreleasepool {
                NSURL *baseUrl = [NSURL URLWithString:basePath];

                NSDirectoryEnumerator *enumerator = [fileManager enumeratorAtURL:baseUrl
                                                      includingPropertiesForKeys:@[NSURLPathKey, NSURLIsDirectoryKey]
                                                                         options:NSDirectoryEnumerationSkipsHiddenFiles
                                                                    errorHandler:NULL];
                if (enumerator == nil) {
                    fprintf(stderr, "Unable to get a directory enumerator for path %s\n", [basePath cStringUsingEncoding:NSUTF8StringEncoding]);
                    return 1;
                }


                for (NSURL *fileURL in enumerator) {
                    @autoreleasepool {
                        NSNumber *isDirectory;
                        [fileURL getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:nil];
                        if ([isDirectory boolValue] == YES) {
                            continue;
                        }

                        NSString *filePath;
                        [fileURL getResourceValue:&filePath forKey:NSURLPathKey error:nil];
                        NSString *hashString = hashStringForFile(fileURL);

                        printf("%s (%s)\n", [filePath cStringUsingEncoding:NSUTF8StringEncoding], [hashString cStringUsingEncoding:NSUTF8StringEncoding]);

                        NSUInteger hashId = insertHash(database, hashString);
                        insertFile(database, filePath, hashId);
                    }
                }
            }

            printf("Checking for duplicate files...\n");
            updateHashes(database);
            printf("Done. Run 'dupetool report -db %s' to get a list of duplicate files.\n", [databasePath cStringUsingEncoding:NSUTF8StringEncoding]);
        } else if (shouldReport) {
            // Nested autoreleasepool because I need to make sure things get released after each file is scanned.
            @autoreleasepool {
                FMResultSet *duplicateHashResults = [database executeQuery:@"SELECT id FROM hashes WHERE count > 1"];
                NSMutableArray *duplicateHashes = [NSMutableArray array];
                while ([duplicateHashResults next]) {
                    [duplicateHashes addObject:[duplicateHashResults objectForColumnIndex:0]];
                }
                [duplicateHashResults close];

                printf("Duplicate files:\n");
                for (NSNumber *hashId in duplicateHashes) {
                    FMResultSet *pathResult = [database executeQuery:@"SELECT path FROM files WHERE hash_id = ?", hashId];
                    while ([pathResult next]) {
                        NSString *path = [pathResult stringForColumnIndex:0];
                        printf("%s\n", [path cStringUsingEncoding:NSUTF8StringEncoding]);
                    }
                    [pathResult close];
                    printf("\n");
                }
            }
        } else {
            fprintf(stderr, "I've no idea what happened, but this branch of the program should never be reached.");
            return 1;
        }
        
        [database close];
    }
    return 0;
}

