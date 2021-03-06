//
//  NSString+Password.m
//
//  Created by
//  Copyright (c) . All rights reserved.
//

#import "NSString+Password.h"
#import <CommonCrypto/CommonDigest.h>

static NSString *token = @"fashfkdashfjkldashfjkdashfjkdah23423sfjdasjkvcxnm%^&%^$&^uireqwyi1237281643";

@implementation NSString (Password)

- (NSString *)myMD5
{
    NSString *str = [NSString stringWithFormat:@"%@%@", self, token];
    
    return [str MD5];
}

#pragma mark 使用MD5加密字符串
- (NSString *)MD5
{
    const char *cStr = [self UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];

    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);

    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];

    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }

    return result;
}

#pragma mark 使用SHA1加密字符串
- (NSString *)SHA1
{
    const char *cStr = [self UTF8String];
    NSData *data = [NSData dataWithBytes:cStr length:self.length];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];

    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);

    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];

    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
}

@end
