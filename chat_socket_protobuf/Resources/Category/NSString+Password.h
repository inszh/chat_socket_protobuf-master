//
//  Created by
//  Copyright (c)  All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Password)

- (NSString *)myMD5;

/**
 *  32位MD5加密
 *
 *  @return 32位MD5加密结果
 */
- (NSString *)MD5;

/**
 *  SHA1加密
 *
 *  @return SHA1加密结果
 */
- (NSString *)SHA1;

@end
