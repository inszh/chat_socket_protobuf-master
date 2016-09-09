//
//  EncryTools.h
//  LeftHand
//
//  Created by chenstone on 15-4-24.
//  Copyright (c) 2015年 chenstone. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "oi_tea.h"

@interface EncryTools : NSObject
/**
 *  加密
 *
 *  @param proto序列化后的data
 *  @return 将要给服务器上传的data
 */
+(NSData *)encryt : (NSData *) data_input andKey:(const char *)keyWord;

/**
 *  解密
 *
 *  @param 从服务器上获取的data
 *  @return 将要反序列化成proto的data
 */
+(NSData *)uncryt : (NSData *) data_input andKey:(const char *)keyWord;

@end
