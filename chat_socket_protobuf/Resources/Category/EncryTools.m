//
//  EncryTools.m
//  LeftHand
//
//  Created by chenstone on 15-4-24.
//  Copyright (c) 2015年 chenstone. All rights reserved.
//

#import "EncryTools.h"

@implementation EncryTools
//加密
+(NSData *)encryt : (NSData *) data_input andKey:(const char *)keyWord{
    
    char * char_input = (char *)[data_input bytes];
//    NSLog(@"%lu,%lu", (unsigned long)[data_input length], strlen(char_input));
//    NSLog(@"转化后的char_*%s", char_input);
    // 加点盐
    const char *key = keyWord;
    int outlen= 81920;
    // 加密输出
    static char outbufEncrypt[81920] = {0};
    if(!isiPhone4){
        oi_symmetry_encrypt2(char_input, (int)[data_input length], key, outbufEncrypt, &outlen);
    }else{
          oi_symmetry_encrypt2_align(char_input, (int)[data_input length], key, outbufEncrypt, &outlen);
    }
    
//      oi_symmetry_encrypt2(char_input, (int)[data_input length], key, outbufEncrypt, &outlen);
//    oi_symmetry_encrypt_impl2(char_input, (int)[data_input length], key, outbufEncrypt, &outlen);

    //    char *char_output = (char *)malloc(sizeof(char) * outlen);
    //    memcpy(char_output, outbufEncrypt, outlen);
//    printf("outbufEncrypt=%s,outlen=%d\n",outbufEncrypt,outlen);
    NSData *data_output = [NSData dataWithBytes: outbufEncrypt length: outlen];
    return data_output;
}

//解密
+(NSData *)uncryt : (NSData *) data_input andKey:(const char *)keyWord{
    const char *cStr_input = (char *)[data_input bytes];
    int outlen_1 = 81920;
    static char outbufDecode[81920] = {0};
    const char *key = keyWord;
    if(!isiPhone4){
        oi_symmetry_decrypt2(cStr_input,(int)[data_input length], key, outbufDecode, &outlen_1);
    }else{
        oi_symmetry_decrypt2_align(cStr_input,(int)[data_input length], key, outbufDecode, &outlen_1);
    }
    
    //oi_symmetry_decrypt2(cStr_input,(int)[data_input length], key, outbufDecode, &outlen_1);
    //oi_symmetry_decrypt_impl2(cStr_input,(int)[data_input length], key, outbufDecode, &outlen_1);


//    printf("outbufDecode=%s,outlen=%d\n",outbufDecode,outlen_1);
    NSData *data_out = [NSData dataWithBytes: outbufDecode length: outlen_1];
    return data_out;
}

@end
