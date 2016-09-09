//
//  ProtoHead.m
//  socket_tutorial
//
//  Created by 小华 on 16/2/27.
//  Copyright © 2016年 ark. All rights reserved.
//

#import "protoHead.h"


@implementation ProtoHead

+(instancetype)protoHead
{
    return [[self alloc]initProtoHead];
}

-(instancetype)initProtoHead
{
    if (self=[super init]) {
        
        CSHeadBuilder *build_CSHead = [CSHead builder];
        [build_CSHead setInt32Version:0x00010001];
        [build_CSHead setInt32FromUid:_fromUid];
        [build_CSHead setInt32Maincmd:_maincmd];
        [build_CSHead setInt32Subcmd:_subcmd];
        [build_CSHead setInt32MsgSeq:[self getRan32]];
        [build_CSHead setUint32RetryTimes:0];
        [build_CSHead setUint32SessionId:0];
        [build_CSHead setUint32ResultCode:0];
        [build_CSHead setUint32ResultSubcode:0];
        [build_CSHead setStrErrorMsg:@"error"];
        [build_CSHead setClientIp:_clientIp];
        [build_CSHead setClientPort:_socketPort];
        [build_CSHead setStrPhoneNum:_PhoneNum];
        [build_CSHead setInt32ToUid:_toUid];
        
        NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
        double doubleVersion = [[[UIDevice currentDevice] systemVersion] doubleValue];
        NSString *OSVersion = [NSString stringWithFormat:@"%.1f", doubleVersion];
        NSString *app_version = [infoDict objectForKey:@"CFBundleShortVersionString"];
        NSString *app_build = [infoDict objectForKey:@"CFBundleVersion"];
        NSString *strVersion = [NSString stringWithFormat:@"ios_%@|V%@|Build%@", OSVersion, app_version, app_build];

        [build_CSHead setStrOsVersion:strVersion];
        CSHead *csHead = [build_CSHead build];
        HeadBuilder *build_Head = [Head builder];
        [build_Head setInt32HeadType:0x01];
        [build_Head setInt32ModuleId:0x01];
        [build_Head setMsgCshead:csHead];
        [build_Head setMsgLoginSig:_sig];//第一次注册不需要
        self.head = [build_Head build];     //生成的头文件data

    }
    
    return self;
}

-(int)getRan32{
    static dispatch_once_t onceToken = 0;
    dispatch_once(&onceToken, ^{
        srand((unsigned int)time(NULL));
    });
    return rand();
}

-(NSData *)bodyWithHead:(NSData *)head body:(NSData *)body
{
    NSUInteger length_body = [body length];//数据体长
    NSUInteger length_head = [head length];//头长
    NSUInteger length_total = length_body + length_head + 12;//总长
    int length_total_networkingType = htonl(length_total);//总长网络序
    int length_body_networkingType = htonl(length_body);//体长网络序
    int length_head_networking = htonl(length_head);//头长网络序
    NSMutableData *dataToServer = [NSMutableData dataWithBytes:&length_total_networkingType length:4];
    [dataToServer appendBytes:&length_head_networking length:4];
    [dataToServer appendBytes:&length_body_networkingType length:4];
    [dataToServer appendData:head];
    [dataToServer appendData:body];
    return dataToServer;
}


+(void)MessageFromReadData:(NSData *)data andBlock:(void(^)(NSData *head, NSData *body))block
{    
    //读取头长
    NSUInteger length_head = 0;
    [data getBytes:&length_head range:NSMakeRange(4, 8)];
    NSUInteger length_net_head = ntohl(length_head);
    //读取体长
    NSUInteger length_body = 0;
    [data getBytes:&length_body range:NSMakeRange(8, 8)];
    NSUInteger length_net_body = ntohl(length_body);
    //获取头数据
    NSData *data_head = [data subdataWithRange:NSMakeRange(12, length_net_head)];
    NSData *data_body = [data subdataWithRange:NSMakeRange(12+length_net_head, length_net_body)];
    
    Head *headData = [Head parseFromData:data_head];
    
    [[NSUserDefaults standardUserDefaults] setValue:headData.msgCshead.clientIp forKey:@"clientIp"];
     NSString *clientPort=[NSString stringWithFormat:@"%d",headData.msgCshead.clientPort];
    [[NSUserDefaults standardUserDefaults] setValue: clientPort forKey:@"clientPort"];
 
    
    block(data_head, data_body);
}



@end
