//
//  ProtoHead.h
//  socket_tutorial
//
//  Created by 小华 on 16/2/27.
//  Copyright © 2016年 ark. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Zsapp_im_msg_head.pb.h"
#import "MJExtension.h"

@interface ProtoHead : NSObject

@property(nonatomic,assign)int fromUid;
@property(nonatomic,assign)int maincmd;
@property(nonatomic,assign)int subcmd;
@property(nonatomic,assign)int msgSeq;
@property(nonatomic,assign)int retryTimes;
@property(nonatomic,assign)int sessionId;
@property(nonatomic,assign)int resultCode;
@property(nonatomic,assign)int resultSubcode;
@property(nonatomic,copy)NSString * clientIp;
@property(nonatomic,assign)int socketPort;
@property(nonatomic,copy)NSString *PhoneNum;
@property(nonatomic,assign)int toUid;
@property(nonatomic,strong)LoginSig * sig;
@property(nonatomic,strong)Head * head;

-(instancetype)initProtoHead;
+(instancetype)protoHead;
-(NSData *)bodyWithHead:(NSData *)head body:(NSData *)body;
+(void)MessageFromReadData:(NSData *)data andBlock:(void(^)(NSData *head, NSData *body))block;

-(int)getRan32;

@end
