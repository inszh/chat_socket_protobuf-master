//
//  ViewController.m
//  chat_socket_protobuf
//
//  Created by 小华 on 16/3/3.
//  Copyright © 2016年 ark. All rights reserved.
//

#import "ViewController.h"
#import "ProtoHead.h"
#import "Singleton.h"
#import "Zsapp_im_msg_register.pb.h"
#import "NSString+Password.h"
#import "EncryTools.h"

#define number @"14423192015"
#define code @"m9a7k5j4";
#define ip [[NSUserDefaults standardUserDefaults] objectForKey:@"clientIp"]
#define port [[NSUserDefaults standardUserDefaults] objectForKey:@"clientPort"]

//181 116 245
@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *identL;

@end




@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    int socketPort=8000;
    NSString *registerip=@"im-roammsg-c2c.zuoshouwang.com";
    
    
    NSString *kitClientIp =ip;// [[NSUserDefaults standardUserDefaults] objectForKey:@"clientIp"];
    NSNumber *kitClientPort =port;// [[NSUserDefaults standardUserDefaults] objectForKey:@"clientPort"];
    if (kitClientIp) {
        registerip=kitClientIp;
        socketPort=[kitClientPort intValue];
    } else {
        registerip=@"im-roammsg-c2c.zuoshouwang.com";
        socketPort=8000;
        
    }
    
    
    
    //注册
    [Singleton sharedInstance].socketHost =registerip; // 注册
    [Singleton sharedInstance].socketPort = socketPort;// port设定
    
    // 在连接前先进行手动断开
    [Singleton sharedInstance].socket.userData = SocketOfflineByUser;
    [[Singleton sharedInstance] cutOffSocket];
    
    // 确保断开后再连，如果对一个正处于连接状态的socket进行连接，会出现崩溃
    [Singleton sharedInstance].socket.userData = SocketOfflineByServer;
    [[Singleton sharedInstance] socketConnectHost];
    
    [Singleton sharedInstance].isConnectBlock=^{
        [self registerToSERVICE];
    };
    
}

-(void)registerToSERVICE
{
    register_getsms_num_reqBuilder *builder = [register_getsms_num_req builder];
    [builder setStrPhoneNum:number];
    register_getsms_num_req *numBody_req = [builder build];
    
    ProtoHead *protoHead=[ProtoHead new];
    protoHead.fromUid=000001;
    protoHead.maincmd=0x103;
    protoHead.clientIp=ip;
    protoHead.socketPort=[port intValue];
    protoHead.PhoneNum=number;
    
    ProtoHead *protoHead2= [protoHead initProtoHead];
    Head *head=protoHead2.head;
    NSData *dataToServer= [protoHead bodyWithHead:head.data body:numBody_req.data];
    [[Singleton sharedInstance].socket writeData:dataToServer withTimeout:1 tag:0];
    
    [Singleton sharedInstance].didReadDataBlock=^(NSData *data,long tag){
        
        [ProtoHead MessageFromReadData:data andBlock:^(NSData *head, NSData *body) {
            
            Head *headData = [Head parseFromData:head];

            DLog(@"---------------------%@",headData.msgCshead.strErrorMsg);

            register_rsp *obj_body = [register_rsp parseFromData:body];
            NSLog(@"------------------------拿到了%d",(int)obj_body.int32Uid);
            if (obj_body.int32Uid>0) {
                [self setupPWD:obj_body.int32Uid];
            }
        }];
    };
    
}

//验证验证码
-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    register_reqBuilder *builder_msg = [register_req builder];
    [builder_msg setStrPhoneNum:number];
    [builder_msg setStrSecureNum:self.identL.text];
    [builder_msg setBytesValideCodeSig:nil];
    
    NSLog(@"%@",self.identL.text);
    
    register_req *msg_register = [builder_msg build];
    
    ProtoHead *protoHead=[ProtoHead protoHead];
    protoHead.fromUid=000001;
    protoHead.maincmd=0x105;
    protoHead.clientIp=ip;
    protoHead.socketPort=[port intValue];
    protoHead.PhoneNum=number;
    ProtoHead *protoHead2= [protoHead initProtoHead];
    Head *head=protoHead2.head;
    NSData *dataToServer= [protoHead bodyWithHead:head.data body:msg_register.data];
    [[Singleton sharedInstance].socket writeData:dataToServer withTimeout:1 tag:0];
    
}

- (void)setupPWD:(int)uid
{
    NSString *num_phone = number;
    
    NSString *num_identi = self.identL.text;
    
    NSString *str_sugar = code;
    
    NSString *str_MD5MD5 = [[str_sugar MD5] MD5];
    
    NSData *str_data = [str_MD5MD5 dataUsingEncoding:NSUTF8StringEncoding];
    
    register_set_passwd_reqBuilder *builder_passWord = [register_set_passwd_req builder];
    
    [builder_passWord setStrPhoneNum:num_phone];
    
    [builder_passWord setInt32Uid:uid];
    
    [builder_passWord setBytesPasswdMd5Salt: str_data];
    
    register_set_passwd_req *msg_register = [builder_passWord build];
    
    NSData *data_body = msg_register.data;//包体数据
    
    NSString *str_key = [NSString stringWithFormat:@"%@%@", num_identi, @"ZuoShou@@@"];
    
    const char * keyWord = [str_key UTF8String];
    
    NSData *data_body_encry = [EncryTools encryt:data_body andKey:keyWord];//经过加密的包体数据
    
    ProtoHead *protoHead=[ProtoHead protoHead];
    protoHead.fromUid=000001;
    protoHead.maincmd=0x107;
    protoHead.fromUid=uid;
    protoHead.clientIp=ip;
    protoHead.socketPort=[port intValue];
    protoHead.PhoneNum=number;
    ProtoHead *protoHead2= [protoHead initProtoHead];
    Head *head=protoHead2.head;
    
    NSData *dataToServer= [protoHead bodyWithHead:head.data body:data_body_encry];
    [[Singleton sharedInstance].socket writeData:dataToServer withTimeout:1 tag:0];


}

@end
