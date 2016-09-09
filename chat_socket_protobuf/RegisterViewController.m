//
//  RegisterViewController.m
//  chat_socket_protobuf
//
//  Created by 小华 on 16/3/3.
//  Copyright © 2016年 ark. All rights reserved.
//



#import "RegisterViewController.h"
#import "ProtoHead.h"
#import "Singleton.h"
#import "Zsapp_im_msg_register.pb.h"
#import "Zsapp_im_msg_login.pb.h"
#import "NSString+Password.h"
#import "EncryTools.h"



@interface RegisterViewController ()
@property (weak, nonatomic) IBOutlet UITextField *phoneNT;
@property (weak, nonatomic) IBOutlet UITextField *identNT;
@property (weak, nonatomic) IBOutlet UIButton *identB;
@property (weak, nonatomic) IBOutlet UITextField *pwdT;
@property(nonatomic,assign)int uid;
@property(nonatomic,strong)NSTimer* timer1;
@property(nonatomic)int count;
@property(nonatomic, strong)NSString *str16;

@end

@implementation RegisterViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    self.view.backgroundColor=k_BACKGROUNDCOLOR;
    self.navigationController.navigationBar.hidden=NO;
    [self connectService];
    
    [[NSNotificationCenter defaultCenter]addObserver:self selector:@selector(keyboardWillChangeFrame:) name:UIKeyboardWillChangeFrameNotification object:nil];
    
    [self.phoneNT addTarget:self action:@selector(textFieldDidChange:) forControlEvents:UIControlEventEditingChanged];
     [self.identNT addTarget:self action:@selector(textFieldDidChange:) forControlEvents:UIControlEventEditingChanged];
     [self.pwdT addTarget:self action:@selector(textFieldDidChange:) forControlEvents:UIControlEventEditingChanged];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(applicationWillResignActive:)
                                                 name:UIApplicationWillResignActiveNotification object:nil];
    self.identB.enabled =NO;
    self.navigationItem.rightBarButtonItem.enabled=NO;
}

-(void)connectService
{
    int socketPort=8000;
    NSString *registerip=@"im-roammsg-c2c.zuoshouwang.com";
    
    
    NSString *kitClientIp =ip;
    NSNumber *kitClientPort =Rport;
    NSString *sig=[[NSUserDefaults standardUserDefaults] objectForKey:@"USERSIG"];
    if (sig) {
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
    
    [Singleton sharedInstance].didReadDataBlock=^(NSData *data,long tag){
        
        [ProtoHead MessageFromReadData:data andBlock:^(NSData *head, NSData *body) {
            
            Head *headData = [Head parseFromData:head];

            register_rsp *obj_body = [register_rsp parseFromData:body];
            DLog(@"------------------------拿到了%d",(int)obj_body.int32Uid);
            DLog(@"---%@---%d",headData.msgCshead.strErrorMsg,headData.msgCshead.uint32ResultCode);
            switch (headData.msgCshead.int32Maincmd) {
                case 260:
                    DLog(@"验证码发送成功");
                    break;
                case 262:
                {
                    register_rsp *obj_body = [register_rsp parseFromData:body];
                    NSLog(@"---------拿到了%d",(int)obj_body.int32Uid);
                    NSString *uid=[NSString stringWithFormat:@"%d",obj_body.int32Uid];
                    [[NSUserDefaults standardUserDefaults] setValue:uid forKey:@"userid"];
                    [self registerToSERVICE];
                }
                    break;
                case 264:
                    DLog(@"设置密码成功");
                    [self setSIG];
                    break;
                    
                case 290:
                case 292:
                {
                    DLog(@"登陆成功");

                    const char *code = [self.str16 UTF8String];
                    
                    NSData *data_uncryBody = [EncryTools uncryt:data andKey:code];
                    
                    login_pw_rsp *objc_login_pw_rsp = [login_pw_rsp parseFromData:data];

                    cookie_login_rsp *objc_cookie_login_rsp = [cookie_login_rsp parseFromData:data_uncryBody];

                    login_pw_rsp *objc_login_pw=(login_pw_rsp*)objc_login_pw_rsp;
                    
                    int uid_text = objc_login_pw.int32Uid;
                    
                    NSString *str_cookie = objc_login_pw.strCookieKey;
                    
                    NSData *sig = objc_login_pw.bytesCookieSig;
                    
                    NSLog(@"正确的UID是:%d", uid_text);
                    
                    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
                    
                    [defaults setValue:sig forKey:USERSIG];
                    
                    [defaults setValue:str_cookie forKey:USERCOOKIE];
                    
                    [defaults setValue:self.phoneNT.text forKey:USERPHONENUM];

                
                }
                    break;
 
                default:
                    break;
            }

        }];
    };

    
}


- (IBAction)getIdentClick:(UIButton *)btn
{
    [self.identNT becomeFirstResponder];
    [self fireTime];
    
    register_getsms_num_reqBuilder *builder = [register_getsms_num_req builder];
    [builder setStrPhoneNum:self.phoneNT.text];
    register_getsms_num_req *numBody_req = [builder build];
    
    ProtoHead *protoHead=[ProtoHead new];
    protoHead.fromUid=000001;
    protoHead.maincmd=0x103;
    protoHead.clientIp=ip;
    protoHead.socketPort=[Rport intValue];
    protoHead.PhoneNum=self.phoneNT.text;
    
    ProtoHead *protoHead2= [protoHead initProtoHead];
    Head *head=protoHead2.head;
    NSData *dataToServer= [protoHead bodyWithHead:head.data body:numBody_req.data];
    [[Singleton sharedInstance].socket writeData:dataToServer withTimeout:1 tag:0];
    
}


-(void)registerToSERVICE
{
    NSString *num_phone = self.phoneNT.text;
    
    NSString *num_identi = self.identNT.text;
    
    NSString *str_sugar = self.pwdT.text;
    
    NSString *str_MD5MD5 = [[str_sugar MD5] MD5];
    
    NSData *str_data = [str_MD5MD5 dataUsingEncoding:NSUTF8StringEncoding];
    
    register_set_passwd_reqBuilder *builder_passWord = [register_set_passwd_req builder];
    
    [builder_passWord setStrPhoneNum:num_phone];
    
    [builder_passWord setInt32Uid:self.uid];
    
    [builder_passWord setBytesPasswdMd5Salt: str_data];
    
    register_set_passwd_req *msg_register = [builder_passWord build];
    
    NSData *data_body = msg_register.data;//包体数据
    
    NSString *str_key = [NSString stringWithFormat:@"%@%@", num_identi, @"ZuoShou@@@"];
    
    const char * keyWord = [str_key UTF8String];
    
    NSData *data_body_encry = [EncryTools encryt:data_body andKey:keyWord];//经过加密的包体数据
    
    ProtoHead *protoHead=[ProtoHead protoHead];
    protoHead.fromUid=000001;
    protoHead.maincmd=0x107;
    protoHead.fromUid=self.uid;
    protoHead.clientIp=ip;
    protoHead.socketPort=[Rport intValue];
    protoHead.PhoneNum=self.phoneNT.text;
    ProtoHead *protoHead2= [protoHead initProtoHead];
    Head *head=protoHead2.head;
    
    NSData *dataToServer= [protoHead bodyWithHead:head.data body:data_body_encry];
    [[Singleton sharedInstance].socket writeData:dataToServer withTimeout:1 tag:0];
    
}


- (IBAction)done:(id)sender
{
    register_reqBuilder *builder_msg = [register_req builder];
    [builder_msg setStrPhoneNum:self.phoneNT.text];
    [builder_msg setStrSecureNum:self.identNT.text];
    [builder_msg setBytesValideCodeSig:nil];
    
    NSLog(@"%@",self.identNT.text);
    
    register_req *msg_register = [builder_msg build];
    
    ProtoHead *protoHead=[ProtoHead protoHead];
    protoHead.fromUid=000001;
    protoHead.maincmd=0x105;
    protoHead.clientIp=ip;
    protoHead.socketPort=[Rport intValue];
    protoHead.PhoneNum=self.phoneNT.text;
    ProtoHead *protoHead2= [protoHead initProtoHead];
    Head *head=protoHead2.head;
    NSData *dataToServer= [protoHead bodyWithHead:head.data body:msg_register.data];
    [[Singleton sharedInstance].socket writeData:dataToServer withTimeout:1 tag:0];
}


-(void)setSIG
{
        int wTGTGTVer = 1;
        
        NSMutableData *data = [[NSMutableData alloc] initWithBytes:&wTGTGTVer length:2];
        
        int dwRandom = arc4random();
        
        [data appendBytes:&dwRandom length:4];
        
        int dwAppId = 1;
        
        [data appendBytes:&dwAppId length:4];
        
        int dwAppClientVer = 1;
        
        [data appendBytes:&dwAppClientVer length:4];
        
        int Uid = 0;
        
        [data appendBytes:&Uid length:4];
        
        NSDate* dat = [NSDate dateWithTimeIntervalSinceNow:0];
        
        NSTimeInterval a=[dat timeIntervalSince1970]*1000;
        
        NSString *dwInitTime = [NSString stringWithFormat:@"%f", a];
        
        [data appendBytes:&dwInitTime length:4];
        
        int dwClientIP = 0;
        
        [data appendBytes:&dwClientIP length:4];
        
        NSString *str_code = [NSString stringWithFormat:@"%d",[[ProtoHead protoHead] getRan32]];
        
        const char *code_16 = [str_code UTF8String];
        
        self.str16 = str_code;
        
        NSData *data_code = [NSData dataWithBytes:code_16 length:16];
        
        [data appendData:data_code];
        
        NSString *str_pwd = self.pwdT.text;
        
        NSString *str_MD5 = [[str_pwd MD5] MD5];
        
        NSString *str_MD5_16 = [str_MD5 substringToIndex:16];
        
        const char *keyWord = [str_MD5_16 UTF8String];
        
        NSData *data_encry = [EncryTools encryt:data andKey:keyWord];     //生成bin
        
        LoginSigBuilder *builder_loginSig = [LoginSig builder];
        
        [builder_loginSig setInt32SigType:1];
        
        [builder_loginSig setBytesSig:data_encry];
        
        LoginSig *sig = [builder_loginSig build];    //生成LoginSig.msg
    
        ProtoHead *protoHead=[ProtoHead protoHead];
        protoHead.fromUid=000001;
        protoHead.maincmd=0x121;
        protoHead.clientIp=ip;
        protoHead.socketPort=[Rport intValue];
        protoHead.PhoneNum=self.phoneNT.text;
        protoHead.sig=sig;
        ProtoHead *protoHead2= [protoHead initProtoHead];
        Head *head=protoHead2.head;
    
        login_pw_requestBuilder *builder_login_pw_request = [login_pw_request builder];
        
        [builder_login_pw_request setInt32Uid:0];
        
        [builder_login_pw_request setStrPhoneNum:self.phoneNT.text];
        
        [builder_login_pw_request setStrEmail:nil];
    
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

        [builder_login_pw_request setBytesDeviceToken:[defaults objectForKey:USERDEVICETOKEN]];
    
        login_pw_request *request = [builder_login_pw_request build];
    
        NSData *dataToServer= [protoHead bodyWithHead:head.data body:request.data];
        [[Singleton sharedInstance].socket writeData:dataToServer withTimeout:1 tag:0];

}

- (IBAction)pop:(id)sender
{
    [self.view endEditing:YES];

    self.navigationController.navigationBar.hidden=YES;
    
    [self.navigationController popViewControllerAnimated:YES];

}


-(void)keyboardWillChangeFrame:(NSNotification *)note
{
    CGFloat duration = [note.userInfo[UIKeyboardAnimationDurationUserInfoKey] doubleValue];
    
    CGRect keyboardFrame = [note.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    
    CGFloat transformY = keyboardFrame.origin.y - self.view.frame.size.height;
    
    [UIView animateWithDuration:duration animations:^{
        self.view.transform = CGAffineTransformMakeTranslation(0, transformY);
    }];
    
}

-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self.view endEditing:YES];
}

- (void)applicationWillResignActive:(NSNotification *)notification

{
    [self.view endEditing:YES];
}

- (void)textFieldDidChange:(UITextField *)textField
{

    if (textField ==self.phoneNT) {
        

        if (textField.text.length > 11)
            
            textField.text = [textField.text substringToIndex:11];
            self.identB.enabled =(self.phoneNT.text.length==11);

    }else if (textField ==self.identNT) {
        
        if (textField.text.length > 6)
            
            textField.text = [textField.text substringToIndex:6];
    }
    self.navigationItem.rightBarButtonItem.enabled=(self.phoneNT.text.length&&self.identNT.text.length&&self.pwdT.text.length);
}

-(void)fireTime
{
    NSTimer* timer1=[NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(updateTime) userInfo:nil repeats:YES];
    
    if(self.timer1){
        
        [self.timer1 invalidate];
        
    }
    self.timer1 = timer1;
    [self.timer1 fire];
}

-(void)updateTime
{
    self.count++;
    if (self.count >kIdentCount){
        self.count = 0;
        [self.timer1 invalidate];
        self.identB.enabled = YES;
        [self.identB setTitle:@"获取验证码" forState:UIControlStateNormal];
        
    }else{
        
        NSString *str = [NSString stringWithFormat:@"%i",kIdentCount-self.count];
        self.identB.enabled = NO;
        [self.identB setTitle:str forState:UIControlStateDisabled];
        
    }
}

-(void)dealloc
{
    [[NSNotificationCenter defaultCenter]removeObserver:self];
}


@end
