// Generated by the protocol buffer compiler.  DO NOT EDIT!

#import "ProtocolBuffers.h"

// @@protoc_insertion_point(imports)

@class cookie_login_req;
@class cookie_login_reqBuilder;
@class cookie_login_rsp;
@class cookie_login_rspBuilder;
@class login_pw_request;
@class login_pw_requestBuilder;
@class login_pw_rsp;
@class login_pw_rspBuilder;



@interface ZsappImMsgLoginRoot : NSObject {
}
+ (PBExtensionRegistry*) extensionRegistry;
+ (void) registerAllExtensions:(PBMutableExtensionRegistry*) registry;
@end

#define login_pw_request_int32_uid @"int32Uid"
#define login_pw_request_str_phone_num @"strPhoneNum"
#define login_pw_request_str_email @"strEmail"
#define login_pw_request_str_validate_code @"strValidateCode"
#define login_pw_request_bytes_valide_buff @"bytesValideBuff"
#define login_pw_request_bytes_device_token @"bytesDeviceToken"
@interface login_pw_request : PBGeneratedMessage<GeneratedMessageProtocol> {
@private
  BOOL hasInt32Uid_:1;
  BOOL hasStrPhoneNum_:1;
  BOOL hasStrEmail_:1;
  BOOL hasStrValidateCode_:1;
  BOOL hasBytesValideBuff_:1;
  BOOL hasBytesDeviceToken_:1;
  SInt32 int32Uid;
  NSString* strPhoneNum;
  NSString* strEmail;
  NSString* strValidateCode;
  NSData* bytesValideBuff;
  NSData* bytesDeviceToken;
}
- (BOOL) hasInt32Uid;
- (BOOL) hasStrPhoneNum;
- (BOOL) hasStrEmail;
- (BOOL) hasStrValidateCode;
- (BOOL) hasBytesValideBuff;
- (BOOL) hasBytesDeviceToken;
@property (readonly) SInt32 int32Uid;
@property (readonly, strong) NSString* strPhoneNum;
@property (readonly, strong) NSString* strEmail;
@property (readonly, strong) NSString* strValidateCode;
@property (readonly, strong) NSData* bytesValideBuff;
@property (readonly, strong) NSData* bytesDeviceToken;

+ (instancetype) defaultInstance;
- (instancetype) defaultInstance;

- (BOOL) isInitialized;
- (void) writeToCodedOutputStream:(PBCodedOutputStream*) output;
- (login_pw_requestBuilder*) builder;
+ (login_pw_requestBuilder*) builder;
+ (login_pw_requestBuilder*) builderWithPrototype:(login_pw_request*) prototype;
- (login_pw_requestBuilder*) toBuilder;

+ (login_pw_request*) parseFromData:(NSData*) data;
+ (login_pw_request*) parseFromData:(NSData*) data extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (login_pw_request*) parseFromInputStream:(NSInputStream*) input;
+ (login_pw_request*) parseFromInputStream:(NSInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (login_pw_request*) parseFromCodedInputStream:(PBCodedInputStream*) input;
+ (login_pw_request*) parseFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
@end

@interface login_pw_requestBuilder : PBGeneratedMessageBuilder {
@private
  login_pw_request* resultLoginPwRequest;
}

- (login_pw_request*) defaultInstance;

- (login_pw_requestBuilder*) clear;
- (login_pw_requestBuilder*) clone;

- (login_pw_request*) build;
- (login_pw_request*) buildPartial;

- (login_pw_requestBuilder*) mergeFrom:(login_pw_request*) other;
- (login_pw_requestBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input;
- (login_pw_requestBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;

- (BOOL) hasInt32Uid;
- (SInt32) int32Uid;
- (login_pw_requestBuilder*) setInt32Uid:(SInt32) value;
- (login_pw_requestBuilder*) clearInt32Uid;

- (BOOL) hasStrPhoneNum;
- (NSString*) strPhoneNum;
- (login_pw_requestBuilder*) setStrPhoneNum:(NSString*) value;
- (login_pw_requestBuilder*) clearStrPhoneNum;

- (BOOL) hasStrEmail;
- (NSString*) strEmail;
- (login_pw_requestBuilder*) setStrEmail:(NSString*) value;
- (login_pw_requestBuilder*) clearStrEmail;

- (BOOL) hasStrValidateCode;
- (NSString*) strValidateCode;
- (login_pw_requestBuilder*) setStrValidateCode:(NSString*) value;
- (login_pw_requestBuilder*) clearStrValidateCode;

- (BOOL) hasBytesValideBuff;
- (NSData*) bytesValideBuff;
- (login_pw_requestBuilder*) setBytesValideBuff:(NSData*) value;
- (login_pw_requestBuilder*) clearBytesValideBuff;

- (BOOL) hasBytesDeviceToken;
- (NSData*) bytesDeviceToken;
- (login_pw_requestBuilder*) setBytesDeviceToken:(NSData*) value;
- (login_pw_requestBuilder*) clearBytesDeviceToken;
@end

#define login_pw_rsp_int32_uid @"int32Uid"
#define login_pw_rsp_int32_login_result_code @"int32LoginResultCode"
#define login_pw_rsp_str_error_msg @"strErrorMsg"
#define login_pw_rsp_str_cookie_key @"strCookieKey"
#define login_pw_rsp_bytes_cookie_sig @"bytesCookieSig"
#define login_pw_rsp_str_dst_ip @"strDstIp"
#define login_pw_rsp_str_dst_port @"strDstPort"
@interface login_pw_rsp : PBGeneratedMessage<GeneratedMessageProtocol> {
@private
  BOOL hasInt32Uid_:1;
  BOOL hasInt32LoginResultCode_:1;
  BOOL hasStrErrorMsg_:1;
  BOOL hasStrCookieKey_:1;
  BOOL hasStrDstIp_:1;
  BOOL hasStrDstPort_:1;
  BOOL hasBytesCookieSig_:1;
  SInt32 int32Uid;
  SInt32 int32LoginResultCode;
  NSString* strErrorMsg;
  NSString* strCookieKey;
  NSString* strDstIp;
  NSString* strDstPort;
  NSData* bytesCookieSig;
}
- (BOOL) hasInt32Uid;
- (BOOL) hasInt32LoginResultCode;
- (BOOL) hasStrErrorMsg;
- (BOOL) hasStrCookieKey;
- (BOOL) hasBytesCookieSig;
- (BOOL) hasStrDstIp;
- (BOOL) hasStrDstPort;
@property (readonly) SInt32 int32Uid;
@property (readonly) SInt32 int32LoginResultCode;
@property (readonly, strong) NSString* strErrorMsg;
@property (readonly, strong) NSString* strCookieKey;
@property (readonly, strong) NSData* bytesCookieSig;
@property (readonly, strong) NSString* strDstIp;
@property (readonly, strong) NSString* strDstPort;

+ (instancetype) defaultInstance;
- (instancetype) defaultInstance;

- (BOOL) isInitialized;
- (void) writeToCodedOutputStream:(PBCodedOutputStream*) output;
- (login_pw_rspBuilder*) builder;
+ (login_pw_rspBuilder*) builder;
+ (login_pw_rspBuilder*) builderWithPrototype:(login_pw_rsp*) prototype;
- (login_pw_rspBuilder*) toBuilder;

+ (login_pw_rsp*) parseFromData:(NSData*) data;
+ (login_pw_rsp*) parseFromData:(NSData*) data extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (login_pw_rsp*) parseFromInputStream:(NSInputStream*) input;
+ (login_pw_rsp*) parseFromInputStream:(NSInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (login_pw_rsp*) parseFromCodedInputStream:(PBCodedInputStream*) input;
+ (login_pw_rsp*) parseFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
@end

@interface login_pw_rspBuilder : PBGeneratedMessageBuilder {
@private
  login_pw_rsp* resultLoginPwRsp;
}

- (login_pw_rsp*) defaultInstance;

- (login_pw_rspBuilder*) clear;
- (login_pw_rspBuilder*) clone;

- (login_pw_rsp*) build;
- (login_pw_rsp*) buildPartial;

- (login_pw_rspBuilder*) mergeFrom:(login_pw_rsp*) other;
- (login_pw_rspBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input;
- (login_pw_rspBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;

- (BOOL) hasInt32Uid;
- (SInt32) int32Uid;
- (login_pw_rspBuilder*) setInt32Uid:(SInt32) value;
- (login_pw_rspBuilder*) clearInt32Uid;

- (BOOL) hasInt32LoginResultCode;
- (SInt32) int32LoginResultCode;
- (login_pw_rspBuilder*) setInt32LoginResultCode:(SInt32) value;
- (login_pw_rspBuilder*) clearInt32LoginResultCode;

- (BOOL) hasStrErrorMsg;
- (NSString*) strErrorMsg;
- (login_pw_rspBuilder*) setStrErrorMsg:(NSString*) value;
- (login_pw_rspBuilder*) clearStrErrorMsg;

- (BOOL) hasStrCookieKey;
- (NSString*) strCookieKey;
- (login_pw_rspBuilder*) setStrCookieKey:(NSString*) value;
- (login_pw_rspBuilder*) clearStrCookieKey;

- (BOOL) hasBytesCookieSig;
- (NSData*) bytesCookieSig;
- (login_pw_rspBuilder*) setBytesCookieSig:(NSData*) value;
- (login_pw_rspBuilder*) clearBytesCookieSig;

- (BOOL) hasStrDstIp;
- (NSString*) strDstIp;
- (login_pw_rspBuilder*) setStrDstIp:(NSString*) value;
- (login_pw_rspBuilder*) clearStrDstIp;

- (BOOL) hasStrDstPort;
- (NSString*) strDstPort;
- (login_pw_rspBuilder*) setStrDstPort:(NSString*) value;
- (login_pw_rspBuilder*) clearStrDstPort;
@end

#define cookie_login_req_int32_uid @"int32Uid"
#define cookie_login_req_bytes_cookie_sig @"bytesCookieSig"
#define cookie_login_req_str_validate_code @"strValidateCode"
#define cookie_login_req_bytes_validate_code_buff @"bytesValidateCodeBuff"
#define cookie_login_req_bytes_device_token @"bytesDeviceToken"
@interface cookie_login_req : PBGeneratedMessage<GeneratedMessageProtocol> {
@private
  BOOL hasInt32Uid_:1;
  BOOL hasStrValidateCode_:1;
  BOOL hasBytesCookieSig_:1;
  BOOL hasBytesValidateCodeBuff_:1;
  BOOL hasBytesDeviceToken_:1;
  SInt32 int32Uid;
  NSString* strValidateCode;
  NSData* bytesCookieSig;
  NSData* bytesValidateCodeBuff;
  NSData* bytesDeviceToken;
}
- (BOOL) hasInt32Uid;
- (BOOL) hasBytesCookieSig;
- (BOOL) hasStrValidateCode;
- (BOOL) hasBytesValidateCodeBuff;
- (BOOL) hasBytesDeviceToken;
@property (readonly) SInt32 int32Uid;
@property (readonly, strong) NSData* bytesCookieSig;
@property (readonly, strong) NSString* strValidateCode;
@property (readonly, strong) NSData* bytesValidateCodeBuff;
@property (readonly, strong) NSData* bytesDeviceToken;

+ (instancetype) defaultInstance;
- (instancetype) defaultInstance;

- (BOOL) isInitialized;
- (void) writeToCodedOutputStream:(PBCodedOutputStream*) output;
- (cookie_login_reqBuilder*) builder;
+ (cookie_login_reqBuilder*) builder;
+ (cookie_login_reqBuilder*) builderWithPrototype:(cookie_login_req*) prototype;
- (cookie_login_reqBuilder*) toBuilder;

+ (cookie_login_req*) parseFromData:(NSData*) data;
+ (cookie_login_req*) parseFromData:(NSData*) data extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (cookie_login_req*) parseFromInputStream:(NSInputStream*) input;
+ (cookie_login_req*) parseFromInputStream:(NSInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (cookie_login_req*) parseFromCodedInputStream:(PBCodedInputStream*) input;
+ (cookie_login_req*) parseFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
@end

@interface cookie_login_reqBuilder : PBGeneratedMessageBuilder {
@private
  cookie_login_req* resultCookieLoginReq;
}

- (cookie_login_req*) defaultInstance;

- (cookie_login_reqBuilder*) clear;
- (cookie_login_reqBuilder*) clone;

- (cookie_login_req*) build;
- (cookie_login_req*) buildPartial;

- (cookie_login_reqBuilder*) mergeFrom:(cookie_login_req*) other;
- (cookie_login_reqBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input;
- (cookie_login_reqBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;

- (BOOL) hasInt32Uid;
- (SInt32) int32Uid;
- (cookie_login_reqBuilder*) setInt32Uid:(SInt32) value;
- (cookie_login_reqBuilder*) clearInt32Uid;

- (BOOL) hasBytesCookieSig;
- (NSData*) bytesCookieSig;
- (cookie_login_reqBuilder*) setBytesCookieSig:(NSData*) value;
- (cookie_login_reqBuilder*) clearBytesCookieSig;

- (BOOL) hasStrValidateCode;
- (NSString*) strValidateCode;
- (cookie_login_reqBuilder*) setStrValidateCode:(NSString*) value;
- (cookie_login_reqBuilder*) clearStrValidateCode;

- (BOOL) hasBytesValidateCodeBuff;
- (NSData*) bytesValidateCodeBuff;
- (cookie_login_reqBuilder*) setBytesValidateCodeBuff:(NSData*) value;
- (cookie_login_reqBuilder*) clearBytesValidateCodeBuff;

- (BOOL) hasBytesDeviceToken;
- (NSData*) bytesDeviceToken;
- (cookie_login_reqBuilder*) setBytesDeviceToken:(NSData*) value;
- (cookie_login_reqBuilder*) clearBytesDeviceToken;
@end

#define cookie_login_rsp_int32_uid @"int32Uid"
#define cookie_login_rsp_int32_cookie_login_result_code @"int32CookieLoginResultCode"
#define cookie_login_rsp_str_error_msg @"strErrorMsg"
#define cookie_login_rsp_str_dst_ip @"strDstIp"
#define cookie_login_rsp_str_dst_port @"strDstPort"
@interface cookie_login_rsp : PBGeneratedMessage<GeneratedMessageProtocol> {
@private
  BOOL hasInt32Uid_:1;
  BOOL hasInt32CookieLoginResultCode_:1;
  BOOL hasStrErrorMsg_:1;
  BOOL hasStrDstIp_:1;
  BOOL hasStrDstPort_:1;
  SInt32 int32Uid;
  SInt32 int32CookieLoginResultCode;
  NSString* strErrorMsg;
  NSString* strDstIp;
  NSString* strDstPort;
}
- (BOOL) hasInt32Uid;
- (BOOL) hasInt32CookieLoginResultCode;
- (BOOL) hasStrErrorMsg;
- (BOOL) hasStrDstIp;
- (BOOL) hasStrDstPort;
@property (readonly) SInt32 int32Uid;
@property (readonly) SInt32 int32CookieLoginResultCode;
@property (readonly, strong) NSString* strErrorMsg;
@property (readonly, strong) NSString* strDstIp;
@property (readonly, strong) NSString* strDstPort;

+ (instancetype) defaultInstance;
- (instancetype) defaultInstance;

- (BOOL) isInitialized;
- (void) writeToCodedOutputStream:(PBCodedOutputStream*) output;
- (cookie_login_rspBuilder*) builder;
+ (cookie_login_rspBuilder*) builder;
+ (cookie_login_rspBuilder*) builderWithPrototype:(cookie_login_rsp*) prototype;
- (cookie_login_rspBuilder*) toBuilder;

+ (cookie_login_rsp*) parseFromData:(NSData*) data;
+ (cookie_login_rsp*) parseFromData:(NSData*) data extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (cookie_login_rsp*) parseFromInputStream:(NSInputStream*) input;
+ (cookie_login_rsp*) parseFromInputStream:(NSInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
+ (cookie_login_rsp*) parseFromCodedInputStream:(PBCodedInputStream*) input;
+ (cookie_login_rsp*) parseFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;
@end

@interface cookie_login_rspBuilder : PBGeneratedMessageBuilder {
@private
  cookie_login_rsp* resultCookieLoginRsp;
}

- (cookie_login_rsp*) defaultInstance;

- (cookie_login_rspBuilder*) clear;
- (cookie_login_rspBuilder*) clone;

- (cookie_login_rsp*) build;
- (cookie_login_rsp*) buildPartial;

- (cookie_login_rspBuilder*) mergeFrom:(cookie_login_rsp*) other;
- (cookie_login_rspBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input;
- (cookie_login_rspBuilder*) mergeFromCodedInputStream:(PBCodedInputStream*) input extensionRegistry:(PBExtensionRegistry*) extensionRegistry;

- (BOOL) hasInt32Uid;
- (SInt32) int32Uid;
- (cookie_login_rspBuilder*) setInt32Uid:(SInt32) value;
- (cookie_login_rspBuilder*) clearInt32Uid;

- (BOOL) hasInt32CookieLoginResultCode;
- (SInt32) int32CookieLoginResultCode;
- (cookie_login_rspBuilder*) setInt32CookieLoginResultCode:(SInt32) value;
- (cookie_login_rspBuilder*) clearInt32CookieLoginResultCode;

- (BOOL) hasStrErrorMsg;
- (NSString*) strErrorMsg;
- (cookie_login_rspBuilder*) setStrErrorMsg:(NSString*) value;
- (cookie_login_rspBuilder*) clearStrErrorMsg;

- (BOOL) hasStrDstIp;
- (NSString*) strDstIp;
- (cookie_login_rspBuilder*) setStrDstIp:(NSString*) value;
- (cookie_login_rspBuilder*) clearStrDstIp;

- (BOOL) hasStrDstPort;
- (NSString*) strDstPort;
- (cookie_login_rspBuilder*) setStrDstPort:(NSString*) value;
- (cookie_login_rspBuilder*) clearStrDstPort;
@end


// @@protoc_insertion_point(global_scope)