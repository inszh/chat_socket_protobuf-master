//
//  UIImage+Extension.h
//  01-QQ聊天布局
//
//  Created by apple on 14-4-2.
//  Copyright (c) 2014年 itcast. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface UIImage (Extension)
+ (UIImage *)resizableImage:(NSString *)name;
//截图
+ (instancetype)captureWithView:(UIView *)view;
//切圆
+ (instancetype)circleImageWithName:(UIImage *)oldImage borderWidth:(CGFloat)borderWidth borderColor:(UIColor *)borderColor;

/**
 *  打水印
 *
 *  @param bg   背景图片
 *  @param logo 右下角的水印图片
 */
//+ (instancetype)waterImageWithBg:(NSString *)bg logo:(NSString *)logo;
+ (instancetype)waterImageWithBg:(UIImage *)bgImage logo:(UIImage *)waterImage;


+ (UIImage *)imageWithTransImage:(UIImage *)useImage addtransparentImage:(UIImage *)transparentimg;

+ (UIImage *)imageWithColor:(UIColor *)color;

+ (UIImage *)imageBy:(UIImage*)img Alpha:(CGFloat)alpha;
@end