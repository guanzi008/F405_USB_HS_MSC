#pragma once

#include<stdio.h>
#include<stdarg.h>
#include<string.h>
#include<stdint.h>

#include "main.h"
#include "usart.h"//用串口打印调试信息

#ifdef __cplusplus
extern "C" {
#endif


#define THE_DEBUG_UART_HAND huart6//调试用的串口的句柄
#define THE_DEBUG_UART_INIT MX_USART6_UART_Init//调试用的串口初始化

/**
 * @brief 初始化串口以使用打印
 * 
 */
void printInit(void);




#ifdef __cplusplus
}
#endif