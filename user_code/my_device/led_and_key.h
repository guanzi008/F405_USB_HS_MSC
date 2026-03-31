/**
 * @file LEDandKEY.h
 * @author 蔡云蔚 (you@domain.com)
 * @brief 发光二极管和按键
 * @version 0.1
 * @date 2024-08-29
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#pragma once


#include "main.h"
#include "gpio.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


// void LED0_Init(void);

void LED0_ON(void);

void LED0_OFF(void);

void LED0_Toggle(void);





// void Key0_Init();

/**
 * @brief 检查按键是否按下
 * 
 * @return true 按下
 * @return false 松开
 */
bool KEY0_check();

#ifdef __cplusplus
}
#endif