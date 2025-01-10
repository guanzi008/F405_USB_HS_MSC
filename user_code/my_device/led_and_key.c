/**
 * @file led_and_key.c
 * @author 蔡云蔚 (you@domain.com)
 * @brief 发光二极管和按键
 * @version 0.1
 * @date 2024-08-29
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "led_and_key.h"




//LED                 
// #define LED0_GPIO_CLK_ENABLE()    __HAL_RCC_GPIOC_CLK_ENABLE()

// void LED0_Init(void)
// {
//     /* GPIO Ports Clock Enable */
//     LED0_GPIO_CLK_ENABLE();    

//     /*Configure GPIO pins */
//     GPIO_InitTypeDef GPIO_InitStruct = {0};
//     GPIO_InitStruct.Pin = LED0_Pin;
//     GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
//     GPIO_InitStruct.Pull = GPIO_PULLUP;
//     GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
//     HAL_GPIO_Init(LED0_GPIO_Port, &GPIO_InitStruct);

//     LED0_OFF();
// }

void LED0_ON(void)
{
    HAL_GPIO_WritePin(LED0_GPIO_Port, LED0_Pin, GPIO_PIN_RESET);
}

void LED0_OFF(void)
{
    HAL_GPIO_WritePin(LED0_GPIO_Port, LED0_Pin, GPIO_PIN_SET);
}

void LED0_Toggle(void)
{
    if(HAL_GPIO_ReadPin(LED0_GPIO_Port, LED0_Pin) == GPIO_PIN_SET)
    {
        LED0_ON();
    }
    else
    {
        LED0_OFF();
    }
}


// //KEY                
// #define KEY0_GPIO_CLK_ENABLE()    __HAL_RCC_GPIOC_CLK_ENABLE()

// void Key0_Init()
// {

//     /* GPIO Ports Clock Enable */
//     KEY0_GPIO_CLK_ENABLE();

//     /*Configure GPIO pin : PtPin */
//     GPIO_InitTypeDef GPIO_InitStruct = {0};
//     GPIO_InitStruct.Pin = Key0_Pin;
//     GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
//     GPIO_InitStruct.Pull = GPIO_NOPULL;
//     HAL_GPIO_Init(Key0_GPIO_Port, &GPIO_InitStruct);

//     // /* EXTI interrupt init*/
//     // HAL_NVIC_SetPriority(EXTI1_IRQn, 10, 0);
//     // HAL_NVIC_EnableIRQ(EXTI1_IRQn);
// }

bool KEY0_check()
{
    if(HAL_GPIO_ReadPin(KEY0_GPIO_Port, KEY0_Pin) == GPIO_PIN_RESET)
    {
        return true;
    }
    else
        return false;
}

