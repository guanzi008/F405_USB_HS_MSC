/*****************************************************************//**
 * \file   memxx_supplement.h
 * \brief  内存(memory)操作函数的补充
 * \brief  注意标准库中string.h中的memxxx相关函数也不以'\0'为结束。
 * \brief  或者说u8数组的一些操作
 *
 * \author CaiYunWei
 * \date   July 2024
 *********************************************************************/
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif


 /**
 * 十六进制打印一段内存（u8数组）.
 *
 * \param target 目标数组起始地址
 * \param number 要打印的长度
 */
void memPrint(const void* target, size_t number);



/**
 * 反转一段内存（u8数组）.
 *
 * \param start 起始地址
 * \param end 结束地址
 */
void memReversalV1(const void* start, const void* end);

/**
 * 反转一段内存（u8数组）.
 *
 * \param start 起始地址
 * \param number 要处理的长度
 */
void memReversalV2(const void* start, size_t number);


/**
 * 在主u8数组中寻找子u8数组（朴素）.
 *
 * \param major 主数组地址
 * \param num1 主数组长度
 * \param target 模式数组地址
 * \param num2 模式数组长度
 * \return 主数组major中，第一个匹配模式数组target的地址
 * \return NULL未找到
 */
void* memMathingNative(const void* major, size_t num1, const void* target, size_t num2);

/**
 * 在主u8数组中寻找u8子数组（KMP）.
 *
 * \param major 主数组地址
 * \param num1 主数组长度
 * \param target 模式数组地址
 * \param num2 模式数组长度
 * \return 主数组major中，第一个匹配模式数组target的地址
 * \return NULL未找到
 */
void* memMathingKMP(const void* major, size_t num1, const void* target, size_t num2);



#ifdef __cplusplus
}
#endif