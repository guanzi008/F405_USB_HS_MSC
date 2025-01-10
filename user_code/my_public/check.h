/*****************************************************************//**
 * \file   check.h
 * \brief  一些校验函数
 * 
 * \author CaiYunWei
 * \date   September 2024
 *********************************************************************/
#pragma once

#include <memxx_supplement.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 得到8位加法校验和.
 *
 * \param pStart 数据起始地址
 * \param count 数据数量
 * \param pResult 结果保存位置
 */
void additionChecksum_8BIT(const void* pStart, size_t count, uint8_t* pResult);



#ifdef __cplusplus
}
#endif