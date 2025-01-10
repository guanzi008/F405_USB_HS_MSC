/**
 * @file check.c
 * @author 蔡云蔚 (you@domain.com)
 * @brief 一些校验函数
 * @version 0.1
 * @date 2024-10-30
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include "check.h"

void additionChecksum_8BIT(const void *pStart, size_t count, uint8_t *pResult)
{
    uint8_t sum    = 0X00;
    uint8_t *pData = (uint8_t *)pStart;
    for (size_t i = 0; i < count; i++) {
        sum += pData[i];
    }

    *pResult = sum;
}

#define POLY_8 0x07//0000 0111
/**
 * @brief CRC-8校验
 *
 * @param pStart 校验数据起始位置
 * @param count 校验数据长度
 * @param pResult 校验码保存位置
 */
void CRC_8(const void *pStart, size_t count, void *pResult)
{
    uint8_t crc   = 0x00; // 初始值
    uint8_t *p    = (uint8_t *)pStart;
    uint8_t *pEnd = (uint8_t *)pStart + count - 1;
    int i;
    for (; p <= pEnd; p++) {
        crc ^= *p;              // 与crc初始值异或
        for (i = 0; i < 8; i++) // 循环8位
        {
            if (crc & 0x80) // 左移移出的位为1，左移后与多项式异或
            {
                crc <<= 1;
                crc ^= POLY_8;
            } else // 否则直接左移
            {
                crc <<= 1;
            }
        }
    }

    *((uint8_t *)pResult) = crc;
}
