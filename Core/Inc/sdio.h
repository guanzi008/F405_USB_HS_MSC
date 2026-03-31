/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    sdio.h
  * @brief   This file contains all the function prototypes for
  *          the sdio.c file
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __SDIO_H__
#define __SDIO_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* USER CODE BEGIN Includes */
#include <stdbool.h>
/* USER CODE END Includes */

extern SD_HandleTypeDef hsd;

/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

void MX_SDIO_SD_Init(void);

/* USER CODE BEGIN Prototypes */

/**
 * @brief SD卡初始化
 * 
 * @return HAL_StatusTypeDef 
 */
HAL_StatusTypeDef My_SDIO_SD_Init_Fixed(void);

/**
  * @brief  Reads block(s) from a specified address in a card. The Data transfer
  *         is managed by polling mode.
  * @param  pData: pointer to the buffer that will contain the received data
  * @param  BlockAdd: Block Address from where data is to be read
  * @param  NumberOfBlocks: Number of SD blocks to read
  * @retval HAL status
  * @note 参照使用fatfs时，sd_diskio.c中的函数编写，以更加完备
  */
HAL_StatusTypeDef My_SD_ReadBlocks(uint8_t *pData, uint32_t BlockAdd, uint32_t NumberOfBlocks);



/**
  * @brief  Reads block(s) from a specified address in a card. The Data transfer
  *         is managed by DMA mode.
  * @param  pData: Pointer to the buffer that will contain the received data
  * @param  BlockAdd: Block Address from where data is to be read
  * @param  NumberOfBlocks: Number of blocks to read.
  * @retval HAL status
  * @note 参照使用fatfs时，sd_diskio.c中的函数编写，以更加完备
  */
HAL_StatusTypeDef My_SD_ReadBlocks_DMA(uint8_t *pData, uint32_t BlockAdd, uint32_t NumberOfBlocks);

/**
  * @brief  Allows to write block(s) to a specified address in a card. The Data
  *         transfer is managed by polling mode.
  * @param  pData: pointer to the buffer that will contain the data to transmit
  * @param  BlockAdd: Block Address where data will be written
  * @param  NumberOfBlocks: Number of SD blocks to write
  * @retval HAL status
  * @note 参照使用fatfs时，sd_diskio.c中的函数编写，以更加完备
  */
HAL_StatusTypeDef My_SD_WriteBlocks(uint8_t *pData, uint32_t BlockAdd, uint32_t NumberOfBlocks);

/**
  * @brief  Writes block(s) to a specified address in a card. The Data transfer
  *         is managed by DMA mode.
  * @param  pData: Pointer to the buffer that will contain the data to transmit
  * @param  BlockAdd: Block Address where data will be written
  * @param  NumberOfBlocks: Number of blocks to write
  * @retval HAL status
  * @note 参照使用fatfs时，sd_diskio.c中的函数编写，以更加完备
  */
HAL_StatusTypeDef My_SD_WriteBlocks_DMA(uint8_t *pData, uint32_t BlockAdd, uint32_t NumberOfBlocks);


HAL_StatusTypeDef My_SD_CheckStatusWithTimeout(uint32_t timeout);
/* USER CODE END Prototypes */

#ifdef __cplusplus
}
#endif

#endif /* __SDIO_H__ */

