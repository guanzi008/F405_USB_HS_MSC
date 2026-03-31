/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : usb_device.c
  * @version        : v1.0_Cube
  * @brief          : This file implements the USB Device
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/

#include "usb_device.h"
#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_composite_builder.h"
#include "usbd_hid.h"
#include "usbd_msc.h"
#include "usbd_storage_if.h"

/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/
static uint8_t s_dap_hid_ep_add[2] = { DAP_HID_EPIN_ADDR, DAP_HID_EPOUT_ADDR };
static uint8_t s_fido_hid_ep_add[2] = { FIDO_HID_EPIN_ADDR, FIDO_HID_EPOUT_ADDR };
static uint8_t s_msc_ep_add[2] = { MSC_EPIN_ADDR, MSC_EPOUT_ADDR };

/* USER CODE END PV */

/* USER CODE BEGIN PFP */
/* Private function prototypes -----------------------------------------------*/

/* USER CODE END PFP */

/* USB Device Core handle declaration. */
USBD_HandleTypeDef hUsbDeviceHS;

/*
 * -- Insert your variables declaration here --
 */
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/*
 * -- Insert your external function declaration here --
 */
/* USER CODE BEGIN 1 */
USBD_StatusTypeDef My_USB_HS_HID_MSC_Init(void)
{
  USBD_StatusTypeDef result;
  uint32_t msc_class_id;

  /* Init Device Library, add supported class and start the library. */
  result = USBD_Init(&hUsbDeviceHS, &HS_Desc, DEVICE_HS);
  if (result != USBD_OK)
    return result;

  result = USBD_RegisterClassComposite(&hUsbDeviceHS,
                                       &USBD_HID,
                                       CLASS_TYPE_HID,
                                       s_dap_hid_ep_add);
  if (result != USBD_OK)
    return result;

  result = USBD_RegisterClassComposite(&hUsbDeviceHS,
                                       &USBD_HID,
                                       CLASS_TYPE_CHID,
                                       s_fido_hid_ep_add);
  if (result != USBD_OK)
    return result;

  result = USBD_RegisterClassComposite(&hUsbDeviceHS,
                                       &USBD_MSC,
                                       CLASS_TYPE_MSC,
                                       s_msc_ep_add);
  if (result != USBD_OK)
    return result;

  msc_class_id = USBD_CMPSIT_SetClassID(&hUsbDeviceHS, CLASS_TYPE_MSC, 0U);
  if (msc_class_id == 0xFFU)
    return USBD_FAIL;

  result = (USBD_StatusTypeDef)USBD_MSC_RegisterStorage(&hUsbDeviceHS, &USBD_Storage_Interface_fops_HS);
  if (result != USBD_OK)
    return result;

  result = USBD_Start(&hUsbDeviceHS);

  return result;
}

USBD_StatusTypeDef My_USB_HS_HID_Init(void)
{
  return My_USB_HS_HID_MSC_Init();
}

USBD_StatusTypeDef My_USB_HS_HID_DeInit(void)
{
  return USBD_DeInit(&hUsbDeviceHS);
}

/* USER CODE END 1 */

/**
  * Init USB device Library, add supported class and start the library
  * @retval None
  */
void MX_USB_DEVICE_Init(void)
{
  /* USER CODE BEGIN USB_DEVICE_Init_PreTreatment */

  /* USER CODE END USB_DEVICE_Init_PreTreatment */

  /* Init Device Library, add supported class and start the library. */
  if (My_USB_HS_HID_MSC_Init() != USBD_OK)
  {
    Error_Handler();
  }

  /* USER CODE BEGIN USB_DEVICE_Init_PostTreatment */

  /* USER CODE END USB_DEVICE_Init_PostTreatment */
}

/**
  * @}
  */

/**
  * @}
  */

