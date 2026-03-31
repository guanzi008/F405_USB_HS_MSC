/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : usbd_conf.h
  * @version        : v1.0_Cube
  * @brief          : Header for usbd_conf.c file.
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

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __USBD_CONF__H__
#define __USBD_CONF__H__

#ifdef __cplusplus
 extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "stm32f4xx.h"
#include "stm32f4xx_hal.h"

/* USER CODE BEGIN INCLUDE */

/* USER CODE END INCLUDE */

/** @addtogroup USBD_OTG_DRIVER
  * @brief Driver for Usb device.
  * @{
  */

/** @defgroup USBD_CONF USBD_CONF
  * @brief Configuration file for Usb otg low level driver.
  * @{
  */

/** @defgroup USBD_CONF_Exported_Variables USBD_CONF_Exported_Variables
  * @brief Public variables.
  * @{
  */

/**
  * @}
  */

/** @defgroup USBD_CONF_Exported_Defines USBD_CONF_Exported_Defines
  * @brief Defines for configuration of the Usb device.
  * @{
  */

/*---------- -----------*/
#define USBD_MAX_NUM_INTERFACES     3U
/*---------- -----------*/
#define USBD_MAX_NUM_CONFIGURATION     1U
/*---------- -----------*/
#define USBD_MAX_STR_DESC_SIZ     512U
/*---------- -----------*/
#define USBD_DEBUG_LEVEL     0U
/*---------- -----------*/
#define USBD_LPM_ENABLED     0U
/*---------- -----------*/
#define USBD_SELF_POWERED     1U
/*---------- -----------*/
#define MSC_MEDIA_PACKET     8192U

#define USE_USB_HS
#define USE_USBD_COMPOSITE
#define USBD_CMPSIT_ACTIVATE_HID 1U
#define USBD_CMPSIT_ACTIVATE_MSC 1U
#define USBD_MAX_SUPPORTED_CLASS 3U
#define USBD_MAX_CLASS_ENDPOINTS 3U
#define USBD_MAX_CLASS_INTERFACES 2U
#define USBD_CMPST_MAX_CONFDESC_SZ 128U

#define DAP_HID_EPIN_ADDR  0x81U
#define DAP_HID_EPOUT_ADDR 0x03U
#define FIDO_HID_EPIN_ADDR 0x83U
#define FIDO_HID_EPOUT_ADDR 0x05U
#define HID_EPIN_ADDR  DAP_HID_EPIN_ADDR
#define HID_EPOUT_ADDR DAP_HID_EPOUT_ADDR
#define MSC_EPIN_ADDR  0x82U
#define MSC_EPOUT_ADDR 0x01U
#define FIDO_STORAGE_RESERVED_BYTES (1024U * 1024U)

/****************************************/
/* #define for FS and HS identification */
#define DEVICE_FS 		0
#define DEVICE_HS 		1

/**
  * @}
  */

/** @defgroup USBD_CONF_Exported_Macros USBD_CONF_Exported_Macros
  * @brief Aliases.
  * @{
  */
/* Memory management macros make sure to use static memory allocation */
/** Alias for memory allocation. */

#define USBD_malloc         (void *)USBD_static_malloc

/** Alias for memory release. */
#define USBD_free           USBD_static_free

/** Alias for memory set. */
#define USBD_memset         memset

/** Alias for memory copy. */
#define USBD_memcpy         memcpy

/** Alias for delay. */
#define USBD_Delay          HAL_Delay

/* DEBUG macros */

#if (USBD_DEBUG_LEVEL > 0)
#define USBD_UsrLog(...)    printf(__VA_ARGS__);\
                            printf("\n");
#else
#define USBD_UsrLog(...)
#endif /* (USBD_DEBUG_LEVEL > 0U) */

#if (USBD_DEBUG_LEVEL > 1)

#define USBD_ErrLog(...)    printf("ERROR: ");\
                            printf(__VA_ARGS__);\
                            printf("\n");
#else
#define USBD_ErrLog(...)
#endif /* (USBD_DEBUG_LEVEL > 1U) */

#if (USBD_DEBUG_LEVEL > 2)
#define USBD_DbgLog(...)    printf("DEBUG : ");\
                            printf(__VA_ARGS__);\
                            printf("\n");
#else
#define USBD_DbgLog(...)
#endif /* (USBD_DEBUG_LEVEL > 2U) */

/**
  * @}
  */

/** @defgroup USBD_CONF_Exported_Types USBD_CONF_Exported_Types
  * @brief Types.
  * @{
  */

/**
  * @}
  */

/** @defgroup USBD_CONF_Exported_FunctionsPrototype USBD_CONF_Exported_FunctionsPrototype
  * @brief Declaration of public functions for Usb device.
  * @{
  */

/* Exported functions -------------------------------------------------------*/
void *USBD_static_malloc(uint32_t size);
void USBD_static_free(void *p);

typedef struct
{
  uint32_t irq_count;
  uint32_t reset_count;
  uint32_t setup_count;
  uint32_t data_out_count;
  uint32_t data_in_count;
  uint32_t suspend_count;
  uint32_t resume_count;
  uint32_t connect_count;
  uint32_t disconnect_count;
  uint32_t activate_setup_count;
  uint32_t ep0_out_start_count;
  uint32_t open_ep_count;
  uint32_t open_ep_fail_count;
  uint32_t last_open_ep_addr;
  uint32_t last_open_ep_type;
  uint32_t last_open_ep_mps;
  uint32_t last_open_ep_status;
  uint32_t malloc_call_count;
  uint32_t malloc_fail_count;
  uint32_t malloc_last_size;
  uint32_t malloc_last_words;
  uint32_t malloc_last_start;
  uint32_t malloc_last_limit;
  uint32_t malloc_last_ptr;
  uint32_t malloc_last_offset;
  uint32_t malloc_alloc_count;
  uint32_t cmsis_rx_count;
  uint32_t cmsis_tx_count;
  uint32_t cmsis_last_req_len;
  uint32_t cmsis_last_rsp_len;
  uint32_t cmsis_last_req_word0;
  uint32_t cmsis_last_req_word1;
  uint32_t cmsis_last_rsp_word0;
  uint32_t cmsis_last_rsp_word1;
  uint32_t hid_setup_count;
  uint32_t hid_last_class;
  uint32_t hid_last_bmRequest;
  uint32_t hid_last_bRequest;
  uint32_t hid_last_wValue;
  uint32_t hid_last_wIndex;
  uint32_t hid_last_wLength;
  uint32_t hid_last_report_len;
  uint32_t itf_req_count;
  uint32_t itf_last_index;
  uint32_t itf_last_class;
  uint32_t itf_last_bmRequest;
  uint32_t itf_last_bRequest;
  uint32_t itf_last_status;
  uint32_t fido_rx_count;
  uint32_t fido_tx_count;
  uint32_t fido_last_req_len;
  uint32_t fido_last_rsp_len;
  uint32_t fido_last_req_word0;
  uint32_t fido_last_req_word1;
  uint32_t fido_last_rsp_word0;
  uint32_t fido_last_rsp_word1;
  uint32_t fido_last_status;
  uint32_t fido_last_ctap_cmd;
  uint32_t fido_last_ctap_status;
  uint32_t fido_last_allow_count;
  uint32_t fido_last_match_count;
  uint32_t fido_last_auto_confirm;
  uint32_t fido_rx_expected_total;
  uint32_t fido_rx_received_total;
  uint32_t fido_rx_seq_next;
  uint32_t fido_rx_active;
  uint32_t set_cfg_call_count;
  uint32_t last_set_cfg_class;
  uint32_t last_set_cfg_cfgidx;
  uint32_t last_set_cfg_status;
  uint32_t set_cfg_fail_class;
  uint32_t set_cfg_fail_status;
  uint32_t last_setup_word0;
  uint32_t last_setup_word1;
  uint32_t gintsts;
  uint32_t gintmsk;
  uint32_t gotgctl;
  uint32_t gotgint;
  uint32_t gusbcfg;
  uint32_t gccfg;
  uint32_t dcfg;
  uint32_t dsts;
  uint32_t dctl;
  uint32_t daint;
  uint32_t daintmsk;
  uint32_t diepint0;
  uint32_t doepint0;
  uint32_t doeptsiz0;
} A_USB_DiagRuntime;

extern volatile A_USB_DiagRuntime g_a_usb_diag_runtime;

void a_usb_diag_note_irq(void);
void a_usb_diag_note_activate_setup(void);
void a_usb_diag_note_ep0_out_start(void);
void a_usb_diag_capture_registers(void);

/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif /* __USBD_CONF__H__ */

