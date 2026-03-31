/**
  ******************************************************************************
  * @file    usbd_hid.c
  * @author  MCD Application Team
  * @brief   This file provides the HID core functions.
  *
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2015 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  * @verbatim
  *
  *          ===================================================================
  *                                HID Class  Description
  *          ===================================================================
  *           This module manages the HID class V1.11 following the "Device Class Definition
  *           for Human Interface Devices (HID) Version 1.11 Jun 27, 2001".
  *           This driver implements the following aspects of the specification:
  *             - The Boot Interface Subclass
  *             - The Mouse protocol
  *             - Usage Page : Generic Desktop
  *             - Usage : Joystick
  *             - Collection : Application
  *
  * @note     In HS mode and when the DMA is used, all variables and data structures
  *           dealing with the DMA during the transaction process should be 32-bit aligned.
  *
  *
  *  @endverbatim
  *
  ******************************************************************************
  */

/* BSPDependencies
- "stm32xxxxx_{eval}{discovery}{nucleo_144}.c"
- "stm32xxxxx_{eval}{discovery}_io.c"
EndBSPDependencies */

/* Includes ------------------------------------------------------------------*/
#include "usbd_hid.h"
#include "usbd_ctlreq.h"
#include "usbd_hid_cmsisdap.h"
#include "usbd_hid_fido.h"


/** @addtogroup STM32_USB_DEVICE_LIBRARY
  * @{
  */


/** @defgroup USBD_HID
  * @brief usbd core module
  * @{
  */

/** @defgroup USBD_HID_Private_TypesDefinitions
  * @{
  */
/**
  * @}
  */


/** @defgroup USBD_HID_Private_Defines
  * @{
  */

/**
  * @}
  */


/** @defgroup USBD_HID_Private_Macros
  * @{
  */
/**
  * @}
  */


/** @defgroup USBD_HID_Private_FunctionPrototypes
  * @{
  */

static uint8_t USBD_HID_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_HID_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_HID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
static uint8_t USBD_HID_EP0_RxReady(USBD_HandleTypeDef *pdev);
static uint8_t USBD_HID_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum);
static uint8_t USBD_HID_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum);
#ifndef USE_USBD_COMPOSITE
static uint8_t *USBD_HID_GetFSCfgDesc(uint16_t *length);
static uint8_t *USBD_HID_GetHSCfgDesc(uint16_t *length);
static uint8_t *USBD_HID_GetOtherSpeedCfgDesc(uint16_t *length);
static uint8_t *USBD_HID_GetDeviceQualifierDesc(uint16_t *length);
#endif /* USE_USBD_COMPOSITE  */
static uint8_t USBD_HID_GetInEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id);
static uint8_t USBD_HID_GetOutEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id);
static uint16_t USBD_HID_GetReportDescForClass(USBD_HandleTypeDef *pdev,
                                               uint8_t class_id,
                                               uint8_t **pbuf);
static uint8_t *USBD_HID_GetDescForClass(USBD_HandleTypeDef *pdev, uint8_t class_id);
static uint16_t USBD_HID_ProcessOutputReport(USBD_HandleTypeDef *pdev,
                                             uint8_t class_id,
                                             USBD_HID_HandleTypeDef *hhid,
                                             const uint8_t *report,
                                             uint16_t report_len);
/**
  * @}
  */

/** @defgroup USBD_HID_Private_Variables
  * @{
  */

USBD_ClassTypeDef USBD_HID =
{
  USBD_HID_Init,
  USBD_HID_DeInit,
  USBD_HID_Setup,
  NULL,              /* EP0_TxSent */
  USBD_HID_EP0_RxReady,
  USBD_HID_DataIn,   /* DataIn */
  USBD_HID_DataOut,  /* DataOut */
  NULL,              /* SOF */
  NULL,
  NULL,
#ifdef USE_USBD_COMPOSITE
  NULL,
  NULL,
  NULL,
  NULL,
#else
  USBD_HID_GetHSCfgDesc,
  USBD_HID_GetFSCfgDesc,
  USBD_HID_GetOtherSpeedCfgDesc,
  USBD_HID_GetDeviceQualifierDesc,
#endif /* USE_USBD_COMPOSITE  */
#if (USBD_SUPPORT_USER_STRING_DESC == 1U)
  NULL,
#endif /* USBD_SUPPORT_USER_STRING_DESC  */
};

#ifndef USE_USBD_COMPOSITE
/* USB HID device FS Configuration Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_CfgDesc[USB_HID_CONFIG_DESC_SIZ] __ALIGN_END =
{
  0x09,                                               /* bLength: Configuration Descriptor size */
  USB_DESC_TYPE_CONFIGURATION,                        /* bDescriptorType: Configuration */
  USB_HID_CONFIG_DESC_SIZ,                            /* wTotalLength: Bytes returned */
  0x00,
  0x01,                                               /* bNumInterfaces: 1 interface */
  0x01,                                               /* bConfigurationValue: Configuration value */
  0x00,                                               /* iConfiguration: Index of string descriptor
                                                         describing the configuration */
#if (USBD_SELF_POWERED == 1U)
  0xE0,                                               /* bmAttributes: Bus Powered according to user configuration */
#else
  0xA0,                                               /* bmAttributes: Bus Powered according to user configuration */
#endif /* USBD_SELF_POWERED */
  USBD_MAX_POWER,                                     /* MaxPower (mA) */

  /******************** Descriptor of CMSIS-DAP HID interface ****************/
  /* 09 */
  0x09,                                               /* bLength: Interface Descriptor size */
  USB_DESC_TYPE_INTERFACE,                            /* bDescriptorType: Interface descriptor type */
  0x00,                                               /* bInterfaceNumber: Number of Interface */
  0x00,                                               /* bAlternateSetting: Alternate setting */
  0x02,                                               /* bNumEndpoints */
  0x03,                                               /* bInterfaceClass: HID */
  0x00,                                               /* bInterfaceSubClass : vendor usage */
  0x00,                                               /* nInterfaceProtocol : vendor usage */
  0,                                                  /* iInterface: Index of string descriptor */
  /******************** Descriptor of CMSIS-DAP HID ********************/
  /* 18 */
  0x09,                                               /* bLength: HID Descriptor size */
  HID_DESCRIPTOR_TYPE,                                /* bDescriptorType: HID */
  0x11,                                               /* bcdHID: HID Class Spec release number */
  0x01,
  0x00,                                               /* bCountryCode: Hardware target country */
  0x01,                                               /* bNumDescriptors: Number of HID class descriptors to follow */
  0x22,                                               /* bDescriptorType */
  HID_REPORT_DESC_SIZE,                               /* wItemLength: Total length of Report descriptor */
  0x00,
  /******************** Descriptor of CMSIS-DAP IN endpoint ********************/
  /* 27 */
  0x07,                                               /* bLength: Endpoint Descriptor size */
  USB_DESC_TYPE_ENDPOINT,                             /* bDescriptorType:*/

  HID_EPIN_ADDR,                                      /* bEndpointAddress: Endpoint Address (IN) */
  0x03,                                               /* bmAttributes: Interrupt endpoint */
  HID_EPIN_SIZE,                                      /* wMaxPacketSize */
  0x00,
  HID_FS_BINTERVAL,                                   /* bInterval: Polling Interval */
  /******************** Descriptor of CMSIS-DAP OUT endpoint ********************/
  0x07,
  USB_DESC_TYPE_ENDPOINT,
  HID_EPOUT_ADDR,
  0x03,
  HID_EPOUT_SIZE,
  0x00,
  HID_FS_BINTERVAL,
};
#endif /* USE_USBD_COMPOSITE  */

/* USB HID device Configuration Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_Desc[USB_HID_DESC_SIZ] __ALIGN_END =
{
  /* 18 */
  0x09,                                               /* bLength: HID Descriptor size */
  HID_DESCRIPTOR_TYPE,                                /* bDescriptorType: HID */
  0x11,                                               /* bcdHID: HID Class Spec release number */
  0x01,
  0x00,                                               /* bCountryCode: Hardware target country */
  0x01,                                               /* bNumDescriptors: Number of HID class descriptors to follow */
  0x22,                                               /* bDescriptorType */
  HID_REPORT_DESC_SIZE,                               /* wItemLength: Total length of Report descriptor */
  0x00,
};
__ALIGN_BEGIN static uint8_t USBD_HID_DescRuntime[USB_HID_DESC_SIZ] __ALIGN_END;

#ifndef USE_USBD_COMPOSITE
/* USB Standard Device Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_DeviceQualifierDesc[USB_LEN_DEV_QUALIFIER_DESC] __ALIGN_END =
{
  USB_LEN_DEV_QUALIFIER_DESC,
  USB_DESC_TYPE_DEVICE_QUALIFIER,
  0x00,
  0x02,
  0x00,
  0x00,
  0x00,
  0x40,
  0x01,
  0x00,
};
#endif /* USE_USBD_COMPOSITE  */

__ALIGN_BEGIN static uint8_t HID_ReportDesc[HID_REPORT_DESC_SIZE] __ALIGN_END =
{
  0x06, 0x00, 0xFF,  /* Usage Page (Vendor Defined 0xFF00)     */
  0x09, 0x01,        /* Usage (0x01)                           */
  0xA1, 0x01,        /* Collection (Application)               */
  0x15, 0x00,        /*   Logical Minimum (0)                  */
  0x26, 0xFF, 0x00,  /*   Logical Maximum (255)                */
  0x75, 0x08,        /*   Report Size (8)                      */
  0x95, 0x40,        /*   Report Count (64)                    */
  0x09, 0x01,        /*   Usage (0x01)                         */
  0x81, 0x02,        /*   Input (Data,Var,Abs)                 */
  0x95, 0x40,        /*   Report Count (64)                    */
  0x09, 0x01,        /*   Usage (0x01)                         */
  0x91, 0x02,        /*   Output (Data,Var,Abs)                */
  0x95, 0x01,        /*   Report Count (1)                     */
  0x09, 0x01,        /*   Usage (0x01)                         */
  0xB1, 0x02,        /*   Feature (Data,Var,Abs)               */
  0xC0               /* End Collection                         */
};
static uint8_t HIDInEpAdd = HID_EPIN_ADDR;
static uint8_t HIDOutEpAdd = HID_EPOUT_ADDR;
static usbd_hid_fido_state_t s_fido_state;

static uint8_t USBD_HID_GetInEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id)
{
#ifdef USE_USBD_COMPOSITE
  return USBD_CoreGetEPAdd(pdev, USBD_EP_IN, USBD_EP_TYPE_INTR, class_id);
#else
  UNUSED(pdev);
  UNUSED(class_id);
  return HID_EPIN_ADDR;
#endif
}

static uint8_t USBD_HID_GetOutEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id)
{
#ifdef USE_USBD_COMPOSITE
  return USBD_CoreGetEPAdd(pdev, USBD_EP_OUT, USBD_EP_TYPE_INTR, class_id);
#else
  UNUSED(pdev);
  UNUSED(class_id);
  return HID_EPOUT_ADDR;
#endif
}

static uint16_t USBD_HID_GetReportDescForClass(USBD_HandleTypeDef *pdev,
                                               uint8_t class_id,
                                               uint8_t **pbuf)
{
  const uint8_t *fido_desc;

  if ((pdev->tclasslist[class_id].ClassType == CLASS_TYPE_CHID) &&
      (usbd_hid_fido_get_report_desc(&fido_desc) != 0U))
  {
    *pbuf = (uint8_t *)fido_desc;
    return FIDO_HID_REPORT_DESC_SIZE;
  }

  *pbuf = HID_ReportDesc;
  return HID_REPORT_DESC_SIZE;
}

static uint8_t *USBD_HID_GetDescForClass(USBD_HandleTypeDef *pdev, uint8_t class_id)
{
  uint16_t report_len;
  uint8_t *report_desc;

  report_len = USBD_HID_GetReportDescForClass(pdev, class_id, &report_desc);
  UNUSED(report_desc);
  USBD_memcpy(USBD_HID_DescRuntime, USBD_HID_Desc, USB_HID_DESC_SIZ);
  USBD_HID_DescRuntime[7] = (uint8_t)(report_len & 0xFFU);
  USBD_HID_DescRuntime[8] = (uint8_t)(report_len >> 8);
  return USBD_HID_DescRuntime;
}

static uint16_t USBD_HID_ProcessOutputReport(USBD_HandleTypeDef *pdev,
                                             uint8_t class_id,
                                             USBD_HID_HandleTypeDef *hhid,
                                             const uint8_t *report,
                                             uint16_t report_len)
{
  if ((hhid == NULL) || (report == NULL))
  {
    return 0U;
  }

  if (pdev->tclasslist[class_id].ClassType == CLASS_TYPE_CHID)
  {
    return usbd_hid_fido_process(pdev,
                                 class_id,
                                 &s_fido_state,
                                 report,
                                 report_len,
                                 hhid->tx_report,
                                 sizeof(hhid->tx_report));
  }

  return usbd_hid_cmsisdap_process(pdev,
                                   class_id,
                                   report,
                                   report_len,
                                   hhid->tx_report,
                                   sizeof(hhid->tx_report));
}

/**
  * @}
  */

/** @defgroup USBD_HID_Private_Functions
  * @{
  */

/**
  * @brief  USBD_HID_Init
  *         Initialize the HID interface
  * @param  pdev: device instance
  * @param  cfgidx: Configuration index
  * @retval status
  */
static uint8_t USBD_HID_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  UNUSED(cfgidx);

  USBD_HID_HandleTypeDef *hhid;

  hhid = (USBD_HID_HandleTypeDef *)USBD_malloc(sizeof(USBD_HID_HandleTypeDef));

  if (hhid == NULL)
  {
    pdev->pClassDataCmsit[pdev->classId] = NULL;
    return (uint8_t)USBD_EMEM;
  }

  pdev->pClassDataCmsit[pdev->classId] = (void *)hhid;
  pdev->pClassData = pdev->pClassDataCmsit[pdev->classId];

#ifdef USE_USBD_COMPOSITE
  /* Get the Endpoints addresses allocated for this class instance */
  HIDInEpAdd  = USBD_HID_GetInEpAdd(pdev, (uint8_t)pdev->classId);
  HIDOutEpAdd = USBD_HID_GetOutEpAdd(pdev, (uint8_t)pdev->classId);
#endif /* USE_USBD_COMPOSITE */

  if (pdev->dev_speed == USBD_SPEED_HIGH)
  {
    pdev->ep_in[HIDInEpAdd & 0xFU].bInterval = HID_HS_BINTERVAL;
  }
  else   /* LOW and FULL-speed endpoints */
  {
    pdev->ep_in[HIDInEpAdd & 0xFU].bInterval = HID_FS_BINTERVAL;
  }

  /* Open EP IN */
  (void)USBD_LL_OpenEP(pdev, HIDInEpAdd, USBD_EP_TYPE_INTR, HID_EPIN_SIZE);
  pdev->ep_in[HIDInEpAdd & 0xFU].is_used = 1U;

  /* Open EP OUT */
  (void)USBD_LL_OpenEP(pdev, HIDOutEpAdd, USBD_EP_TYPE_INTR, HID_EPOUT_SIZE);
  pdev->ep_out[HIDOutEpAdd & 0xFU].is_used = 1U;

  (void)USBD_LL_PrepareReceive(pdev, HIDOutEpAdd, hhid->rx_report, HID_EPOUT_SIZE);

  hhid->state = USBD_HID_IDLE;
  hhid->rx_len = 0U;
  hhid->tx_len = 0U;
  hhid->pending_tx_len = 0U;
  hhid->ctrl_report_len = 0U;
  hhid->ctrl_report_id = 0U;
  hhid->ctrl_report_type = 0U;
  hhid->pending_tx = 0U;
  if (pdev->tclasslist[pdev->classId].ClassType == CLASS_TYPE_CHID)
  {
    usbd_hid_fido_init(&s_fido_state);
  }

  return (uint8_t)USBD_OK;
}

/**
  * @brief  USBD_HID_DeInit
  *         DeInitialize the HID layer
  * @param  pdev: device instance
  * @param  cfgidx: Configuration index
  * @retval status
  */
static uint8_t USBD_HID_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  UNUSED(cfgidx);

#ifdef USE_USBD_COMPOSITE
  /* Get the Endpoints addresses allocated for this class instance */
  HIDInEpAdd  = USBD_HID_GetInEpAdd(pdev, (uint8_t)pdev->classId);
  HIDOutEpAdd = USBD_HID_GetOutEpAdd(pdev, (uint8_t)pdev->classId);
#endif /* USE_USBD_COMPOSITE */

  /* Close HID EPs */
  (void)USBD_LL_CloseEP(pdev, HIDInEpAdd);
  (void)USBD_LL_CloseEP(pdev, HIDOutEpAdd);
  pdev->ep_in[HIDInEpAdd & 0xFU].is_used = 0U;
  pdev->ep_out[HIDOutEpAdd & 0xFU].is_used = 0U;
  pdev->ep_in[HIDInEpAdd & 0xFU].bInterval = 0U;

  /* Free allocated memory */
  if (pdev->pClassDataCmsit[pdev->classId] != NULL)
  {
    (void)USBD_free(pdev->pClassDataCmsit[pdev->classId]);
    pdev->pClassDataCmsit[pdev->classId] = NULL;
  }

  return (uint8_t)USBD_OK;
}

/**
  * @brief  USBD_HID_Setup
  *         Handle the HID specific requests
  * @param  pdev: instance
  * @param  req: usb requests
  * @retval status
  */
static uint8_t USBD_HID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req)
{
  USBD_HID_HandleTypeDef *hhid = (USBD_HID_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  USBD_StatusTypeDef ret = USBD_OK;
  uint16_t len;
  uint8_t *pbuf;
  uint16_t status_info = 0U;

  if (hhid == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

  g_a_usb_diag_runtime.hid_setup_count++;
  g_a_usb_diag_runtime.hid_last_class = pdev->classId;
  g_a_usb_diag_runtime.hid_last_bmRequest = req->bmRequest;
  g_a_usb_diag_runtime.hid_last_bRequest = req->bRequest;
  g_a_usb_diag_runtime.hid_last_wValue = req->wValue;
  g_a_usb_diag_runtime.hid_last_wIndex = req->wIndex;
  g_a_usb_diag_runtime.hid_last_wLength = req->wLength;
  g_a_usb_diag_runtime.hid_last_report_len = 0U;

  switch (req->bmRequest & USB_REQ_TYPE_MASK)
  {
    case USB_REQ_TYPE_CLASS :
      switch (req->bRequest)
      {
        case USBD_HID_REQ_SET_PROTOCOL:
          hhid->Protocol = (uint8_t)(req->wValue);
          break;

        case USBD_HID_REQ_GET_PROTOCOL:
          (void)USBD_CtlSendData(pdev, (uint8_t *)&hhid->Protocol, 1U);
          break;

        case USBD_HID_REQ_SET_IDLE:
          hhid->IdleState = (uint8_t)(req->wValue >> 8);
          break;

        case USBD_HID_REQ_GET_IDLE:
          (void)USBD_CtlSendData(pdev, (uint8_t *)&hhid->IdleState, 1U);
          break;

        case USBD_HID_REQ_GET_REPORT:
        {
          len = MIN(req->wLength, (uint16_t)HID_CTRL_REPORT_SIZE);
          hhid->ctrl_report_len = len;
          hhid->ctrl_report_type = (uint8_t)(req->wValue >> 8);
          hhid->ctrl_report_id = (uint8_t)(req->wValue & 0xFFU);
          USBD_memset(hhid->ctrl_report, 0, sizeof(hhid->ctrl_report));
          if ((hhid->ctrl_report_id != 0U) && (len != 0U))
          {
            hhid->ctrl_report[0] = hhid->ctrl_report_id;
          }
          (void)USBD_CtlSendData(pdev, hhid->ctrl_report, len);
          break;
        }

        case USBD_HID_REQ_SET_REPORT:
          len = MIN(req->wLength, (uint16_t)HID_CTRL_REPORT_SIZE);
          hhid->ctrl_report_len = len;
          hhid->ctrl_report_type = (uint8_t)(req->wValue >> 8);
          hhid->ctrl_report_id = (uint8_t)(req->wValue & 0xFFU);
          if (len != 0U)
          {
            (void)USBD_CtlPrepareRx(pdev, hhid->ctrl_report, len);
          }
          break;

        default:
          USBD_CtlError(pdev, req);
          ret = USBD_FAIL;
          break;
      }
      break;
    case USB_REQ_TYPE_STANDARD:
      switch (req->bRequest)
      {
        case USB_REQ_GET_STATUS:
          if (pdev->dev_state == USBD_STATE_CONFIGURED)
          {
            (void)USBD_CtlSendData(pdev, (uint8_t *)&status_info, 2U);
          }
          else
          {
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
          }
          break;

        case USB_REQ_GET_DESCRIPTOR:
          if ((req->wValue >> 8) == HID_REPORT_DESC)
          {
            len = MIN(USBD_HID_GetReportDescForClass(pdev, (uint8_t)pdev->classId, &pbuf), req->wLength);
            g_a_usb_diag_runtime.hid_last_report_len = len;
          }
          else if ((req->wValue >> 8) == HID_DESCRIPTOR_TYPE)
          {
            pbuf = USBD_HID_GetDescForClass(pdev, (uint8_t)pdev->classId);
            len = MIN(USB_HID_DESC_SIZ, req->wLength);
            g_a_usb_diag_runtime.hid_last_report_len = len;
          }
          else
          {
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
            break;
          }
          (void)USBD_CtlSendData(pdev, pbuf, len);
          break;

        case USB_REQ_GET_INTERFACE :
          if (pdev->dev_state == USBD_STATE_CONFIGURED)
          {
            (void)USBD_CtlSendData(pdev, (uint8_t *)&hhid->AltSetting, 1U);
          }
          else
          {
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
          }
          break;

        case USB_REQ_SET_INTERFACE:
          if (pdev->dev_state == USBD_STATE_CONFIGURED)
          {
            hhid->AltSetting = (uint8_t)(req->wValue);
          }
          else
          {
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
          }
          break;

        case USB_REQ_CLEAR_FEATURE:
          break;

        default:
          USBD_CtlError(pdev, req);
          ret = USBD_FAIL;
          break;
      }
      break;

    default:
      USBD_CtlError(pdev, req);
      ret = USBD_FAIL;
      break;
  }

  return (uint8_t)ret;
}

static uint8_t USBD_HID_EP0_RxReady(USBD_HandleTypeDef *pdev)
{
  USBD_HID_HandleTypeDef *hhid = (USBD_HID_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  uint16_t report_len;
  const uint8_t *report;
  uint16_t tx_len;
  uint8_t in_ep_add;

  if (hhid == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

  report = hhid->ctrl_report;
  report_len = hhid->ctrl_report_len;

  if ((hhid->ctrl_report_id != 0U) &&
      (report_len > 1U) &&
      (report[0] == hhid->ctrl_report_id))
  {
    report = &report[1];
    report_len--;
  }

  tx_len = USBD_HID_ProcessOutputReport(pdev,
                                        (uint8_t)pdev->classId,
                                        hhid,
                                        report,
                                        report_len);
  if (tx_len != 0U)
  {
    in_ep_add = USBD_HID_GetInEpAdd(pdev, (uint8_t)pdev->classId);
    hhid->tx_len = tx_len;
    if (hhid->state == USBD_HID_IDLE)
    {
      hhid->state = USBD_HID_BUSY;
      (void)USBD_LL_Transmit(pdev, in_ep_add, hhid->tx_report, tx_len);
    }
    else
    {
      hhid->pending_tx = 1U;
      hhid->pending_tx_len = tx_len;
    }
  }

  hhid->ctrl_report_len = 0U;
  hhid->ctrl_report_id = 0U;
  hhid->ctrl_report_type = 0U;

  return (uint8_t)USBD_OK;
}


/**
  * @brief  USBD_HID_SendReport
  *         Send HID Report
  * @param  pdev: device instance
  * @param  buff: pointer to report
  * @param  ClassId: The Class ID
  * @retval status
  */
#ifdef USE_USBD_COMPOSITE
uint8_t USBD_HID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len, uint8_t ClassId)
{
  USBD_HID_HandleTypeDef *hhid = (USBD_HID_HandleTypeDef *)pdev->pClassDataCmsit[ClassId];
#else
uint8_t USBD_HID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len)
{
  USBD_HID_HandleTypeDef *hhid = (USBD_HID_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
#endif /* USE_USBD_COMPOSITE */

  if (hhid == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

#ifdef USE_USBD_COMPOSITE
  /* Get the Endpoints addresses allocated for this class instance */
  HIDInEpAdd = USBD_CoreGetEPAdd(pdev, USBD_EP_IN, USBD_EP_TYPE_INTR, ClassId);
#endif /* USE_USBD_COMPOSITE */

  if (pdev->dev_state == USBD_STATE_CONFIGURED)
  {
    if (hhid->state == USBD_HID_IDLE)
    {
      hhid->state = USBD_HID_BUSY;
      (void)USBD_LL_Transmit(pdev, HIDInEpAdd, report, len);
    }
  }

  return (uint8_t)USBD_OK;
}

/**
  * @brief  USBD_HID_GetPollingInterval
  *         return polling interval from endpoint descriptor
  * @param  pdev: device instance
  * @retval polling interval
  */
uint32_t USBD_HID_GetPollingInterval(USBD_HandleTypeDef *pdev)
{
  uint32_t polling_interval;

  /* HIGH-speed endpoints */
  if (pdev->dev_speed == USBD_SPEED_HIGH)
  {
    /* Sets the data transfer polling interval for high speed transfers.
     Values between 1..16 are allowed. Values correspond to interval
     of 2 ^ (bInterval-1). This option (8 ms, corresponds to HID_HS_BINTERVAL */
    polling_interval = (((1U << (HID_HS_BINTERVAL - 1U))) / 8U);
  }
  else   /* LOW and FULL-speed endpoints */
  {
    /* Sets the data transfer polling interval for low and full
    speed transfers */
    polling_interval =  HID_FS_BINTERVAL;
  }

  return ((uint32_t)(polling_interval));
}

#ifndef USE_USBD_COMPOSITE
/**
  * @brief  USBD_HID_GetCfgFSDesc
  *         return FS configuration descriptor
  * @param  speed : current device speed
  * @param  length : pointer data length
  * @retval pointer to descriptor buffer
  */
static uint8_t *USBD_HID_GetFSCfgDesc(uint16_t *length)
{
  USBD_EpDescTypeDef *pEpDesc = USBD_GetEpDesc(USBD_HID_CfgDesc, HID_EPIN_ADDR);

  if (pEpDesc != NULL)
  {
    pEpDesc->bInterval = HID_FS_BINTERVAL;
  }

  *length = (uint16_t)sizeof(USBD_HID_CfgDesc);
  return USBD_HID_CfgDesc;
}

/**
  * @brief  USBD_HID_GetCfgHSDesc
  *         return HS configuration descriptor
  * @param  speed : current device speed
  * @param  length : pointer data length
  * @retval pointer to descriptor buffer
  */
static uint8_t *USBD_HID_GetHSCfgDesc(uint16_t *length)
{
  USBD_EpDescTypeDef *pEpDesc = USBD_GetEpDesc(USBD_HID_CfgDesc, HID_EPIN_ADDR);

  if (pEpDesc != NULL)
  {
    pEpDesc->bInterval = HID_HS_BINTERVAL;
  }

  *length = (uint16_t)sizeof(USBD_HID_CfgDesc);
  return USBD_HID_CfgDesc;
}

/**
  * @brief  USBD_HID_GetOtherSpeedCfgDesc
  *         return other speed configuration descriptor
  * @param  speed : current device speed
  * @param  length : pointer data length
  * @retval pointer to descriptor buffer
  */
static uint8_t *USBD_HID_GetOtherSpeedCfgDesc(uint16_t *length)
{
  USBD_EpDescTypeDef *pEpDesc = USBD_GetEpDesc(USBD_HID_CfgDesc, HID_EPIN_ADDR);

  if (pEpDesc != NULL)
  {
    pEpDesc->bInterval = HID_FS_BINTERVAL;
  }

  *length = (uint16_t)sizeof(USBD_HID_CfgDesc);
  return USBD_HID_CfgDesc;
}
#endif /* USE_USBD_COMPOSITE  */

/**
  * @brief  USBD_HID_DataIn
  *         handle data IN Stage
  * @param  pdev: device instance
  * @param  epnum: endpoint index
  * @retval status
  */
static uint8_t USBD_HID_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
  USBD_HID_HandleTypeDef *hhid;
  uint8_t in_ep_add;

  UNUSED(epnum);

  hhid = (USBD_HID_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  if (hhid == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

  hhid->state = USBD_HID_IDLE;

  if ((hhid->pending_tx != 0U) && (hhid->pending_tx_len != 0U))
  {
    in_ep_add = USBD_HID_GetInEpAdd(pdev, (uint8_t)pdev->classId);
    hhid->state = USBD_HID_BUSY;
    hhid->tx_len = hhid->pending_tx_len;
    hhid->pending_tx = 0U;
    hhid->pending_tx_len = 0U;
    (void)USBD_LL_Transmit(pdev, in_ep_add, hhid->tx_report, hhid->tx_len);
  }

  return (uint8_t)USBD_OK;
}

static uint8_t USBD_HID_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
  USBD_HID_HandleTypeDef *hhid;
  uint16_t rx_len;
  uint16_t tx_len;
  uint8_t out_ep_add;
  uint8_t in_ep_add;

  out_ep_add = USBD_HID_GetOutEpAdd(pdev, (uint8_t)pdev->classId);
  in_ep_add = USBD_HID_GetInEpAdd(pdev, (uint8_t)pdev->classId);

  if ((epnum & 0x7FU) != (out_ep_add & 0x7FU))
  {
    return (uint8_t)USBD_OK;
  }

  hhid = (USBD_HID_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  if (hhid == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

  rx_len = (uint16_t)USBD_LL_GetRxDataSize(pdev, epnum);
  hhid->rx_len = rx_len;
  tx_len = USBD_HID_ProcessOutputReport(pdev,
                                        (uint8_t)pdev->classId,
                                        hhid,
                                        hhid->rx_report,
                                        rx_len);
  if (tx_len != 0U)
  {
    hhid->tx_len = tx_len;
    if (hhid->state == USBD_HID_IDLE)
    {
      hhid->state = USBD_HID_BUSY;
      (void)USBD_LL_Transmit(pdev, in_ep_add, hhid->tx_report, tx_len);
    }
    else
    {
      hhid->pending_tx = 1U;
      hhid->pending_tx_len = tx_len;
    }
  }

  (void)USBD_LL_PrepareReceive(pdev, out_ep_add, hhid->rx_report, HID_EPOUT_SIZE);

  return (uint8_t)USBD_OK;
}

#ifndef USE_USBD_COMPOSITE
/**
  * @brief  DeviceQualifierDescriptor
  *         return Device Qualifier descriptor
  * @param  length : pointer data length
  * @retval pointer to descriptor buffer
  */
static uint8_t *USBD_HID_GetDeviceQualifierDesc(uint16_t *length)
{
  *length = (uint16_t)sizeof(USBD_HID_DeviceQualifierDesc);

  return USBD_HID_DeviceQualifierDesc;
}
#endif /* USE_USBD_COMPOSITE  */
/**
  * @}
  */


/**
  * @}
  */


/**
  * @}
  */
