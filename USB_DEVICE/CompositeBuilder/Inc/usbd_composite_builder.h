/**
  ******************************************************************************
  * @file    usbd_composite_builder.h
  * @brief   Minimal composite descriptor builder for HID + MSC on STM32 USB
  ******************************************************************************
  */

#ifndef __USBD_COMPOSITE_BUILDER_H__
#define __USBD_COMPOSITE_BUILDER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "usbd_ioreq.h"
#include "usbd_hid.h"
#include "usbd_msc.h"

#ifndef USBD_CMPST_MAX_CONFDESC_SZ
#define USBD_CMPST_MAX_CONFDESC_SZ 64U
#endif

typedef struct
{
  uint8_t bLength;
  uint8_t bDescriptorType;
  uint8_t bFirstInterface;
  uint8_t bInterfaceCount;
  uint8_t bFunctionClass;
  uint8_t bFunctionSubClass;
  uint8_t bFunctionProtocol;
  uint8_t iFunction;
} USBD_IadDescTypeDef;

typedef struct
{
  uint8_t bLength;
  uint8_t bDescriptorType;
  uint8_t bInterfaceNumber;
  uint8_t bAlternateSetting;
  uint8_t bNumEndpoints;
  uint8_t bInterfaceClass;
  uint8_t bInterfaceSubClass;
  uint8_t bInterfaceProtocol;
  uint8_t iInterface;
} USBD_IfDescTypeDef;

extern USBD_ClassTypeDef USBD_CMPSIT;

uint8_t USBD_CMPSIT_AddToConfDesc(USBD_HandleTypeDef *pdev);
uint8_t USBD_CMPSIT_AddClass(USBD_HandleTypeDef *pdev,
                             USBD_ClassTypeDef *pclass,
                             USBD_CompositeClassTypeDef class_type,
                             uint8_t cfgidx);
uint32_t USBD_CMPSIT_SetClassID(USBD_HandleTypeDef *pdev,
                                USBD_CompositeClassTypeDef class_type,
                                uint32_t instance);
uint32_t USBD_CMPSIT_GetClassID(USBD_HandleTypeDef *pdev,
                                USBD_CompositeClassTypeDef class_type,
                                uint32_t instance);
uint8_t USBD_CMPST_ClearConfDesc(USBD_HandleTypeDef *pdev);

#define __USBD_CMPSIT_SET_EP(epadd, eptype, epsize, hs_interval, fs_interval) \
  do { \
    pEpDesc = (USBD_EpDescTypeDef *)((uint32_t)pConf + *Sze); \
    pEpDesc->bLength = (uint8_t)sizeof(USBD_EpDescTypeDef); \
    pEpDesc->bDescriptorType = USB_DESC_TYPE_ENDPOINT; \
    pEpDesc->bEndpointAddress = (epadd); \
    pEpDesc->bmAttributes = (eptype); \
    pEpDesc->wMaxPacketSize = (uint16_t)(epsize); \
    pEpDesc->bInterval = ((speed) == (uint8_t)USBD_SPEED_HIGH) ? (hs_interval) : (fs_interval); \
    *Sze += (uint32_t)sizeof(USBD_EpDescTypeDef); \
  } while (0)

#define __USBD_CMPSIT_SET_IF(ifnum, alt, eps, cls, subcls, proto, istring) \
  do { \
    pIfDesc = (USBD_IfDescTypeDef *)((uint32_t)pConf + *Sze); \
    pIfDesc->bLength = (uint8_t)sizeof(USBD_IfDescTypeDef); \
    pIfDesc->bDescriptorType = USB_DESC_TYPE_INTERFACE; \
    pIfDesc->bInterfaceNumber = (ifnum); \
    pIfDesc->bAlternateSetting = (alt); \
    pIfDesc->bNumEndpoints = (eps); \
    pIfDesc->bInterfaceClass = (cls); \
    pIfDesc->bInterfaceSubClass = (subcls); \
    pIfDesc->bInterfaceProtocol = (proto); \
    pIfDesc->iInterface = (istring); \
    *Sze += (uint32_t)sizeof(USBD_IfDescTypeDef); \
  } while (0)

#ifdef __cplusplus
}
#endif

#endif /* __USBD_COMPOSITE_BUILDER_H__ */
