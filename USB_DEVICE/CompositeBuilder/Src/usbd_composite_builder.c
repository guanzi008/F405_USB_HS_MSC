/**
  ******************************************************************************
  * @file    usbd_composite_builder.c
  * @brief   Minimal composite builder for HID + MSC
  ******************************************************************************
  */

#include "usbd_composite_builder.h"
#include "usbd_hid_fido.h"
#include "usbd_hid_km.h"

#ifdef USE_USBD_COMPOSITE

static uint8_t *USBD_CMPSIT_GetFSCfgDesc(uint16_t *length);
#ifdef USE_USB_HS
static uint8_t *USBD_CMPSIT_GetHSCfgDesc(uint16_t *length);
#endif
static uint8_t *USBD_CMPSIT_GetOtherSpeedCfgDesc(uint16_t *length);
static uint8_t *USBD_CMPSIT_GetDeviceQualifierDescriptor(uint16_t *length);

static uint8_t USBD_CMPSIT_FindFreeIFNbr(USBD_HandleTypeDef *pdev);
static void USBD_CMPSIT_AddConfDesc(uint32_t conf, __IO uint32_t *size);
static void USBD_CMPSIT_AssignEp(USBD_HandleTypeDef *pdev, uint8_t add, uint8_t type, uint32_t size);
static void USBD_CMPSIT_HIDDesc(USBD_HandleTypeDef *pdev,
                                uint32_t pConf,
                                __IO uint32_t *Sze,
                                uint8_t speed,
                                USBD_CompositeClassTypeDef class_type);
static void USBD_CMPSIT_HIDKmDesc(USBD_HandleTypeDef *pdev,
                                  uint32_t pConf,
                                  __IO uint32_t *Sze,
                                  uint8_t speed);
static void USBD_CMPSIT_MSCDesc(USBD_HandleTypeDef *pdev, uint32_t pConf, __IO uint32_t *Sze, uint8_t speed);

USBD_ClassTypeDef USBD_CMPSIT =
{
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#ifdef USE_USB_HS
  USBD_CMPSIT_GetHSCfgDesc,
#else
  NULL,
#endif
  USBD_CMPSIT_GetFSCfgDesc,
  USBD_CMPSIT_GetOtherSpeedCfgDesc,
  USBD_CMPSIT_GetDeviceQualifierDescriptor,
#if (USBD_SUPPORT_USER_STRING_DESC == 1U)
  NULL,
#endif
};

__ALIGN_BEGIN static uint8_t USBD_CMPSIT_FSCfgDesc[USBD_CMPST_MAX_CONFDESC_SZ] __ALIGN_END;
static __IO uint32_t CurrFSConfDescSz = 0U;
#ifdef USE_USB_HS
__ALIGN_BEGIN static uint8_t USBD_CMPSIT_HSCfgDesc[USBD_CMPST_MAX_CONFDESC_SZ] __ALIGN_END;
static __IO uint32_t CurrHSConfDescSz = 0U;
#endif

__ALIGN_BEGIN static uint8_t USBD_CMPSIT_DeviceQualifierDesc[USB_LEN_DEV_QUALIFIER_DESC] __ALIGN_END =
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

uint8_t USBD_CMPSIT_AddClass(USBD_HandleTypeDef *pdev,
                             USBD_ClassTypeDef *pclass,
                             USBD_CompositeClassTypeDef class_type,
                             uint8_t cfgidx)
{
  UNUSED(cfgidx);

  if ((pdev->classId < USBD_MAX_SUPPORTED_CLASS) &&
      (pdev->tclasslist[pdev->classId].Active == 0U))
  {
    pdev->pClass[pdev->classId] = pclass;
    pdev->tclasslist[pdev->classId].ClassId = pdev->classId;
    pdev->tclasslist[pdev->classId].Active = 1U;
    pdev->tclasslist[pdev->classId].ClassType = class_type;

    if (USBD_CMPSIT_AddToConfDesc(pdev) != (uint8_t)USBD_OK)
    {
      return (uint8_t)USBD_FAIL;
    }
  }

  return (uint8_t)USBD_OK;
}

uint8_t USBD_CMPSIT_AddToConfDesc(USBD_HandleTypeDef *pdev)
{
  uint8_t idxIf;
  uint8_t iEp;

  if (pdev->classId == 0U)
  {
    (void)USBD_CMPST_ClearConfDesc(pdev);
    USBD_CMPSIT_AddConfDesc((uint32_t)USBD_CMPSIT_FSCfgDesc, &CurrFSConfDescSz);
#ifdef USE_USB_HS
    USBD_CMPSIT_AddConfDesc((uint32_t)USBD_CMPSIT_HSCfgDesc, &CurrHSConfDescSz);
#endif
  }

  switch (pdev->tclasslist[pdev->classId].ClassType)
  {
    case CLASS_TYPE_HID:
      pdev->tclasslist[pdev->classId].CurrPcktSze = HID_EPIN_SIZE;
      idxIf = USBD_CMPSIT_FindFreeIFNbr(pdev);
      pdev->tclasslist[pdev->classId].NumIf = 1U;
      pdev->tclasslist[pdev->classId].Ifs[0] = idxIf;
      pdev->tclasslist[pdev->classId].NumEps = 2U;
      iEp = pdev->tclasslist[pdev->classId].EpAdd[0];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_INTR, HID_EPIN_SIZE);
      iEp = pdev->tclasslist[pdev->classId].EpAdd[1];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_INTR, HID_EPOUT_SIZE);
      USBD_CMPSIT_HIDDesc(pdev,
                          (uint32_t)USBD_CMPSIT_FSCfgDesc,
                          &CurrFSConfDescSz,
                          (uint8_t)USBD_SPEED_FULL,
                          pdev->tclasslist[pdev->classId].ClassType);
#ifdef USE_USB_HS
      USBD_CMPSIT_HIDDesc(pdev,
                          (uint32_t)USBD_CMPSIT_HSCfgDesc,
                          &CurrHSConfDescSz,
                          (uint8_t)USBD_SPEED_HIGH,
                          pdev->tclasslist[pdev->classId].ClassType);
#endif
      break;

    case CLASS_TYPE_HID_KM:
      pdev->tclasslist[pdev->classId].CurrPcktSze = HID_KM_KEYBOARD_PACKET_SIZE;
      idxIf = USBD_CMPSIT_FindFreeIFNbr(pdev);
      pdev->tclasslist[pdev->classId].NumIf = 2U;
      pdev->tclasslist[pdev->classId].Ifs[0] = idxIf;
      pdev->tclasslist[pdev->classId].Ifs[1] = (uint8_t)(idxIf + 1U);
      pdev->tclasslist[pdev->classId].NumEps = 2U;
      iEp = pdev->tclasslist[pdev->classId].EpAdd[0];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_INTR, HID_KM_KEYBOARD_PACKET_SIZE);
      iEp = pdev->tclasslist[pdev->classId].EpAdd[1];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_INTR, HID_KM_MOUSE_PACKET_SIZE);
      USBD_CMPSIT_HIDKmDesc(pdev,
                            (uint32_t)USBD_CMPSIT_FSCfgDesc,
                            &CurrFSConfDescSz,
                            (uint8_t)USBD_SPEED_FULL);
#ifdef USE_USB_HS
      USBD_CMPSIT_HIDKmDesc(pdev,
                            (uint32_t)USBD_CMPSIT_HSCfgDesc,
                            &CurrHSConfDescSz,
                            (uint8_t)USBD_SPEED_HIGH);
#endif
      break;

    case CLASS_TYPE_CHID:
      pdev->tclasslist[pdev->classId].CurrPcktSze = FIDO_HID_PACKET_SIZE;
      idxIf = USBD_CMPSIT_FindFreeIFNbr(pdev);
      pdev->tclasslist[pdev->classId].NumIf = 1U;
      pdev->tclasslist[pdev->classId].Ifs[0] = idxIf;
      pdev->tclasslist[pdev->classId].NumEps = 2U;
      iEp = pdev->tclasslist[pdev->classId].EpAdd[0];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_INTR, FIDO_HID_PACKET_SIZE);
      iEp = pdev->tclasslist[pdev->classId].EpAdd[1];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_INTR, FIDO_HID_PACKET_SIZE);
      USBD_CMPSIT_HIDDesc(pdev,
                          (uint32_t)USBD_CMPSIT_FSCfgDesc,
                          &CurrFSConfDescSz,
                          (uint8_t)USBD_SPEED_FULL,
                          CLASS_TYPE_CHID);
#ifdef USE_USB_HS
      USBD_CMPSIT_HIDDesc(pdev,
                          (uint32_t)USBD_CMPSIT_HSCfgDesc,
                          &CurrHSConfDescSz,
                          (uint8_t)USBD_SPEED_HIGH,
                          CLASS_TYPE_CHID);
#endif
      break;

    case CLASS_TYPE_MSC:
      pdev->tclasslist[pdev->classId].CurrPcktSze = MSC_MAX_FS_PACKET;
      idxIf = USBD_CMPSIT_FindFreeIFNbr(pdev);
      pdev->tclasslist[pdev->classId].NumIf = 1U;
      pdev->tclasslist[pdev->classId].Ifs[0] = idxIf;
      pdev->tclasslist[pdev->classId].NumEps = 2U;
      iEp = pdev->tclasslist[pdev->classId].EpAdd[0];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_BULK, MSC_MAX_FS_PACKET);
      iEp = pdev->tclasslist[pdev->classId].EpAdd[1];
      USBD_CMPSIT_AssignEp(pdev, iEp, USBD_EP_TYPE_BULK, MSC_MAX_FS_PACKET);
      USBD_CMPSIT_MSCDesc(pdev, (uint32_t)USBD_CMPSIT_FSCfgDesc, &CurrFSConfDescSz, (uint8_t)USBD_SPEED_FULL);
#ifdef USE_USB_HS
      USBD_CMPSIT_MSCDesc(pdev, (uint32_t)USBD_CMPSIT_HSCfgDesc, &CurrHSConfDescSz, (uint8_t)USBD_SPEED_HIGH);
#endif
      break;

    default:
      return (uint8_t)USBD_FAIL;
  }

  return (uint8_t)USBD_OK;
}

uint32_t USBD_CMPSIT_SetClassID(USBD_HandleTypeDef *pdev,
                                USBD_CompositeClassTypeDef class_type,
                                uint32_t instance)
{
  uint32_t idx;
  uint32_t inst = 0U;

  for (idx = 0U; idx < pdev->NumClasses; idx++)
  {
    if ((pdev->tclasslist[idx].ClassType == class_type) &&
        (pdev->tclasslist[idx].Active == 1U))
    {
      if (inst == instance)
      {
        pdev->classId = idx;
        return idx;
      }
      inst++;
    }
  }

  return 0xFFU;
}

uint32_t USBD_CMPSIT_GetClassID(USBD_HandleTypeDef *pdev,
                                USBD_CompositeClassTypeDef class_type,
                                uint32_t instance)
{
  uint32_t idx;
  uint32_t inst = 0U;

  for (idx = 0U; idx < pdev->NumClasses; idx++)
  {
    if ((pdev->tclasslist[idx].ClassType == class_type) &&
        (pdev->tclasslist[idx].Active == 1U))
    {
      if (inst == instance)
      {
        return idx;
      }
      inst++;
    }
  }

  return 0xFFU;
}

uint8_t USBD_CMPST_ClearConfDesc(USBD_HandleTypeDef *pdev)
{
  uint32_t idx;

  (void)pdev;
  CurrFSConfDescSz = 0U;
  USBD_memset(USBD_CMPSIT_FSCfgDesc, 0, sizeof(USBD_CMPSIT_FSCfgDesc));
#ifdef USE_USB_HS
  CurrHSConfDescSz = 0U;
  USBD_memset(USBD_CMPSIT_HSCfgDesc, 0, sizeof(USBD_CMPSIT_HSCfgDesc));
#endif

  for (idx = 0U; idx < USBD_MAX_SUPPORTED_CLASS; idx++)
  {
    uint32_t ep_idx;
    pdev->tclasslist[idx].NumEps = 0U;
    pdev->tclasslist[idx].NumIf = 0U;
    pdev->tclasslist[idx].CurrPcktSze = 0U;
    for (ep_idx = 0U; ep_idx < USBD_MAX_CLASS_ENDPOINTS; ep_idx++)
    {
      pdev->tclasslist[idx].Eps[ep_idx].add = 0U;
      pdev->tclasslist[idx].Eps[ep_idx].type = 0U;
      pdev->tclasslist[idx].Eps[ep_idx].size = 0U;
      pdev->tclasslist[idx].Eps[ep_idx].is_used = 0U;
    }
  }

  return (uint8_t)USBD_OK;
}

static uint8_t *USBD_CMPSIT_GetFSCfgDesc(uint16_t *length)
{
  *length = (uint16_t)CurrFSConfDescSz;
  return USBD_CMPSIT_FSCfgDesc;
}

#ifdef USE_USB_HS
static uint8_t *USBD_CMPSIT_GetHSCfgDesc(uint16_t *length)
{
  *length = (uint16_t)CurrHSConfDescSz;
  return USBD_CMPSIT_HSCfgDesc;
}
#endif

static uint8_t *USBD_CMPSIT_GetOtherSpeedCfgDesc(uint16_t *length)
{
  *length = (uint16_t)CurrFSConfDescSz;
  return USBD_CMPSIT_FSCfgDesc;
}

static uint8_t *USBD_CMPSIT_GetDeviceQualifierDescriptor(uint16_t *length)
{
  *length = (uint16_t)sizeof(USBD_CMPSIT_DeviceQualifierDesc);
  return USBD_CMPSIT_DeviceQualifierDesc;
}

static uint8_t USBD_CMPSIT_FindFreeIFNbr(USBD_HandleTypeDef *pdev)
{
  uint32_t idx = 0U;
  uint32_t i;
  uint32_t j;

  for (i = 0U; i < pdev->NumClasses; i++)
  {
    for (j = 0U; j < pdev->tclasslist[i].NumIf; j++)
    {
      idx++;
    }
  }

  return (uint8_t)idx;
}

static void USBD_CMPSIT_AddConfDesc(uint32_t conf, __IO uint32_t *size)
{
  USBD_ConfigDescTypeDef *ptr = (USBD_ConfigDescTypeDef *)conf;

  ptr->bLength = (uint8_t)sizeof(USBD_ConfigDescTypeDef);
  ptr->bDescriptorType = USB_DESC_TYPE_CONFIGURATION;
  ptr->wTotalLength = 0U;
  ptr->bNumInterfaces = 0U;
  ptr->bConfigurationValue = 1U;
  ptr->iConfiguration = USBD_IDX_CONFIG_STR;
#if (USBD_SELF_POWERED == 1U)
  ptr->bmAttributes = 0xC0U;
#else
  ptr->bmAttributes = 0x80U;
#endif
  ptr->bMaxPower = USBD_MAX_POWER;
  *size += sizeof(USBD_ConfigDescTypeDef);
}

static void USBD_CMPSIT_AssignEp(USBD_HandleTypeDef *pdev, uint8_t add, uint8_t type, uint32_t size)
{
  uint32_t idx = 0U;

  while ((idx < pdev->tclasslist[pdev->classId].NumEps) &&
         (pdev->tclasslist[pdev->classId].Eps[idx].is_used != 0U))
  {
    idx++;
  }

  pdev->tclasslist[pdev->classId].Eps[idx].add = add;
  pdev->tclasslist[pdev->classId].Eps[idx].type = type;
  pdev->tclasslist[pdev->classId].Eps[idx].size = (uint8_t)size;
  pdev->tclasslist[pdev->classId].Eps[idx].is_used = 1U;
}

static void USBD_CMPSIT_HIDDesc(USBD_HandleTypeDef *pdev,
                                uint32_t pConf,
                                __IO uint32_t *Sze,
                                uint8_t speed,
                                USBD_CompositeClassTypeDef class_type)
{
  USBD_IfDescTypeDef *pIfDesc;
  USBD_EpDescTypeDef *pEpDesc;
  USBD_HIDDescTypeDef *pHidDesc;
  uint16_t report_length = HID_REPORT_DESC_SIZE;
  uint16_t packet_size = HID_EPIN_SIZE;

  if (class_type == CLASS_TYPE_CHID)
  {
    report_length = FIDO_HID_REPORT_DESC_SIZE;
    packet_size = FIDO_HID_PACKET_SIZE;
  }

  __USBD_CMPSIT_SET_IF(pdev->tclasslist[pdev->classId].Ifs[0], 0U,
                       (uint8_t)pdev->tclasslist[pdev->classId].NumEps,
                       0x03U, 0x00U, 0x00U, USBD_IDX_INTERFACE_STR);

  pHidDesc = (USBD_HIDDescTypeDef *)((uint32_t)pConf + *Sze);
  pHidDesc->bLength = (uint8_t)sizeof(USBD_HIDDescTypeDef);
  pHidDesc->bDescriptorType = HID_DESCRIPTOR_TYPE;
  pHidDesc->bcdHID = 0x0111U;
  pHidDesc->bCountryCode = 0x00U;
  pHidDesc->bNumDescriptors = 0x01U;
  pHidDesc->bHIDDescriptorType = 0x22U;
  pHidDesc->wItemLength = report_length;
  *Sze += (uint32_t)sizeof(USBD_HIDDescTypeDef);

  __USBD_CMPSIT_SET_EP(pdev->tclasslist[pdev->classId].Eps[0].add,
                       USBD_EP_TYPE_INTR,
                       packet_size,
                       HID_HS_BINTERVAL,
                       HID_FS_BINTERVAL);

  __USBD_CMPSIT_SET_EP(pdev->tclasslist[pdev->classId].Eps[1].add,
                       USBD_EP_TYPE_INTR,
                       packet_size,
                       HID_HS_BINTERVAL,
                       HID_FS_BINTERVAL);

  ((USBD_ConfigDescTypeDef *)pConf)->bNumInterfaces += 1U;
  ((USBD_ConfigDescTypeDef *)pConf)->wTotalLength = (uint16_t)(*Sze);
}

static void USBD_CMPSIT_HIDKmDesc(USBD_HandleTypeDef *pdev,
                                  uint32_t pConf,
                                  __IO uint32_t *Sze,
                                  uint8_t speed)
{
  USBD_IfDescTypeDef *pIfDesc;
  USBD_EpDescTypeDef *pEpDesc;
  USBD_HIDDescTypeDef *pHidDesc;
  const uint8_t *report_desc;
  uint16_t report_length;

  report_length = usbd_hid_km_get_keyboard_report_desc(&report_desc);
  UNUSED(report_desc);
  __USBD_CMPSIT_SET_IF(pdev->tclasslist[pdev->classId].Ifs[0], 0U,
                       1U, 0x03U, 0x00U, 0x00U, USBD_IDX_INTERFACE_STR);
  pHidDesc = (USBD_HIDDescTypeDef *)((uint32_t)pConf + *Sze);
  pHidDesc->bLength = (uint8_t)sizeof(USBD_HIDDescTypeDef);
  pHidDesc->bDescriptorType = HID_DESCRIPTOR_TYPE;
  pHidDesc->bcdHID = 0x0111U;
  pHidDesc->bCountryCode = 0x00U;
  pHidDesc->bNumDescriptors = 0x01U;
  pHidDesc->bHIDDescriptorType = HID_REPORT_DESC;
  pHidDesc->wItemLength = report_length;
  *Sze += (uint32_t)sizeof(USBD_HIDDescTypeDef);
  __USBD_CMPSIT_SET_EP(pdev->tclasslist[pdev->classId].Eps[0].add,
                       USBD_EP_TYPE_INTR,
                       HID_KM_KEYBOARD_PACKET_SIZE,
                       HID_HS_BINTERVAL,
                       HID_FS_BINTERVAL);

  report_length = usbd_hid_km_get_mouse_report_desc(&report_desc);
  UNUSED(report_desc);
  __USBD_CMPSIT_SET_IF(pdev->tclasslist[pdev->classId].Ifs[1], 0U,
                       1U, 0x03U, 0x00U, 0x00U, USBD_IDX_INTERFACE_STR);
  pHidDesc = (USBD_HIDDescTypeDef *)((uint32_t)pConf + *Sze);
  pHidDesc->bLength = (uint8_t)sizeof(USBD_HIDDescTypeDef);
  pHidDesc->bDescriptorType = HID_DESCRIPTOR_TYPE;
  pHidDesc->bcdHID = 0x0111U;
  pHidDesc->bCountryCode = 0x00U;
  pHidDesc->bNumDescriptors = 0x01U;
  pHidDesc->bHIDDescriptorType = HID_REPORT_DESC;
  pHidDesc->wItemLength = report_length;
  *Sze += (uint32_t)sizeof(USBD_HIDDescTypeDef);
  __USBD_CMPSIT_SET_EP(pdev->tclasslist[pdev->classId].Eps[1].add,
                       USBD_EP_TYPE_INTR,
                       HID_KM_MOUSE_PACKET_SIZE,
                       HID_HS_BINTERVAL,
                       HID_FS_BINTERVAL);

  ((USBD_ConfigDescTypeDef *)pConf)->bNumInterfaces += 2U;
  ((USBD_ConfigDescTypeDef *)pConf)->wTotalLength = (uint16_t)(*Sze);
}

static void USBD_CMPSIT_MSCDesc(USBD_HandleTypeDef *pdev, uint32_t pConf, __IO uint32_t *Sze, uint8_t speed)
{
  USBD_IfDescTypeDef *pIfDesc;
  USBD_EpDescTypeDef *pEpDesc;
  uint16_t packet = MSC_MAX_FS_PACKET;

  __USBD_CMPSIT_SET_IF(pdev->tclasslist[pdev->classId].Ifs[0], 0U,
                       (uint8_t)pdev->tclasslist[pdev->classId].NumEps,
                       0x08U, 0x06U, 0x50U, 0U);

  if (speed == (uint8_t)USBD_SPEED_HIGH)
  {
    packet = MSC_MAX_HS_PACKET;
  }

  __USBD_CMPSIT_SET_EP(pdev->tclasslist[pdev->classId].Eps[0].add,
                       USBD_EP_TYPE_BULK,
                       packet,
                       0U,
                       0U);

  __USBD_CMPSIT_SET_EP(pdev->tclasslist[pdev->classId].Eps[1].add,
                       USBD_EP_TYPE_BULK,
                       packet,
                       0U,
                       0U);

  ((USBD_ConfigDescTypeDef *)pConf)->bNumInterfaces += 1U;
  ((USBD_ConfigDescTypeDef *)pConf)->wTotalLength = (uint16_t)(*Sze);
}

#endif /* USE_USBD_COMPOSITE */
