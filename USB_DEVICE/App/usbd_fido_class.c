#include "usbd_fido_class.h"

#include "usbd_ctlreq.h"
#include "usbd_conf.h"
#ifdef USE_USBD_COMPOSITE
#include "usbd_composite_builder.h"
#endif

static uint8_t USBD_FIDO_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_FIDO_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_FIDO_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
static uint8_t USBD_FIDO_EP0_RxReady(USBD_HandleTypeDef *pdev);
static uint8_t USBD_FIDO_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum);
static uint8_t USBD_FIDO_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum);

static uint8_t USBD_FIDO_GetInEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id);
static uint8_t USBD_FIDO_GetOutEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id);
static uint8_t *USBD_FIDO_GetDesc(uint16_t *report_len);
static uint16_t USBD_FIDO_Process(USBD_HandleTypeDef *pdev,
                                  uint8_t class_id,
                                  USBD_FIDO_HandleTypeDef *hfido,
                                  const uint8_t *report,
                                  uint16_t report_len);

USBD_ClassTypeDef USBD_FIDO_HID =
{
  USBD_FIDO_Init,
  USBD_FIDO_DeInit,
  USBD_FIDO_Setup,
  NULL,
  USBD_FIDO_EP0_RxReady,
  USBD_FIDO_DataIn,
  USBD_FIDO_DataOut,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
#if (USBD_SUPPORT_USER_STRING_DESC == 1U)
  NULL,
#endif
};

__ALIGN_BEGIN static uint8_t USBD_FIDO_Desc[USB_FIDO_HID_DESC_SIZ] __ALIGN_END =
{
  0x09,
  HID_DESCRIPTOR_TYPE,
  0x11,
  0x01,
  0x00,
  0x01,
  0x22,
  0x00,
  0x00,
};

static uint8_t USBD_FIDO_GetInEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id)
{
#ifdef USE_USBD_COMPOSITE
  return USBD_CoreGetEPAdd(pdev, USBD_EP_IN, USBD_EP_TYPE_INTR, class_id);
#else
  UNUSED(pdev);
  UNUSED(class_id);
  return FIDO_HID_EPIN_ADDR;
#endif
}

static uint8_t USBD_FIDO_GetOutEpAdd(USBD_HandleTypeDef *pdev, uint8_t class_id)
{
#ifdef USE_USBD_COMPOSITE
  return USBD_CoreGetEPAdd(pdev, USBD_EP_OUT, USBD_EP_TYPE_INTR, class_id);
#else
  UNUSED(pdev);
  UNUSED(class_id);
  return FIDO_HID_EPOUT_ADDR;
#endif
}

static uint8_t *USBD_FIDO_GetDesc(uint16_t *report_len)
{
  const uint8_t *report_desc;

  *report_len = usbd_hid_fido_get_report_desc(&report_desc);
  USBD_memcpy(USBD_FIDO_Desc, (uint8_t[]){0x09, HID_DESCRIPTOR_TYPE, 0x11, 0x01, 0x00, 0x01, 0x22, 0x00, 0x00},
              USB_FIDO_HID_DESC_SIZ);
  USBD_FIDO_Desc[7] = (uint8_t)(*report_len & 0xFFU);
  USBD_FIDO_Desc[8] = (uint8_t)(*report_len >> 8);
  return USBD_FIDO_Desc;
}

static uint16_t USBD_FIDO_Process(USBD_HandleTypeDef *pdev,
                                  uint8_t class_id,
                                  USBD_FIDO_HandleTypeDef *hfido,
                                  const uint8_t *report,
                                  uint16_t report_len)
{
  if ((hfido == NULL) || (report == NULL))
  {
    return 0U;
  }

  return usbd_hid_fido_process(pdev,
                               class_id,
                               &hfido->fido,
                               report,
                               report_len,
                               hfido->tx_report,
                               (uint16_t)sizeof(hfido->tx_report));
}

void USBD_FIDO_Service(USBD_HandleTypeDef *pdev, uint32_t now_ms)
{
  USBD_FIDO_HandleTypeDef *hfido;
  uint8_t class_id;
  uint8_t in_ep_add;
  uint16_t tx_len;

  if ((pdev == NULL) || (pdev->dev_state != USBD_STATE_CONFIGURED))
  {
    return;
  }

#ifdef USE_USBD_COMPOSITE
  class_id = (uint8_t)USBD_CMPSIT_GetClassID(pdev, CLASS_TYPE_CHID, 0U);
  if (class_id == 0xFFU)
  {
    return;
  }
#else
  class_id = (uint8_t)pdev->classId;
#endif

  hfido = (USBD_FIDO_HandleTypeDef *)pdev->pClassDataCmsit[class_id];
  if ((hfido == NULL) || (hfido->state != USBD_FIDO_IDLE))
  {
    return;
  }

  tx_len = usbd_hid_fido_service(pdev,
                                 class_id,
                                 &hfido->fido,
                                 hfido->tx_report,
                                 (uint16_t)sizeof(hfido->tx_report),
                                 now_ms);
  if (tx_len == 0U)
  {
    return;
  }

  hfido->tx_len = tx_len;
  hfido->state = USBD_FIDO_BUSY;
  in_ep_add = USBD_FIDO_GetInEpAdd(pdev, class_id);
  (void)USBD_LL_Transmit(pdev, in_ep_add, hfido->tx_report, tx_len);
}

static uint8_t USBD_FIDO_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  USBD_FIDO_HandleTypeDef *hfido;
  uint8_t in_ep_add;
  uint8_t out_ep_add;

  UNUSED(cfgidx);

  hfido = (USBD_FIDO_HandleTypeDef *)USBD_malloc(sizeof(USBD_FIDO_HandleTypeDef));
  if (hfido == NULL)
  {
    pdev->pClassDataCmsit[pdev->classId] = NULL;
    return (uint8_t)USBD_EMEM;
  }

  USBD_memset(hfido, 0, sizeof(*hfido));
  pdev->pClassDataCmsit[pdev->classId] = (void *)hfido;
  pdev->pClassData = pdev->pClassDataCmsit[pdev->classId];

  in_ep_add = USBD_FIDO_GetInEpAdd(pdev, (uint8_t)pdev->classId);
  out_ep_add = USBD_FIDO_GetOutEpAdd(pdev, (uint8_t)pdev->classId);

  if (pdev->dev_speed == USBD_SPEED_HIGH)
  {
    pdev->ep_in[in_ep_add & 0xFU].bInterval = HID_HS_BINTERVAL;
  }
  else
  {
    pdev->ep_in[in_ep_add & 0xFU].bInterval = HID_FS_BINTERVAL;
  }

  (void)USBD_LL_OpenEP(pdev, in_ep_add, USBD_EP_TYPE_INTR, FIDO_HID_PACKET_SIZE);
  pdev->ep_in[in_ep_add & 0xFU].is_used = 1U;

  (void)USBD_LL_OpenEP(pdev, out_ep_add, USBD_EP_TYPE_INTR, FIDO_HID_PACKET_SIZE);
  pdev->ep_out[out_ep_add & 0xFU].is_used = 1U;

  (void)USBD_LL_PrepareReceive(pdev, out_ep_add, hfido->rx_report, FIDO_HID_PACKET_SIZE);

  hfido->state = USBD_FIDO_IDLE;
  usbd_hid_fido_init(&hfido->fido);

  return (uint8_t)USBD_OK;
}

static uint8_t USBD_FIDO_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  uint8_t in_ep_add;
  uint8_t out_ep_add;

  UNUSED(cfgidx);

  in_ep_add = USBD_FIDO_GetInEpAdd(pdev, (uint8_t)pdev->classId);
  out_ep_add = USBD_FIDO_GetOutEpAdd(pdev, (uint8_t)pdev->classId);

  (void)USBD_LL_CloseEP(pdev, in_ep_add);
  (void)USBD_LL_CloseEP(pdev, out_ep_add);
  pdev->ep_in[in_ep_add & 0xFU].is_used = 0U;
  pdev->ep_out[out_ep_add & 0xFU].is_used = 0U;
  pdev->ep_in[in_ep_add & 0xFU].bInterval = 0U;

  if (pdev->pClassDataCmsit[pdev->classId] != NULL)
  {
    (void)USBD_free(pdev->pClassDataCmsit[pdev->classId]);
    pdev->pClassDataCmsit[pdev->classId] = NULL;
  }

  return (uint8_t)USBD_OK;
}

static uint8_t USBD_FIDO_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req)
{
  USBD_FIDO_HandleTypeDef *hfido = (USBD_FIDO_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  uint16_t len;
  uint8_t *pbuf;
  uint16_t status_info = 0U;

  if (hfido == NULL)
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
    case USB_REQ_TYPE_CLASS:
      switch (req->bRequest)
      {
        case USBD_HID_REQ_SET_PROTOCOL:
          hfido->Protocol = (uint8_t)req->wValue;
          break;

        case USBD_HID_REQ_GET_PROTOCOL:
          (void)USBD_CtlSendData(pdev, (uint8_t *)&hfido->Protocol, 1U);
          break;

        case USBD_HID_REQ_SET_IDLE:
          hfido->IdleState = (uint8_t)(req->wValue >> 8);
          break;

        case USBD_HID_REQ_GET_IDLE:
          (void)USBD_CtlSendData(pdev, (uint8_t *)&hfido->IdleState, 1U);
          break;

        case USBD_HID_REQ_GET_REPORT:
          len = MIN(req->wLength, (uint16_t)FIDO_CTRL_REPORT_SIZE);
          hfido->ctrl_report_len = (uint8_t)len;
          hfido->ctrl_report_type = (uint8_t)(req->wValue >> 8);
          hfido->ctrl_report_id = (uint8_t)(req->wValue & 0xFFU);
          USBD_memset(hfido->ctrl_report, 0, sizeof(hfido->ctrl_report));
          if ((hfido->ctrl_report_id != 0U) && (len != 0U))
          {
            hfido->ctrl_report[0] = hfido->ctrl_report_id;
          }
          (void)USBD_CtlSendData(pdev, hfido->ctrl_report, len);
          break;

        case USBD_HID_REQ_SET_REPORT:
          len = MIN(req->wLength, (uint16_t)FIDO_CTRL_REPORT_SIZE);
          hfido->ctrl_report_len = (uint8_t)len;
          hfido->ctrl_report_type = (uint8_t)(req->wValue >> 8);
          hfido->ctrl_report_id = (uint8_t)(req->wValue & 0xFFU);
          if (len != 0U)
          {
            (void)USBD_CtlPrepareRx(pdev, hfido->ctrl_report, len);
          }
          break;

        default:
          USBD_CtlError(pdev, req);
          return (uint8_t)USBD_FAIL;
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
            return (uint8_t)USBD_FAIL;
          }
          break;

        case USB_REQ_GET_DESCRIPTOR:
          if ((req->wValue >> 8) == HID_REPORT_DESC)
          {
            const uint8_t *report_desc;
            len = MIN(usbd_hid_fido_get_report_desc(&report_desc), req->wLength);
            pbuf = (uint8_t *)report_desc;
            g_a_usb_diag_runtime.hid_last_report_len = len;
          }
          else if ((req->wValue >> 8) == HID_DESCRIPTOR_TYPE)
          {
            pbuf = USBD_FIDO_GetDesc(&len);
            len = MIN(len, req->wLength);
            g_a_usb_diag_runtime.hid_last_report_len = len;
          }
          else
          {
            USBD_CtlError(pdev, req);
            return (uint8_t)USBD_FAIL;
          }
          (void)USBD_CtlSendData(pdev, pbuf, len);
          break;

        case USB_REQ_GET_INTERFACE:
          if (pdev->dev_state == USBD_STATE_CONFIGURED)
          {
            (void)USBD_CtlSendData(pdev, (uint8_t *)&hfido->AltSetting, 1U);
          }
          else
          {
            USBD_CtlError(pdev, req);
            return (uint8_t)USBD_FAIL;
          }
          break;

        case USB_REQ_SET_INTERFACE:
          if (pdev->dev_state == USBD_STATE_CONFIGURED)
          {
            hfido->AltSetting = (uint8_t)req->wValue;
          }
          else
          {
            USBD_CtlError(pdev, req);
            return (uint8_t)USBD_FAIL;
          }
          break;

        case USB_REQ_CLEAR_FEATURE:
          break;

        default:
          USBD_CtlError(pdev, req);
          return (uint8_t)USBD_FAIL;
      }
      break;

    default:
      USBD_CtlError(pdev, req);
      return (uint8_t)USBD_FAIL;
  }

  return (uint8_t)USBD_OK;
}

static uint8_t USBD_FIDO_EP0_RxReady(USBD_HandleTypeDef *pdev)
{
  USBD_FIDO_HandleTypeDef *hfido = (USBD_FIDO_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  const uint8_t *report;
  uint16_t report_len;
  uint16_t tx_len;
  uint8_t in_ep_add;

  if (hfido == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

  report = hfido->ctrl_report;
  report_len = hfido->ctrl_report_len;
  if ((hfido->ctrl_report_id != 0U) &&
      (report_len > 1U) &&
      (report[0] == hfido->ctrl_report_id))
  {
    report = &report[1];
    report_len--;
  }

  tx_len = USBD_FIDO_Process(pdev, (uint8_t)pdev->classId, hfido, report, report_len);
  if (tx_len != 0U)
  {
    in_ep_add = USBD_FIDO_GetInEpAdd(pdev, (uint8_t)pdev->classId);
    hfido->tx_len = tx_len;
    if (hfido->state == USBD_FIDO_IDLE)
    {
      hfido->state = USBD_FIDO_BUSY;
      (void)USBD_LL_Transmit(pdev, in_ep_add, hfido->tx_report, tx_len);
    }
    else
    {
      hfido->pending_tx = 1U;
      hfido->pending_tx_len = tx_len;
    }
  }

  hfido->ctrl_report_len = 0U;
  hfido->ctrl_report_id = 0U;
  hfido->ctrl_report_type = 0U;

  return (uint8_t)USBD_OK;
}

static uint8_t USBD_FIDO_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
  USBD_FIDO_HandleTypeDef *hfido = (USBD_FIDO_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  uint8_t in_ep_add;

  UNUSED(epnum);

  if (hfido == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

  hfido->state = USBD_FIDO_IDLE;
  if (hfido->fido.tx_active != 0U)
  {
    uint16_t tx_len = usbd_hid_fido_continue(&hfido->fido,
                                             hfido->tx_report,
                                             (uint16_t)sizeof(hfido->tx_report));

    if (tx_len != 0U)
    {
      in_ep_add = USBD_FIDO_GetInEpAdd(pdev, (uint8_t)pdev->classId);
      hfido->state = USBD_FIDO_BUSY;
      hfido->tx_len = tx_len;
      (void)USBD_LL_Transmit(pdev, in_ep_add, hfido->tx_report, tx_len);
      return (uint8_t)USBD_OK;
    }
  }

  if ((hfido->pending_tx != 0U) && (hfido->pending_tx_len != 0U))
  {
    in_ep_add = USBD_FIDO_GetInEpAdd(pdev, (uint8_t)pdev->classId);
    hfido->state = USBD_FIDO_BUSY;
    hfido->tx_len = hfido->pending_tx_len;
    hfido->pending_tx = 0U;
    hfido->pending_tx_len = 0U;
    (void)USBD_LL_Transmit(pdev, in_ep_add, hfido->tx_report, hfido->tx_len);
  }

  return (uint8_t)USBD_OK;
}

static uint8_t USBD_FIDO_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
  USBD_FIDO_HandleTypeDef *hfido = (USBD_FIDO_HandleTypeDef *)pdev->pClassDataCmsit[pdev->classId];
  uint8_t out_ep_add;
  uint8_t in_ep_add;
  uint16_t rx_len;
  uint16_t tx_len;

  if (hfido == NULL)
  {
    return (uint8_t)USBD_FAIL;
  }

  out_ep_add = USBD_FIDO_GetOutEpAdd(pdev, (uint8_t)pdev->classId);
  in_ep_add = USBD_FIDO_GetInEpAdd(pdev, (uint8_t)pdev->classId);

  if ((epnum & 0x7FU) != (out_ep_add & 0x7FU))
  {
    return (uint8_t)USBD_OK;
  }

  rx_len = (uint16_t)USBD_LL_GetRxDataSize(pdev, epnum);
  hfido->rx_len = rx_len;
  tx_len = USBD_FIDO_Process(pdev, (uint8_t)pdev->classId, hfido, hfido->rx_report, rx_len);
  if (tx_len != 0U)
  {
    hfido->tx_len = tx_len;
    if (hfido->state == USBD_FIDO_IDLE)
    {
      hfido->state = USBD_FIDO_BUSY;
      (void)USBD_LL_Transmit(pdev, in_ep_add, hfido->tx_report, tx_len);
    }
    else
    {
      hfido->pending_tx = 1U;
      hfido->pending_tx_len = tx_len;
    }
  }

  (void)USBD_LL_PrepareReceive(pdev, out_ep_add, hfido->rx_report, FIDO_HID_PACKET_SIZE);
  return (uint8_t)USBD_OK;
}
