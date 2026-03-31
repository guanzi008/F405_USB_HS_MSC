#ifndef USBD_FIDO_CLASS_H
#define USBD_FIDO_CLASS_H

#include "usbd_ioreq.h"
#include "usbd_core.h"
#include "usbd_hid.h"
#include "usbd_hid_fido.h"

#define USB_FIDO_HID_DESC_SIZ 9U
#define FIDO_CTRL_REPORT_SIZE (FIDO_HID_PACKET_SIZE + 1U)

typedef enum
{
  USBD_FIDO_IDLE = 0,
  USBD_FIDO_BUSY,
} USBD_FIDO_StateTypeDef;

typedef struct
{
  uint32_t Protocol;
  uint32_t IdleState;
  uint32_t AltSetting;
  USBD_FIDO_StateTypeDef state;
  uint32_t rx_len;
  uint32_t tx_len;
  uint32_t pending_tx_len;
  uint8_t pending_tx;
  uint8_t ctrl_report_len;
  uint8_t ctrl_report_id;
  uint8_t ctrl_report_type;
  uint8_t rx_report[FIDO_HID_PACKET_SIZE];
  uint8_t tx_report[FIDO_HID_PACKET_SIZE];
  uint8_t ctrl_report[FIDO_CTRL_REPORT_SIZE];
  usbd_hid_fido_state_t fido;
} USBD_FIDO_HandleTypeDef;

extern USBD_ClassTypeDef USBD_FIDO_HID;
void USBD_FIDO_Service(USBD_HandleTypeDef *pdev, uint32_t now_ms);

#endif
