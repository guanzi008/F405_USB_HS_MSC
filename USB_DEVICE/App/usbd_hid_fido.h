#ifndef USBD_HID_FIDO_H
#define USBD_HID_FIDO_H

#include <stdint.h>

#include "usbd_core.h"
#include "fido_crypto.h"

#define FIDO_HID_PACKET_SIZE        64U
#define FIDO_HID_MSG_MAX            1024U
#define FIDO_HID_REPORT_DESC_SIZE   34U
#define FIDO_HID_BROADCAST_CID      0xFFFFFFFFU

#define FIDO_HID_CMD_PING           0x01U
#define FIDO_HID_CMD_INIT           0x06U
#define FIDO_HID_CMD_CBOR           0x10U
#define FIDO_HID_CMD_CANCEL         0x11U
#define FIDO_HID_CMD_ERROR          0x3FU
#define FIDO_HID_CMD_KEEPALIVE      0x3BU

#define FIDO_HID_KEEPALIVE_PROCESSING 0x01U
#define FIDO_HID_KEEPALIVE_UPNEEDED   0x02U

#define FIDO_HID_ERR_INVALID_CMD     0x01U
#define FIDO_HID_ERR_INVALID_PAR     0x02U
#define FIDO_HID_ERR_INVALID_LEN     0x03U
#define FIDO_HID_ERR_INVALID_SEQ     0x04U
#define FIDO_HID_ERR_REQ_TIMEOUT     0x05U
#define FIDO_HID_ERR_BUSY            0x06U
#define FIDO_HID_ERR_INVALID_CHANNEL 0x0BU
#define FIDO_HID_ERR_OTHER           0x7FU

typedef struct
{
  uint32_t next_cid;
  uint32_t rx_cid;
  uint32_t tx_cid;
  uint16_t rx_expected_len;
  uint16_t rx_received_len;
  uint16_t tx_len;
  uint16_t tx_offset;
  uint8_t rx_cmd;
  uint8_t rx_seq;
  uint8_t tx_cmd;
  uint8_t tx_seq;
  uint8_t rx_active;
  uint8_t tx_active;
  uint8_t wait_user_presence;
  uint8_t pending_req_valid;
  uint16_t pending_cbor_len;
  uint32_t last_keepalive_ms;
  uint8_t pending_req_hash[FIDO_SHA256_SIZE];
  uint8_t rx_buf[FIDO_HID_MSG_MAX];
  uint8_t tx_buf[FIDO_HID_MSG_MAX];
} usbd_hid_fido_state_t;

uint16_t usbd_hid_fido_get_report_desc(const uint8_t **desc);
void usbd_hid_fido_init(usbd_hid_fido_state_t *state);
uint16_t usbd_hid_fido_process(USBD_HandleTypeDef *pdev,
                               uint8_t class_id,
                               usbd_hid_fido_state_t *state,
                               const uint8_t *request,
                               uint16_t request_len,
                               uint8_t *response,
                               uint16_t response_cap);
uint16_t usbd_hid_fido_service(USBD_HandleTypeDef *pdev,
                               uint8_t class_id,
                               usbd_hid_fido_state_t *state,
                               uint8_t *response,
                               uint16_t response_cap,
                               uint32_t now_ms);
uint16_t usbd_hid_fido_continue(usbd_hid_fido_state_t *state,
                                uint8_t *response,
                                uint16_t response_cap);

#endif
