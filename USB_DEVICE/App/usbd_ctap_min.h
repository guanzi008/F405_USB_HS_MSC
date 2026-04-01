#ifndef USBD_CTAP_MIN_H
#define USBD_CTAP_MIN_H

#include <stddef.h>
#include <stdint.h>

#define CTAP_CMD_MAKE_CREDENTIAL 0x01U
#define CTAP_CMD_GET_ASSERTION   0x02U
#define CTAP_CMD_GET_INFO        0x04U
#define CTAP_CMD_CLIENT_PIN      0x06U
#define CTAP_CMD_RESET           0x07U
#define CTAP_CMD_CRED_MGMT       0x0AU
#define CTAP_CMD_CONFIG          0x0DU
#define CTAP_CMD_CRED_MGMT_PRE   0x41U

#define CTAP_STATUS_OK                 0x00U
#define CTAP_ERR_INVALID_COMMAND       0x01U
#define CTAP_ERR_INVALID_PARAMETER     0x02U
#define CTAP_ERR_INVALID_LENGTH        0x03U
#define CTAP_ERR_CBOR_UNEXPECTED_TYPE  0x11U
#define CTAP_ERR_INVALID_CBOR          0x12U
#define CTAP_ERR_MISSING_PARAMETER     0x14U
#define CTAP_ERR_CREDENTIAL_EXCLUDED   0x19U
#define CTAP_ERR_UNSUPPORTED_ALGORITHM 0x26U
#define CTAP_ERR_OPERATION_DENIED      0x27U
#define CTAP_ERR_NO_CREDENTIALS        0x2EU
#define CTAP_ERR_NOT_ALLOWED           0x30U
#define CTAP_ERR_PIN_INVALID           0x31U
#define CTAP_ERR_PIN_BLOCKED           0x32U
#define CTAP_ERR_PIN_AUTH_INVALID      0x33U
#define CTAP_ERR_PIN_AUTH_BLOCKED      0x34U
#define CTAP_ERR_PIN_NOT_SET           0x35U
#define CTAP_ERR_PIN_REQUIRED          0x36U
#define CTAP_ERR_PIN_POLICY_VIOLATION  0x37U
#define CTAP_ERR_INTERNAL              0x7FU

#define USBD_CTAP_MIN_DONE             0x01U
#define USBD_CTAP_MIN_PENDING          0x02U

#define USBD_CTAP_UI_IDLE              0x00U
#define USBD_CTAP_UI_WAIT_TOUCH        0x01U
#define USBD_CTAP_UI_CONFIRMED         0x02U
#define USBD_CTAP_UI_DENIED            0x03U

typedef struct
{
  uint8_t ui_state;
  uint8_t pending_cmd;
  uint8_t selection_count;
  uint8_t selection_index;
  char selection_name[32];
} usbd_ctap_min_ui_status_t;

uint8_t usbd_ctap_min_handle_cbor(const uint8_t *req,
                                  uint16_t req_len,
                                  uint8_t *resp,
                                  uint16_t resp_cap,
                                  uint16_t *resp_len);
uint8_t usbd_ctap_min_complete_pending(const uint8_t *req,
                                       uint16_t req_len,
                                       uint8_t confirmed,
                                       uint8_t *resp,
                                       uint16_t resp_cap,
                                       uint16_t *resp_len);
void usbd_ctap_min_note_user_presence(void);
void usbd_ctap_min_note_user_denied(void);
void usbd_ctap_min_next_selection(void);
void usbd_ctap_min_prev_selection(void);
void usbd_ctap_min_get_ui_status(usbd_ctap_min_ui_status_t *status);
void usbd_ctap_min_begin_external_wait(uint8_t pending_cmd);
void usbd_ctap_min_finish_external_wait(void);

#endif
