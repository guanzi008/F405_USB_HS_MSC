#ifndef USBD_CTAP_MIN_H
#define USBD_CTAP_MIN_H

#include <stddef.h>
#include <stdint.h>

#define CTAP_CMD_MAKE_CREDENTIAL 0x01U
#define CTAP_CMD_GET_ASSERTION   0x02U
#define CTAP_CMD_GET_INFO        0x04U

#define CTAP_STATUS_OK                 0x00U
#define CTAP_ERR_INVALID_COMMAND       0x01U
#define CTAP_ERR_INVALID_PARAMETER     0x02U
#define CTAP_ERR_INVALID_LENGTH        0x03U
#define CTAP_ERR_OPERATION_DENIED      0x27U
#define CTAP_ERR_INTERNAL              0x7FU

uint8_t usbd_ctap_min_handle_cbor(const uint8_t *req,
                                  uint16_t req_len,
                                  uint8_t *resp,
                                  uint16_t resp_cap,
                                  uint16_t *resp_len);

#endif
