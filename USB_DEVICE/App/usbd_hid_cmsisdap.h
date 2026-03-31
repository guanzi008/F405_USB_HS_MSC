#ifndef USBD_HID_CMSISDAP_H
#define USBD_HID_CMSISDAP_H

#include <stdint.h>
#include "usbd_core.h"

#ifdef __cplusplus
extern "C" {
#endif

uint16_t usbd_hid_cmsisdap_process(USBD_HandleTypeDef *pdev,
                                   uint8_t class_id,
                                   const uint8_t *request,
                                   uint16_t request_len,
                                   uint8_t *response,
                                   uint16_t response_cap);

#ifdef __cplusplus
}
#endif

#endif
