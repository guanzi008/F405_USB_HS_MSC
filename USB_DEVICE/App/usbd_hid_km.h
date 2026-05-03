#ifndef USBD_HID_KM_H
#define USBD_HID_KM_H

#include "usbd_def.h"

#include <stdint.h>

#define HID_KM_KEYBOARD_PACKET_SIZE 8u
#define HID_KM_MOUSE_PACKET_SIZE    4u

typedef struct {
  uint32_t rx_bytes;
  uint32_t cmd_count;
  uint32_t key_reports;
  uint32_t mouse_reports;
  uint32_t dropped_reports;
  uint8_t queue_depth;
  uint8_t led_report;
  char last_cmd[24];
} usbd_hid_km_status_t;

extern USBD_ClassTypeDef USBD_HID_KM;

void usbd_hid_km_init(void);
uint16_t usbd_hid_km_get_keyboard_report_desc(const uint8_t **desc);
uint16_t usbd_hid_km_get_mouse_report_desc(const uint8_t **desc);
void usbd_hid_km_feed_serial_byte(uint8_t byte);
void usbd_hid_km_service(USBD_HandleTypeDef *pdev, uint32_t now_ms);
void usbd_hid_km_get_status(usbd_hid_km_status_t *status);

#endif
