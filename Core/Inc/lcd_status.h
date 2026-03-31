#ifndef LCD_STATUS_H
#define LCD_STATUS_H

#include <stdint.h>

#define LCD_STATUS_APP_USB_DEBUG   0u
#define LCD_STATUS_APP_SECURITY    1u
#define LCD_STATUS_APP_FLASH       2u
#define LCD_STATUS_APP_INPUT       3u
#define LCD_STATUS_APP_WIPE        4u
#define LCD_STATUS_APP_DELETE_KEY  5u

void lcd_status_init(void);
uint8_t lcd_status_is_menu_active(void);
void lcd_status_next_page(void);
void lcd_status_prev_page(void);
void lcd_status_confirm(void);
void lcd_status_back(void);
uint8_t lcd_status_get_active_app(void);
void lcd_status_set_fido_store_result(uint8_t result);
void lcd_status_set_fido_store_progress(uint8_t active, uint8_t progress);
void lcd_status_set_fido_delete_progress(uint8_t active, uint8_t progress);
void lcd_status_set_fido_delete_state(uint16_t count, uint16_t index, const char *name);
void lcd_status_tick(uint32_t now_ms);
void lcd_status_update(uint8_t dev_state,
                       uint8_t dev_config,
                       uint32_t reset_count,
                       uint32_t setup_count,
                       uint32_t data_out_count,
                       uint32_t data_in_count,
                       uint32_t suspend_count,
                       uint32_t dap_rx_count,
                       uint32_t dap_tx_count,
                       uint32_t fido_rx_count,
                       uint32_t fido_tx_count,
                       uint32_t fido_last_req_word0,
                       uint32_t fido_last_rsp_word0,
                       uint32_t fido_last_status,
                       uint8_t fido_ui_state,
                       uint8_t fido_pending_cmd,
                       uint8_t fido_selection_count,
                       uint8_t fido_selection_index,
                       const char *fido_selection_name,
                       uint8_t flash_present,
                       uint32_t flash_jedec_id,
                       uint32_t flash_capacity_bytes,
                       uint8_t flash_mode,
                       uint8_t enc_a,
                       uint8_t enc_b,
                       uint8_t enc_btn,
                       int32_t encoder_position,
                       uint32_t last_events);

#endif
