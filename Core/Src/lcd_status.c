#include "lcd_status.h"

#include "lcd_zh.h"
#include "ls013_lcd.h"
#include "usbd_ctap_min.h"
#include "usbd_hid_km.h"
#include "wouo_ls013.h"

#include <stdio.h>
#include <string.h>

#define LCD_APP_COUNT 7u
#define LCD_FIDO_RESERVED_BYTES (1024u * 1024u)
#define LCD_WOUO_SCALE 16
#define LCD_WOUO_FRAME_MS 33u
#define LCD_WOUO_LIST_LINE_H 15
#define LCD_WOUO_LIST_TEXT_Y 4
#define LCD_WOUO_TILE_ICON_W 34
#define LCD_WOUO_TILE_ICON_H 34
#define LCD_WOUO_TILE_STEP 44

static uint8_t s_lcd_ready;
static uint8_t s_last_dev_state;
static uint8_t s_last_dev_config;
static uint32_t s_last_reset_count;
static uint32_t s_last_setup_count;
static uint32_t s_last_data_out_count;
static uint32_t s_last_data_in_count;
static uint32_t s_last_suspend_count;
static uint32_t s_last_dap_rx_count;
static uint32_t s_last_dap_tx_count;
static uint32_t s_last_fido_rx_count;
static uint32_t s_last_fido_tx_count;
static uint32_t s_last_fido_last_req_word0;
static uint32_t s_last_fido_last_rsp_word0;
static uint32_t s_last_fido_last_status;
static uint8_t s_last_fido_ui_state;
static uint8_t s_last_fido_pending_cmd;
static uint8_t s_last_fido_selection_count;
static uint8_t s_last_fido_selection_index;
static char s_last_fido_selection_name[32];
static uint8_t s_last_flash_present;
static uint32_t s_last_flash_jedec_id;
static uint32_t s_last_flash_capacity_bytes;
static uint8_t s_last_flash_mode;
static uint8_t s_last_enc_a;
static uint8_t s_last_enc_b;
static uint8_t s_last_enc_btn;
static int32_t s_last_encoder_position;
static uint32_t s_last_events;
static uint8_t s_menu_active;
static uint8_t s_menu_index;
static uint8_t s_active_app;
static uint8_t s_page_dirty;
static uint8_t s_last_fido_store_result;
static uint8_t s_fido_wipe_active;
static uint8_t s_fido_wipe_progress;
static uint8_t s_fido_delete_active;
static uint8_t s_fido_delete_progress;
static uint16_t s_last_fido_delete_count;
static uint16_t s_last_fido_delete_index;
static char s_last_fido_delete_name[32];
static uint32_t s_last_anim_ms;
static int16_t s_wouo_tile_x;
static int16_t s_wouo_tile_x_trg;
static int16_t s_wouo_tile_y;
static int16_t s_wouo_tile_y_trg;
static int16_t s_wouo_title_y;
static int16_t s_wouo_title_y_trg;
static int16_t s_wouo_indi_w;
static int16_t s_wouo_indi_w_trg;
static int16_t s_wouo_list_y;
static int16_t s_wouo_list_y_trg;
static int16_t s_wouo_list_box_y;
static int16_t s_wouo_list_box_y_trg;
static int16_t s_wouo_list_box_w;
static int16_t s_wouo_list_box_w_trg;
static int16_t s_wouo_list_bar_y;
static int16_t s_wouo_list_bar_y_trg;
static int16_t s_wouo_popup_y;
static int16_t s_wouo_popup_y_trg;
static uint8_t s_wouo_anim_active;
static uint8_t s_wouo_last_menu_index;
static uint8_t s_wouo_last_menu_active;
static uint8_t s_wouo_last_active_app;

typedef struct {
    lcd_zh_id_t title;
    const char *name;
    const char *hint;
} lcd_wouo_app_t;

static const lcd_wouo_app_t s_wouo_apps[LCD_APP_COUNT] = {
    {LCD_ZH_MENU_USB_DEBUG, "USB", "CMSIS-DAP"},
    {LCD_ZH_MENU_SECURITY_KEY, "KEY", "FIDO/CTAP"},
    {LCD_ZH_MENU_SPI_FLASH, "FLASH", "W25Q MSC"},
    {LCD_ZH_MENU_INPUT_DEV, "INPUT", "ENCODER"},
    {LCD_ZH_MENU_WIPE_KEY, "WIPE", "CLEAR"},
    {LCD_ZH_MENU_DELETE_KEY, "DEL", "CREDENTIAL"},
    {LCD_ZH_INPUT, "HID", "UART K/M"},
};

static void lcd_draw_text_at(uint8_t x, uint8_t y, uint8_t clear_w, const char *text)
{
    wouo_draw_text_6x8(x, y, clear_w, text, 1u, 0u);
}

static void lcd_draw_text_color_at(uint8_t x, uint8_t y, uint8_t clear_w, const char *text, uint8_t fg, uint8_t bg)
{
    wouo_draw_text_6x8(x, y, clear_w, text, fg, bg);
}

static void lcd_draw_bitmap_1bpp_color(uint8_t x, uint8_t y, const uint8_t *bitmap, uint8_t width, uint8_t height, uint8_t on);

static void lcd_draw_zh_at(uint8_t x, uint8_t y, uint8_t clear_w, lcd_zh_id_t id)
{
    const lcd_zh_bitmap_t *bmp = lcd_zh_get(id);

    if (bmp == NULL) {
        return;
    }

    ls013_lcd_rect(x, y, clear_w, (uint8_t)(bmp->height + 1u), 0u);
    lcd_draw_bitmap_1bpp_color(x, y, bmp->data, bmp->width, bmp->height, 1u);
}

static void lcd_draw_zh_invert_at(uint8_t x, uint8_t y, lcd_zh_id_t id)
{
    const lcd_zh_bitmap_t *bmp = lcd_zh_get(id);

    if (bmp == NULL) {
        return;
    }

    lcd_draw_bitmap_1bpp_color(x, y, bmp->data, bmp->width, bmp->height, 0u);
}

static void lcd_draw_bitmap_1bpp_color(uint8_t x, uint8_t y, const uint8_t *bitmap, uint8_t width, uint8_t height, uint8_t on)
{
    wouo_draw_bitmap_rows(x, y, bitmap, width, height, on);
}

static void lcd_draw_progress_bar(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint8_t progress)
{
    wouo_draw_progress_bar(x, y, w, h, progress);
}

static int16_t lcd_wouo_px(int16_t value)
{
    return (int16_t)(value / LCD_WOUO_SCALE);
}

static uint8_t lcd_wouo_anim(int16_t *value, int16_t target, uint8_t weight)
{
    return wouo_anim_i16(value, target, weight);
}

static void lcd_wouo_prepare_menu_anim(uint8_t force)
{
    int16_t target_x = (int16_t)((64 - (LCD_WOUO_TILE_ICON_W / 2) -
                                  ((int16_t)s_menu_index * LCD_WOUO_TILE_STEP)) * LCD_WOUO_SCALE);

    s_wouo_tile_x_trg = target_x;
    s_wouo_tile_y_trg = 14 * LCD_WOUO_SCALE;
    s_wouo_title_y_trg = 61 * LCD_WOUO_SCALE;
    s_wouo_indi_w_trg = 10 * LCD_WOUO_SCALE;
    if (force != 0u) {
        s_wouo_tile_x = target_x;
        s_wouo_tile_y = -LCD_WOUO_TILE_ICON_H * LCD_WOUO_SCALE;
        s_wouo_title_y = 94 * LCD_WOUO_SCALE;
        s_wouo_indi_w = 0;
    }
    s_wouo_anim_active = 1u;
}

static void lcd_wouo_prepare_list_anim(uint8_t force)
{
    uint8_t selected = 0u;
    uint8_t width = 54u;

    if (s_active_app == LCD_STATUS_APP_DELETE_KEY && s_last_fido_delete_count != 0u) {
        selected = 2u;
        width = 96u;
    } else if (s_active_app == LCD_STATUS_APP_WIPE) {
        selected = 2u;
        width = 86u;
    } else if (s_active_app == LCD_STATUS_APP_SECURITY && s_last_fido_ui_state == USBD_CTAP_UI_WAIT_TOUCH) {
        selected = 4u;
        width = 86u;
    }

    s_wouo_list_y_trg = 0;
    s_wouo_list_box_y_trg = (int16_t)((20 + ((int16_t)selected * LCD_WOUO_LIST_LINE_H)) * LCD_WOUO_SCALE);
    s_wouo_list_box_w_trg = (int16_t)(width * LCD_WOUO_SCALE);
    s_wouo_list_bar_y_trg = (int16_t)(((selected + 1u) * 18u) * LCD_WOUO_SCALE);
    if (force != 0u) {
        s_wouo_list_y = 16 * LCD_WOUO_SCALE;
        s_wouo_list_box_y = 0;
        s_wouo_list_box_w = 0;
        s_wouo_list_bar_y = 0;
    }
    s_wouo_anim_active = 1u;
}

static void lcd_wouo_step_anim(void)
{
    uint8_t active = 0u;

    active |= lcd_wouo_anim(&s_wouo_tile_x, s_wouo_tile_x_trg, 4u);
    active |= lcd_wouo_anim(&s_wouo_tile_y, s_wouo_tile_y_trg, 5u);
    active |= lcd_wouo_anim(&s_wouo_title_y, s_wouo_title_y_trg, 5u);
    active |= lcd_wouo_anim(&s_wouo_indi_w, s_wouo_indi_w_trg, 5u);
    active |= lcd_wouo_anim(&s_wouo_list_y, s_wouo_list_y_trg, 5u);
    active |= lcd_wouo_anim(&s_wouo_list_box_y, s_wouo_list_box_y_trg, 5u);
    active |= lcd_wouo_anim(&s_wouo_list_box_w, s_wouo_list_box_w_trg, 5u);
    active |= lcd_wouo_anim(&s_wouo_list_bar_y, s_wouo_list_bar_y_trg, 5u);
    active |= lcd_wouo_anim(&s_wouo_popup_y, s_wouo_popup_y_trg, 4u);
    s_wouo_anim_active = active;
}

static void lcd_draw_wouo_scroll_bar(uint8_t y)
{
    ls013_lcd_hline(122u, 4u, 5u, 1u);
    ls013_lcd_hline(122u, 123u, 5u, 1u);
    ls013_lcd_vline(124u, 4u, 120u, 1u);
    if (y > 118u) {
        y = 118u;
    }
    ls013_lcd_rect(122u, y, 5u, 8u, 1u);
}

static void lcd_draw_wouo_list_row(uint8_t row, const char *text, uint8_t selected)
{
    uint8_t y = (uint8_t)(20u + (row * LCD_WOUO_LIST_LINE_H) + lcd_wouo_px(s_wouo_list_y));

    if (y > 121u) {
        return;
    }
    if (selected != 0u) {
        ls013_lcd_rect(0u, (uint8_t)(y - 3u), (uint8_t)lcd_wouo_px(s_wouo_list_box_w), LCD_WOUO_LIST_LINE_H, 1u);
        lcd_draw_text_color_at(5u, (uint8_t)(y + LCD_WOUO_LIST_TEXT_Y), 112u, text, 0u, 1u);
    } else {
        lcd_draw_text_color_at(5u, (uint8_t)(y + LCD_WOUO_LIST_TEXT_Y), 112u, text, 1u, 0u);
    }
}

static void lcd_draw_wouo_tag(uint8_t x, uint8_t y, lcd_zh_id_t title_id, uint8_t min_w)
{
    const lcd_zh_bitmap_t *bmp = lcd_zh_get(title_id);
    uint8_t w;

    if (bmp == NULL) {
        return;
    }
    w = (uint8_t)(bmp->width + 10u);
    if (w < min_w) {
        w = min_w;
    }
    if ((uint16_t)x + w > 126u) {
        w = (uint8_t)(126u - x);
    }
    ls013_lcd_rect(x, y, w, 15u, 1u);
    lcd_draw_zh_invert_at((uint8_t)(x + 5u), (uint8_t)(y + 2u), title_id);
}

static void lcd_draw_wouo_icon(uint8_t index, int16_t x, uint8_t y, uint8_t selected)
{
    uint8_t x8;

    if ((x < 0) || (x > 128)) {
        return;
    }
    x8 = (uint8_t)x;
    if (selected != 0u) {
        ls013_lcd_rect(x8, y, LCD_WOUO_TILE_ICON_W, LCD_WOUO_TILE_ICON_H, 1u);
        ls013_lcd_rect((uint8_t)(x8 + 3u), (uint8_t)(y + 3u),
                       (uint8_t)(LCD_WOUO_TILE_ICON_W - 6u),
                       (uint8_t)(LCD_WOUO_TILE_ICON_H - 6u), 0u);
    } else {
        ls013_lcd_frame(x8, y, LCD_WOUO_TILE_ICON_W, LCD_WOUO_TILE_ICON_H, 1u);
    }

    switch (index) {
        case LCD_STATUS_APP_USB_DEBUG:
            ls013_lcd_hline((uint8_t)(x8 + 9u), (uint8_t)(y + 10u), 16u, 1u);
            ls013_lcd_vline((uint8_t)(x8 + 17u), (uint8_t)(y + 10u), 16u, 1u);
            ls013_lcd_rect((uint8_t)(x8 + 12u), (uint8_t)(y + 23u), 11u, 5u, 1u);
            break;
        case LCD_STATUS_APP_SECURITY:
            ls013_lcd_frame((uint8_t)(x8 + 10u), (uint8_t)(y + 15u), 15u, 13u, 1u);
            ls013_lcd_frame((uint8_t)(x8 + 13u), (uint8_t)(y + 8u), 9u, 10u, 1u);
            break;
        case LCD_STATUS_APP_FLASH:
            ls013_lcd_frame((uint8_t)(x8 + 8u), (uint8_t)(y + 9u), 18u, 18u, 1u);
            ls013_lcd_hline((uint8_t)(x8 + 11u), (uint8_t)(y + 15u), 12u, 1u);
            ls013_lcd_hline((uint8_t)(x8 + 11u), (uint8_t)(y + 21u), 12u, 1u);
            break;
        case LCD_STATUS_APP_INPUT:
            ls013_lcd_frame((uint8_t)(x8 + 8u), (uint8_t)(y + 8u), 18u, 18u, 1u);
            ls013_lcd_vline((uint8_t)(x8 + 17u), (uint8_t)(y + 11u), 12u, 1u);
            ls013_lcd_hline((uint8_t)(x8 + 11u), (uint8_t)(y + 17u), 12u, 1u);
            break;
        case LCD_STATUS_APP_HID_INPUT:
            ls013_lcd_frame((uint8_t)(x8 + 7u), (uint8_t)(y + 9u), 20u, 11u, 1u);
            ls013_lcd_hline((uint8_t)(x8 + 10u), (uint8_t)(y + 23u), 14u, 1u);
            ls013_lcd_rect((uint8_t)(x8 + 21u), (uint8_t)(y + 22u), 5u, 7u, 1u);
            break;
        case LCD_STATUS_APP_WIPE:
            ls013_lcd_frame((uint8_t)(x8 + 10u), (uint8_t)(y + 9u), 14u, 19u, 1u);
            ls013_lcd_hline((uint8_t)(x8 + 8u), (uint8_t)(y + 9u), 18u, 1u);
            break;
        default:
            ls013_lcd_frame((uint8_t)(x8 + 9u), (uint8_t)(y + 13u), 16u, 12u, 1u);
            ls013_lcd_hline((uint8_t)(x8 + 13u), (uint8_t)(y + 10u), 8u, 1u);
            break;
    }
}

static void lcd_draw_wouo_list_page(lcd_zh_id_t title_id)
{
    ls013_lcd_clear(0xFFu);
    lcd_draw_wouo_tag(0u, 0u, title_id, 34u);
}

static void lcd_draw_menu_page(void) {
    uint8_t i;
    uint8_t title_w;

    ls013_lcd_clear(0xFFu);
    for (i = 0u; i < LCD_APP_COUNT; ++i) {
        lcd_draw_wouo_icon(i,
                           (int16_t)(lcd_wouo_px(s_wouo_tile_x) + ((int16_t)i * LCD_WOUO_TILE_STEP)),
                           (uint8_t)lcd_wouo_px(s_wouo_tile_y),
                           (uint8_t)(i == s_menu_index));
    }
    ls013_lcd_rect(0u, 57u, (uint8_t)lcd_wouo_px(s_wouo_indi_w), 39u, 1u);
    title_w = (uint8_t)(lcd_zh_get(s_wouo_apps[s_menu_index].title)->width + 8u);
    if (title_w > 108u) {
        title_w = 108u;
    }
    ls013_lcd_rect(12u, 60u, title_w, 18u, 1u);
    lcd_draw_zh_invert_at(16u, (uint8_t)lcd_wouo_px(s_wouo_title_y), s_wouo_apps[s_menu_index].title);
    lcd_draw_text_color_at(18u, 102u, 96u, s_wouo_apps[s_menu_index].hint, 1u, 0u);
    lcd_draw_wouo_scroll_bar((uint8_t)(10u + (s_menu_index * 18u)));
}

static void lcd_draw_usb_page(void) {
    char line[24];

    lcd_draw_wouo_list_page(LCD_ZH_DEBUG);
    snprintf(line, sizeof(line), "DS:%u CFG:%u", s_last_dev_state, s_last_dev_config);
    lcd_draw_wouo_list_row(0u, line, 1u);
    snprintf(line, sizeof(line), "RST:%lu SET:%lu", s_last_reset_count, s_last_setup_count);
    lcd_draw_wouo_list_row(1u, line, 0u);
    snprintf(line, sizeof(line), "OUT:%lu IN:%lu", s_last_data_out_count, s_last_data_in_count);
    lcd_draw_wouo_list_row(2u, line, 0u);
    snprintf(line, sizeof(line), "SUSP:%lu", s_last_suspend_count);
    lcd_draw_wouo_list_row(3u, line, 0u);
    snprintf(line, sizeof(line), "DAPRX:%lu", s_last_dap_rx_count);
    lcd_draw_wouo_list_row(4u, line, 0u);
    snprintf(line, sizeof(line), "DAPTX:%lu", s_last_dap_tx_count);
    lcd_draw_wouo_list_row(5u, line, 0u);
    lcd_draw_wouo_list_row(6u, "USB CMSIS-DAP", 0u);
    lcd_draw_wouo_scroll_bar((uint8_t)lcd_wouo_px(s_wouo_list_bar_y));
}

static void lcd_draw_security_page(void) {
    char line[24];
    const char *ui_text = "IDLE";
    const char *cmd_text = "--";

    lcd_draw_wouo_list_page(LCD_ZH_KEY);
    switch (s_last_fido_ui_state) {
        case 1u: ui_text = "WAIT"; break;
        case 2u: ui_text = "OK"; break;
        case 3u: ui_text = "DENY"; break;
        default: ui_text = "IDLE"; break;
    }
    switch (s_last_fido_pending_cmd) {
        case 0x01u: cmd_text = "MC"; break;
        case 0x02u: cmd_text = "GA"; break;
        case 0x04u: cmd_text = "GI"; break;
        case 0x07u: cmd_text = "RST"; break;
        default: cmd_text = "--"; break;
    }
    snprintf(line, sizeof(line), "RX:%lu TX:%lu", s_last_fido_rx_count, s_last_fido_tx_count);
    lcd_draw_wouo_list_row(0u, line, 1u);
    snprintf(line, sizeof(line), "REQ:%08lX", s_last_fido_last_req_word0);
    lcd_draw_wouo_list_row(1u, line, 0u);
    snprintf(line, sizeof(line), "RSP:%08lX", s_last_fido_last_rsp_word0);
    lcd_draw_wouo_list_row(2u, line, 0u);
    snprintf(line, sizeof(line), "STAT:%02lX", s_last_fido_last_status & 0xFFu);
    lcd_draw_wouo_list_row(3u, line, 0u);
    snprintf(line, sizeof(line), "UI:%s CMD:%s", ui_text, cmd_text);
    lcd_draw_wouo_list_row(4u, line, s_last_fido_ui_state == 1u);
    if (s_last_fido_ui_state == 1u) {
        lcd_draw_zh_at(6u, 101u, 108u, LCD_ZH_WAIT_CONFIRM);
    } else {
        lcd_draw_zh_at(6u, 101u, 108u, LCD_ZH_BUTTON_CONFIRM);
    }
    lcd_draw_wouo_scroll_bar((uint8_t)lcd_wouo_px(s_wouo_list_bar_y));
}

static void lcd_draw_flash_page(void) {
    char line[24];

    lcd_draw_wouo_list_page(LCD_ZH_FLASH);
    if (s_last_flash_present != 0u) {
        lcd_draw_zh_at(6u, 24u, 112u, LCD_ZH_PRESENT);
        snprintf(line, sizeof(line), "ID:%06lX", s_last_flash_jedec_id & 0xFFFFFFu);
        lcd_draw_wouo_list_row(1u, line, 1u);
        snprintf(line, sizeof(line), "CAP:%luM", s_last_flash_capacity_bytes >> 20);
        lcd_draw_wouo_list_row(2u, line, 0u);
        snprintf(line, sizeof(line), "MODE:%u", s_last_flash_mode);
        lcd_draw_wouo_list_row(3u, line, 0u);
        snprintf(line, sizeof(line), "MSC:%luM", (s_last_flash_capacity_bytes - LCD_FIDO_RESERVED_BYTES) >> 20);
        lcd_draw_wouo_list_row(4u, line, 0u);
        lcd_draw_wouo_list_row(5u, "FIDO RESV:1M", 0u);
    } else {
        lcd_draw_zh_at(6u, 44u, 112u, LCD_ZH_NOT_FOUND);
        lcd_draw_zh_at(6u, 62u, 112u, LCD_ZH_CHECK_SPI1);
    }
    lcd_draw_wouo_list_row(6u, "PB3 PA6 PA7", 0u);
    lcd_draw_wouo_list_row(7u, "CS:PA4", 0u);
    lcd_draw_wouo_scroll_bar((uint8_t)lcd_wouo_px(s_wouo_list_bar_y));
}

static void lcd_draw_input_page(void) {
    char line[24];

    lcd_draw_wouo_list_page(LCD_ZH_INPUT);
    snprintf(line, sizeof(line), "A:%u B:%u K:%u", s_last_enc_a, s_last_enc_b, s_last_enc_btn);
    lcd_draw_wouo_list_row(0u, line, 1u);
    snprintf(line, sizeof(line), "POS:%ld", (long)s_last_encoder_position);
    lcd_draw_wouo_list_row(1u, line, 0u);
    snprintf(line, sizeof(line), "EV:%08lX", s_last_events);
    lcd_draw_wouo_list_row(2u, line, 0u);
    lcd_draw_wouo_list_row(4u, "ENC BUZ RGB", 0u);
    lcd_draw_wouo_list_row(5u, "SHORT CYAN", 0u);
    lcd_draw_wouo_list_row(6u, "LONG PURPLE", 0u);
    lcd_draw_wouo_scroll_bar((uint8_t)lcd_wouo_px(s_wouo_list_bar_y));
}

static void lcd_draw_hid_input_page(void) {
    char line[24];
    usbd_hid_km_status_t status;

    usbd_hid_km_get_status(&status);
    lcd_draw_wouo_list_page(LCD_ZH_INPUT);
    lcd_draw_wouo_list_row(0u, "UART4 115200", 1u);
    snprintf(line, sizeof(line), "RX:%lu CMD:%lu", status.rx_bytes, status.cmd_count);
    lcd_draw_wouo_list_row(1u, line, 0u);
    snprintf(line, sizeof(line), "KEY:%lu MOU:%lu", status.key_reports, status.mouse_reports);
    lcd_draw_wouo_list_row(2u, line, 0u);
    snprintf(line, sizeof(line), "Q:%u DROP:%lu", status.queue_depth, status.dropped_reports);
    lcd_draw_wouo_list_row(3u, line, 0u);
    snprintf(line, sizeof(line), "LED:%02X", status.led_report);
    lcd_draw_wouo_list_row(4u, line, 0u);
    lcd_draw_wouo_list_row(5u, status.last_cmd, 0u);
    lcd_draw_wouo_list_row(6u, "t TXT key/m/click", 0u);
    lcd_draw_wouo_scroll_bar((uint8_t)lcd_wouo_px(s_wouo_list_bar_y));
}

static void lcd_draw_fido_wipe_page(void) {
    char line[24];

    lcd_draw_wouo_list_page(LCD_ZH_WIPE);
    if (s_fido_wipe_active != 0u) {
        lcd_draw_zh_at(6u, 42u, 112u, LCD_ZH_ERASING);
        lcd_draw_progress_bar(8u, 66u, 104u, 10u, s_fido_wipe_progress);
        snprintf(line, sizeof(line), "ERASE %u%%", (unsigned)s_fido_wipe_progress);
        lcd_draw_wouo_list_row(4u, line, 1u);
        lcd_draw_zh_at(6u, 98u, 112u, LCD_ZH_PLEASE_WAIT);
    } else if (s_last_fido_store_result == 1u) {
        lcd_draw_zh_at(6u, 98u, 112u, LCD_ZH_DONE);
    } else if (s_last_fido_store_result == 2u) {
        lcd_draw_zh_at(6u, 98u, 112u, LCD_ZH_ERASE_FAIL);
    } else {
        lcd_draw_zh_at(6u, 50u, 112u, LCD_ZH_SHORT_ERASE);
        lcd_draw_zh_at(6u, 68u, 112u, LCD_ZH_LONG_BACK);
        lcd_draw_wouo_list_row(5u, "READY", 1u);
    }
    lcd_draw_zh_at(6u, 112u, 108u, LCD_ZH_REREGISTER);
    lcd_draw_wouo_scroll_bar((uint8_t)lcd_wouo_px(s_wouo_list_bar_y));
}

static void lcd_draw_fido_delete_page(void) {
    char line[24];

    lcd_draw_wouo_list_page(LCD_ZH_DELETE);
    if (s_fido_delete_active != 0u) {
        lcd_draw_zh_at(6u, 44u, 112u, LCD_ZH_ACCOUNT);
        lcd_draw_text_at(48u, 51u, 60u,
                         s_last_fido_delete_name[0] != '\0' ? s_last_fido_delete_name : "USER");
        lcd_draw_progress_bar(8u, 68u, 104u, 10u, s_fido_delete_progress);
        snprintf(line, sizeof(line), "DELETE %u%%", (unsigned)s_fido_delete_progress);
        lcd_draw_wouo_list_row(4u, line, 1u);
        lcd_draw_zh_at(6u, 98u, 112u, LCD_ZH_PLEASE_WAIT);
        return;
    }

    if (s_last_fido_delete_count == 0u) {
        if (s_last_fido_store_result == 1u) {
            lcd_draw_zh_at(6u, 50u, 112u, LCD_ZH_DONE);
        } else if (s_last_fido_store_result == 2u) {
            lcd_draw_zh_at(6u, 50u, 112u, LCD_ZH_DELETE_FAIL);
        } else {
            lcd_draw_zh_at(6u, 50u, 112u, LCD_ZH_NO_KEY);
        }
        lcd_draw_zh_at(6u, 68u, 112u, LCD_ZH_LONG_BACK);
        lcd_draw_zh_at(6u, 86u, 112u, LCD_ZH_REREGISTER);
        return;
    }

    lcd_draw_zh_at(6u, 44u, 28u, LCD_ZH_ACCOUNT);
    snprintf(line, sizeof(line), "%u/%u",
             (unsigned)(s_last_fido_delete_index + 1u),
             (unsigned)s_last_fido_delete_count);
    lcd_draw_text_at(48u, 49u, 40u, line);
    lcd_draw_wouo_list_row(2u,
                           s_last_fido_delete_name[0] != '\0' ? s_last_fido_delete_name : "USER",
                           1u);
    lcd_draw_zh_at(6u, 84u, 112u, LCD_ZH_KNOB_SELECT);

    if (s_last_fido_store_result == 1u) {
        lcd_draw_zh_at(6u, 102u, 112u, LCD_ZH_DONE);
    } else if (s_last_fido_store_result == 2u) {
        lcd_draw_zh_at(6u, 102u, 112u, LCD_ZH_DELETE_FAIL);
    } else {
        lcd_draw_zh_at(6u, 100u, 112u, LCD_ZH_SHORT_DELETE);
        lcd_draw_zh_at(6u, 114u, 112u, LCD_ZH_LONG_BACK);
    }
    lcd_draw_wouo_scroll_bar((uint8_t)lcd_wouo_px(s_wouo_list_bar_y));
}

static void lcd_draw_fido_popup(void)
{
    lcd_zh_id_t cmd_text = LCD_ZH_GET_INFO;
    uint8_t draw_reset_text = 0u;
    char line[24];

    if (s_last_fido_pending_cmd == CTAP_CMD_MAKE_CREDENTIAL) {
        cmd_text = LCD_ZH_MAKE_CRED;
    } else if (s_last_fido_pending_cmd == CTAP_CMD_GET_ASSERTION) {
        cmd_text = LCD_ZH_GET_ASSERT;
    } else if (s_last_fido_pending_cmd == CTAP_CMD_RESET) {
        draw_reset_text = 1u;
    }

    int16_t popup_y_i = lcd_wouo_px(s_wouo_popup_y);
    uint8_t popup_y;

    if ((popup_y_i < 0) || (popup_y_i > 127)) {
        return;
    }
    popup_y = (uint8_t)popup_y_i;

    ls013_lcd_rect(14u, popup_y, 100u, 86u, 0u);
    ls013_lcd_frame(14u, popup_y, 100u, 86u, 1u);
    lcd_draw_wouo_tag(18u, (uint8_t)(popup_y + 5u), LCD_ZH_FIDO_CONFIRM, 68u);
    if (draw_reset_text != 0u) {
        lcd_draw_text_at(22u, (uint8_t)(popup_y + 31u), 88u, "AUTH RESET");
    } else {
        lcd_draw_zh_at(22u, (uint8_t)(popup_y + 30u), 88u, cmd_text);
    }
    if ((s_last_fido_selection_count > 1u) && (s_last_fido_pending_cmd == CTAP_CMD_GET_ASSERTION)) {
        lcd_draw_zh_at(22u, (uint8_t)(popup_y + 45u), 28u, LCD_ZH_ACCOUNT);
        snprintf(line, sizeof(line), "%u/%u",
                 (unsigned)(s_last_fido_selection_index + 1u),
                 (unsigned)s_last_fido_selection_count);
        lcd_draw_text_at(52u, (uint8_t)(popup_y + 48u), 26u, line);
        lcd_draw_text_at(22u, (uint8_t)(popup_y + 61u), 88u, s_last_fido_selection_name[0] != '\0' ? s_last_fido_selection_name : "USER");
        lcd_draw_zh_at(22u, (uint8_t)(popup_y + 73u), 88u, LCD_ZH_KNOB_SELECT);
    } else {
        lcd_draw_zh_at(22u, (uint8_t)(popup_y + 49u), 88u, LCD_ZH_SHORT_OK);
        lcd_draw_zh_at(22u, (uint8_t)(popup_y + 67u), 88u, LCD_ZH_LONG_CANCEL);
    }
}

static void lcd_redraw_page(void) {
    uint8_t force_anim = 0u;

    if ((s_wouo_last_menu_active != s_menu_active) ||
        (s_wouo_last_active_app != s_active_app)) {
        force_anim = 1u;
    }
    s_wouo_last_menu_active = s_menu_active;
    s_wouo_last_menu_index = s_menu_index;
    s_wouo_last_active_app = s_active_app;

    if (s_menu_active != 0u) {
        lcd_wouo_prepare_menu_anim(force_anim);
    } else {
        lcd_wouo_prepare_list_anim(force_anim);
    }
    s_wouo_popup_y_trg = ((s_last_fido_ui_state == USBD_CTAP_UI_WAIT_TOUCH) &&
                          !((s_menu_active == 0u) &&
                            ((s_active_app == LCD_STATUS_APP_WIPE) ||
                             (s_active_app == LCD_STATUS_APP_DELETE_KEY)))) ?
                         (18 * LCD_WOUO_SCALE) : (-96 * LCD_WOUO_SCALE);
    lcd_wouo_step_anim();

    if (s_menu_active != 0u) {
        lcd_draw_menu_page();
    } else {
      switch (s_active_app) {
        case LCD_STATUS_APP_USB_DEBUG:
            lcd_draw_usb_page();
            break;
        case LCD_STATUS_APP_SECURITY:
            lcd_draw_security_page();
            break;
        case LCD_STATUS_APP_FLASH:
            lcd_draw_flash_page();
            break;
        case LCD_STATUS_APP_WIPE:
            lcd_draw_fido_wipe_page();
            break;
        case LCD_STATUS_APP_DELETE_KEY:
            lcd_draw_fido_delete_page();
            break;
        case LCD_STATUS_APP_HID_INPUT:
            lcd_draw_hid_input_page();
            break;
        default:
            lcd_draw_input_page();
            break;
      }
    }
    if ((s_last_fido_ui_state == USBD_CTAP_UI_WAIT_TOUCH) &&
        !((s_menu_active == 0u) &&
          ((s_active_app == LCD_STATUS_APP_WIPE) ||
           (s_active_app == LCD_STATUS_APP_DELETE_KEY)))) {
        lcd_draw_fido_popup();
    }
    ls013_lcd_send_frame();
}

static void lcd_status_set_page(uint8_t page) {
    uint8_t next_page = (uint8_t)(page % LCD_APP_COUNT);

    if (next_page != s_menu_index) {
        s_menu_index = next_page;
        s_page_dirty = 1u;
    }
}

void lcd_status_init(void) {
    s_lcd_ready = 1u;
    s_last_dev_state = 0xFFu;
    s_last_dev_config = 0xFFu;
    s_last_reset_count = 0xFFFFFFFFu;
    s_last_setup_count = 0xFFFFFFFFu;
    s_last_data_out_count = 0xFFFFFFFFu;
    s_last_data_in_count = 0xFFFFFFFFu;
    s_last_suspend_count = 0xFFFFFFFFu;
    s_last_dap_rx_count = 0xFFFFFFFFu;
    s_last_dap_tx_count = 0xFFFFFFFFu;
    s_last_fido_rx_count = 0xFFFFFFFFu;
    s_last_fido_tx_count = 0xFFFFFFFFu;
    s_last_fido_last_req_word0 = 0xFFFFFFFFu;
    s_last_fido_last_rsp_word0 = 0xFFFFFFFFu;
    s_last_fido_last_status = 0xFFFFFFFFu;
    s_last_fido_ui_state = 0xFFu;
    s_last_fido_pending_cmd = 0xFFu;
    s_last_fido_selection_count = 0xFFu;
    s_last_fido_selection_index = 0xFFu;
    memset(s_last_fido_selection_name, 0, sizeof(s_last_fido_selection_name));
    s_last_flash_present = 0xFFu;
    s_last_flash_jedec_id = 0xFFFFFFFFu;
    s_last_flash_capacity_bytes = 0xFFFFFFFFu;
    s_last_flash_mode = 0xFFu;
    s_last_enc_a = 0xFFu;
    s_last_enc_b = 0xFFu;
    s_last_enc_btn = 0xFFu;
    s_last_encoder_position = 0x7FFFFFFFu;
    s_last_events = 0xFFFFFFFFu;
    s_menu_active = 1u;
    s_menu_index = 0u;
    s_active_app = 0u;
    s_page_dirty = 1u;
    s_last_fido_store_result = 0u;
    s_fido_wipe_active = 0u;
    s_fido_wipe_progress = 0u;
    s_fido_delete_active = 0u;
    s_fido_delete_progress = 0u;
    s_last_fido_delete_count = 0xFFFFu;
    s_last_fido_delete_index = 0xFFFFu;
    memset(s_last_fido_delete_name, 0, sizeof(s_last_fido_delete_name));
    s_last_anim_ms = 0u;
    s_wouo_tile_x = 0;
    s_wouo_tile_x_trg = 0;
    s_wouo_tile_y = -LCD_WOUO_TILE_ICON_H * LCD_WOUO_SCALE;
    s_wouo_tile_y_trg = 14 * LCD_WOUO_SCALE;
    s_wouo_title_y = 94 * LCD_WOUO_SCALE;
    s_wouo_title_y_trg = 61 * LCD_WOUO_SCALE;
    s_wouo_indi_w = 0;
    s_wouo_indi_w_trg = 10 * LCD_WOUO_SCALE;
    s_wouo_list_y = 16 * LCD_WOUO_SCALE;
    s_wouo_list_y_trg = 0;
    s_wouo_list_box_y = 0;
    s_wouo_list_box_y_trg = 20 * LCD_WOUO_SCALE;
    s_wouo_list_box_w = 0;
    s_wouo_list_box_w_trg = 64 * LCD_WOUO_SCALE;
    s_wouo_list_bar_y = 0;
    s_wouo_list_bar_y_trg = 18 * LCD_WOUO_SCALE;
    s_wouo_popup_y = -96 * LCD_WOUO_SCALE;
    s_wouo_popup_y_trg = -96 * LCD_WOUO_SCALE;
    s_wouo_anim_active = 1u;
    s_wouo_last_menu_index = 0xFFu;
    s_wouo_last_menu_active = 0xFFu;
    s_wouo_last_active_app = 0xFFu;

    ls013_lcd_init();
    lcd_redraw_page();
}

uint8_t lcd_status_is_menu_active(void) {
    return s_menu_active;
}

void lcd_status_next_page(void) {
    if (s_menu_active != 0u) {
        lcd_status_set_page((uint8_t)(s_menu_index + 1u));
    }
}

void lcd_status_prev_page(void) {
    if (s_menu_active != 0u) {
        lcd_status_set_page((uint8_t)(s_menu_index + LCD_APP_COUNT - 1u));
    }
}

void lcd_status_confirm(void) {
    if (s_menu_active != 0u) {
        s_active_app = s_menu_index;
        s_menu_active = 0u;
        s_last_fido_store_result = 0u;
        s_page_dirty = 1u;
    }
}

void lcd_status_back(void) {
    if (s_menu_active == 0u) {
        s_menu_active = 1u;
        s_menu_index = s_active_app;
        s_page_dirty = 1u;
    }
}

uint8_t lcd_status_get_active_app(void) {
    return s_active_app;
}

void lcd_status_set_fido_store_result(uint8_t result) {
    if (s_last_fido_store_result != result) {
        s_last_fido_store_result = result;
        s_page_dirty = 1u;
    }
}

void lcd_status_set_fido_store_progress(uint8_t active, uint8_t progress) {
    if ((s_fido_wipe_active != active) || (s_fido_wipe_progress != progress)) {
        s_fido_wipe_active = active;
        s_fido_wipe_progress = progress;
        s_page_dirty = 1u;
        if (s_lcd_ready != 0u) {
            lcd_redraw_page();
        }
    }
}

void lcd_status_set_fido_delete_progress(uint8_t active, uint8_t progress) {
    if ((s_fido_delete_active != active) || (s_fido_delete_progress != progress)) {
        s_fido_delete_active = active;
        s_fido_delete_progress = progress;
        s_page_dirty = 1u;
        if (s_lcd_ready != 0u) {
            lcd_redraw_page();
        }
    }
}

void lcd_status_set_fido_delete_state(uint16_t count, uint16_t index, const char *name) {
    if ((s_last_fido_delete_count != count) ||
        (s_last_fido_delete_index != index) ||
        (strcmp((name != NULL) ? name : "", s_last_fido_delete_name) != 0)) {
        s_last_fido_delete_count = count;
        s_last_fido_delete_index = index;
        memset(s_last_fido_delete_name, 0, sizeof(s_last_fido_delete_name));
        if (name != NULL) {
            strncpy(s_last_fido_delete_name, name, sizeof(s_last_fido_delete_name) - 1u);
        }
        s_page_dirty = 1u;
    }
}

void lcd_status_tick(uint32_t now_ms) {
    if (s_lcd_ready == 0u) {
        return;
    }
    ls013_lcd_tick(now_ms);
    if ((s_wouo_anim_active != 0u) &&
        ((uint32_t)(now_ms - s_last_anim_ms) >= LCD_WOUO_FRAME_MS)) {
        s_last_anim_ms = now_ms;
        lcd_redraw_page();
    } else if ((s_menu_active == 0u) &&
               (s_active_app == LCD_STATUS_APP_HID_INPUT) &&
               ((uint32_t)(now_ms - s_last_anim_ms) >= 200u)) {
        s_last_anim_ms = now_ms;
        lcd_redraw_page();
    }
}

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
                       uint32_t last_events) {
    if (s_lcd_ready == 0u) {
        return;
    }

    if (dev_state == s_last_dev_state &&
        dev_config == s_last_dev_config &&
        reset_count == s_last_reset_count &&
        setup_count == s_last_setup_count &&
        data_out_count == s_last_data_out_count &&
        data_in_count == s_last_data_in_count &&
        suspend_count == s_last_suspend_count &&
        dap_rx_count == s_last_dap_rx_count &&
        dap_tx_count == s_last_dap_tx_count &&
        fido_rx_count == s_last_fido_rx_count &&
        fido_tx_count == s_last_fido_tx_count &&
        fido_last_req_word0 == s_last_fido_last_req_word0 &&
        fido_last_rsp_word0 == s_last_fido_last_rsp_word0 &&
        fido_last_status == s_last_fido_last_status &&
        fido_ui_state == s_last_fido_ui_state &&
        fido_pending_cmd == s_last_fido_pending_cmd &&
        fido_selection_count == s_last_fido_selection_count &&
        fido_selection_index == s_last_fido_selection_index &&
        strcmp((fido_selection_name != NULL) ? fido_selection_name : "", s_last_fido_selection_name) == 0 &&
        flash_present == s_last_flash_present &&
        flash_jedec_id == s_last_flash_jedec_id &&
        flash_capacity_bytes == s_last_flash_capacity_bytes &&
        flash_mode == s_last_flash_mode &&
        enc_a == s_last_enc_a &&
        enc_b == s_last_enc_b &&
        enc_btn == s_last_enc_btn &&
        encoder_position == s_last_encoder_position &&
        last_events == s_last_events &&
        s_page_dirty == 0u) {
        return;
    }

    s_last_dev_state = dev_state;
    s_last_dev_config = dev_config;
    s_last_reset_count = reset_count;
    s_last_setup_count = setup_count;
    s_last_data_out_count = data_out_count;
    s_last_data_in_count = data_in_count;
    s_last_suspend_count = suspend_count;
    s_last_dap_rx_count = dap_rx_count;
    s_last_dap_tx_count = dap_tx_count;
    s_last_fido_rx_count = fido_rx_count;
    s_last_fido_tx_count = fido_tx_count;
    s_last_fido_last_req_word0 = fido_last_req_word0;
    s_last_fido_last_rsp_word0 = fido_last_rsp_word0;
    s_last_fido_last_status = fido_last_status;
    s_last_fido_ui_state = fido_ui_state;
    s_last_fido_pending_cmd = fido_pending_cmd;
    s_last_fido_selection_count = fido_selection_count;
    s_last_fido_selection_index = fido_selection_index;
    memset(s_last_fido_selection_name, 0, sizeof(s_last_fido_selection_name));
    if (fido_selection_name != NULL) {
        strncpy(s_last_fido_selection_name, fido_selection_name, sizeof(s_last_fido_selection_name) - 1u);
    }
    s_last_flash_present = flash_present;
    s_last_flash_jedec_id = flash_jedec_id;
    s_last_flash_capacity_bytes = flash_capacity_bytes;
    s_last_flash_mode = flash_mode;
    s_last_enc_a = enc_a;
    s_last_enc_b = enc_b;
    s_last_enc_btn = enc_btn;
    s_last_encoder_position = encoder_position;
    s_last_events = last_events;
    s_page_dirty = 0u;
    lcd_redraw_page();
}
