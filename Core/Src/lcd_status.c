#include "lcd_status.h"

#include "ls013_lcd.h"
#include "usbd_ctap_min.h"

#include <stdio.h>
#include <string.h>

#define LCD_TEXT_X 8u
#define LCD_TEXT_Y0 36u
#define LCD_TEXT_PITCH 9u
#define LCD_APP_COUNT 5u
#define LCD_FIDO_RESERVED_BYTES (1024u * 1024u)
#define TITLE_W 28u
#define TITLE_H 22u
#define TITLE_ROW_BYTES 4u
#define TITLE_X 10u
#define TITLE_Y 8u

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

static const uint8_t k_title_debug[TITLE_H * TITLE_ROW_BYTES] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x27,0xF8,0xC1,0xA0,0x14,0x08,0x40,0x80,
    0x05,0xE8,0x1F,0xE0,0x04,0x48,0x00,0x80,0x74,0x49,0xC0,0x80,0x15,0xE8,0x40,0x80,
    0x14,0x08,0x5E,0x80,0x15,0xE8,0x44,0x80,0x15,0x28,0x44,0x80,0x15,0x28,0x44,0x80,
    0x1D,0xE8,0x66,0x80,0x3C,0x08,0xD8,0x60,0x08,0x38,0x00,0x60,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const uint8_t k_title_security[TITLE_H * TITLE_ROW_BYTES] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x02,0x00,0x04,0x00,0x03,0x00,0x0C,0x00,0x7F,0xF8,0x12,0x00,
    0x40,0x08,0x31,0x00,0x42,0x08,0x60,0x80,0x04,0x01,0x80,0x60,0x7F,0xF9,0x7F,0xE0,
    0x08,0x40,0x04,0x00,0x18,0x40,0x04,0x00,0x1C,0x80,0x7F,0x80,0x03,0x80,0x04,0x00,
    0x07,0xE0,0x04,0x00,0x1C,0x31,0xFF,0xE0,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const uint8_t k_title_storage[TITLE_H * TITLE_ROW_BYTES] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x04,0x00,0x41,0x00,0x04,0x00,0x61,0x20,0x7F,0xF8,0x97,0xE0,
    0x08,0x00,0x81,0x40,0x08,0x01,0x81,0xC0,0x13,0xF1,0xF7,0xE0,0x10,0x30,0x91,0x00,
    0x30,0x40,0x97,0xE0,0x70,0x40,0x9E,0x20,0x17,0xF8,0x92,0x20,0x10,0x40,0x93,0xE0,
    0x10,0x40,0x9A,0x20,0x10,0x40,0x93,0xE0,0x11,0x80,0x82,0x20,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const uint8_t k_title_input[TITLE_H * TITLE_ROW_BYTES] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x20,0x40,0x00,0x00,0x20,0xC0,0x00,0x00,0x79,0xB0,0x10,0x00,
    0x23,0x18,0x08,0x00,0x31,0xF0,0x0C,0x00,0x50,0x00,0x0C,0x00,0x53,0xC8,0x0A,0x00,
    0x7A,0x68,0x1A,0x00,0x13,0xE8,0x11,0x00,0x12,0x68,0x31,0x80,0x7B,0xE8,0x60,0x80,
    0x12,0x48,0xC0,0x40,0x12,0x49,0x80,0x20,0x12,0x98,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const uint8_t *font5x7_get(char ch) {
    static const uint8_t blank[5] = {0, 0, 0, 0, 0};
    switch (ch) {
        case 'A': { static const uint8_t g[5] = {0x7e, 0x09, 0x09, 0x09, 0x7e}; return g; }
        case 'B': { static const uint8_t g[5] = {0x7f, 0x49, 0x49, 0x49, 0x36}; return g; }
        case 'C': { static const uint8_t g[5] = {0x3e, 0x41, 0x41, 0x41, 0x22}; return g; }
        case 'D': { static const uint8_t g[5] = {0x7f, 0x41, 0x41, 0x22, 0x1c}; return g; }
        case 'E': { static const uint8_t g[5] = {0x7f, 0x49, 0x49, 0x49, 0x41}; return g; }
        case 'F': { static const uint8_t g[5] = {0x7f, 0x09, 0x09, 0x09, 0x01}; return g; }
        case 'G': { static const uint8_t g[5] = {0x3e, 0x41, 0x49, 0x49, 0x7a}; return g; }
        case 'H': { static const uint8_t g[5] = {0x7f, 0x08, 0x08, 0x08, 0x7f}; return g; }
        case 'I': { static const uint8_t g[5] = {0x00, 0x41, 0x7f, 0x41, 0x00}; return g; }
        case 'J': { static const uint8_t g[5] = {0x20, 0x40, 0x41, 0x3f, 0x01}; return g; }
        case 'K': { static const uint8_t g[5] = {0x7f, 0x08, 0x14, 0x22, 0x41}; return g; }
        case 'L': { static const uint8_t g[5] = {0x7f, 0x40, 0x40, 0x40, 0x40}; return g; }
        case 'M': { static const uint8_t g[5] = {0x7f, 0x02, 0x0c, 0x02, 0x7f}; return g; }
        case 'N': { static const uint8_t g[5] = {0x7f, 0x04, 0x08, 0x10, 0x7f}; return g; }
        case 'O': { static const uint8_t g[5] = {0x3e, 0x41, 0x41, 0x41, 0x3e}; return g; }
        case 'P': { static const uint8_t g[5] = {0x7f, 0x09, 0x09, 0x09, 0x06}; return g; }
        case 'Q': { static const uint8_t g[5] = {0x3e, 0x41, 0x51, 0x21, 0x5e}; return g; }
        case 'R': { static const uint8_t g[5] = {0x7f, 0x09, 0x19, 0x29, 0x46}; return g; }
        case 'S': { static const uint8_t g[5] = {0x46, 0x49, 0x49, 0x49, 0x31}; return g; }
        case 'T': { static const uint8_t g[5] = {0x01, 0x01, 0x7f, 0x01, 0x01}; return g; }
        case 'U': { static const uint8_t g[5] = {0x3f, 0x40, 0x40, 0x40, 0x3f}; return g; }
        case 'V': { static const uint8_t g[5] = {0x1f, 0x20, 0x40, 0x20, 0x1f}; return g; }
        case 'W': { static const uint8_t g[5] = {0x3f, 0x40, 0x38, 0x40, 0x3f}; return g; }
        case 'X': { static const uint8_t g[5] = {0x63, 0x14, 0x08, 0x14, 0x63}; return g; }
        case 'Y': { static const uint8_t g[5] = {0x07, 0x08, 0x70, 0x08, 0x07}; return g; }
        case 'Z': { static const uint8_t g[5] = {0x61, 0x51, 0x49, 0x45, 0x43}; return g; }
        case '0': { static const uint8_t g[5] = {0x3e, 0x41, 0x41, 0x41, 0x3e}; return g; }
        case '1': { static const uint8_t g[5] = {0x00, 0x42, 0x7f, 0x40, 0x00}; return g; }
        case '2': { static const uint8_t g[5] = {0x42, 0x61, 0x51, 0x49, 0x46}; return g; }
        case '3': { static const uint8_t g[5] = {0x21, 0x41, 0x49, 0x4d, 0x32}; return g; }
        case '4': { static const uint8_t g[5] = {0x18, 0x14, 0x12, 0x7f, 0x10}; return g; }
        case '5': { static const uint8_t g[5] = {0x27, 0x45, 0x45, 0x45, 0x39}; return g; }
        case '6': { static const uint8_t g[5] = {0x3e, 0x49, 0x49, 0x49, 0x32}; return g; }
        case '7': { static const uint8_t g[5] = {0x01, 0x71, 0x09, 0x05, 0x03}; return g; }
        case '8': { static const uint8_t g[5] = {0x36, 0x49, 0x49, 0x49, 0x36}; return g; }
        case '9': { static const uint8_t g[5] = {0x26, 0x49, 0x49, 0x49, 0x3e}; return g; }
        case '.': { static const uint8_t g[5] = {0x00, 0x60, 0x60, 0x00, 0x00}; return g; }
        case ':': { static const uint8_t g[5] = {0x00, 0x36, 0x36, 0x00, 0x00}; return g; }
        case '-': { static const uint8_t g[5] = {0x08, 0x08, 0x08, 0x08, 0x08}; return g; }
        case '/': { static const uint8_t g[5] = {0x20, 0x10, 0x08, 0x04, 0x02}; return g; }
        case '+': { static const uint8_t g[5] = {0x08, 0x08, 0x3e, 0x08, 0x08}; return g; }
        case '_': { static const uint8_t g[5] = {0x40, 0x40, 0x40, 0x40, 0x40}; return g; }
        case ' ': return blank;
        default: { static const uint8_t g[5] = {0x02, 0x01, 0x59, 0x09, 0x06}; return g; }
    }
}

static void lcd_draw_char(uint8_t x, uint8_t y, char ch) {
    const uint8_t *glyph;
    uint8_t col;
    uint8_t row;

    if (ch >= 'a' && ch <= 'z') {
        ch = (char)(ch - 'a' + 'A');
    }

    glyph = font5x7_get(ch);
    ls013_lcd_rect(x, y, 6u, 8u, 0u);
    for (col = 0u; col < 5u; ++col) {
        uint8_t bits = glyph[col];
        for (row = 0u; row < 7u; ++row) {
            if (((bits >> row) & 0x01u) != 0u) {
                ls013_lcd_set_pixel((uint8_t)(x + col), (uint8_t)(y + row), 1u);
            }
        }
    }
}

static void lcd_draw_text_line(uint8_t row, const char *text) {
    uint8_t x = LCD_TEXT_X;
    uint8_t y = (uint8_t)(LCD_TEXT_Y0 + row * LCD_TEXT_PITCH);

    ls013_lcd_rect(LCD_TEXT_X, (uint8_t)(y - 1u), 112u, 8u, 0u);
    while (*text != '\0' && x <= 118u) {
        lcd_draw_char(x, y, *text++);
        x = (uint8_t)(x + 6u);
    }
}

static void lcd_draw_text_at(uint8_t x, uint8_t y, uint8_t clear_w, const char *text)
{
    uint8_t draw_x = x;

    ls013_lcd_rect(x, (uint8_t)(y - 1u), clear_w, 8u, 0u);
    while (*text != '\0' && draw_x < (uint8_t)(x + clear_w - 5u)) {
        lcd_draw_char(draw_x, y, *text++);
        draw_x = (uint8_t)(draw_x + 6u);
    }
}

static void lcd_draw_bitmap_1bpp(uint8_t x, uint8_t y, const uint8_t *bitmap, uint8_t width, uint8_t height)
{
    uint8_t row;
    uint8_t col;
    uint8_t row_bytes = (uint8_t)((width + 7u) / 8u);

    for (row = 0u; row < height; ++row) {
        for (col = 0u; col < width; ++col) {
            uint8_t byte = bitmap[(uint16_t)row * row_bytes + (uint16_t)(col >> 3)];
            uint8_t bit = (uint8_t)(0x80u >> (col & 7u));
            if ((byte & bit) != 0u) {
                ls013_lcd_set_pixel((uint8_t)(x + col), (uint8_t)(y + row), 1u);
            }
        }
    }
}

static void lcd_draw_shell(const uint8_t *title_bitmap, const char *ascii_title) {
    char line[16];

    ls013_lcd_clear(0xFFu);
    ls013_lcd_frame(0u, 0u, 128u, 128u, 1u);
    ls013_lcd_frame(4u, 4u, 120u, 120u, 1u);
    ls013_lcd_hline(8u, 31u, 112u, 1u);
    lcd_draw_bitmap_1bpp(TITLE_X, TITLE_Y, title_bitmap, TITLE_W, TITLE_H);
    lcd_draw_text_line(0u, ascii_title);
    if (s_menu_active != 0u) {
        snprintf(line, sizeof(line), "MENU %u/%u", (unsigned)(s_menu_index + 1u), (unsigned)LCD_APP_COUNT);
    } else {
        snprintf(line, sizeof(line), "APP %u/%u", (unsigned)(s_active_app + 1u), (unsigned)LCD_APP_COUNT);
    }
    lcd_draw_text_line(11u, line);
}

static void lcd_draw_menu_page(void) {
    char line[24];

    lcd_draw_shell(k_title_input, "MENU");
    lcd_draw_text_line(1u, (s_menu_index == 0u) ? "> USB DEBUG" : "  USB DEBUG");
    lcd_draw_text_line(2u, (s_menu_index == 1u) ? "> FIDO KEY" : "  FIDO KEY");
    lcd_draw_text_line(3u, (s_menu_index == 2u) ? "> SPI FLASH" : "  SPI FLASH");
    lcd_draw_text_line(4u, (s_menu_index == 3u) ? "> INPUTS" : "  INPUTS");
    lcd_draw_text_line(5u, (s_menu_index == 4u) ? "> FIDO WIPE" : "  FIDO WIPE");
    snprintf(line, sizeof(line), "POS:%ld", (long)s_last_encoder_position);
    lcd_draw_text_line(6u, line);
    snprintf(line, sizeof(line), "A:%u B:%u K:%u", s_last_enc_a, s_last_enc_b, s_last_enc_btn);
    lcd_draw_text_line(7u, line);
    snprintf(line, sizeof(line), "EV:%08lX", s_last_events);
    lcd_draw_text_line(8u, line);
    lcd_draw_text_line(9u, "SHORT ENTER");
    lcd_draw_text_line(10u, "LONG BACK");
}

static void lcd_draw_usb_page(void) {
    char line[24];

    lcd_draw_shell(k_title_debug, "DEBUG");
    snprintf(line, sizeof(line), "DS:%u CFG:%u", s_last_dev_state, s_last_dev_config);
    lcd_draw_text_line(1u, line);
    snprintf(line, sizeof(line), "RST:%lu SET:%lu", s_last_reset_count, s_last_setup_count);
    lcd_draw_text_line(2u, line);
    snprintf(line, sizeof(line), "OUT:%lu IN:%lu", s_last_data_out_count, s_last_data_in_count);
    lcd_draw_text_line(3u, line);
    snprintf(line, sizeof(line), "SUSP:%lu", s_last_suspend_count);
    lcd_draw_text_line(4u, line);
    snprintf(line, sizeof(line), "DAP RX:%lu", s_last_dap_rx_count);
    lcd_draw_text_line(6u, line);
    snprintf(line, sizeof(line), "DAP TX:%lu", s_last_dap_tx_count);
    lcd_draw_text_line(7u, line);
    lcd_draw_text_line(9u, "USB CMSIS-DAP");
}

static void lcd_draw_security_page(void) {
    char line[24];
    const char *ui_text = "IDLE";
    const char *cmd_text = "--";

    lcd_draw_shell(k_title_security, "FIDO");
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
        default: cmd_text = "--"; break;
    }
    snprintf(line, sizeof(line), "RX:%lu TX:%lu", s_last_fido_rx_count, s_last_fido_tx_count);
    lcd_draw_text_line(1u, line);
    snprintf(line, sizeof(line), "REQ:%08lX", s_last_fido_last_req_word0);
    lcd_draw_text_line(2u, line);
    snprintf(line, sizeof(line), "RSP:%08lX", s_last_fido_last_rsp_word0);
    lcd_draw_text_line(3u, line);
    snprintf(line, sizeof(line), "STAT:%02lX", s_last_fido_last_status & 0xFFu);
    lcd_draw_text_line(4u, line);
    snprintf(line, sizeof(line), "UI:%s CMD:%s", ui_text, cmd_text);
    lcd_draw_text_line(6u, line);
    if (s_last_fido_ui_state == 1u) {
        lcd_draw_text_line(7u, "PRESS KNOB");
    } else {
        lcd_draw_text_line(7u, "MC/GA BUTTON");
    }
}

static void lcd_draw_flash_page(void) {
    char line[24];

    lcd_draw_shell(k_title_storage, "FLASH");
    if (s_last_flash_present != 0u) {
        lcd_draw_text_line(1u, "PRESENT");
        snprintf(line, sizeof(line), "ID:%06lX", s_last_flash_jedec_id & 0xFFFFFFu);
        lcd_draw_text_line(2u, line);
        snprintf(line, sizeof(line), "CAP:%luM", s_last_flash_capacity_bytes >> 20);
        lcd_draw_text_line(3u, line);
        snprintf(line, sizeof(line), "MODE:%u", s_last_flash_mode);
        lcd_draw_text_line(4u, line);
        snprintf(line, sizeof(line), "MSC:%luM", (s_last_flash_capacity_bytes - LCD_FIDO_RESERVED_BYTES) >> 20);
        lcd_draw_text_line(6u, line);
        lcd_draw_text_line(7u, "FIDO:RESV 1M");
    } else {
        lcd_draw_text_line(1u, "NOT FOUND");
        lcd_draw_text_line(2u, "CHK SPI1");
    }
    lcd_draw_text_line(9u, "PB3 PA6 PA7");
    lcd_draw_text_line(10u, "CS PA4");
}

static void lcd_draw_input_page(void) {
    char line[24];

    lcd_draw_shell(k_title_input, "INPUT");
    snprintf(line, sizeof(line), "A:%u B:%u K:%u", s_last_enc_a, s_last_enc_b, s_last_enc_btn);
    lcd_draw_text_line(1u, line);
    snprintf(line, sizeof(line), "POS:%ld", (long)s_last_encoder_position);
    lcd_draw_text_line(2u, line);
    snprintf(line, sizeof(line), "EV:%08lX", s_last_events);
    lcd_draw_text_line(3u, line);
    lcd_draw_text_line(5u, "ENC BUZ RGB");
    lcd_draw_text_line(6u, "SHORT:CYAN");
    lcd_draw_text_line(7u, "LONG:PURPLE");
}

static void lcd_draw_fido_wipe_page(void) {
    char line[24];

    lcd_draw_shell(k_title_security, "WIPE");
    lcd_draw_text_line(1u, "CLEAR FIDO STORE");
    if (s_fido_wipe_active != 0u) {
        snprintf(line, sizeof(line), "ERASE %u%%", (unsigned)s_fido_wipe_progress);
        lcd_draw_text_line(3u, line);
        lcd_draw_text_line(4u, "PLEASE WAIT");
    } else {
        lcd_draw_text_line(3u, "SHORT: ERASE");
        lcd_draw_text_line(4u, "LONG : BACK");
    }
    if (s_last_fido_store_result == 1u) {
        lcd_draw_text_line(6u, "DONE");
    } else if (s_last_fido_store_result == 2u) {
        lcd_draw_text_line(6u, "ERASE FAIL");
    } else {
        lcd_draw_text_line(6u, "READY");
    }
    lcd_draw_text_line(8u, "RE-REGISTER KEY");
}

static void lcd_draw_fido_popup(void)
{
    const char *cmd_text = "SECURITY";
    char line[24];

    if (s_last_fido_pending_cmd == CTAP_CMD_MAKE_CREDENTIAL) {
        cmd_text = "MAKE CRED";
    } else if (s_last_fido_pending_cmd == CTAP_CMD_GET_ASSERTION) {
        cmd_text = "GET ASSERT";
    } else if (s_last_fido_pending_cmd == CTAP_CMD_GET_INFO) {
        cmd_text = "GET INFO";
    }

    ls013_lcd_rect(12u, 34u, 104u, 60u, 0u);
    ls013_lcd_frame(12u, 34u, 104u, 60u, 1u);
    ls013_lcd_frame(14u, 36u, 100u, 56u, 1u);
    lcd_draw_text_at(24u, 43u, 80u, "FIDO CONFIRM");
    lcd_draw_text_at(28u, 58u, 72u, cmd_text);
    if ((s_last_fido_selection_count > 1u) && (s_last_fido_pending_cmd == CTAP_CMD_GET_ASSERTION)) {
        snprintf(line, sizeof(line), "USER %u/%u",
                 (unsigned)(s_last_fido_selection_index + 1u),
                 (unsigned)s_last_fido_selection_count);
        lcd_draw_text_at(22u, 70u, 84u, line);
        lcd_draw_text_at(22u, 78u, 84u, s_last_fido_selection_name[0] != '\0' ? s_last_fido_selection_name : "ACCOUNT");
        lcd_draw_text_at(22u, 86u, 84u, "KNOB SELECT");
        lcd_draw_text_at(22u, 94u, 84u, "SHORT OK");
    } else {
        lcd_draw_text_at(22u, 74u, 84u, "SHORT  OK");
        lcd_draw_text_at(22u, 84u, 84u, "LONG   BACK");
    }
}

static void lcd_redraw_page(void) {
    if (s_menu_active != 0u) {
        lcd_draw_menu_page();
    } else {
      switch (s_active_app) {
        case 0u:
            lcd_draw_usb_page();
            break;
        case 1u:
            lcd_draw_security_page();
            break;
        case 2u:
            lcd_draw_flash_page();
            break;
        case 4u:
            lcd_draw_fido_wipe_page();
            break;
        default:
            lcd_draw_input_page();
            break;
      }
    }
    if (s_last_fido_ui_state == USBD_CTAP_UI_WAIT_TOUCH) {
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

void lcd_status_tick(uint32_t now_ms) {
    if (s_lcd_ready == 0u) {
        return;
    }
    ls013_lcd_tick(now_ms);
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
