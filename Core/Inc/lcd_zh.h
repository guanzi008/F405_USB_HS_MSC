#ifndef LCD_ZH_H
#define LCD_ZH_H

#include <stdint.h>

typedef struct {
    uint8_t width;
    uint8_t height;
    const uint8_t *data;
} lcd_zh_bitmap_t;

typedef enum {
    LCD_ZH_MENU = 0,
    LCD_ZH_DEBUG = 1,
    LCD_ZH_KEY = 2,
    LCD_ZH_FLASH = 3,
    LCD_ZH_INPUT = 4,
    LCD_ZH_WIPE = 5,
    LCD_ZH_DELETE = 6,
    LCD_ZH_MENU_USB_DEBUG = 7,
    LCD_ZH_MENU_SECURITY_KEY = 8,
    LCD_ZH_MENU_SPI_FLASH = 9,
    LCD_ZH_MENU_INPUT_DEV = 10,
    LCD_ZH_MENU_WIPE_KEY = 11,
    LCD_ZH_MENU_DELETE_KEY = 12,
    LCD_ZH_SHORT_ENTER = 13,
    LCD_ZH_LONG_BACK = 14,
    LCD_ZH_WAIT_CONFIRM = 15,
    LCD_ZH_BUTTON_CONFIRM = 16,
    LCD_ZH_PRESENT = 17,
    LCD_ZH_NOT_FOUND = 18,
    LCD_ZH_CHECK_SPI1 = 19,
    LCD_ZH_FIDO_CONFIRM = 20,
    LCD_ZH_MAKE_CRED = 21,
    LCD_ZH_GET_ASSERT = 22,
    LCD_ZH_GET_INFO = 23,
    LCD_ZH_SHORT_OK = 24,
    LCD_ZH_LONG_CANCEL = 25,
    LCD_ZH_KNOB_SELECT = 26,
    LCD_ZH_ACCOUNT = 27,
    LCD_ZH_CLEAR_STORE = 28,
    LCD_ZH_ERASING = 29,
    LCD_ZH_PLEASE_WAIT = 30,
    LCD_ZH_SHORT_ERASE = 31,
    LCD_ZH_SHORT_DELETE = 32,
    LCD_ZH_DONE = 33,
    LCD_ZH_ERASE_FAIL = 34,
    LCD_ZH_DELETE_FAIL = 35,
    LCD_ZH_REREGISTER = 36,
    LCD_ZH_NO_KEY = 37,
    LCD_ZH_COUNT
} lcd_zh_id_t;

const lcd_zh_bitmap_t *lcd_zh_get(lcd_zh_id_t id);

#endif
