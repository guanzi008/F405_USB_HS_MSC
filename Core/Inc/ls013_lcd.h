#ifndef LS013_LCD_H
#define LS013_LCD_H

#include <stdint.h>

#define LS013_LCD_ROWS 128u
#define LS013_LCD_COLS 128u
#define LS013_LCD_LINE_BYTES 16u

void ls013_lcd_init(void);
void ls013_lcd_tick(uint32_t now_ms);

void ls013_lcd_clear(uint8_t fill_byte);
void ls013_lcd_set_pixel(uint8_t x, uint8_t y, uint8_t on);
void ls013_lcd_hline(uint8_t x, uint8_t y, uint8_t w, uint8_t on);
void ls013_lcd_vline(uint8_t x, uint8_t y, uint8_t h, uint8_t on);
void ls013_lcd_rect(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint8_t on);
void ls013_lcd_frame(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint8_t on);
void ls013_lcd_send_frame(void);

#endif
