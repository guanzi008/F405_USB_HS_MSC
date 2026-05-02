#ifndef WOUO_LS013_H
#define WOUO_LS013_H

#include <stdint.h>

typedef struct {
    int16_t x;
    int16_t y;
    int16_t w;
    int16_t h;
} wouo_window_t;

void wouo_draw_text_6x8(uint8_t x, uint8_t y, uint8_t clear_w, const char *text, uint8_t fg, uint8_t bg);
uint8_t wouo_text_width_6x8(const char *text);
void wouo_draw_bitmap_rows(uint8_t x, uint8_t y, const uint8_t *bitmap, uint8_t width, uint8_t height, uint8_t on);
void wouo_draw_progress_bar(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint8_t progress);
uint8_t wouo_anim_i16(int16_t *value, int16_t target, uint8_t weight);

#endif
