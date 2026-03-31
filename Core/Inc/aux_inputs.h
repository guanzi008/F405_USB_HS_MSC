#ifndef AUX_INPUTS_H
#define AUX_INPUTS_H

#include <stdint.h>

#define AUX_INPUT_EVENT_NONE      0x00000000u
#define AUX_INPUT_EVENT_CW        0x00000001u
#define AUX_INPUT_EVENT_CCW       0x00000002u
#define AUX_INPUT_EVENT_BTN_SHORT 0x00000004u
#define AUX_INPUT_EVENT_BTN_LONG  0x00000008u

typedef struct {
    uint8_t enc_a;
    uint8_t enc_b;
    uint8_t enc_btn;
    int32_t encoder_position;
    uint32_t last_events;
    uint32_t event_count;
} aux_inputs_status_t;

void aux_inputs_init(void);
uint32_t aux_inputs_poll(uint32_t now_ms);
void aux_inputs_get_status(aux_inputs_status_t *status);
void aux_inputs_handle_exti(uint16_t gpio_pin, uint32_t now_ms);

void aux_rgb_set(uint8_t r, uint8_t g, uint8_t b);
void aux_beep(uint16_t freq_hz, uint16_t dur_ms);

#endif
