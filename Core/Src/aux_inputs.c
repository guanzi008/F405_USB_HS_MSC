#include "aux_inputs.h"

#include "main.h"

#define ENC_A_Pin GPIO_PIN_15
#define ENC_A_GPIO_Port GPIOC
#define ENC_B_Pin GPIO_PIN_13
#define ENC_B_GPIO_Port GPIOC
#define ENC_BTN_Pin GPIO_PIN_14
#define ENC_BTN_GPIO_Port GPIOC

#define RGB_R_Pin GPIO_PIN_8
#define RGB_R_GPIO_Port GPIOA
#define RGB_G_Pin GPIO_PIN_9
#define RGB_G_GPIO_Port GPIOA
#define RGB_B_Pin GPIO_PIN_10
#define RGB_B_GPIO_Port GPIOA

#define BUZZER_Pin GPIO_PIN_14
#define BUZZER_GPIO_Port GPIOB
#define ENC_POSITION_STEP 2

typedef struct {
    uint8_t last_ab;
    int8_t accum;
    uint8_t btn_last_sample;
    uint8_t btn_stable;
    uint32_t btn_last_change_ms;
    uint32_t btn_press_start_ms;
    uint8_t long_reported;
    int32_t encoder_position;
    uint32_t last_events;
    uint32_t event_count;
    uint32_t pending_events;
} aux_state_t;

static volatile aux_state_t s_aux;

static int8_t aux_quad_delta(uint8_t prev_state, uint8_t curr_state) {
    static const int8_t k_delta[16] = {
         0,  1, -1,  0,
        -1,  0,  0,  1,
         1,  0,  0, -1,
         0, -1,  1,  0
    };
    return k_delta[((prev_state & 0x3u) << 2) | (curr_state & 0x3u)];
}

static uint8_t aux_read_ab(void) {
    uint32_t idr = GPIOC->IDR;
    uint8_t a = ((idr & ENC_A_Pin) != 0u) ? 1u : 0u;
    uint8_t b = ((idr & ENC_B_Pin) != 0u) ? 1u : 0u;
    return (uint8_t)((a << 1) | b);
}

static uint8_t aux_read_btn(void) {
    return ((GPIOC->IDR & ENC_BTN_Pin) != 0u) ? 1u : 0u;
}

static void aux_record_events(uint32_t events) {
    if (events == AUX_INPUT_EVENT_NONE) {
        return;
    }

    s_aux.pending_events |= events;
    s_aux.last_events = events;
    s_aux.event_count += 1u;
}

static void aux_process_ab_sample(uint32_t now_ms) {
    uint8_t ab = aux_read_ab();

    (void)now_ms;

    if (ab != s_aux.last_ab) {
        int8_t delta = aux_quad_delta(s_aux.last_ab, ab);
        s_aux.last_ab = ab;
        if (delta == 0) {
            s_aux.accum = 0;
        } else {
            uint32_t events = AUX_INPUT_EVENT_NONE;

            s_aux.accum = (int8_t)(s_aux.accum + delta);
            if (s_aux.accum >= ENC_POSITION_STEP) {
                s_aux.accum = 0;
                s_aux.encoder_position += 1;
                events |= AUX_INPUT_EVENT_CW;
            } else if (s_aux.accum <= -ENC_POSITION_STEP) {
                s_aux.accum = 0;
                s_aux.encoder_position -= 1;
                events |= AUX_INPUT_EVENT_CCW;
            }
            aux_record_events(events);
        }
    }
}

static void aux_config_outputs(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();

    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;

    GPIO_InitStruct.Pin = RGB_R_Pin | RGB_G_Pin | RGB_B_Pin;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = BUZZER_Pin;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    HAL_GPIO_WritePin(GPIOA, RGB_R_Pin | RGB_G_Pin | RGB_B_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(GPIOB, BUZZER_Pin, GPIO_PIN_RESET);
}

static void aux_config_inputs(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    __HAL_RCC_GPIOC_CLK_ENABLE();

    GPIO_InitStruct.Pin = ENC_A_Pin | ENC_B_Pin;
    GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING_FALLING;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = ENC_BTN_Pin;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

    HAL_NVIC_SetPriority(EXTI15_10_IRQn, 5u, 0u);
    HAL_NVIC_EnableIRQ(EXTI15_10_IRQn);
}

static void aux_apply_event_feedback(uint32_t events) {
    if ((events & AUX_INPUT_EVENT_BTN_SHORT) != 0u) {
        aux_rgb_set(0u, 1u, 1u);
        aux_beep(2800u, 36u);
    }

    if ((events & AUX_INPUT_EVENT_BTN_LONG) != 0u) {
        aux_rgb_set(1u, 0u, 1u);
        aux_beep(1200u, 90u);
    }
}

void aux_inputs_init(void) {
    aux_config_outputs();
    aux_config_inputs();

    s_aux.last_ab = aux_read_ab();
    s_aux.accum = 0;
    s_aux.btn_last_sample = aux_read_btn();
    s_aux.btn_stable = s_aux.btn_last_sample;
    s_aux.btn_last_change_ms = 0u;
    s_aux.btn_press_start_ms = 0u;
    s_aux.long_reported = 0u;
    s_aux.encoder_position = 0;
    s_aux.last_events = AUX_INPUT_EVENT_NONE;
    s_aux.event_count = 0u;
    s_aux.pending_events = AUX_INPUT_EVENT_NONE;

    aux_rgb_set(0u, 0u, 1u);
}

uint32_t aux_inputs_poll(uint32_t now_ms) {
    uint32_t events = AUX_INPUT_EVENT_NONE;
    uint8_t btn = aux_read_btn();
    uint32_t pending_events;

    if (btn != s_aux.btn_last_sample) {
        s_aux.btn_last_sample = btn;
        s_aux.btn_last_change_ms = now_ms;
    }

    if ((uint32_t)(now_ms - s_aux.btn_last_change_ms) >= 5u) {
        if (s_aux.btn_stable != s_aux.btn_last_sample) {
            s_aux.btn_stable = s_aux.btn_last_sample;
            if (s_aux.btn_stable == 0u) {
                s_aux.btn_press_start_ms = now_ms;
                s_aux.long_reported = 0u;
            } else if (s_aux.long_reported == 0u) {
                events |= AUX_INPUT_EVENT_BTN_SHORT;
            }
        }
    }

    if ((s_aux.btn_stable == 0u) &&
        (s_aux.long_reported == 0u) &&
        ((uint32_t)(now_ms - s_aux.btn_press_start_ms) >= 500u)) {
        s_aux.long_reported = 1u;
        events |= AUX_INPUT_EVENT_BTN_LONG;
    }

    __disable_irq();
    pending_events = s_aux.pending_events;
    s_aux.pending_events = AUX_INPUT_EVENT_NONE;
    __enable_irq();
    events |= pending_events;

    if (events != AUX_INPUT_EVENT_NONE) {
        if ((events & (AUX_INPUT_EVENT_BTN_SHORT | AUX_INPUT_EVENT_BTN_LONG)) != 0u) {
            s_aux.last_events = events;
            s_aux.event_count += 1u;
        }
        aux_apply_event_feedback(events);
    } else {
        aux_rgb_set(0u, 0u, 0u);
    }

    return events;
}

void aux_inputs_get_status(aux_inputs_status_t *status) {
    if (status == 0) {
        return;
    }

    status->enc_a = (uint8_t)((aux_read_ab() >> 1) & 0x1u);
    status->enc_b = (uint8_t)(aux_read_ab() & 0x1u);
    status->enc_btn = aux_read_btn();
    status->encoder_position = s_aux.encoder_position;
    status->last_events = s_aux.last_events;
    status->event_count = s_aux.event_count;
}

void aux_rgb_set(uint8_t r, uint8_t g, uint8_t b) {
    HAL_GPIO_WritePin(RGB_R_GPIO_Port, RGB_R_Pin, r ? GPIO_PIN_SET : GPIO_PIN_RESET);
    HAL_GPIO_WritePin(RGB_G_GPIO_Port, RGB_G_Pin, g ? GPIO_PIN_SET : GPIO_PIN_RESET);
    HAL_GPIO_WritePin(RGB_B_GPIO_Port, RGB_B_Pin, b ? GPIO_PIN_SET : GPIO_PIN_RESET);
}

void aux_beep(uint16_t freq_hz, uint16_t dur_ms) {
    uint32_t cycles;
    uint32_t half_period_us;
    uint32_t i;

    if ((freq_hz == 0u) || (dur_ms == 0u)) {
        return;
    }

    half_period_us = 500000u / (uint32_t)freq_hz;
    if (half_period_us == 0u) {
        half_period_us = 1u;
    }
    cycles = ((uint32_t)dur_ms * (uint32_t)freq_hz) / 1000u;
    if (cycles == 0u) {
        cycles = 1u;
    }

    for (i = 0u; i < cycles; ++i) {
        HAL_GPIO_WritePin(BUZZER_GPIO_Port, BUZZER_Pin, GPIO_PIN_SET);
        HAL_Delay(0);
        for (volatile uint32_t wait = 0u; wait < (half_period_us * 18u); ++wait) {
            __asm volatile ("nop");
        }
        HAL_GPIO_WritePin(BUZZER_GPIO_Port, BUZZER_Pin, GPIO_PIN_RESET);
        for (volatile uint32_t wait = 0u; wait < (half_period_us * 18u); ++wait) {
            __asm volatile ("nop");
        }
    }
}

void aux_inputs_handle_exti(uint16_t gpio_pin, uint32_t now_ms) {
    if ((gpio_pin == ENC_A_Pin) || (gpio_pin == ENC_B_Pin)) {
        aux_process_ab_sample(now_ms);
    }
}
