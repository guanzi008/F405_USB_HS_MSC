#include "ls013_lcd.h"

#include <stdint.h>
#include <string.h>

#define REG32(addr) (*(volatile uint32_t *)(addr))

#define RCC_BASE 0x40023800u
#define RCC_AHB1ENR REG32(RCC_BASE + 0x30u)
#define RCC_APB1ENR REG32(RCC_BASE + 0x40u)

#define GPIOB_BASE 0x40020400u
#define GPIOC_BASE 0x40020800u

#define GPIO_MODER(base) REG32((base) + 0x00u)
#define GPIO_OTYPER(base) REG32((base) + 0x04u)
#define GPIO_OSPEEDR(base) REG32((base) + 0x08u)
#define GPIO_PUPDR(base) REG32((base) + 0x0Cu)
#define GPIO_BSRR(base) REG32((base) + 0x18u)
#define GPIO_AFRL(base) REG32((base) + 0x20u)
#define GPIO_AFRH(base) REG32((base) + 0x24u)

#define SPI3_BASE 0x40003C00u
#define SPI_CR1(base) REG32((base) + 0x00u)
#define SPI_SR(base) REG32((base) + 0x08u)
#define SPI_DR8(base) (*(volatile uint8_t *)((base) + 0x0Cu))

#define LCD_PAGE_PACKET_BYTES 146u
#define LCD_PAGE_ROW_COUNT 8u
#define LCD_FB_BYTES (LS013_LCD_ROWS * LS013_LCD_LINE_BYTES)
#define LCD_FRAME_PAGES (LS013_LCD_ROWS / LCD_PAGE_ROW_COUNT)
#define LCD_FRAME_REFRESH_MS 1000u

#define LCD_DISP_GPIO GPIOC_BASE
#define LCD_DISP_PIN 5u
#define LCD_SCS_GPIO GPIOC_BASE
#define LCD_SCS_PIN 4u

static uint8_t s_vcom_phase;
static uint32_t s_last_frame_ms;
static uint8_t s_fb[LCD_FB_BYTES];

static void gpio_output_pp(uint32_t gpio, uint8_t pin) {
    uint32_t sh2 = (uint32_t)pin * 2u;
    GPIO_MODER(gpio) &= ~(0x3u << sh2);
    GPIO_MODER(gpio) |= (0x1u << sh2);
    GPIO_OTYPER(gpio) &= ~(1u << pin);
    GPIO_OSPEEDR(gpio) &= ~(0x3u << sh2);
    GPIO_OSPEEDR(gpio) |= (0x2u << sh2);
    GPIO_PUPDR(gpio) &= ~(0x3u << sh2);
}

static void gpio_set_af(uint32_t gpio, uint8_t pin, uint8_t af) {
    uint32_t sh2 = (uint32_t)pin * 2u;
    uint32_t sh4;

    GPIO_MODER(gpio) &= ~(0x3u << sh2);
    GPIO_MODER(gpio) |= (0x2u << sh2);
    GPIO_OTYPER(gpio) &= ~(1u << pin);
    GPIO_OSPEEDR(gpio) &= ~(0x3u << sh2);
    GPIO_OSPEEDR(gpio) |= (0x2u << sh2);
    GPIO_PUPDR(gpio) &= ~(0x3u << sh2);

    if (pin < 8u) {
        sh4 = (uint32_t)pin * 4u;
        GPIO_AFRL(gpio) &= ~(0xFu << sh4);
        GPIO_AFRL(gpio) |= ((uint32_t)af << sh4);
    } else {
        sh4 = ((uint32_t)pin - 8u) * 4u;
        GPIO_AFRH(gpio) &= ~(0xFu << sh4);
        GPIO_AFRH(gpio) |= ((uint32_t)af << sh4);
    }
}

static void gpio_write(uint32_t gpio, uint8_t pin, uint8_t high) {
    if (high != 0u) {
        GPIO_BSRR(gpio) = (1u << pin);
    } else {
        GPIO_BSRR(gpio) = (1u << (pin + 16u));
    }
}

static void spi_send_bytes_hw(const uint8_t *data, uint16_t len) {
    uint16_t i;
    volatile uint32_t v;

    if ((SPI_SR(SPI3_BASE) & ((1u << 0) | (1u << 6))) != 0u) {
        v = SPI_DR8(SPI3_BASE);
        v = SPI_SR(SPI3_BASE);
        (void)v;
    }

    for (i = 0u; i < len; ++i) {
        while ((SPI_SR(SPI3_BASE) & (1u << 1)) == 0u) {
        }
        SPI_DR8(SPI3_BASE) = data[i];
        while ((SPI_SR(SPI3_BASE) & (1u << 0)) == 0u) {
        }
        v = SPI_DR8(SPI3_BASE);
        (void)v;
    }

    while ((SPI_SR(SPI3_BASE) & (1u << 7)) != 0u) {
    }

    if ((SPI_SR(SPI3_BASE) & (1u << 6)) != 0u) {
        v = SPI_DR8(SPI3_BASE);
        v = SPI_SR(SPI3_BASE);
        (void)v;
    }
}

static void lcd_spi3_init(void) {
    uint32_t cr1;

    RCC_AHB1ENR |= (1u << 1) | (1u << 2);
    RCC_APB1ENR |= (1u << 15);

    gpio_set_af(GPIOC_BASE, 10u, 6u);
    gpio_set_af(GPIOC_BASE, 12u, 6u);
    gpio_set_af(GPIOB_BASE, 4u, 6u);

    gpio_output_pp(LCD_SCS_GPIO, LCD_SCS_PIN);
    gpio_output_pp(LCD_DISP_GPIO, LCD_DISP_PIN);
    gpio_write(LCD_SCS_GPIO, LCD_SCS_PIN, 0u);
    gpio_write(LCD_DISP_GPIO, LCD_DISP_PIN, 1u);

    cr1 = (1u << 2) | (2u << 3) | (1u << 9) | (1u << 8) | (1u << 6);
    SPI_CR1(SPI3_BASE) = 0u;
    SPI_CR1(SPI3_BASE) = cr1;
}

static uint8_t bitrev8(uint8_t v) {
    v = (uint8_t)(((v & 0x55u) << 1) | ((v & 0xAAu) >> 1));
    v = (uint8_t)(((v & 0x33u) << 2) | ((v & 0xCCu) >> 2));
    v = (uint8_t)(((v & 0x0Fu) << 4) | ((v & 0xF0u) >> 4));
    return v;
}

static void lcd_tx_begin(void) {
    gpio_write(LCD_SCS_GPIO, LCD_SCS_PIN, 1u);
}

static void lcd_tx_end(void) {
    gpio_write(LCD_SCS_GPIO, LCD_SCS_PIN, 0u);
}

static void lcd_build_page_packet(uint8_t page_idx, uint8_t cmd, uint8_t *pkt) {
    uint8_t row;

    pkt[0] = cmd;
    for (row = 0u; row < LCD_PAGE_ROW_COUNT; ++row) {
        uint8_t y = (uint8_t)(page_idx * LCD_PAGE_ROW_COUNT + row);
        uint16_t base = (uint16_t)(1u + row * 18u);
        uint8_t xb;

        pkt[base] = bitrev8((uint8_t)(y + 1u));
        for (xb = 0u; xb < LS013_LCD_LINE_BYTES; ++xb) {
            pkt[(uint16_t)(base + 1u + xb)] = bitrev8(s_fb[(uint16_t)y * LS013_LCD_LINE_BYTES + xb]);
        }
        pkt[(uint16_t)(base + 17u)] = 0x00u;
    }
    pkt[LCD_PAGE_PACKET_BYTES - 1u] = 0x00u;
}

static void lcd_send_page(uint8_t page_idx) {
    uint8_t pkt[LCD_PAGE_PACKET_BYTES];
    uint8_t cmd = (s_vcom_phase != 0u) ? 0xC0u : 0x80u;

    lcd_build_page_packet(page_idx, cmd, pkt);
    lcd_tx_begin();
    spi_send_bytes_hw(pkt, (uint16_t)sizeof(pkt));
    lcd_tx_end();
}

void ls013_lcd_clear(uint8_t fill_byte) {
    memset(s_fb, fill_byte, sizeof(s_fb));
}

void ls013_lcd_set_pixel(uint8_t x, uint8_t y, uint8_t on) {
    uint16_t idx;
    uint8_t mask;

    if (x >= LS013_LCD_COLS || y >= LS013_LCD_ROWS) {
        return;
    }

    idx = (uint16_t)y * LS013_LCD_LINE_BYTES + (uint16_t)(x >> 3);
    mask = (uint8_t)(1u << (x & 7u));
    if (on != 0u) {
        s_fb[idx] &= (uint8_t)(~mask);
    } else {
        s_fb[idx] |= mask;
    }
}

void ls013_lcd_hline(uint8_t x, uint8_t y, uint8_t w, uint8_t on) {
    uint8_t i;
    for (i = 0u; i < w; ++i) {
        ls013_lcd_set_pixel((uint8_t)(x + i), y, on);
    }
}

void ls013_lcd_vline(uint8_t x, uint8_t y, uint8_t h, uint8_t on) {
    uint8_t i;
    for (i = 0u; i < h; ++i) {
        ls013_lcd_set_pixel(x, (uint8_t)(y + i), on);
    }
}

void ls013_lcd_rect(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint8_t on) {
    uint8_t i;
    for (i = 0u; i < h; ++i) {
        ls013_lcd_hline(x, (uint8_t)(y + i), w, on);
    }
}

void ls013_lcd_frame(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint8_t on) {
    if (w == 0u || h == 0u) {
        return;
    }
    ls013_lcd_hline(x, y, w, on);
    ls013_lcd_hline(x, (uint8_t)(y + h - 1u), w, on);
    ls013_lcd_vline(x, y, h, on);
    ls013_lcd_vline((uint8_t)(x + w - 1u), y, h, on);
}

void ls013_lcd_send_frame(void) {
    uint8_t page;
    for (page = 0u; page < LCD_FRAME_PAGES; ++page) {
        lcd_send_page(page);
    }
    s_vcom_phase ^= 1u;
}

void ls013_lcd_init(void) {
    lcd_spi3_init();
    s_vcom_phase = 0u;
    s_last_frame_ms = 0u;
    ls013_lcd_clear(0xFFu);
}

void ls013_lcd_tick(uint32_t now_ms) {
    if ((uint32_t)(now_ms - s_last_frame_ms) >= LCD_FRAME_REFRESH_MS) {
        s_last_frame_ms = now_ms;
        ls013_lcd_send_frame();
    }
}
