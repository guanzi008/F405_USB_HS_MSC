#include "ext_flash_w25q.h"

#include <string.h>

#define REG32(addr) (*(volatile uint32_t *)(addr))
#define REG8(addr) (*(volatile uint8_t *)(addr))

#define RCC_BASE 0x40023800u
#define RCC_AHB1ENR REG32(RCC_BASE + 0x30u)
#define RCC_APB2ENR REG32(RCC_BASE + 0x44u)

#define GPIOA_BASE 0x40020000u
#define GPIOB_BASE 0x40020400u

#define GPIO_MODER(base) REG32((base) + 0x00u)
#define GPIO_OTYPER(base) REG32((base) + 0x04u)
#define GPIO_OSPEEDR(base) REG32((base) + 0x08u)
#define GPIO_PUPDR(base) REG32((base) + 0x0Cu)
#define GPIO_BSRR(base) REG32((base) + 0x18u)
#define GPIO_AFRL(base) REG32((base) + 0x20u)

#define SPI1_BASE 0x40013000u
#define SPI_CR1(base) REG32((base) + 0x00u)
#define SPI_SR(base) REG32((base) + 0x08u)
#define SPI_DR8(base) REG8((base) + 0x0Cu)

#define FLASH_CS_GPIO GPIOA_BASE
#define FLASH_CS_PIN 4u

#define FLASH_CMD_READ_JEDEC_ID 0x9Fu
#define FLASH_CMD_WRITE_ENABLE 0x06u
#define FLASH_CMD_READ_STATUS1 0x05u
#define FLASH_CMD_READ_DATA_3B 0x03u
#define FLASH_CMD_READ_DATA_4B 0x13u
#define FLASH_CMD_PAGE_PROGRAM_3B 0x02u
#define FLASH_CMD_PAGE_PROGRAM_4B 0x12u
#define FLASH_CMD_SECTOR_ERASE_3B 0x20u
#define FLASH_CMD_SECTOR_ERASE_4B 0x21u

#define FLASH_STATUS_BUSY 0x01u
#define FLASH_PAGE_SIZE 256u
#define FLASH_SECTOR_SIZE 4096u

static ext_flash_info_t s_flash_info;
static uint8_t s_sector_buf[FLASH_SECTOR_SIZE];

static void gpio_output_pp(uint32_t gpio, uint8_t pin)
{
  uint32_t sh2 = (uint32_t)pin * 2u;
  GPIO_MODER(gpio) &= ~(0x3u << sh2);
  GPIO_MODER(gpio) |= (0x1u << sh2);
  GPIO_OTYPER(gpio) &= ~(1u << pin);
  GPIO_OSPEEDR(gpio) &= ~(0x3u << sh2);
  GPIO_OSPEEDR(gpio) |= (0x2u << sh2);
  GPIO_PUPDR(gpio) &= ~(0x3u << sh2);
}

static void gpio_set_af(uint32_t gpio, uint8_t pin, uint8_t af)
{
  uint32_t sh2 = (uint32_t)pin * 2u;
  uint32_t sh4 = (uint32_t)pin * 4u;

  GPIO_MODER(gpio) &= ~(0x3u << sh2);
  GPIO_MODER(gpio) |= (0x2u << sh2);
  GPIO_OTYPER(gpio) &= ~(1u << pin);
  GPIO_OSPEEDR(gpio) &= ~(0x3u << sh2);
  GPIO_OSPEEDR(gpio) |= (0x2u << sh2);
  GPIO_PUPDR(gpio) &= ~(0x3u << sh2);
  GPIO_AFRL(gpio) &= ~(0xFu << sh4);
  GPIO_AFRL(gpio) |= ((uint32_t)af << sh4);
}

static void gpio_write(uint32_t gpio, uint8_t pin, uint8_t high)
{
  if (high != 0u)
  {
    GPIO_BSRR(gpio) = (1u << pin);
  }
  else
  {
    GPIO_BSRR(gpio) = (1u << (pin + 16u));
  }
}

static void flash_spi1_init(uint8_t mode)
{
  uint32_t cr1 = 0u;

  RCC_AHB1ENR |= (1u << 0) | (1u << 1);
  RCC_APB2ENR |= (1u << 12);

  gpio_output_pp(FLASH_CS_GPIO, FLASH_CS_PIN);
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 1u);

  gpio_set_af(GPIOB_BASE, 3u, 5u);
  gpio_set_af(GPIOA_BASE, 6u, 5u);
  gpio_set_af(GPIOA_BASE, 7u, 5u);

  SPI_CR1(SPI1_BASE) = 0u;
  cr1 |= (1u << 2);         /* master */
  cr1 |= (3u << 3);         /* fPCLK/16 */
  cr1 |= (1u << 8) | (1u << 9); /* SSI/SSM */
  if ((mode & 0x1u) != 0u)
  {
    cr1 |= (1u << 0);
  }
  if ((mode & 0x2u) != 0u)
  {
    cr1 |= (1u << 1);
  }
  cr1 |= (1u << 6);         /* SPE */
  SPI_CR1(SPI1_BASE) = cr1;
}

static uint8_t flash_spi1_xfer(uint8_t tx)
{
  while ((SPI_SR(SPI1_BASE) & (1u << 1)) == 0u)
  {
  }

  SPI_DR8(SPI1_BASE) = tx;

  while ((SPI_SR(SPI1_BASE) & (1u << 0)) == 0u)
  {
  }

  return SPI_DR8(SPI1_BASE);
}

static void flash_wait_not_busy(void)
{
  uint8_t status;

  do
  {
    gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 0u);
    (void)flash_spi1_xfer(FLASH_CMD_READ_STATUS1);
    status = flash_spi1_xfer(0xFFu);
    gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 1u);
  } while ((status & FLASH_STATUS_BUSY) != 0u);
}

static void flash_write_enable(void)
{
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 0u);
  (void)flash_spi1_xfer(FLASH_CMD_WRITE_ENABLE);
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 1u);
}

static uint8_t flash_use_4byte_addr(uint32_t address_end)
{
  return (s_flash_info.capacity_bytes > 0x01000000u) ||
         (address_end > 0x01000000u);
}

static void flash_send_address(uint32_t address, uint8_t use_4byte)
{
  if (use_4byte != 0u)
  {
    (void)flash_spi1_xfer((uint8_t)(address >> 24));
  }
  (void)flash_spi1_xfer((uint8_t)(address >> 16));
  (void)flash_spi1_xfer((uint8_t)(address >> 8));
  (void)flash_spi1_xfer((uint8_t)(address));
}

static uint32_t flash_read_jedec_id(void)
{
  uint32_t id;

  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 0u);
  (void)flash_spi1_xfer(FLASH_CMD_READ_JEDEC_ID);
  id  = ((uint32_t)flash_spi1_xfer(0xFFu) << 16);
  id |= ((uint32_t)flash_spi1_xfer(0xFFu) << 8);
  id |= ((uint32_t)flash_spi1_xfer(0xFFu));
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 1u);

  return id;
}

static uint32_t flash_decode_capacity(uint32_t jedec_id)
{
  uint8_t capacity_code = (uint8_t)(jedec_id & 0xFFu);

  switch (jedec_id & 0xFFFFFFu)
  {
    case 0xEF4018u:
      return 16u * 1024u * 1024u;
    case 0xEF4019u:
      return 32u * 1024u * 1024u;
    case 0xEF401Au:
    case 0xEF4020u:
    case 0xEF7119u:
      return 64u * 1024u * 1024u;
    default:
      break;
  }

  if ((capacity_code >= 0x15u) && (capacity_code <= 0x1Au))
  {
    return (1u << capacity_code);
  }

  return 0u;
}

static uint8_t flash_page_program(uint32_t address, const uint8_t *buf, uint32_t len)
{
  uint8_t use_4byte = flash_use_4byte_addr(address + len);
  uint8_t cmd = (use_4byte != 0u) ? FLASH_CMD_PAGE_PROGRAM_4B : FLASH_CMD_PAGE_PROGRAM_3B;
  uint32_t i;

  flash_write_enable();
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 0u);
  (void)flash_spi1_xfer(cmd);
  flash_send_address(address, use_4byte);
  for (i = 0u; i < len; ++i)
  {
    (void)flash_spi1_xfer(buf[i]);
  }
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 1u);
  flash_wait_not_busy();
  return 1u;
}

static uint8_t flash_sector_erase(uint32_t address)
{
  uint8_t use_4byte = flash_use_4byte_addr(address + FLASH_SECTOR_SIZE);
  uint8_t cmd = (use_4byte != 0u) ? FLASH_CMD_SECTOR_ERASE_4B : FLASH_CMD_SECTOR_ERASE_3B;

  flash_write_enable();
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 0u);
  (void)flash_spi1_xfer(cmd);
  flash_send_address(address, use_4byte);
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 1u);
  flash_wait_not_busy();
  return 1u;
}

void ext_flash_init(void)
{
  memset(&s_flash_info, 0, sizeof(s_flash_info));
  (void)ext_flash_probe();
}

uint8_t ext_flash_probe(void)
{
  uint8_t mode;

  for (mode = 0u; mode < 4u; mode += 3u)
  {
    uint32_t jedec_id;
    uint32_t capacity_bytes;

    flash_spi1_init(mode);
    jedec_id = flash_read_jedec_id();
    capacity_bytes = flash_decode_capacity(jedec_id);
    if ((jedec_id != 0u) && (jedec_id != 0xFFFFFFu) && (capacity_bytes != 0u))
    {
      s_flash_info.present = 1u;
      s_flash_info.spi_mode = mode;
      s_flash_info.jedec_id = jedec_id;
      s_flash_info.capacity_bytes = capacity_bytes;
      return 1u;
    }
  }

  memset(&s_flash_info, 0, sizeof(s_flash_info));
  return 0u;
}

void ext_flash_get_info(ext_flash_info_t *info)
{
  if (info == 0)
  {
    return;
  }

  *info = s_flash_info;
}

uint32_t ext_flash_get_capacity_bytes(void)
{
  return s_flash_info.capacity_bytes;
}

uint8_t ext_flash_read(uint32_t address, uint8_t *buf, uint32_t len)
{
  uint8_t use_4byte;
  uint8_t cmd;
  uint32_t i;

  if ((buf == 0) || (len == 0u))
  {
    return 0u;
  }

  if ((s_flash_info.present == 0u) ||
      ((address + len) > s_flash_info.capacity_bytes))
  {
    return 0u;
  }

  use_4byte = flash_use_4byte_addr(address + len);
  cmd = (use_4byte != 0u) ? FLASH_CMD_READ_DATA_4B : FLASH_CMD_READ_DATA_3B;

  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 0u);
  (void)flash_spi1_xfer(cmd);
  flash_send_address(address, use_4byte);
  for (i = 0u; i < len; ++i)
  {
    buf[i] = flash_spi1_xfer(0xFFu);
  }
  gpio_write(FLASH_CS_GPIO, FLASH_CS_PIN, 1u);
  return 1u;
}

uint8_t ext_flash_write(uint32_t address, const uint8_t *buf, uint32_t len)
{
  while (len != 0u)
  {
    uint32_t sector_base;
    uint32_t sector_offset;
    uint32_t chunk;
    uint32_t page_offset;

    if ((buf == 0) || (s_flash_info.present == 0u) ||
        ((address + len) > s_flash_info.capacity_bytes))
    {
      return 0u;
    }

    sector_base = address & ~(FLASH_SECTOR_SIZE - 1u);
    sector_offset = address - sector_base;
    chunk = FLASH_SECTOR_SIZE - sector_offset;
    if (chunk > len)
    {
      chunk = len;
    }

    if (ext_flash_read(sector_base, s_sector_buf, FLASH_SECTOR_SIZE) == 0u)
    {
      return 0u;
    }

    memcpy(&s_sector_buf[sector_offset], buf, chunk);

    if (flash_sector_erase(sector_base) == 0u)
    {
      return 0u;
    }

    for (page_offset = 0u; page_offset < FLASH_SECTOR_SIZE; page_offset += FLASH_PAGE_SIZE)
    {
      uint32_t j;
      uint8_t needs_program = 0u;

      for (j = 0u; j < FLASH_PAGE_SIZE; ++j)
      {
        if (s_sector_buf[page_offset + j] != 0xFFu)
        {
          needs_program = 1u;
          break;
        }
      }

      if (needs_program != 0u)
      {
        if (flash_page_program(sector_base + page_offset,
                               &s_sector_buf[page_offset],
                               FLASH_PAGE_SIZE) == 0u)
        {
          return 0u;
        }
      }
    }

    address += chunk;
    buf += chunk;
    len -= chunk;
  }

  return 1u;
}
