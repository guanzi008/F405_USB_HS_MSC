#ifndef EXT_FLASH_W25Q_H
#define EXT_FLASH_W25Q_H

#include <stdint.h>

typedef struct
{
  uint8_t present;
  uint8_t spi_mode;
  uint32_t jedec_id;
  uint32_t capacity_bytes;
} ext_flash_info_t;

void ext_flash_init(void);
uint8_t ext_flash_probe(void);
void ext_flash_get_info(ext_flash_info_t *info);
uint32_t ext_flash_get_capacity_bytes(void);
uint8_t ext_flash_read(uint32_t address, uint8_t *buf, uint32_t len);
uint8_t ext_flash_write(uint32_t address, const uint8_t *buf, uint32_t len);

#endif
