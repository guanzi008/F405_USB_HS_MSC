#include "fido_store.h"

#include <string.h>

#include "ext_flash_w25q.h"

#define FIDO_STORE_MAGIC   0x554C4644u
#define FIDO_STORE_VERSION 0x0001u

typedef struct
{
  uint32_t magic;
  uint16_t version;
  uint16_t credential_id_len;
  uint32_t counter;
  uint32_t sign_count;
  uint8_t rp_id_hash[FIDO_SHA256_SIZE];
  uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE];
  uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE];
  uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE];
} fido_store_slot_t;

static uint32_t fido_store_base_address(void)
{
  uint32_t capacity = ext_flash_get_capacity_bytes();

  if (capacity <= FIDO_STORE_RESERVED_BYTES)
  {
    return 0U;
  }

  return capacity - FIDO_STORE_RESERVED_BYTES;
}

static uint32_t fido_store_slot_address(uint32_t slot_index)
{
  return fido_store_base_address() + (slot_index * FIDO_STORE_SLOT_SIZE);
}

static uint8_t fido_store_read_slot(uint32_t slot_index, fido_store_slot_t *slot)
{
  if ((slot == NULL) || (slot_index >= FIDO_STORE_CREDENTIALS_MAX))
  {
    return 0U;
  }

  return ext_flash_read(fido_store_slot_address(slot_index), (uint8_t *)slot, sizeof(*slot));
}

static uint8_t fido_store_write_slot(uint32_t slot_index, const fido_store_slot_t *slot)
{
  if ((slot == NULL) || (slot_index >= FIDO_STORE_CREDENTIALS_MAX))
  {
    return 0U;
  }

  return ext_flash_write(fido_store_slot_address(slot_index), (const uint8_t *)slot, sizeof(*slot));
}

static uint8_t fido_store_slot_valid(const fido_store_slot_t *slot)
{
  return (uint8_t)((slot != NULL) &&
                   (slot->magic == FIDO_STORE_MAGIC) &&
                   (slot->version == FIDO_STORE_VERSION) &&
                   (slot->credential_id_len != 0U) &&
                   (slot->credential_id_len <= FIDO_CREDENTIAL_ID_SIZE));
}

static void fido_store_copy_out(const fido_store_slot_t *slot, fido_store_credential_t *credential)
{
  memset(credential, 0, sizeof(*credential));
  credential->counter = slot->counter;
  credential->sign_count = slot->sign_count;
  credential->credential_id_len = slot->credential_id_len;
  memcpy(credential->rp_id_hash, slot->rp_id_hash, sizeof(credential->rp_id_hash));
  memcpy(credential->credential_id, slot->credential_id, sizeof(credential->credential_id));
  memcpy(credential->private_key, slot->private_key, sizeof(credential->private_key));
  memcpy(credential->public_key, slot->public_key, sizeof(credential->public_key));
}

uint8_t fido_store_is_ready(void)
{
  ext_flash_info_t info;

  ext_flash_get_info(&info);
  return (uint8_t)((info.present != 0U) && (info.capacity_bytes > FIDO_STORE_RESERVED_BYTES));
}

uint8_t fido_store_register(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                            const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                            fido_store_credential_t *credential)
{
  fido_store_slot_t slot;
  uint32_t slot_index;
  uint32_t free_slot = FIDO_STORE_CREDENTIALS_MAX;
  uint32_t next_counter = 1U;

  if ((credential == NULL) || (rp_id_hash == NULL) || (client_data_hash == NULL) || (fido_store_is_ready() == 0U))
  {
    return 0U;
  }

  memset(&slot, 0xFF, sizeof(slot));
  for (slot_index = 0U; slot_index < FIDO_STORE_CREDENTIALS_MAX; ++slot_index)
  {
    if (fido_store_read_slot(slot_index, &slot) == 0U)
    {
      return 0U;
    }
    if (fido_store_slot_valid(&slot) == 0U)
    {
      if (free_slot == FIDO_STORE_CREDENTIALS_MAX)
      {
        free_slot = slot_index;
      }
      continue;
    }
    if ((slot.counter + 1U) > next_counter)
    {
      next_counter = slot.counter + 1U;
    }
  }

  if (free_slot == FIDO_STORE_CREDENTIALS_MAX)
  {
    return 0U;
  }

  memset(&slot, 0xFF, sizeof(slot));
  slot.magic = FIDO_STORE_MAGIC;
  slot.version = FIDO_STORE_VERSION;
  slot.counter = next_counter;
  slot.sign_count = 0U;
  slot.credential_id_len = FIDO_CREDENTIAL_ID_SIZE;
  memcpy(slot.rp_id_hash, rp_id_hash, FIDO_SHA256_SIZE);

  if (fido_crypto_make_credential_key(slot.rp_id_hash,
                                      client_data_hash,
                                      slot.counter,
                                      slot.credential_id,
                                      slot.private_key,
                                      slot.public_key) == 0U)
  {
    return 0U;
  }

  if (fido_store_write_slot(free_slot, &slot) == 0U)
  {
    return 0U;
  }

  fido_store_copy_out(&slot, credential);
  return 1U;
}

uint8_t fido_store_find(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                        const uint8_t *credential_id,
                        uint16_t credential_id_len,
                        fido_store_credential_t *credential,
                        uint32_t *slot_index)
{
  fido_store_slot_t slot;
  uint32_t i;

  if ((credential == NULL) || (rp_id_hash == NULL) || (fido_store_is_ready() == 0U))
  {
    return 0U;
  }

  for (i = 0U; i < FIDO_STORE_CREDENTIALS_MAX; ++i)
  {
    if (fido_store_read_slot(i, &slot) == 0U)
    {
      return 0U;
    }
    if (fido_store_slot_valid(&slot) == 0U)
    {
      continue;
    }
    if (memcmp(slot.rp_id_hash, rp_id_hash, FIDO_SHA256_SIZE) != 0)
    {
      continue;
    }
    if ((credential_id != NULL) && (credential_id_len != 0U))
    {
      if ((slot.credential_id_len != credential_id_len) ||
          (memcmp(slot.credential_id, credential_id, credential_id_len) != 0))
      {
        continue;
      }
    }

    fido_store_copy_out(&slot, credential);
    if (slot_index != NULL)
    {
      *slot_index = i;
    }
    return 1U;
  }

  return 0U;
}

uint8_t fido_store_update_sign_count(uint32_t slot_index, uint32_t sign_count)
{
  fido_store_slot_t slot;

  if ((fido_store_is_ready() == 0U) || (fido_store_read_slot(slot_index, &slot) == 0U))
  {
    return 0U;
  }
  if (fido_store_slot_valid(&slot) == 0U)
  {
    return 0U;
  }

  slot.sign_count = sign_count;
  return fido_store_write_slot(slot_index, &slot);
}

uint8_t fido_store_clear(void)
{
  uint8_t blank[FIDO_STORE_SLOT_SIZE];
  uint32_t slot_index;

  if (fido_store_is_ready() == 0U)
  {
    return 0U;
  }

  memset(blank, 0xFF, sizeof(blank));

  for (slot_index = 0U; slot_index < FIDO_STORE_CREDENTIALS_MAX; ++slot_index)
  {
    if (ext_flash_write(fido_store_slot_address(slot_index), blank, sizeof(blank)) == 0U)
    {
      return 0U;
    }
  }

  return 1U;
}
