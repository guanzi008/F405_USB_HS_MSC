#include "fido_store.h"

#include <string.h>

#include "ext_flash_w25q.h"

#define FIDO_STORE_MAGIC   0x554C4644u
#define FIDO_STORE_VERSION_V1 0x0001u
#define FIDO_STORE_VERSION 0x0002u

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
  uint16_t user_id_len;
  uint8_t user_id[64];
  char user_name[64];
  char user_display_name[64];
} fido_store_slot_t;

static uint32_t s_runtime_sign_count[FIDO_STORE_CREDENTIALS_MAX];
static uint8_t s_runtime_sign_count_valid[FIDO_STORE_CREDENTIALS_MAX];

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
                   ((slot->version == FIDO_STORE_VERSION_V1) || (slot->version == FIDO_STORE_VERSION)) &&
                   (slot->credential_id_len != 0U) &&
                   (slot->credential_id_len <= FIDO_CREDENTIAL_ID_SIZE));
}

static void fido_store_copy_out(uint32_t slot_index,
                                const fido_store_slot_t *slot,
                                fido_store_credential_t *credential)
{
  memset(credential, 0, sizeof(*credential));
  credential->counter = slot->counter;
  credential->sign_count = slot->sign_count;
  credential->credential_id_len = slot->credential_id_len;
  memcpy(credential->rp_id_hash, slot->rp_id_hash, sizeof(credential->rp_id_hash));
  memcpy(credential->credential_id, slot->credential_id, sizeof(credential->credential_id));
  memcpy(credential->private_key, slot->private_key, sizeof(credential->private_key));
  memcpy(credential->public_key, slot->public_key, sizeof(credential->public_key));
  if (slot->version >= FIDO_STORE_VERSION)
  {
    if (slot->user_id_len <= sizeof(credential->user_id))
    {
      credential->user_id_len = slot->user_id_len;
      memcpy(credential->user_id, slot->user_id, sizeof(credential->user_id));
    }
    memcpy(credential->user_name, slot->user_name, sizeof(credential->user_name));
    credential->user_name[sizeof(credential->user_name) - 1U] = '\0';
    memcpy(credential->user_display_name, slot->user_display_name, sizeof(credential->user_display_name));
    credential->user_display_name[sizeof(credential->user_display_name) - 1U] = '\0';
  }

  if ((slot_index < FIDO_STORE_CREDENTIALS_MAX) &&
      (s_runtime_sign_count_valid[slot_index] != 0U) &&
      (s_runtime_sign_count[slot_index] > credential->sign_count))
  {
    credential->sign_count = s_runtime_sign_count[slot_index];
  }
}

uint8_t fido_store_is_ready(void)
{
  ext_flash_info_t info;

  ext_flash_get_info(&info);
  return (uint8_t)((info.present != 0U) && (info.capacity_bytes > FIDO_STORE_RESERVED_BYTES));
}

uint8_t fido_store_register(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                            const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                            const uint8_t *user_id,
                            uint16_t user_id_len,
                            const char *user_name,
                            const char *user_display_name,
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
  if ((user_id_len > sizeof(slot.user_id)) ||
      ((user_id == NULL) && (user_id_len != 0U)))
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
  slot.user_id_len = user_id_len;
  memcpy(slot.rp_id_hash, rp_id_hash, FIDO_SHA256_SIZE);
  if (user_id_len != 0U)
  {
    memcpy(slot.user_id, user_id, user_id_len);
  }
  if (user_name != NULL)
  {
    strncpy(slot.user_name, user_name, sizeof(slot.user_name) - 1U);
  }
  if (user_display_name != NULL)
  {
    strncpy(slot.user_display_name, user_display_name, sizeof(slot.user_display_name) - 1U);
  }

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

  s_runtime_sign_count_valid[free_slot] = 1U;
  s_runtime_sign_count[free_slot] = slot.sign_count;
  fido_store_copy_out(free_slot, &slot, credential);
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

    fido_store_copy_out(i, &slot, credential);
    if (slot_index != NULL)
    {
      *slot_index = i;
    }
    return 1U;
  }

  return 0U;
}

uint8_t fido_store_get_by_index(uint32_t slot_index, fido_store_credential_t *credential)
{
  fido_store_slot_t slot;

  if ((credential == NULL) || (fido_store_is_ready() == 0U) || (slot_index >= FIDO_STORE_CREDENTIALS_MAX))
  {
    return 0U;
  }
  if ((fido_store_read_slot(slot_index, &slot) == 0U) || (fido_store_slot_valid(&slot) == 0U))
  {
    return 0U;
  }

  fido_store_copy_out(slot_index, &slot, credential);
  return 1U;
}

uint8_t fido_store_update_sign_count(uint32_t slot_index, uint32_t sign_count)
{
  if ((fido_store_is_ready() == 0U) || (slot_index >= FIDO_STORE_CREDENTIALS_MAX))
  {
    return 0U;
  }

  s_runtime_sign_count_valid[slot_index] = 1U;
  if (sign_count > s_runtime_sign_count[slot_index])
  {
    s_runtime_sign_count[slot_index] = sign_count;
  }
  return 1U;
}

uint8_t fido_store_clear_with_progress(fido_store_progress_cb_t progress_cb, void *ctx)
{
  uint8_t blank[FIDO_STORE_SLOT_SIZE];
  uint32_t slot_index;

  if (fido_store_is_ready() == 0U)
  {
    return 0U;
  }

  memset(blank, 0xFF, sizeof(blank));
  memset(s_runtime_sign_count, 0, sizeof(s_runtime_sign_count));
  memset(s_runtime_sign_count_valid, 0, sizeof(s_runtime_sign_count_valid));

  for (slot_index = 0U; slot_index < FIDO_STORE_CREDENTIALS_MAX; ++slot_index)
  {
    if (progress_cb != NULL)
    {
      progress_cb((uint16_t)slot_index, (uint16_t)FIDO_STORE_CREDENTIALS_MAX, ctx);
    }
    if (ext_flash_write(fido_store_slot_address(slot_index), blank, sizeof(blank)) == 0U)
    {
      return 0U;
    }
  }

  if (progress_cb != NULL)
  {
    progress_cb((uint16_t)FIDO_STORE_CREDENTIALS_MAX, (uint16_t)FIDO_STORE_CREDENTIALS_MAX, ctx);
  }

  return 1U;
}

uint8_t fido_store_clear(void)
{
  return fido_store_clear_with_progress(NULL, NULL);
}
