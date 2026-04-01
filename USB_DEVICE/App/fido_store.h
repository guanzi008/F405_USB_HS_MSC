#ifndef FIDO_STORE_H
#define FIDO_STORE_H

#include <stdint.h>

#include "fido_crypto.h"

#define FIDO_STORE_RESERVED_BYTES   (1024u * 1024u)
#define FIDO_STORE_SLOT_SIZE        4096u
#define FIDO_STORE_CREDENTIALS_MAX  (FIDO_STORE_RESERVED_BYTES / FIDO_STORE_SLOT_SIZE)

typedef struct
{
  uint32_t counter;
  uint32_t sign_count;
  uint8_t cred_protect_policy;
  uint16_t credential_id_len;
  uint16_t user_id_len;
  uint8_t rp_id_hash[FIDO_SHA256_SIZE];
  char rp_id[96];
  uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE];
  uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE];
  uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE];
  uint8_t user_id[64];
  char user_name[64];
  char user_display_name[64];
} fido_store_credential_t;

typedef void (*fido_store_progress_cb_t)(uint16_t current, uint16_t total, void *ctx);

uint8_t fido_store_is_ready(void);
uint8_t fido_store_register(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                            const char *rp_id,
                            const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                            uint8_t cred_protect_policy,
                            const uint8_t *user_id,
                            uint16_t user_id_len,
                            const char *user_name,
                            const char *user_display_name,
                            fido_store_credential_t *credential);
uint8_t fido_store_find(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                        const uint8_t *credential_id,
                        uint16_t credential_id_len,
                        fido_store_credential_t *credential,
                        uint32_t *slot_index);
uint8_t fido_store_find_by_credential_id(const uint8_t *credential_id,
                                         uint16_t credential_id_len,
                                         fido_store_credential_t *credential,
                                         uint32_t *slot_index);
uint8_t fido_store_get_by_index(uint32_t slot_index, fido_store_credential_t *credential);
uint16_t fido_store_count(void);
uint8_t fido_store_get_nth(uint16_t ordinal,
                           fido_store_credential_t *credential,
                           uint32_t *slot_index);
uint8_t fido_store_delete(uint32_t slot_index);
uint8_t fido_store_delete_with_progress(uint32_t slot_index,
                                        fido_store_progress_cb_t progress_cb,
                                        void *ctx);
uint8_t fido_store_update_user(uint32_t slot_index,
                               const uint8_t *user_id,
                               uint16_t user_id_len,
                               const char *user_name,
                               const char *user_display_name);
uint8_t fido_store_update_sign_count(uint32_t slot_index, uint32_t sign_count);
uint8_t fido_store_clear(void);
uint8_t fido_store_clear_with_progress(fido_store_progress_cb_t progress_cb, void *ctx);
uint8_t fido_store_client_pin_is_set(void);
uint8_t fido_store_client_pin_get_hash(uint8_t pin_hash16[16]);
uint8_t fido_store_client_pin_set_hash(const uint8_t pin_hash16[16]);
uint8_t fido_store_client_pin_clear(void);
uint8_t fido_store_client_pin_get_min_len(uint8_t *min_len);
uint8_t fido_store_client_pin_set_min_len(uint8_t min_len);
uint8_t fido_store_client_pin_get_force_change(uint8_t *force_change);
uint8_t fido_store_client_pin_set_force_change(uint8_t force_change);
uint8_t fido_store_client_pin_get_always_uv(uint8_t *always_uv);
uint8_t fido_store_client_pin_set_always_uv(uint8_t always_uv);

#endif
