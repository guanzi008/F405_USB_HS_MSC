#include "usbd_ctap_min.h"

#include <string.h>

#include "stm32f4xx_hal.h"
#include "fido_crypto.h"
#include "fido_store.h"
#include "usbd_conf.h"

#define CTAP_MC_KEY_CLIENT_DATA_HASH 0x01U
#define CTAP_MC_KEY_RP               0x02U
#define CTAP_MC_KEY_USER             0x03U
#define CTAP_MC_KEY_PUBKEY_PARAMS    0x04U
#define CTAP_MC_KEY_EXCLUDE_LIST     0x05U
#define CTAP_MC_KEY_EXTENSIONS       0x06U
#define CTAP_MC_KEY_OPTIONS          0x07U
#define CTAP_MC_KEY_PIN_UV_AUTH_PARAM    0x08U
#define CTAP_MC_KEY_PIN_UV_AUTH_PROTOCOL 0x09U

#define CTAP_GA_KEY_RP_ID            0x01U
#define CTAP_GA_KEY_CLIENT_DATA_HASH 0x02U
#define CTAP_GA_KEY_ALLOW_LIST       0x03U
#define CTAP_GA_KEY_EXTENSIONS       0x04U
#define CTAP_GA_KEY_OPTIONS          0x05U
#define CTAP_GA_KEY_PIN_UV_AUTH_PARAM    0x06U
#define CTAP_GA_KEY_PIN_UV_AUTH_PROTOCOL 0x07U
#define CTAP_GA_ALLOW_LIST_MAX       64U
#define CTAP_RECENT_APPROVAL_WINDOW_MS 15000U
#define CTAP_RESET_WINDOW_MS         10000U

#define CTAP_PIN_KEY_PROTOCOL        0x01U
#define CTAP_PIN_KEY_SUBCMD          0x02U
#define CTAP_PIN_KEY_AGREEMENT       0x03U
#define CTAP_PIN_KEY_PIN_AUTH        0x04U
#define CTAP_PIN_KEY_NEW_PIN_ENC     0x05U
#define CTAP_PIN_KEY_PIN_HASH_ENC    0x06U

#define CTAP_PIN_SUBCMD_GET_RETRIES       0x01U
#define CTAP_PIN_SUBCMD_GET_KEY_AGREEMENT 0x02U
#define CTAP_PIN_SUBCMD_SET_PIN           0x03U
#define CTAP_PIN_SUBCMD_CHANGE_PIN        0x04U
#define CTAP_PIN_SUBCMD_GET_PIN_TOKEN     0x05U

#define CTAP_PIN_RESP_KEY_AGREEMENT  0x01U
#define CTAP_PIN_RESP_KEY_PIN_TOKEN  0x02U
#define CTAP_PIN_RESP_KEY_RETRIES    0x03U
#define CTAP_PIN_PROTOCOL_ONE        0x01U
#define CTAP_PIN_HASH_SIZE           16U
#define CTAP_PIN_TOKEN_SIZE          32U
#define CTAP_PIN_MAX_ENC_SIZE        64U
#define CTAP_PIN_MIN_LEN             4U
#define CTAP_PIN_MAX_RETRIES         8U

#define CTAP_CRED_MGMT_KEY_SUBCMD       0x01U
#define CTAP_CRED_MGMT_KEY_PARAMS       0x02U
#define CTAP_CRED_MGMT_KEY_PROTOCOL     0x03U
#define CTAP_CRED_MGMT_KEY_PIN_AUTH     0x04U

#define CTAP_CRED_MGMT_SUBCMD_METADATA  0x01U
#define CTAP_CRED_MGMT_SUBCMD_RP_BEGIN  0x02U
#define CTAP_CRED_MGMT_SUBCMD_RP_NEXT   0x03U
#define CTAP_CRED_MGMT_SUBCMD_RK_BEGIN  0x04U
#define CTAP_CRED_MGMT_SUBCMD_RK_NEXT   0x05U
#define CTAP_CRED_MGMT_SUBCMD_DELETE    0x06U

#define CTAP_CONFIG_KEY_SUBCMD          0x01U
#define CTAP_CONFIG_KEY_PARAMS          0x02U
#define CTAP_CONFIG_KEY_PROTOCOL        0x03U
#define CTAP_CONFIG_KEY_PIN_AUTH        0x04U

#define CTAP_CONFIG_SUBCMD_ALWAYS_UV        0x02U
#define CTAP_CONFIG_SUBCMD_SET_MIN_PIN_LEN  0x03U

#define CTAP_CONFIG_PARAM_NEW_MIN_PIN_LEN   0x01U
#define CTAP_CONFIG_PARAM_MIN_PIN_RPIDS     0x02U
#define CTAP_CONFIG_PARAM_FORCE_CHANGE_PIN  0x03U

#define CTAP_FLAG_USER_PRESENT 0x01U
#define CTAP_FLAG_ATTESTED     0x40U
#define CTAP_FLAG_EXTENSION_DATA 0x80U

#define CTAP_CRED_PROTECT_UV_OPTIONAL       0x01U
#define CTAP_CRED_PROTECT_UV_OR_CRED_ID_REQ 0x02U
#define CTAP_CRED_PROTECT_UV_REQUIRED       0x03U

typedef struct
{
  const uint8_t *buf;
  uint16_t len;
  uint16_t off;
} cbor_reader_t;

typedef struct
{
  const uint8_t *ptr;
  uint16_t len;
} cbor_span_t;

typedef struct
{
  uint8_t client_data_hash[FIDO_SHA256_SIZE];
  char rp_id[96];
  uint8_t user_id[64];
  uint16_t user_id_len;
  char user_name[64];
  char user_display_name[64];
  uint8_t has_client_data_hash;
  uint8_t has_rp_id;
  uint8_t has_user;
  uint8_t es256_ok;
  uint8_t option_rk_present;
  uint8_t option_rk;
  uint8_t option_uv_present;
  uint8_t option_uv;
  uint8_t cred_protect_present;
  uint8_t cred_protect_policy;
  uint8_t has_pin_uv_auth_param;
  uint8_t pin_uv_auth_param[16];
  uint8_t has_pin_uv_auth_protocol;
  uint8_t pin_uv_auth_protocol;
  uint8_t exclude_credential_ids[CTAP_GA_ALLOW_LIST_MAX][FIDO_CREDENTIAL_ID_SIZE];
  uint16_t exclude_credential_id_lens[CTAP_GA_ALLOW_LIST_MAX];
  uint8_t exclude_credential_count;
  uint16_t exclude_credential_total;
} ctap_make_credential_req_t;

typedef struct
{
  uint8_t client_data_hash[FIDO_SHA256_SIZE];
  char rp_id[96];
  uint8_t allow_credential_ids[CTAP_GA_ALLOW_LIST_MAX][FIDO_CREDENTIAL_ID_SIZE];
  uint16_t allow_credential_id_lens[CTAP_GA_ALLOW_LIST_MAX];
  uint8_t allow_credential_count;
  uint16_t allow_credential_total;
  uint8_t option_up_present;
  uint8_t option_up;
  uint8_t option_uv_present;
  uint8_t option_uv;
  uint8_t has_pin_uv_auth_param;
  uint8_t pin_uv_auth_param[16];
  uint8_t has_pin_uv_auth_protocol;
  uint8_t pin_uv_auth_protocol;
  uint8_t has_client_data_hash;
  uint8_t has_rp_id;
} ctap_get_assertion_req_t;

typedef struct
{
  uint8_t protocol;
  uint8_t subcmd;
  uint8_t has_protocol;
  uint8_t has_subcmd;
  uint8_t has_key_agreement;
  uint8_t has_pin_auth;
  uint8_t has_new_pin_enc;
  uint8_t has_pin_hash_enc;
  uint8_t key_agreement_pub[FIDO_P256_PUBLIC_KEY_SIZE];
  uint8_t pin_auth[16];
  uint8_t new_pin_enc[CTAP_PIN_MAX_ENC_SIZE];
  uint16_t new_pin_enc_len;
  uint8_t pin_hash_enc[16];
  uint16_t pin_hash_enc_len;
} ctap_client_pin_req_t;

typedef struct
{
  uint8_t protocol;
  uint8_t subcmd;
  uint8_t has_protocol;
  uint8_t has_subcmd;
  uint8_t has_pin_auth;
  uint8_t has_subcmd_params;
  uint8_t has_rp_id_hash;
  uint8_t has_credential_id;
  uint8_t pin_auth[16];
  cbor_span_t subcmd_params;
  uint8_t rp_id_hash[FIDO_SHA256_SIZE];
  uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE];
  uint16_t credential_id_len;
} ctap_cred_mgmt_req_t;

typedef struct
{
  uint8_t protocol;
  uint8_t subcmd;
  uint8_t has_protocol;
  uint8_t has_subcmd;
  uint8_t has_pin_auth;
  uint8_t has_subcmd_params;
  uint8_t has_new_min_pin_len;
  uint8_t new_min_pin_len;
  uint8_t has_force_change_pin;
  uint8_t force_change_pin;
  uint8_t pin_auth[16];
  cbor_span_t subcmd_params;
} ctap_config_req_t;

static uint8_t s_ctap_user_presence_latched;
static uint8_t s_ctap_pending_cmd;
static uint8_t s_ctap_ui_state;
static uint8_t s_ctap_selection_count;
static uint8_t s_ctap_selection_index;
static fido_store_credential_t s_ctap_candidates[CTAP_GA_ALLOW_LIST_MAX];
static uint32_t s_ctap_candidate_slots[CTAP_GA_ALLOW_LIST_MAX];
static uint8_t s_ctap_recent_cmd;
static uint32_t s_ctap_recent_approved_at_ms;
static uint8_t s_ctap_recent_req_hash[FIDO_SHA256_SIZE];
static uint32_t s_ctap_boot_ms;
static uint8_t s_ctap_boot_ms_valid;
static uint8_t s_ctap_pin_retries = CTAP_PIN_MAX_RETRIES;
static uint8_t s_ctap_pin_consecutive_failures;
static uint8_t s_ctap_pin_power_cycle_blocked;
static uint8_t s_ctap_pin_token[CTAP_PIN_TOKEN_SIZE];
static uint8_t s_ctap_pin_token_valid;
static uint8_t s_ctap_pin_key_agreement_priv[FIDO_P256_PRIVATE_KEY_SIZE];
static uint8_t s_ctap_pin_key_agreement_pub[FIDO_P256_PUBLIC_KEY_SIZE];
static uint8_t s_ctap_pin_key_agreement_valid;
static uint8_t s_ctap_credman_rp_hash[FIDO_SHA256_SIZE];
static uint16_t s_ctap_credman_rp_cursor;
static uint16_t s_ctap_credman_rp_total;
static uint16_t s_ctap_credman_rk_cursor;
static uint16_t s_ctap_credman_rk_total;

static uint8_t build_cose_public_key(const uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE],
                                     uint8_t *out,
                                     uint16_t out_cap,
                                     uint16_t *out_len);

static void ctap_diag_note_request(uint8_t cmd,
                                   uint32_t allow_count,
                                   uint32_t match_count,
                                   uint32_t auto_confirm)
{
  g_a_usb_diag_runtime.fido_last_ctap_cmd = cmd;
  g_a_usb_diag_runtime.fido_last_ctap_status = 0xFFFFFFFFu;
  g_a_usb_diag_runtime.fido_last_allow_count = allow_count;
  g_a_usb_diag_runtime.fido_last_match_count = match_count;
  g_a_usb_diag_runtime.fido_last_auto_confirm = auto_confirm;
}

static void ctap_diag_note_status(uint8_t status)
{
  g_a_usb_diag_runtime.fido_last_ctap_status = status;
}

static uint8_t ctap_request_matches_recent(uint8_t cmd, const uint8_t *req, uint16_t req_len)
{
  uint8_t req_hash[FIDO_SHA256_SIZE];

  if ((req == NULL) || (req_len == 0U) || (cmd == 0U) || (s_ctap_recent_cmd != cmd))
  {
    return 0U;
  }
  if ((uint32_t)(HAL_GetTick() - s_ctap_recent_approved_at_ms) > CTAP_RECENT_APPROVAL_WINDOW_MS)
  {
    return 0U;
  }

  fido_crypto_sha256(req, req_len, req_hash);
  return (uint8_t)(memcmp(req_hash, s_ctap_recent_req_hash, sizeof(req_hash)) == 0);
}

static void ctap_remember_recent_approval(uint8_t cmd, const uint8_t *req, uint16_t req_len)
{
  if ((req == NULL) || (req_len == 0U) || (cmd == 0U))
  {
    return;
  }

  s_ctap_recent_cmd = cmd;
  s_ctap_recent_approved_at_ms = HAL_GetTick();
  fido_crypto_sha256(req, req_len, s_ctap_recent_req_hash);
}

static void ctap_ensure_boot_reference(void)
{
  if (s_ctap_boot_ms_valid == 0U)
  {
    s_ctap_boot_ms = HAL_GetTick();
    s_ctap_boot_ms_valid = 1U;
  }
}

static uint8_t ctap_is_reset_allowed(void)
{
  ctap_ensure_boot_reference();
  return (uint8_t)((uint32_t)(HAL_GetTick() - s_ctap_boot_ms) <= CTAP_RESET_WINDOW_MS);
}

static void ctap_pin_reset_retries(void)
{
  s_ctap_pin_retries = CTAP_PIN_MAX_RETRIES;
  s_ctap_pin_consecutive_failures = 0U;
  s_ctap_pin_power_cycle_blocked = 0U;
}

static void ctap_pin_reset_token(void)
{
  if (fido_crypto_random(s_ctap_pin_token, sizeof(s_ctap_pin_token)) != 0U)
  {
    s_ctap_pin_token_valid = 1U;
  }
  else
  {
    memset(s_ctap_pin_token, 0, sizeof(s_ctap_pin_token));
    s_ctap_pin_token_valid = 0U;
  }
}

static uint8_t ctap_pin_ensure_key_agreement(void)
{
  if (s_ctap_pin_key_agreement_valid != 0U)
  {
    return 1U;
  }
  if (fido_crypto_make_ecdh_keypair(s_ctap_pin_key_agreement_priv,
                                    s_ctap_pin_key_agreement_pub) == 0U)
  {
    memset(s_ctap_pin_key_agreement_priv, 0, sizeof(s_ctap_pin_key_agreement_priv));
    memset(s_ctap_pin_key_agreement_pub, 0, sizeof(s_ctap_pin_key_agreement_pub));
    s_ctap_pin_key_agreement_valid = 0U;
    return 0U;
  }

  s_ctap_pin_key_agreement_valid = 1U;
  return 1U;
}

static void ctap_pin_note_success(void)
{
  ctap_pin_reset_retries();
  ctap_pin_reset_token();
}

static uint8_t ctap_pin_note_failure(void)
{
  if (s_ctap_pin_retries > 0U)
  {
    s_ctap_pin_retries--;
  }
  if (s_ctap_pin_consecutive_failures < 0xFFU)
  {
    s_ctap_pin_consecutive_failures++;
  }
  if (s_ctap_pin_retries == 0U)
  {
    return CTAP_ERR_PIN_BLOCKED;
  }
  if (s_ctap_pin_consecutive_failures >= 3U)
  {
    s_ctap_pin_power_cycle_blocked = 1U;
    return CTAP_ERR_PIN_AUTH_BLOCKED;
  }

  return CTAP_ERR_PIN_INVALID;
}

static void store_be16(uint8_t *dst, uint16_t value)
{
  dst[0] = (uint8_t)(value >> 8);
  dst[1] = (uint8_t)value;
}

static void store_be32(uint8_t *dst, uint32_t value)
{
  dst[0] = (uint8_t)(value >> 24);
  dst[1] = (uint8_t)(value >> 16);
  dst[2] = (uint8_t)(value >> 8);
  dst[3] = (uint8_t)value;
}

static uint8_t cbor_write_type_value(uint8_t major,
                                     uint32_t value,
                                     uint8_t *out,
                                     uint16_t out_size,
                                     uint16_t *off)
{
  uint16_t pos;

  if ((out == NULL) || (off == NULL))
  {
    return 0U;
  }

  pos = *off;
  if (value <= 23U)
  {
    if ((uint16_t)(pos + 1U) > out_size)
    {
      return 0U;
    }
    out[pos++] = (uint8_t)((major << 5) | (uint8_t)value);
  }
  else if (value <= 0xFFU)
  {
    if ((uint16_t)(pos + 2U) > out_size)
    {
      return 0U;
    }
    out[pos++] = (uint8_t)((major << 5) | 24U);
    out[pos++] = (uint8_t)value;
  }
  else if (value <= 0xFFFFU)
  {
    if ((uint16_t)(pos + 3U) > out_size)
    {
      return 0U;
    }
    out[pos++] = (uint8_t)((major << 5) | 25U);
    out[pos++] = (uint8_t)(value >> 8);
    out[pos++] = (uint8_t)value;
  }
  else
  {
    if ((uint16_t)(pos + 5U) > out_size)
    {
      return 0U;
    }
    out[pos++] = (uint8_t)((major << 5) | 26U);
    out[pos++] = (uint8_t)(value >> 24);
    out[pos++] = (uint8_t)(value >> 16);
    out[pos++] = (uint8_t)(value >> 8);
    out[pos++] = (uint8_t)value;
  }

  *off = pos;
  return 1U;
}

static uint8_t cbor_write_uint(uint32_t value, uint8_t *out, uint16_t out_size, uint16_t *off)
{
  return cbor_write_type_value(0U, value, out, out_size, off);
}

static uint8_t cbor_write_nint(int32_t value, uint8_t *out, uint16_t out_size, uint16_t *off)
{
  if (value >= 0)
  {
    return 0U;
  }
  return cbor_write_type_value(1U, (uint32_t)(-1 - value), out, out_size, off);
}

static uint8_t cbor_write_map(uint32_t count, uint8_t *out, uint16_t out_size, uint16_t *off)
{
  return cbor_write_type_value(5U, count, out, out_size, off);
}

static uint8_t cbor_write_array(uint32_t count, uint8_t *out, uint16_t out_size, uint16_t *off)
{
  return cbor_write_type_value(4U, count, out, out_size, off);
}

static uint8_t cbor_write_text(const char *text, uint8_t *out, uint16_t out_size, uint16_t *off)
{
  uint16_t len;
  uint16_t pos;

  if (text == NULL)
  {
    return 0U;
  }
  len = (uint16_t)strlen(text);
  if (cbor_write_type_value(3U, len, out, out_size, off) == 0U)
  {
    return 0U;
  }

  pos = *off;
  if ((uint16_t)(pos + len) > out_size)
  {
    return 0U;
  }

  memcpy(&out[pos], text, len);
  *off = (uint16_t)(pos + len);
  return 1U;
}

static uint8_t cbor_write_bytes(const uint8_t *data,
                                uint16_t data_len,
                                uint8_t *out,
                                uint16_t out_size,
                                uint16_t *off)
{
  uint16_t pos;

  if (((data == NULL) && (data_len != 0U)) ||
      (cbor_write_type_value(2U, data_len, out, out_size, off) == 0U))
  {
    return 0U;
  }

  pos = *off;
  if ((uint16_t)(pos + data_len) > out_size)
  {
    return 0U;
  }
  if (data_len != 0U)
  {
    memcpy(&out[pos], data, data_len);
  }
  *off = (uint16_t)(pos + data_len);
  return 1U;
}

static uint8_t cbor_write_raw(const uint8_t *data,
                              uint16_t data_len,
                              uint8_t *out,
                              uint16_t out_size,
                              uint16_t *off)
{
  uint16_t pos;

  if (((data == NULL) && (data_len != 0U)) || (out == NULL) || (off == NULL))
  {
    return 0U;
  }

  pos = *off;
  if ((uint16_t)(pos + data_len) > out_size)
  {
    return 0U;
  }
  if (data_len != 0U)
  {
    memcpy(&out[pos], data, data_len);
  }
  *off = (uint16_t)(pos + data_len);
  return 1U;
}

static uint8_t cbor_write_bool(uint8_t value, uint8_t *out, uint16_t out_size, uint16_t *off)
{
  uint16_t pos;

  if ((out == NULL) || (off == NULL))
  {
    return 0U;
  }

  pos = *off;
  if ((uint16_t)(pos + 1U) > out_size)
  {
    return 0U;
  }
  out[pos++] = (value != 0U) ? 0xF5U : 0xF4U;
  *off = pos;
  return 1U;
}

static uint8_t cbor_read_head(cbor_reader_t *reader, uint8_t *major, uint32_t *value)
{
  uint8_t first;
  uint8_t addl;

  if ((reader == NULL) || (major == NULL) || (value == NULL) || (reader->off >= reader->len))
  {
    return 0U;
  }

  first = reader->buf[reader->off++];
  *major = (uint8_t)(first >> 5);
  addl = (uint8_t)(first & 0x1FU);

  if (addl <= 23U)
  {
    *value = addl;
    return 1U;
  }
  if (addl == 24U)
  {
    if ((uint16_t)(reader->off + 1U) > reader->len)
    {
      return 0U;
    }
    *value = reader->buf[reader->off++];
    return 1U;
  }
  if (addl == 25U)
  {
    if ((uint16_t)(reader->off + 2U) > reader->len)
    {
      return 0U;
    }
    *value = ((uint32_t)reader->buf[reader->off] << 8) |
             (uint32_t)reader->buf[reader->off + 1U];
    reader->off = (uint16_t)(reader->off + 2U);
    return 1U;
  }
  if (addl == 26U)
  {
    if ((uint16_t)(reader->off + 4U) > reader->len)
    {
      return 0U;
    }
    *value = ((uint32_t)reader->buf[reader->off] << 24) |
             ((uint32_t)reader->buf[reader->off + 1U] << 16) |
             ((uint32_t)reader->buf[reader->off + 2U] << 8) |
             (uint32_t)reader->buf[reader->off + 3U];
    reader->off = (uint16_t)(reader->off + 4U);
    return 1U;
  }

  return 0U;
}

static uint8_t cbor_read_uint(cbor_reader_t *reader, uint32_t *value)
{
  uint8_t major;
  uint32_t tmp;

  if ((cbor_read_head(reader, &major, &tmp) == 0U) || (major != 0U))
  {
    return 0U;
  }

  *value = tmp;
  return 1U;
}

static uint8_t cbor_read_int(cbor_reader_t *reader, int32_t *value)
{
  uint8_t major;
  uint32_t tmp;

  if ((value == NULL) || (cbor_read_head(reader, &major, &tmp) == 0U))
  {
    return 0U;
  }
  if (major == 0U)
  {
    *value = (int32_t)tmp;
    return 1U;
  }
  if (major == 1U)
  {
    *value = -(int32_t)(tmp + 1U);
    return 1U;
  }
  return 0U;
}

static uint8_t cbor_read_bytes(cbor_reader_t *reader, cbor_span_t *span)
{
  uint8_t major;
  uint32_t len;

  if ((span == NULL) || (cbor_read_head(reader, &major, &len) == 0U) || (major != 2U))
  {
    return 0U;
  }
  if ((uint32_t)reader->off + len > reader->len)
  {
    return 0U;
  }

  span->ptr = &reader->buf[reader->off];
  span->len = (uint16_t)len;
  reader->off = (uint16_t)(reader->off + len);
  return 1U;
}

static uint8_t cbor_read_text(cbor_reader_t *reader, cbor_span_t *span)
{
  uint8_t major;
  uint32_t len;

  if ((span == NULL) || (cbor_read_head(reader, &major, &len) == 0U) || (major != 3U))
  {
    return 0U;
  }
  if ((uint32_t)reader->off + len > reader->len)
  {
    return 0U;
  }

  span->ptr = &reader->buf[reader->off];
  span->len = (uint16_t)len;
  reader->off = (uint16_t)(reader->off + len);
  return 1U;
}

static uint8_t cbor_read_bool(cbor_reader_t *reader, uint8_t *value)
{
  if ((reader == NULL) || (value == NULL) || (reader->off >= reader->len))
  {
    return 0U;
  }

  if (reader->buf[reader->off] == 0xF4U)
  {
    *value = 0U;
    reader->off = (uint16_t)(reader->off + 1U);
    return 1U;
  }
  if (reader->buf[reader->off] == 0xF5U)
  {
    *value = 1U;
    reader->off = (uint16_t)(reader->off + 1U);
    return 1U;
  }

  return 0U;
}

static uint8_t cbor_enter_map(cbor_reader_t *reader, uint32_t *pair_count)
{
  uint8_t major;
  uint32_t count;

  if ((pair_count == NULL) || (cbor_read_head(reader, &major, &count) == 0U) || (major != 5U))
  {
    return 0U;
  }
  *pair_count = count;
  return 1U;
}

static uint8_t cbor_enter_array(cbor_reader_t *reader, uint32_t *item_count)
{
  uint8_t major;
  uint32_t count;

  if ((item_count == NULL) || (cbor_read_head(reader, &major, &count) == 0U) || (major != 4U))
  {
    return 0U;
  }
  *item_count = count;
  return 1U;
}

static uint8_t cbor_skip_item(cbor_reader_t *reader)
{
  uint8_t major;
  uint32_t count;
  uint32_t i;

  if (cbor_read_head(reader, &major, &count) == 0U)
  {
    return 0U;
  }

  switch (major)
  {
    case 0U:
    case 1U:
      return 1U;

    case 2U:
    case 3U:
      if ((uint32_t)reader->off + count > reader->len)
      {
        return 0U;
      }
      reader->off = (uint16_t)(reader->off + count);
      return 1U;

    case 4U:
      for (i = 0U; i < count; ++i)
      {
        if (cbor_skip_item(reader) == 0U)
        {
          return 0U;
        }
      }
      return 1U;

    case 5U:
      for (i = 0U; i < (count * 2U); ++i)
      {
        if (cbor_skip_item(reader) == 0U)
        {
          return 0U;
        }
      }
      return 1U;

    case 7U:
      return 1U;

    default:
      return 0U;
  }
}

static uint8_t cbor_text_eq(const cbor_span_t *span, const char *text)
{
  uint16_t len;

  if ((span == NULL) || (text == NULL))
  {
    return 0U;
  }
  len = (uint16_t)strlen(text);
  return (uint8_t)((span->len == len) && (memcmp(span->ptr, text, len) == 0));
}

static uint8_t parse_rp_map(cbor_reader_t *reader, char *rp_id, uint16_t rp_id_cap)
{
  uint32_t pair_count;
  uint32_t i;
  uint8_t found = 0U;

  if ((rp_id == NULL) || (rp_id_cap == 0U) || (cbor_enter_map(reader, &pair_count) == 0U))
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    cbor_span_t key;

    if (cbor_read_text(reader, &key) == 0U)
    {
      return 0U;
    }

    if (cbor_text_eq(&key, "id") != 0U)
    {
      cbor_span_t value;
      uint16_t copy_len;

      if (cbor_read_text(reader, &value) == 0U)
      {
        return 0U;
      }
      copy_len = value.len;
      if (copy_len >= rp_id_cap)
      {
        copy_len = (uint16_t)(rp_id_cap - 1U);
      }
      memcpy(rp_id, value.ptr, copy_len);
      rp_id[copy_len] = '\0';
      found = 1U;
    }
    else if (cbor_skip_item(reader) == 0U)
    {
      return 0U;
    }
  }

  return found;
}

static uint8_t parse_user_map(cbor_reader_t *reader, ctap_make_credential_req_t *parsed)
{
  uint32_t pair_count;
  uint32_t i;
  uint8_t found_id = 0U;

  if ((parsed == NULL) || (cbor_enter_map(reader, &pair_count) == 0U))
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    cbor_span_t key;

    if (cbor_read_text(reader, &key) == 0U)
    {
      return 0U;
    }

    if (cbor_text_eq(&key, "id") != 0U)
    {
      cbor_span_t value;

      if (cbor_read_bytes(reader, &value) == 0U)
      {
        return 0U;
      }
      if (value.len > sizeof(parsed->user_id))
      {
        return 0U;
      }
      memcpy(parsed->user_id, value.ptr, value.len);
      parsed->user_id_len = value.len;
      found_id = 1U;
    }
    else if (cbor_text_eq(&key, "name") != 0U)
    {
      cbor_span_t value;
      uint16_t copy_len;

      if (cbor_read_text(reader, &value) == 0U)
      {
        return 0U;
      }
      copy_len = value.len;
      if (copy_len >= sizeof(parsed->user_name))
      {
        copy_len = (uint16_t)(sizeof(parsed->user_name) - 1U);
      }
      memcpy(parsed->user_name, value.ptr, copy_len);
      parsed->user_name[copy_len] = '\0';
    }
    else if (cbor_text_eq(&key, "displayName") != 0U)
    {
      cbor_span_t value;
      uint16_t copy_len;

      if (cbor_read_text(reader, &value) == 0U)
      {
        return 0U;
      }
      copy_len = value.len;
      if (copy_len >= sizeof(parsed->user_display_name))
      {
        copy_len = (uint16_t)(sizeof(parsed->user_display_name) - 1U);
      }
      memcpy(parsed->user_display_name, value.ptr, copy_len);
      parsed->user_display_name[copy_len] = '\0';
    }
    else if (cbor_skip_item(reader) == 0U)
    {
      return 0U;
    }
  }

  return found_id;
}

static uint8_t parse_pubkey_params(cbor_reader_t *reader)
{
  uint32_t item_count;
  uint32_t i;
  uint8_t found = 0U;

  if (cbor_enter_array(reader, &item_count) == 0U)
  {
    return 0U;
  }

  for (i = 0U; i < item_count; ++i)
  {
    uint32_t pair_count;
    uint32_t j;
    int32_t alg = 0;
    uint8_t has_alg = 0U;
    uint8_t type_ok = 0U;

    if (cbor_enter_map(reader, &pair_count) == 0U)
    {
      return 0U;
    }
    for (j = 0U; j < pair_count; ++j)
    {
      cbor_span_t key;

      if (cbor_read_text(reader, &key) == 0U)
      {
        return 0U;
      }
      if (cbor_text_eq(&key, "alg") != 0U)
      {
        if (cbor_read_int(reader, &alg) == 0U)
        {
          return 0U;
        }
        has_alg = 1U;
      }
      else if (cbor_text_eq(&key, "type") != 0U)
      {
        cbor_span_t value;

        if (cbor_read_text(reader, &value) == 0U)
        {
          return 0U;
        }
        if (cbor_text_eq(&value, "public-key") != 0U)
        {
          type_ok = 1U;
        }
      }
      else if (cbor_skip_item(reader) == 0U)
      {
        return 0U;
      }
    }
    if ((has_alg != 0U) && (alg == -7) && (type_ok != 0U))
    {
      found = 1U;
    }
  }

  return found;
}

static uint8_t parse_allow_list(cbor_reader_t *reader,
                                uint8_t cred_ids[CTAP_GA_ALLOW_LIST_MAX][FIDO_CREDENTIAL_ID_SIZE],
                                uint16_t *cred_id_lens,
                                uint8_t *cred_id_count,
                                uint16_t *cred_id_total)
{
  uint32_t item_count;
  uint32_t i;

  if ((cred_ids == NULL) || (cred_id_lens == NULL) || (cred_id_count == NULL) ||
      (cred_id_total == NULL) ||
      (cbor_enter_array(reader, &item_count) == 0U))
  {
    return 0U;
  }

  *cred_id_count = 0U;
  *cred_id_total = (uint16_t)((item_count > 0xFFFFU) ? 0xFFFFU : item_count);
  for (i = 0U; i < item_count; ++i)
  {
    uint32_t pair_count;
    uint32_t j;
    uint8_t found = 0U;
    uint8_t entry_id[FIDO_CREDENTIAL_ID_SIZE];
    uint16_t entry_id_len = 0U;

    if (cbor_enter_map(reader, &pair_count) == 0U)
    {
      return 0U;
    }
    for (j = 0U; j < pair_count; ++j)
    {
      cbor_span_t key;

      if (cbor_read_text(reader, &key) == 0U)
      {
        return 0U;
      }
      if (cbor_text_eq(&key, "id") != 0U)
      {
        cbor_span_t value;

        if (cbor_read_bytes(reader, &value) == 0U)
        {
          return 0U;
        }
        if (value.len <= FIDO_CREDENTIAL_ID_SIZE)
        {
          memcpy(entry_id, value.ptr, value.len);
          entry_id_len = value.len;
          found = 1U;
        }
      }
      else if (cbor_skip_item(reader) == 0U)
      {
        return 0U;
      }
    }

    if ((found != 0U) && (*cred_id_count < CTAP_GA_ALLOW_LIST_MAX))
    {
      memcpy(cred_ids[*cred_id_count], entry_id, entry_id_len);
      cred_id_lens[*cred_id_count] = entry_id_len;
      *cred_id_count = (uint8_t)(*cred_id_count + 1U);
    }
  }

  return 1U;
}

static uint8_t parse_make_credential_extensions(cbor_reader_t *reader,
                                                ctap_make_credential_req_t *parsed)
{
  uint32_t ext_count;
  uint32_t ext_index;

  if ((reader == NULL) || (parsed == NULL) || (cbor_enter_map(reader, &ext_count) == 0U))
  {
    return 0U;
  }

  for (ext_index = 0U; ext_index < ext_count; ++ext_index)
  {
    cbor_span_t name;

    if (cbor_read_text(reader, &name) == 0U)
    {
      return 0U;
    }

    if (cbor_text_eq(&name, "credProtect") != 0U)
    {
      uint32_t policy = 0U;

      if ((cbor_read_uint(reader, &policy) == 0U) ||
          (policy < CTAP_CRED_PROTECT_UV_OPTIONAL) ||
          (policy > CTAP_CRED_PROTECT_UV_REQUIRED))
      {
        return 0U;
      }
      parsed->cred_protect_present = 1U;
      parsed->cred_protect_policy = (uint8_t)policy;
    }
    else if (cbor_skip_item(reader) == 0U)
    {
      return 0U;
    }
  }

  return 1U;
}

static uint8_t parse_make_credential_options(cbor_reader_t *reader,
                                             ctap_make_credential_req_t *parsed)
{
  uint32_t opt_count;
  uint32_t opt_index;

  if ((reader == NULL) || (parsed == NULL) || (cbor_enter_map(reader, &opt_count) == 0U))
  {
    return 0U;
  }

  for (opt_index = 0U; opt_index < opt_count; ++opt_index)
  {
    cbor_span_t name;
    uint8_t value_bool;

    if ((cbor_read_text(reader, &name) == 0U) || (cbor_read_bool(reader, &value_bool) == 0U))
    {
      return 0U;
    }

    if (cbor_text_eq(&name, "rk") != 0U)
    {
      parsed->option_rk_present = 1U;
      parsed->option_rk = value_bool;
    }
    else if (cbor_text_eq(&name, "uv") != 0U)
    {
      parsed->option_uv_present = 1U;
      parsed->option_uv = value_bool;
    }
  }

  return 1U;
}

static uint8_t ctap_verify_pin_uv_auth_param(const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                                             uint8_t protocol,
                                             const uint8_t pin_uv_auth_param[16])
{
  uint8_t auth[FIDO_SHA256_SIZE];

  if ((client_data_hash == NULL) || (pin_uv_auth_param == NULL))
  {
    return 0U;
  }
  if ((protocol != CTAP_PIN_PROTOCOL_ONE) || (s_ctap_pin_token_valid == 0U))
  {
    return 0U;
  }

  fido_crypto_hmac_sha256(s_ctap_pin_token,
                          sizeof(s_ctap_pin_token),
                          client_data_hash,
                          FIDO_SHA256_SIZE,
                          auth);
  return (uint8_t)(memcmp(auth, pin_uv_auth_param, 16U) == 0U);
}

static uint8_t parse_make_credential(const uint8_t *req,
                                     uint16_t req_len,
                                     ctap_make_credential_req_t *parsed)
{
  cbor_reader_t reader;
  uint32_t pair_count;
  uint32_t i;

  if ((req == NULL) || (req_len < 2U) || (parsed == NULL))
  {
    return 0U;
  }

  memset(parsed, 0, sizeof(*parsed));
  reader.buf = &req[1];
  reader.len = (uint16_t)(req_len - 1U);
  reader.off = 0U;

  if (cbor_enter_map(&reader, &pair_count) == 0U)
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    uint32_t key;

    if (cbor_read_uint(&reader, &key) == 0U)
    {
      return 0U;
    }

    switch (key)
    {
      case CTAP_MC_KEY_CLIENT_DATA_HASH:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != FIDO_SHA256_SIZE))
        {
          return 0U;
        }
        memcpy(parsed->client_data_hash, span.ptr, FIDO_SHA256_SIZE);
        parsed->has_client_data_hash = 1U;
        break;
      }

      case CTAP_MC_KEY_RP:
        parsed->has_rp_id = parse_rp_map(&reader, parsed->rp_id, sizeof(parsed->rp_id));
        if (parsed->has_rp_id == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_MC_KEY_USER:
        parsed->has_user = parse_user_map(&reader, parsed);
        if (parsed->has_user == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_MC_KEY_PUBKEY_PARAMS:
        parsed->es256_ok = parse_pubkey_params(&reader);
        if (parsed->es256_ok == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_MC_KEY_EXCLUDE_LIST:
        if (parse_allow_list(&reader,
                             parsed->exclude_credential_ids,
                             parsed->exclude_credential_id_lens,
                             &parsed->exclude_credential_count,
                             &parsed->exclude_credential_total) == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_MC_KEY_EXTENSIONS:
        if (parse_make_credential_extensions(&reader, parsed) == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_MC_KEY_OPTIONS:
        if (parse_make_credential_options(&reader, parsed) == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_MC_KEY_PIN_UV_AUTH_PARAM:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != sizeof(parsed->pin_uv_auth_param)))
        {
          return 0U;
        }
        memcpy(parsed->pin_uv_auth_param, span.ptr, sizeof(parsed->pin_uv_auth_param));
        parsed->has_pin_uv_auth_param = 1U;
        break;
      }

      case CTAP_MC_KEY_PIN_UV_AUTH_PROTOCOL:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->pin_uv_auth_protocol = (uint8_t)value;
        parsed->has_pin_uv_auth_protocol = 1U;
        break;
      }

      default:
        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        break;
    }
  }

  return 1U;
}

static uint8_t ctap_make_credential_matches_exclude(const ctap_make_credential_req_t *parsed,
                                                    const uint8_t rp_id_hash[FIDO_SHA256_SIZE])
{
  uint8_t i;

  if ((parsed == NULL) || (rp_id_hash == NULL))
  {
    return 0U;
  }

  for (i = 0U; i < parsed->exclude_credential_count; ++i)
  {
    fido_store_credential_t credential;
    uint32_t slot_index = 0U;

    if (fido_store_find(rp_id_hash,
                        parsed->exclude_credential_ids[i],
                        parsed->exclude_credential_id_lens[i],
                        &credential,
                        &slot_index) != 0U)
    {
      return 1U;
    }
  }

  return 0U;
}

static uint8_t parse_get_assertion(const uint8_t *req,
                                   uint16_t req_len,
                                   ctap_get_assertion_req_t *parsed)
{
  cbor_reader_t reader;
  uint32_t pair_count;
  uint32_t i;

  if ((req == NULL) || (req_len < 2U) || (parsed == NULL))
  {
    return 0U;
  }

  memset(parsed, 0, sizeof(*parsed));
  reader.buf = &req[1];
  reader.len = (uint16_t)(req_len - 1U);
  reader.off = 0U;

  if (cbor_enter_map(&reader, &pair_count) == 0U)
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    uint32_t key;

    if (cbor_read_uint(&reader, &key) == 0U)
    {
      return 0U;
    }

    switch (key)
    {
      case CTAP_GA_KEY_RP_ID:
      {
        cbor_span_t span;
        uint16_t copy_len;

        if (cbor_read_text(&reader, &span) == 0U)
        {
          return 0U;
        }
        copy_len = span.len;
        if (copy_len >= sizeof(parsed->rp_id))
        {
          copy_len = (uint16_t)(sizeof(parsed->rp_id) - 1U);
        }
        memcpy(parsed->rp_id, span.ptr, copy_len);
        parsed->rp_id[copy_len] = '\0';
        parsed->has_rp_id = 1U;
        break;
      }

      case CTAP_GA_KEY_CLIENT_DATA_HASH:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != FIDO_SHA256_SIZE))
        {
          return 0U;
        }
        memcpy(parsed->client_data_hash, span.ptr, FIDO_SHA256_SIZE);
        parsed->has_client_data_hash = 1U;
        break;
      }

      case CTAP_GA_KEY_ALLOW_LIST:
        if (parse_allow_list(&reader,
                             parsed->allow_credential_ids,
                             parsed->allow_credential_id_lens,
                             &parsed->allow_credential_count,
                             &parsed->allow_credential_total) == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_GA_KEY_EXTENSIONS:
        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        break;

      case CTAP_GA_KEY_OPTIONS:
      {
        uint32_t opt_count;
        uint32_t opt_index;

        if (cbor_enter_map(&reader, &opt_count) == 0U)
        {
          return 0U;
        }

        for (opt_index = 0U; opt_index < opt_count; ++opt_index)
        {
          cbor_span_t name;
          uint8_t value_bool;

          if (cbor_read_text(&reader, &name) == 0U)
          {
            return 0U;
          }
          if (cbor_read_bool(&reader, &value_bool) == 0U)
          {
            return 0U;
          }

          if (cbor_text_eq(&name, "up") != 0U)
          {
            parsed->option_up_present = 1U;
            parsed->option_up = value_bool;
          }
          else if (cbor_text_eq(&name, "uv") != 0U)
          {
            parsed->option_uv_present = 1U;
            parsed->option_uv = value_bool;
          }
        }
        break;
      }

      case CTAP_GA_KEY_PIN_UV_AUTH_PARAM:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != sizeof(parsed->pin_uv_auth_param)))
        {
          return 0U;
        }
        memcpy(parsed->pin_uv_auth_param, span.ptr, sizeof(parsed->pin_uv_auth_param));
        parsed->has_pin_uv_auth_param = 1U;
        break;
      }

      case CTAP_GA_KEY_PIN_UV_AUTH_PROTOCOL:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->pin_uv_auth_protocol = (uint8_t)value;
        parsed->has_pin_uv_auth_protocol = 1U;
        break;
      }

      default:
        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        break;
    }
  }

  return 1U;
}

static uint8_t parse_cose_p256_public_key(cbor_reader_t *reader,
                                          uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE])
{
  uint32_t pair_count;
  uint32_t i;
  uint8_t have_x = 0U;
  uint8_t have_y = 0U;

  if ((reader == NULL) || (public_key == NULL) || (cbor_enter_map(reader, &pair_count) == 0U))
  {
    return 0U;
  }

  memset(public_key, 0, FIDO_P256_PUBLIC_KEY_SIZE);
  for (i = 0U; i < pair_count; ++i)
  {
    int32_t key;

    if (cbor_read_int(reader, &key) == 0U)
    {
      return 0U;
    }

    if (key == -2)
    {
      cbor_span_t span;

      if ((cbor_read_bytes(reader, &span) == 0U) || (span.len != 32U))
      {
        return 0U;
      }
      memcpy(&public_key[0], span.ptr, 32U);
      have_x = 1U;
    }
    else if (key == -3)
    {
      cbor_span_t span;

      if ((cbor_read_bytes(reader, &span) == 0U) || (span.len != 32U))
      {
        return 0U;
      }
      memcpy(&public_key[32], span.ptr, 32U);
      have_y = 1U;
    }
    else if (cbor_skip_item(reader) == 0U)
    {
      return 0U;
    }
  }

  return (uint8_t)((have_x != 0U) && (have_y != 0U));
}

static uint8_t parse_client_pin(const uint8_t *req,
                                uint16_t req_len,
                                ctap_client_pin_req_t *parsed)
{
  cbor_reader_t reader;
  uint32_t pair_count;
  uint32_t i;

  if ((req == NULL) || (req_len < 2U) || (parsed == NULL))
  {
    return 0U;
  }

  memset(parsed, 0, sizeof(*parsed));
  reader.buf = &req[1];
  reader.len = (uint16_t)(req_len - 1U);
  reader.off = 0U;
  if (cbor_enter_map(&reader, &pair_count) == 0U)
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    uint32_t key;

    if (cbor_read_uint(&reader, &key) == 0U)
    {
      return 0U;
    }

    switch (key)
    {
      case CTAP_PIN_KEY_PROTOCOL:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->protocol = (uint8_t)value;
        parsed->has_protocol = 1U;
        break;
      }

      case CTAP_PIN_KEY_SUBCMD:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->subcmd = (uint8_t)value;
        parsed->has_subcmd = 1U;
        break;
      }

      case CTAP_PIN_KEY_AGREEMENT:
        if (parse_cose_p256_public_key(&reader, parsed->key_agreement_pub) == 0U)
        {
          return 0U;
        }
        parsed->has_key_agreement = 1U;
        break;

      case CTAP_PIN_KEY_PIN_AUTH:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != sizeof(parsed->pin_auth)))
        {
          return 0U;
        }
        memcpy(parsed->pin_auth, span.ptr, sizeof(parsed->pin_auth));
        parsed->has_pin_auth = 1U;
        break;
      }

      case CTAP_PIN_KEY_NEW_PIN_ENC:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) ||
            (span.len == 0U) ||
            (span.len > sizeof(parsed->new_pin_enc)) ||
            ((span.len & 0x0FU) != 0U))
        {
          return 0U;
        }
        memcpy(parsed->new_pin_enc, span.ptr, span.len);
        parsed->new_pin_enc_len = span.len;
        parsed->has_new_pin_enc = 1U;
        break;
      }

      case CTAP_PIN_KEY_PIN_HASH_ENC:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != sizeof(parsed->pin_hash_enc)))
        {
          return 0U;
        }
        memcpy(parsed->pin_hash_enc, span.ptr, sizeof(parsed->pin_hash_enc));
        parsed->pin_hash_enc_len = span.len;
        parsed->has_pin_hash_enc = 1U;
        break;
      }

      default:
        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        break;
    }
  }

  return 1U;
}

static uint8_t cbor_write_cose_ec2_public_key(const uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE],
                                              int32_t alg,
                                              uint8_t *out,
                                              uint16_t out_cap,
                                              uint16_t *off)
{
  if ((public_key == NULL) || (out == NULL) || (off == NULL))
  {
    return 0U;
  }

  return (uint8_t)(
      (cbor_write_map(5U, out, out_cap, off) != 0U) &&
      (cbor_write_uint(1U, out, out_cap, off) != 0U) &&
      (cbor_write_uint(2U, out, out_cap, off) != 0U) &&
      (cbor_write_uint(3U, out, out_cap, off) != 0U) &&
      (cbor_write_nint(alg, out, out_cap, off) != 0U) &&
      (cbor_write_nint(-1, out, out_cap, off) != 0U) &&
      (cbor_write_uint(1U, out, out_cap, off) != 0U) &&
      (cbor_write_nint(-2, out, out_cap, off) != 0U) &&
      (cbor_write_bytes(&public_key[0], 32U, out, out_cap, off) != 0U) &&
      (cbor_write_nint(-3, out, out_cap, off) != 0U) &&
      (cbor_write_bytes(&public_key[32], 32U, out, out_cap, off) != 0U));
}

static void ctap_pin_hash16_from_pin(const uint8_t *pin, uint16_t pin_len, uint8_t hash16[CTAP_PIN_HASH_SIZE])
{
  uint8_t full_hash[FIDO_SHA256_SIZE];

  fido_crypto_sha256(pin, pin_len, full_hash);
  memcpy(hash16, full_hash, CTAP_PIN_HASH_SIZE);
}

static uint8_t ctap_client_pin_get_shared_secret(const ctap_client_pin_req_t *parsed,
                                                 uint8_t shared_secret[FIDO_SHA256_SIZE])
{
  if ((parsed == NULL) || (shared_secret == NULL) || (parsed->has_key_agreement == 0U))
  {
    return 0U;
  }
  if (ctap_pin_ensure_key_agreement() == 0U)
  {
    return 0U;
  }

  return fido_crypto_ecdh_shared_secret(s_ctap_pin_key_agreement_priv,
                                        parsed->key_agreement_pub,
                                        shared_secret);
}

static uint8_t ctap_client_pin_verify_pin_auth(const uint8_t shared_secret[FIDO_SHA256_SIZE],
                                               const uint8_t *data_a,
                                               uint16_t data_a_len,
                                               const uint8_t *data_b,
                                               uint16_t data_b_len,
                                               const uint8_t pin_auth[16])
{
  uint8_t temp[CTAP_PIN_MAX_ENC_SIZE + 16U];
  uint8_t auth[FIDO_SHA256_SIZE];
  uint16_t total = 0U;

  if ((shared_secret == NULL) || (pin_auth == NULL))
  {
    return 0U;
  }
  if ((data_a_len + data_b_len) > sizeof(temp))
  {
    return 0U;
  }

  memset(temp, 0, sizeof(temp));
  if ((data_a != NULL) && (data_a_len != 0U))
  {
    memcpy(temp, data_a, data_a_len);
    total = data_a_len;
  }
  if ((data_b != NULL) && (data_b_len != 0U))
  {
    memcpy(&temp[total], data_b, data_b_len);
    total = (uint16_t)(total + data_b_len);
  }

  fido_crypto_hmac_sha256(shared_secret, FIDO_SHA256_SIZE, temp, total, auth);
  return (uint8_t)(memcmp(auth, pin_auth, 16U) == 0);
}

static uint8_t ctap_client_pin_decrypt_new_pin(const uint8_t shared_secret[FIDO_SHA256_SIZE],
                                               const ctap_client_pin_req_t *parsed,
                                               uint8_t new_pin[CTAP_PIN_MAX_ENC_SIZE],
                                               uint16_t *new_pin_len)
{
  uint8_t plaintext[CTAP_PIN_MAX_ENC_SIZE];
  uint16_t len = 0U;

  if ((shared_secret == NULL) || (parsed == NULL) || (new_pin == NULL) || (new_pin_len == NULL) ||
      (parsed->has_new_pin_enc == 0U))
  {
    return 0U;
  }
  memset(plaintext, 0, sizeof(plaintext));
  if (fido_crypto_aes256_cbc_zero_iv_decrypt(shared_secret,
                                             parsed->new_pin_enc,
                                             parsed->new_pin_enc_len,
                                             plaintext,
                                             sizeof(plaintext)) == 0U)
  {
    return 0U;
  }

  while ((len < parsed->new_pin_enc_len) && (plaintext[len] != 0U))
  {
    len++;
  }
  if ((len < CTAP_PIN_MIN_LEN) || (len >= parsed->new_pin_enc_len))
  {
    return 0U;
  }

  memcpy(new_pin, plaintext, len);
  *new_pin_len = len;
  return 1U;
}

static uint8_t ctap_client_pin_decrypt_pin_hash(const uint8_t shared_secret[FIDO_SHA256_SIZE],
                                                const ctap_client_pin_req_t *parsed,
                                                uint8_t pin_hash16[CTAP_PIN_HASH_SIZE])
{
  if ((shared_secret == NULL) || (parsed == NULL) || (pin_hash16 == NULL) || (parsed->has_pin_hash_enc == 0U))
  {
    return 0U;
  }

  return fido_crypto_aes256_cbc_zero_iv_decrypt(shared_secret,
                                                parsed->pin_hash_enc,
                                                parsed->pin_hash_enc_len,
                                                pin_hash16,
                                                CTAP_PIN_HASH_SIZE);
}

static uint8_t build_client_pin_retries_response(uint8_t *resp, uint16_t resp_cap, uint16_t *resp_len)
{
  uint16_t off = 1U;

  if ((resp == NULL) || (resp_len == NULL) || (resp_cap < 4U))
  {
    return 0U;
  }

  resp[0] = CTAP_STATUS_OK;
  if ((cbor_write_map(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(CTAP_PIN_RESP_KEY_RETRIES, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(s_ctap_pin_retries, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static uint8_t build_client_pin_key_agreement_response(uint8_t *resp, uint16_t resp_cap, uint16_t *resp_len)
{
  uint16_t off = 1U;

  if ((resp == NULL) || (resp_len == NULL) || (ctap_pin_ensure_key_agreement() == 0U))
  {
    return 0U;
  }

  resp[0] = CTAP_STATUS_OK;
  if ((cbor_write_map(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(CTAP_PIN_RESP_KEY_AGREEMENT, resp, resp_cap, &off) == 0U) ||
      (cbor_write_cose_ec2_public_key(s_ctap_pin_key_agreement_pub, -25, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static uint8_t build_client_pin_token_response(const uint8_t shared_secret[FIDO_SHA256_SIZE],
                                               uint8_t *resp,
                                               uint16_t resp_cap,
                                               uint16_t *resp_len)
{
  uint8_t enc_token[CTAP_PIN_TOKEN_SIZE];
  uint16_t off = 1U;

  if ((shared_secret == NULL) || (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }
  if ((s_ctap_pin_token_valid == 0U) && (fido_crypto_random(s_ctap_pin_token, sizeof(s_ctap_pin_token)) == 0U))
  {
    return 0U;
  }
  s_ctap_pin_token_valid = 1U;
  if (fido_crypto_aes256_cbc_zero_iv_encrypt(shared_secret,
                                             s_ctap_pin_token,
                                             sizeof(s_ctap_pin_token),
                                             enc_token,
                                             sizeof(enc_token)) == 0U)
  {
    return 0U;
  }

  resp[0] = CTAP_STATUS_OK;
  if ((cbor_write_map(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(CTAP_PIN_RESP_KEY_PIN_TOKEN, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(enc_token, sizeof(enc_token), resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static void ctap_credman_reset_state(void)
{
  memset(s_ctap_credman_rp_hash, 0, sizeof(s_ctap_credman_rp_hash));
  s_ctap_credman_rp_cursor = 0U;
  s_ctap_credman_rp_total = 0U;
  s_ctap_credman_rk_cursor = 0U;
  s_ctap_credman_rk_total = 0U;
}

static void ctap_hex_encode(const uint8_t *src, uint16_t src_len, char *dst, uint16_t dst_cap)
{
  static const char kHex[] = "0123456789abcdef";
  uint16_t i;
  uint16_t off = 0U;

  if ((src == NULL) || (dst == NULL) || (dst_cap == 0U))
  {
    return;
  }

  for (i = 0U; (i < src_len) && ((uint16_t)(off + 2U) < dst_cap); ++i)
  {
    dst[off++] = kHex[src[i] >> 4];
    dst[off++] = kHex[src[i] & 0x0FU];
  }
  dst[off] = '\0';
}

static void ctap_credman_format_rp_id(const fido_store_credential_t *credential, char rp_id[96])
{
  if ((credential == NULL) || (rp_id == NULL))
  {
    return;
  }

  if (credential->rp_id[0] != '\0')
  {
    strncpy(rp_id, credential->rp_id, 95U);
    rp_id[95] = '\0';
    return;
  }

  ctap_hex_encode(credential->rp_id_hash, FIDO_SHA256_SIZE, rp_id, 96U);
}

static uint8_t ctap_credman_rp_hash_matches(const fido_store_credential_t *credential,
                                            const uint8_t requested_rp_id_hash[FIDO_SHA256_SIZE])
{
  char rp_id[96];
  uint8_t fallback_hash[FIDO_SHA256_SIZE];

  if ((credential == NULL) || (requested_rp_id_hash == NULL))
  {
    return 0U;
  }

  if (memcmp(credential->rp_id_hash, requested_rp_id_hash, FIDO_SHA256_SIZE) == 0)
  {
    return 1U;
  }

  ctap_credman_format_rp_id(credential, rp_id);
  if (rp_id[0] == '\0')
  {
    return 0U;
  }

  fido_crypto_sha256((const uint8_t *)rp_id, (uint32_t)strlen(rp_id), fallback_hash);
  return (uint8_t)(memcmp(fallback_hash, requested_rp_id_hash, FIDO_SHA256_SIZE) == 0);
}

static uint16_t ctap_credman_count_unique_rps(void)
{
  fido_store_credential_t current;
  fido_store_credential_t previous;
  uint16_t total = fido_store_count();
  uint16_t unique = 0U;
  uint16_t i;
  uint16_t j;

  for (i = 0U; i < total; ++i)
  {
    uint8_t seen = 0U;

    if (fido_store_get_nth(i, &current, NULL) == 0U)
    {
      break;
    }
    for (j = 0U; j < i; ++j)
    {
      if ((fido_store_get_nth(j, &previous, NULL) != 0U) &&
          (memcmp(previous.rp_id_hash, current.rp_id_hash, FIDO_SHA256_SIZE) == 0))
      {
        seen = 1U;
        break;
      }
    }
    if (seen == 0U)
    {
      unique++;
    }
  }

  return unique;
}

static uint8_t ctap_credman_get_nth_rp(uint16_t ordinal, fido_store_credential_t *credential)
{
  fido_store_credential_t current;
  fido_store_credential_t previous;
  fido_store_credential_t chosen;
  uint16_t total = fido_store_count();
  uint16_t unique = 0U;
  uint16_t i;
  uint16_t j;

  if (credential == NULL)
  {
    return 0U;
  }

  for (i = 0U; i < total; ++i)
  {
    uint8_t seen = 0U;

    if (fido_store_get_nth(i, &current, NULL) == 0U)
    {
      return 0U;
    }
    for (j = 0U; j < i; ++j)
    {
      if ((fido_store_get_nth(j, &previous, NULL) != 0U) &&
          (memcmp(previous.rp_id_hash, current.rp_id_hash, FIDO_SHA256_SIZE) == 0))
      {
        seen = 1U;
        break;
      }
    }
    if (seen == 0U)
    {
      chosen = current;
      if (chosen.rp_id[0] == '\0')
      {
        for (j = (uint16_t)(i + 1U); j < total; ++j)
        {
          if ((fido_store_get_nth(j, &previous, NULL) != 0U) &&
              (memcmp(previous.rp_id_hash, current.rp_id_hash, FIDO_SHA256_SIZE) == 0) &&
              (previous.rp_id[0] != '\0'))
          {
            chosen = previous;
            break;
          }
        }
      }
      if (unique == ordinal)
      {
        *credential = chosen;
        return 1U;
      }
      unique++;
    }
  }

  return 0U;
}

static uint16_t ctap_credman_count_rks_for_rp(const uint8_t rp_id_hash[FIDO_SHA256_SIZE])
{
  fido_store_credential_t current;
  uint16_t total = fido_store_count();
  uint16_t count = 0U;
  uint16_t i;

  if (rp_id_hash == NULL)
  {
    return 0U;
  }

  for (i = 0U; i < total; ++i)
  {
    if ((fido_store_get_nth(i, &current, NULL) != 0U) &&
        (ctap_credman_rp_hash_matches(&current, rp_id_hash) != 0U))
    {
      count++;
    }
  }

  return count;
}

static uint8_t ctap_credman_get_nth_rk_for_rp(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                              uint16_t ordinal,
                                              fido_store_credential_t *credential,
                                              uint32_t *slot_index)
{
  fido_store_credential_t current;
  uint32_t current_slot = 0U;
  uint16_t total = fido_store_count();
  uint16_t count = 0U;
  uint16_t i;

  if ((rp_id_hash == NULL) || (credential == NULL))
  {
    return 0U;
  }

  for (i = 0U; i < total; ++i)
  {
    if (fido_store_get_nth(i, &current, &current_slot) == 0U)
    {
      return 0U;
    }
    if (ctap_credman_rp_hash_matches(&current, rp_id_hash) == 0U)
    {
      continue;
    }
    if (count == ordinal)
    {
      *credential = current;
      if (slot_index != NULL)
      {
        *slot_index = current_slot;
      }
      return 1U;
    }
    count++;
  }

  return 0U;
}

static uint8_t parse_credential_descriptor(cbor_reader_t *reader,
                                           uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE],
                                           uint16_t *credential_id_len)
{
  uint32_t pair_count;
  uint32_t i;
  uint8_t found = 0U;

  if ((reader == NULL) || (credential_id == NULL) || (credential_id_len == NULL) ||
      (cbor_enter_map(reader, &pair_count) == 0U))
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    cbor_span_t key;

    if (cbor_read_text(reader, &key) == 0U)
    {
      return 0U;
    }
    if (cbor_text_eq(&key, "id") != 0U)
    {
      cbor_span_t value;

      if ((cbor_read_bytes(reader, &value) == 0U) || (value.len > FIDO_CREDENTIAL_ID_SIZE))
      {
        return 0U;
      }
      memcpy(credential_id, value.ptr, value.len);
      *credential_id_len = value.len;
      found = 1U;
    }
    else if (cbor_skip_item(reader) == 0U)
    {
      return 0U;
    }
  }

  return found;
}

static uint8_t parse_cred_mgmt(const uint8_t *req,
                               uint16_t req_len,
                               ctap_cred_mgmt_req_t *parsed)
{
  cbor_reader_t reader;
  uint32_t pair_count;
  uint32_t i;

  if ((req == NULL) || (req_len < 2U) || (parsed == NULL))
  {
    return 0U;
  }

  memset(parsed, 0, sizeof(*parsed));
  reader.buf = &req[1];
  reader.len = (uint16_t)(req_len - 1U);
  reader.off = 0U;
  if (cbor_enter_map(&reader, &pair_count) == 0U)
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    uint32_t key;

    if (cbor_read_uint(&reader, &key) == 0U)
    {
      return 0U;
    }

    switch (key)
    {
      case CTAP_CRED_MGMT_KEY_SUBCMD:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->subcmd = (uint8_t)value;
        parsed->has_subcmd = 1U;
        break;
      }

      case CTAP_CRED_MGMT_KEY_PARAMS:
      {
        uint16_t start = reader.off;

        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        parsed->subcmd_params.ptr = &reader.buf[start];
        parsed->subcmd_params.len = (uint16_t)(reader.off - start);
        parsed->has_subcmd_params = 1U;
        break;
      }

      case CTAP_CRED_MGMT_KEY_PROTOCOL:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->protocol = (uint8_t)value;
        parsed->has_protocol = 1U;
        break;
      }

      case CTAP_CRED_MGMT_KEY_PIN_AUTH:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != sizeof(parsed->pin_auth)))
        {
          return 0U;
        }
        memcpy(parsed->pin_auth, span.ptr, sizeof(parsed->pin_auth));
        parsed->has_pin_auth = 1U;
        break;
      }

      default:
        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        break;
    }
  }

  if (parsed->has_subcmd_params != 0U)
  {
    cbor_reader_t params_reader;
    uint32_t params_count;
    uint32_t j;

    params_reader.buf = parsed->subcmd_params.ptr;
    params_reader.len = parsed->subcmd_params.len;
    params_reader.off = 0U;
    if (cbor_enter_map(&params_reader, &params_count) == 0U)
    {
      return 0U;
    }
    for (j = 0U; j < params_count; ++j)
    {
      uint32_t param_key;

      if (cbor_read_uint(&params_reader, &param_key) == 0U)
      {
        return 0U;
      }
      if ((parsed->subcmd == CTAP_CRED_MGMT_SUBCMD_RK_BEGIN) && (param_key == 1U))
      {
        cbor_span_t value;

        if ((cbor_read_bytes(&params_reader, &value) == 0U) || (value.len != FIDO_SHA256_SIZE))
        {
          return 0U;
        }
        memcpy(parsed->rp_id_hash, value.ptr, FIDO_SHA256_SIZE);
        parsed->has_rp_id_hash = 1U;
      }
      else if ((parsed->subcmd == CTAP_CRED_MGMT_SUBCMD_DELETE) && (param_key == 2U))
      {
        if (parse_credential_descriptor(&params_reader,
                                        parsed->credential_id,
                                        &parsed->credential_id_len) == 0U)
        {
          return 0U;
        }
        parsed->has_credential_id = 1U;
      }
      else if (cbor_skip_item(&params_reader) == 0U)
      {
        return 0U;
      }
    }
  }

  return 1U;
}

static uint8_t parse_config(const uint8_t *req,
                            uint16_t req_len,
                            ctap_config_req_t *parsed)
{
  cbor_reader_t reader;
  uint32_t pair_count;
  uint32_t i;

  if ((req == NULL) || (req_len < 2U) || (parsed == NULL))
  {
    return 0U;
  }

  memset(parsed, 0, sizeof(*parsed));
  reader.buf = &req[1];
  reader.len = (uint16_t)(req_len - 1U);
  reader.off = 0U;
  if (cbor_enter_map(&reader, &pair_count) == 0U)
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    uint32_t key;

    if (cbor_read_uint(&reader, &key) == 0U)
    {
      return 0U;
    }

    switch (key)
    {
      case CTAP_CONFIG_KEY_SUBCMD:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->subcmd = (uint8_t)value;
        parsed->has_subcmd = 1U;
        break;
      }

      case CTAP_CONFIG_KEY_PARAMS:
      {
        uint16_t start = reader.off;

        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        parsed->subcmd_params.ptr = &reader.buf[start];
        parsed->subcmd_params.len = (uint16_t)(reader.off - start);
        parsed->has_subcmd_params = 1U;
        break;
      }

      case CTAP_CONFIG_KEY_PROTOCOL:
      {
        uint32_t value;

        if (cbor_read_uint(&reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->protocol = (uint8_t)value;
        parsed->has_protocol = 1U;
        break;
      }

      case CTAP_CONFIG_KEY_PIN_AUTH:
      {
        cbor_span_t span;

        if ((cbor_read_bytes(&reader, &span) == 0U) || (span.len != sizeof(parsed->pin_auth)))
        {
          return 0U;
        }
        memcpy(parsed->pin_auth, span.ptr, sizeof(parsed->pin_auth));
        parsed->has_pin_auth = 1U;
        break;
      }

      default:
        if (cbor_skip_item(&reader) == 0U)
        {
          return 0U;
        }
        break;
    }
  }

  if (parsed->has_subcmd_params != 0U)
  {
    cbor_reader_t params_reader;
    uint32_t params_count;
    uint32_t j;

    params_reader.buf = parsed->subcmd_params.ptr;
    params_reader.len = parsed->subcmd_params.len;
    params_reader.off = 0U;
    if (cbor_enter_map(&params_reader, &params_count) == 0U)
    {
      return 0U;
    }
    for (j = 0U; j < params_count; ++j)
    {
      uint32_t param_key;

      if (cbor_read_uint(&params_reader, &param_key) == 0U)
      {
        return 0U;
      }
      if ((parsed->subcmd == CTAP_CONFIG_SUBCMD_SET_MIN_PIN_LEN) &&
          (param_key == CTAP_CONFIG_PARAM_NEW_MIN_PIN_LEN))
      {
        uint32_t value;

        if ((cbor_read_uint(&params_reader, &value) == 0U) || (value > 63U))
        {
          return 0U;
        }
        parsed->new_min_pin_len = (uint8_t)value;
        parsed->has_new_min_pin_len = 1U;
      }
      else if ((parsed->subcmd == CTAP_CONFIG_SUBCMD_SET_MIN_PIN_LEN) &&
               (param_key == CTAP_CONFIG_PARAM_FORCE_CHANGE_PIN))
      {
        uint8_t value;

        if (cbor_read_bool(&params_reader, &value) == 0U)
        {
          return 0U;
        }
        parsed->force_change_pin = value;
        parsed->has_force_change_pin = 1U;
      }
      else if (cbor_skip_item(&params_reader) == 0U)
      {
        return 0U;
      }
    }
  }

  return 1U;
}

static uint8_t ctap_credman_verify_pin_auth(const ctap_cred_mgmt_req_t *parsed)
{
  uint8_t auth[FIDO_SHA256_SIZE];
  uint8_t data[1U + 128U];
  uint16_t data_len = 1U;

  if (parsed == NULL)
  {
    return 0U;
  }
  if (fido_store_client_pin_is_set() == 0U)
  {
    return CTAP_ERR_PIN_NOT_SET;
  }
  if ((parsed->has_protocol == 0U) || (parsed->protocol != CTAP_PIN_PROTOCOL_ONE) || (parsed->has_pin_auth == 0U))
  {
    return CTAP_ERR_PIN_REQUIRED;
  }
  if (s_ctap_pin_token_valid == 0U)
  {
    return CTAP_ERR_PIN_AUTH_INVALID;
  }
  if (parsed->subcmd_params.len > 128U)
  {
    return CTAP_ERR_INVALID_LENGTH;
  }

  data[0] = parsed->subcmd;
  if ((parsed->has_subcmd_params != 0U) && (parsed->subcmd_params.len != 0U))
  {
    memcpy(&data[1], parsed->subcmd_params.ptr, parsed->subcmd_params.len);
    data_len = (uint16_t)(data_len + parsed->subcmd_params.len);
  }

  fido_crypto_hmac_sha256(s_ctap_pin_token, sizeof(s_ctap_pin_token), data, data_len, auth);
  return (uint8_t)(memcmp(auth, parsed->pin_auth, sizeof(parsed->pin_auth)) == 0 ?
                   CTAP_STATUS_OK : CTAP_ERR_PIN_AUTH_INVALID);
}

static uint8_t ctap_config_verify_pin_auth(const ctap_config_req_t *parsed)
{
  uint8_t auth[FIDO_SHA256_SIZE];
  uint8_t data[34U + 128U];
  uint16_t data_len = 34U;

  if (parsed == NULL)
  {
    return 0U;
  }
  if (fido_store_client_pin_is_set() == 0U)
  {
    return CTAP_ERR_PIN_NOT_SET;
  }
  if ((parsed->has_protocol == 0U) || (parsed->protocol != CTAP_PIN_PROTOCOL_ONE) || (parsed->has_pin_auth == 0U))
  {
    return CTAP_ERR_PIN_REQUIRED;
  }
  if (s_ctap_pin_token_valid == 0U)
  {
    return CTAP_ERR_PIN_AUTH_INVALID;
  }
  if (parsed->subcmd_params.len > 128U)
  {
    return CTAP_ERR_INVALID_LENGTH;
  }

  memset(data, 0xFF, 32U);
  data[32] = CTAP_CMD_CONFIG;
  data[33] = parsed->subcmd;
  if ((parsed->has_subcmd_params != 0U) && (parsed->subcmd_params.len != 0U))
  {
    memcpy(&data[34], parsed->subcmd_params.ptr, parsed->subcmd_params.len);
    data_len = (uint16_t)(data_len + parsed->subcmd_params.len);
  }

  fido_crypto_hmac_sha256(s_ctap_pin_token, sizeof(s_ctap_pin_token), data, data_len, auth);
  return (uint8_t)(memcmp(auth, parsed->pin_auth, sizeof(parsed->pin_auth)) == 0 ?
                   CTAP_STATUS_OK : CTAP_ERR_PIN_AUTH_INVALID);
}

static uint8_t ctap_assertion_policy_allows(const ctap_get_assertion_req_t *parsed,
                                            const fido_store_credential_t *credential,
                                            uint8_t pin_uv_verified)
{
  uint8_t policy;

  if ((parsed == NULL) || (credential == NULL))
  {
    return 0U;
  }

  policy = credential->cred_protect_policy;
  if ((policy == 0U) || (policy == CTAP_CRED_PROTECT_UV_OPTIONAL))
  {
    return 1U;
  }
  if (policy == CTAP_CRED_PROTECT_UV_REQUIRED)
  {
    return pin_uv_verified;
  }

  return (uint8_t)(((parsed->allow_credential_total != 0U) || (pin_uv_verified != 0U)) ? 1U : 0U);
}

static uint8_t cbor_write_rp_entity(const char *rp_id,
                                    uint8_t *out,
                                    uint16_t out_cap,
                                    uint16_t *off)
{
  if ((rp_id == NULL) || (out == NULL) || (off == NULL))
  {
    return 0U;
  }

  return (uint8_t)(
      (cbor_write_map(2U, out, out_cap, off) != 0U) &&
      (cbor_write_text("id", out, out_cap, off) != 0U) &&
      (cbor_write_text(rp_id, out, out_cap, off) != 0U) &&
      (cbor_write_text("name", out, out_cap, off) != 0U) &&
      (cbor_write_text(rp_id, out, out_cap, off) != 0U));
}

static uint8_t cbor_write_user_entity(const fido_store_credential_t *credential,
                                      uint8_t *out,
                                      uint16_t out_cap,
                                      uint16_t *off)
{
  uint32_t field_count = 1U;

  if ((credential == NULL) || (out == NULL) || (off == NULL))
  {
    return 0U;
  }
  if (credential->user_name[0] != '\0')
  {
    field_count++;
  }
  if (credential->user_display_name[0] != '\0')
  {
    field_count++;
  }

  if ((cbor_write_map(field_count, out, out_cap, off) == 0U) ||
      (cbor_write_text("id", out, out_cap, off) == 0U) ||
      (cbor_write_bytes(credential->user_id, credential->user_id_len, out, out_cap, off) == 0U))
  {
    return 0U;
  }
  if ((credential->user_name[0] != '\0') &&
      ((cbor_write_text("name", out, out_cap, off) == 0U) ||
       (cbor_write_text(credential->user_name, out, out_cap, off) == 0U)))
  {
    return 0U;
  }
  if ((credential->user_display_name[0] != '\0') &&
      ((cbor_write_text("displayName", out, out_cap, off) == 0U) ||
       (cbor_write_text(credential->user_display_name, out, out_cap, off) == 0U)))
  {
    return 0U;
  }

  return 1U;
}

static uint8_t cbor_write_credential_descriptor(const fido_store_credential_t *credential,
                                                uint8_t *out,
                                                uint16_t out_cap,
                                                uint16_t *off)
{
  if ((credential == NULL) || (out == NULL) || (off == NULL))
  {
    return 0U;
  }

  return (uint8_t)(
      (cbor_write_map(2U, out, out_cap, off) != 0U) &&
      (cbor_write_text("id", out, out_cap, off) != 0U) &&
      (cbor_write_bytes(credential->credential_id, credential->credential_id_len, out, out_cap, off) != 0U) &&
      (cbor_write_text("type", out, out_cap, off) != 0U) &&
      (cbor_write_text("public-key", out, out_cap, off) != 0U));
}

static uint8_t build_credman_metadata_response(uint8_t *resp, uint16_t resp_cap, uint16_t *resp_len)
{
  uint16_t off = 1U;
  uint16_t existing = fido_store_count();
  uint16_t remaining = (uint16_t)((FIDO_STORE_CREDENTIALS_MAX - 1U) - existing);

  if ((resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }

  resp[0] = CTAP_STATUS_OK;
  if ((cbor_write_map(2U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(existing, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(2U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(remaining, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static uint8_t build_credman_rp_response(const fido_store_credential_t *credential,
                                         uint8_t include_total,
                                         uint16_t total,
                                         uint8_t *resp,
                                         uint16_t resp_cap,
                                         uint16_t *resp_len)
{
  uint16_t off = 1U;
  char rp_id[96];

  if ((credential == NULL) || (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }

  ctap_credman_format_rp_id(credential, rp_id);
  resp[0] = CTAP_STATUS_OK;
  if ((cbor_write_map((uint32_t)(include_total != 0U ? 3U : 2U), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(3U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_rp_entity(rp_id, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(4U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(credential->rp_id_hash, FIDO_SHA256_SIZE, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }
  if ((include_total != 0U) &&
      ((cbor_write_uint(5U, resp, resp_cap, &off) == 0U) ||
       (cbor_write_uint(total, resp, resp_cap, &off) == 0U)))
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static uint8_t build_credman_rk_response(const fido_store_credential_t *credential,
                                         uint8_t include_total,
                                         uint16_t total,
                                         uint8_t *resp,
                                         uint16_t resp_cap,
                                         uint16_t *resp_len)
{
  uint8_t cose_key[128];
  uint16_t cose_key_len = 0U;
  uint16_t off = 1U;

  if ((credential == NULL) || (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }
  if (build_cose_public_key(credential->public_key, cose_key, sizeof(cose_key), &cose_key_len) == 0U)
  {
    return 0U;
  }

  resp[0] = CTAP_STATUS_OK;
  if ((cbor_write_map((uint32_t)(include_total != 0U ? 4U : 3U), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(6U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_user_entity(credential, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(7U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_credential_descriptor(credential, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(8U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_raw(cose_key, cose_key_len, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }
  if ((include_total != 0U) &&
      ((cbor_write_uint(9U, resp, resp_cap, &off) == 0U) ||
       (cbor_write_uint(total, resp, resp_cap, &off) == 0U)))
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static uint8_t ctap_append_candidate(const fido_store_credential_t *credential, uint32_t slot_index)
{
  uint8_t i;

  if (credential == NULL)
  {
    return 0U;
  }

  for (i = 0U; i < s_ctap_selection_count; ++i)
  {
    if (s_ctap_candidate_slots[i] == slot_index)
    {
      return 1U;
    }
  }

  if (s_ctap_selection_count >= CTAP_GA_ALLOW_LIST_MAX)
  {
    return 0U;
  }

  s_ctap_candidates[s_ctap_selection_count] = *credential;
  s_ctap_candidate_slots[s_ctap_selection_count] = slot_index;
  s_ctap_selection_count = (uint8_t)(s_ctap_selection_count + 1U);
  return 1U;
}

static uint8_t ctap_collect_assertion_candidates_from_allow_list(const uint8_t *req,
                                                                 uint16_t req_len,
                                                                 const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                                                 const ctap_get_assertion_req_t *parsed,
                                                                 uint8_t pin_uv_verified)
{
  cbor_reader_t reader;
  uint32_t pair_count;
  uint32_t i;

  if ((req == NULL) || (req_len < 2U) || (rp_id_hash == NULL))
  {
    return 0U;
  }

  s_ctap_selection_count = 0U;
  s_ctap_selection_index = 0U;

  reader.buf = &req[1];
  reader.len = (uint16_t)(req_len - 1U);
  reader.off = 0U;

  if (cbor_enter_map(&reader, &pair_count) == 0U)
  {
    return 0U;
  }

  for (i = 0U; i < pair_count; ++i)
  {
    uint32_t key;

    if (cbor_read_uint(&reader, &key) == 0U)
    {
      return 0U;
    }

    if (key == CTAP_GA_KEY_ALLOW_LIST)
    {
      uint32_t item_count;
      uint32_t item_index;

      if (cbor_enter_array(&reader, &item_count) == 0U)
      {
        return 0U;
      }

      g_a_usb_diag_runtime.fido_last_allow_count = (uint32_t)((item_count > 0xFFFFU) ? 0xFFFFU : item_count);
      for (item_index = 0U; item_index < item_count; ++item_index)
      {
        uint32_t field_count;
        uint32_t field_index;
        uint8_t found = 0U;
        uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE];
        uint16_t credential_id_len = 0U;

        if (cbor_enter_map(&reader, &field_count) == 0U)
        {
          return 0U;
        }

        for (field_index = 0U; field_index < field_count; ++field_index)
        {
          cbor_span_t key_text;

          if (cbor_read_text(&reader, &key_text) == 0U)
          {
            return 0U;
          }
          if (cbor_text_eq(&key_text, "id") != 0U)
          {
            cbor_span_t value;

            if (cbor_read_bytes(&reader, &value) == 0U)
            {
              return 0U;
            }
            if (value.len <= FIDO_CREDENTIAL_ID_SIZE)
            {
              memcpy(credential_id, value.ptr, value.len);
              credential_id_len = value.len;
              found = 1U;
            }
          }
          else if (cbor_skip_item(&reader) == 0U)
          {
            return 0U;
          }
        }

        if (found != 0U)
        {
          fido_store_credential_t credential;
          uint32_t slot_index = 0U;

          if (fido_store_find(rp_id_hash,
                              credential_id,
                              credential_id_len,
                              &credential,
                              &slot_index) != 0U)
          {
            if (ctap_assertion_policy_allows(parsed, &credential, pin_uv_verified) != 0U)
            {
              (void)ctap_append_candidate(&credential, slot_index);
            }
          }
        }
      }

      return s_ctap_selection_count;
    }

    if (cbor_skip_item(&reader) == 0U)
    {
      return 0U;
    }
  }

  return 0U;
}

static uint8_t ctap_collect_assertion_candidates(const uint8_t *req,
                                                 uint16_t req_len,
                                                 const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                                 const ctap_get_assertion_req_t *parsed,
                                                 uint8_t pin_uv_verified)
{
  uint32_t slot_index;

  s_ctap_selection_count = 0U;
  s_ctap_selection_index = 0U;

  if ((req == NULL) || (rp_id_hash == NULL) || (parsed == NULL))
  {
    return 0U;
  }

  if (parsed->allow_credential_total != 0U)
  {
    return ctap_collect_assertion_candidates_from_allow_list(req, req_len, rp_id_hash, parsed, pin_uv_verified);
  }

  for (slot_index = 0U; slot_index < FIDO_STORE_CREDENTIALS_MAX; ++slot_index)
  {
    fido_store_credential_t credential;

    if (fido_store_get_by_index(slot_index, &credential) == 0U)
    {
      continue;
    }
    if (memcmp(credential.rp_id_hash, rp_id_hash, FIDO_SHA256_SIZE) != 0)
    {
      continue;
    }
    if (ctap_assertion_policy_allows(parsed, &credential, pin_uv_verified) == 0U)
    {
      continue;
    }

    s_ctap_candidates[s_ctap_selection_count] = credential;
    s_ctap_candidate_slots[s_ctap_selection_count] = slot_index;
    s_ctap_selection_count = (uint8_t)(s_ctap_selection_count + 1U);
    if (s_ctap_selection_count >= CTAP_GA_ALLOW_LIST_MAX)
    {
      break;
    }
  }

  return s_ctap_selection_count;
}

static uint8_t build_cose_public_key(const uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE],
                                     uint8_t *out,
                                     uint16_t out_cap,
                                     uint16_t *out_len)
{
  uint16_t off = 0U;

  if ((public_key == NULL) || (out == NULL) || (out_len == NULL))
  {
    return 0U;
  }

  if ((cbor_write_map(5U, out, out_cap, &off) == 0U) ||
      (cbor_write_uint(1U, out, out_cap, &off) == 0U) ||
      (cbor_write_uint(2U, out, out_cap, &off) == 0U) ||
      (cbor_write_uint(3U, out, out_cap, &off) == 0U) ||
      (cbor_write_nint(-7, out, out_cap, &off) == 0U) ||
      (cbor_write_nint(-1, out, out_cap, &off) == 0U) ||
      (cbor_write_uint(1U, out, out_cap, &off) == 0U) ||
      (cbor_write_nint(-2, out, out_cap, &off) == 0U) ||
      (cbor_write_bytes(&public_key[0], 32U, out, out_cap, &off) == 0U) ||
      (cbor_write_nint(-3, out, out_cap, &off) == 0U) ||
      (cbor_write_bytes(&public_key[32], 32U, out, out_cap, &off) == 0U))
  {
    return 0U;
  }

  *out_len = off;
  return 1U;
}

static uint8_t build_make_credential_auth_data(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                               const fido_store_credential_t *credential,
                                               uint8_t include_cred_protect_ext,
                                               uint8_t *auth_data,
                                               uint16_t auth_cap,
                                               uint16_t *auth_len)
{
  static const uint8_t k_aaguid[16] = {
      0x55U, 0x4CU, 0x54U, 0x52U, 0x41U, 0x4CU, 0x49U, 0x4EU,
      0x4BU, 0x2DU, 0x46U, 0x34U, 0x30U, 0x35U, 0x02U, 0x00U};
  uint8_t cose_key[96];
  uint8_t ext_data[32];
  uint16_t cose_key_len;
  uint16_t ext_len = 0U;
  uint16_t off = 0U;

  if ((rp_id_hash == NULL) || (credential == NULL) || (auth_data == NULL) || (auth_len == NULL))
  {
    return 0U;
  }
  if (build_cose_public_key(credential->public_key, cose_key, sizeof(cose_key), &cose_key_len) == 0U)
  {
    return 0U;
  }
  if ((include_cred_protect_ext != 0U) &&
      ((cbor_write_map(1U, ext_data, sizeof(ext_data), &ext_len) == 0U) ||
       (cbor_write_text("credProtect", ext_data, sizeof(ext_data), &ext_len) == 0U) ||
       (cbor_write_uint(credential->cred_protect_policy, ext_data, sizeof(ext_data), &ext_len) == 0U)))
  {
    return 0U;
  }
  if ((uint16_t)(32U + 1U + 4U + 16U + 2U + credential->credential_id_len + cose_key_len + ext_len) > auth_cap)
  {
    return 0U;
  }

  memcpy(&auth_data[off], rp_id_hash, FIDO_SHA256_SIZE);
  off = (uint16_t)(off + FIDO_SHA256_SIZE);
  auth_data[off++] = (uint8_t)(CTAP_FLAG_USER_PRESENT |
                               CTAP_FLAG_ATTESTED |
                               (include_cred_protect_ext != 0U ? CTAP_FLAG_EXTENSION_DATA : 0U));
  store_be32(&auth_data[off], 0U);
  off = (uint16_t)(off + 4U);
  memcpy(&auth_data[off], k_aaguid, sizeof(k_aaguid));
  off = (uint16_t)(off + sizeof(k_aaguid));
  store_be16(&auth_data[off], credential->credential_id_len);
  off = (uint16_t)(off + 2U);
  memcpy(&auth_data[off], credential->credential_id, credential->credential_id_len);
  off = (uint16_t)(off + credential->credential_id_len);
  memcpy(&auth_data[off], cose_key, cose_key_len);
  off = (uint16_t)(off + cose_key_len);
  if (ext_len != 0U)
  {
    memcpy(&auth_data[off], ext_data, ext_len);
    off = (uint16_t)(off + ext_len);
  }
  *auth_len = off;
  return 1U;
}

static uint8_t build_make_credential_response(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                              const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                                              const fido_store_credential_t *credential,
                                              uint8_t include_cred_protect_ext,
                                              uint8_t *resp,
                                              uint16_t resp_cap,
                                              uint16_t *resp_len)
{
  uint8_t auth_data[256];
  uint8_t signature[80];
  uint16_t auth_len;
  uint16_t signature_len = 0U;
  uint16_t off = 0U;

  if ((client_data_hash == NULL) || (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }
  if (build_make_credential_auth_data(rp_id_hash,
                                      credential,
                                      include_cred_protect_ext,
                                      auth_data,
                                      sizeof(auth_data),
                                      &auth_len) == 0U)
  {
    return 0U;
  }
  if (fido_crypto_sign_es256_der(credential->private_key,
                                 auth_data,
                                 auth_len,
                                 client_data_hash,
                                 signature,
                                 sizeof(signature),
                                 &signature_len) == 0U)
  {
    return 0U;
  }

  resp[off++] = CTAP_STATUS_OK;
  if ((cbor_write_map(3U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x01U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("packed", resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x02U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(auth_data, auth_len, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x03U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_map(2U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("alg", resp, resp_cap, &off) == 0U) ||
      (cbor_write_nint(-7, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("sig", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(signature, signature_len, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static uint8_t build_get_assertion_response(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                            fido_store_credential_t *credential,
                                            uint32_t slot_index,
                                            const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                                            uint8_t user_present,
                                            uint8_t *resp,
                                            uint16_t resp_cap,
                                            uint16_t *resp_len)
{
  uint8_t auth_data[37];
  uint8_t signature[80];
  uint16_t signature_len = 0U;
  uint16_t off = 0U;
  uint32_t next_sign_count;

  if ((rp_id_hash == NULL) || (credential == NULL) || (client_data_hash == NULL) ||
      (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }

  memcpy(&auth_data[0], rp_id_hash, FIDO_SHA256_SIZE);
  auth_data[32] = (uint8_t)((user_present != 0U) ? CTAP_FLAG_USER_PRESENT : 0U);
  next_sign_count = credential->sign_count + ((user_present != 0U) ? 1U : 0U);
  store_be32(&auth_data[33], next_sign_count);

  if ((fido_crypto_sign_es256_der(credential->private_key,
                                  auth_data,
                                  sizeof(auth_data),
                                  client_data_hash,
                                  signature,
                                  sizeof(signature),
                                  &signature_len) == 0U))
  {
    return 0U;
  }

  resp[off++] = CTAP_STATUS_OK;
  if ((cbor_write_map(3U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x01U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_map(2U, resp, resp_cap, &off) == 0U) ||
      /* CTAP canonical CBOR requires shorter text keys first: "id" before "type". */
      (cbor_write_text("id", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(credential->credential_id,
                        credential->credential_id_len,
                        resp,
                        resp_cap,
                        &off) == 0U) ||
      (cbor_write_text("type", resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("public-key", resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x02U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(auth_data, sizeof(auth_data), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x03U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(signature, signature_len, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  if (user_present != 0U)
  {
    (void)fido_store_update_sign_count(slot_index, next_sign_count);
  }

  *resp_len = off;
  return 1U;
}

static uint8_t usbd_ctap_min_build_get_info(uint8_t *resp,
                                            uint16_t resp_cap,
                                            uint16_t *resp_len)
{
  static const uint8_t k_aaguid[16] = {
      0x55U, 0x4CU, 0x54U, 0x52U, 0x41U, 0x4CU, 0x49U, 0x4EU,
      0x4BU, 0x2DU, 0x46U, 0x34U, 0x30U, 0x35U, 0x02U, 0x00U};
  uint16_t off = 0U;
  uint8_t always_uv = 0U;
  uint8_t min_pin_length = 0U;
  uint8_t force_pin_change = 0U;

  if ((resp == NULL) || (resp_len == NULL) || (resp_cap == 0U))
  {
    return 0U;
  }

  (void)fido_store_client_pin_get_always_uv(&always_uv);
  (void)fido_store_client_pin_get_min_len(&min_pin_length);
  (void)fido_store_client_pin_get_force_change(&force_pin_change);

  resp[off++] = CTAP_STATUS_OK;
  if ((cbor_write_map(9U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x01U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_array(3U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("U2F_V2", resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("FIDO_2_0", resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("FIDO_2_1_PRE", resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x02U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_array(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("credProtect", resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x03U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(k_aaguid, sizeof(k_aaguid), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x04U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_map(8U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("rk", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("up", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("plat", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(0U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("alwaysUv", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(always_uv != 0U ? 1U : 0U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("credMgmt", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("authnrCfg", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("clientPin", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(fido_store_client_pin_is_set(), resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("setMinPINLength", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x05U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(1024U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x06U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_array(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(CTAP_PIN_PROTOCOL_ONE, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x0CU, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(force_pin_change != 0U ? 1U : 0U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x0DU, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(min_pin_length, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x1FU, resp, resp_cap, &off) == 0U) ||
      (cbor_write_array(2U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(CTAP_CONFIG_SUBCMD_ALWAYS_UV, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(CTAP_CONFIG_SUBCMD_SET_MIN_PIN_LEN, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  *resp_len = off;
  ctap_diag_note_status(CTAP_STATUS_OK);
  return 1U;
}

static uint8_t usbd_ctap_min_error(uint8_t code, uint8_t *resp, uint16_t resp_cap, uint16_t *resp_len)
{
  if ((resp == NULL) || (resp_len == NULL) || (resp_cap < 1U))
  {
    return 0U;
  }
  resp[0] = code;
  *resp_len = 1U;
  ctap_diag_note_status(code);
  return 1U;
}

static uint8_t usbd_ctap_min_handle_client_pin(const uint8_t *req,
                                               uint16_t req_len,
                                               uint8_t *resp,
                                               uint16_t resp_cap,
                                               uint16_t *resp_len)
{
  ctap_client_pin_req_t parsed;
  uint8_t shared_secret[FIDO_SHA256_SIZE];
  uint8_t stored_pin_hash[CTAP_PIN_HASH_SIZE];
  uint8_t provided_pin_hash[CTAP_PIN_HASH_SIZE];
  uint8_t new_pin[CTAP_PIN_MAX_ENC_SIZE];
  uint16_t new_pin_len = 0U;

  ctap_diag_note_request(CTAP_CMD_CLIENT_PIN, 0U, 0U, 0U);

  if (parse_client_pin(req, req_len, &parsed) == 0U)
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
  }
  if ((parsed.has_protocol == 0U) || (parsed.protocol != CTAP_PIN_PROTOCOL_ONE) || (parsed.has_subcmd == 0U))
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_PARAMETER, resp, resp_cap, resp_len);
  }

  switch (parsed.subcmd)
  {
    case CTAP_PIN_SUBCMD_GET_RETRIES:
      if (build_client_pin_retries_response(resp, resp_cap, resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_PIN_SUBCMD_GET_KEY_AGREEMENT:
      if (build_client_pin_key_agreement_response(resp, resp_cap, resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_PIN_SUBCMD_SET_PIN:
      if (fido_store_client_pin_is_set() != 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_NOT_ALLOWED, resp, resp_cap, resp_len);
      }
      if ((parsed.has_key_agreement == 0U) || (parsed.has_pin_auth == 0U) || (parsed.has_new_pin_enc == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
      }
      if (ctap_client_pin_get_shared_secret(&parsed, shared_secret) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INVALID_PARAMETER, resp, resp_cap, resp_len);
      }
      if (ctap_client_pin_verify_pin_auth(shared_secret,
                                          parsed.new_pin_enc,
                                          parsed.new_pin_enc_len,
                                          NULL,
                                          0U,
                                          parsed.pin_auth) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_AUTH_INVALID, resp, resp_cap, resp_len);
      }
      if (ctap_client_pin_decrypt_new_pin(shared_secret, &parsed, new_pin, &new_pin_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_POLICY_VIOLATION, resp, resp_cap, resp_len);
      }
      ctap_pin_hash16_from_pin(new_pin, new_pin_len, stored_pin_hash);
      if (fido_store_client_pin_set_hash(stored_pin_hash) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_pin_note_success();
      resp[0] = CTAP_STATUS_OK;
      *resp_len = 1U;
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_PIN_SUBCMD_CHANGE_PIN:
      if (fido_store_client_pin_is_set() == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_NOT_SET, resp, resp_cap, resp_len);
      }
      if (s_ctap_pin_power_cycle_blocked != 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_AUTH_BLOCKED, resp, resp_cap, resp_len);
      }
      if ((parsed.has_key_agreement == 0U) ||
          (parsed.has_pin_auth == 0U) ||
          (parsed.has_new_pin_enc == 0U) ||
          (parsed.has_pin_hash_enc == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
      }
      if ((ctap_client_pin_get_shared_secret(&parsed, shared_secret) == 0U) ||
          (fido_store_client_pin_get_hash(stored_pin_hash) == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      if (ctap_client_pin_verify_pin_auth(shared_secret,
                                          parsed.new_pin_enc,
                                          parsed.new_pin_enc_len,
                                          parsed.pin_hash_enc,
                                          parsed.pin_hash_enc_len,
                                          parsed.pin_auth) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_AUTH_INVALID, resp, resp_cap, resp_len);
      }
      if (ctap_client_pin_decrypt_pin_hash(shared_secret, &parsed, provided_pin_hash) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_AUTH_INVALID, resp, resp_cap, resp_len);
      }
      if (memcmp(stored_pin_hash, provided_pin_hash, CTAP_PIN_HASH_SIZE) != 0)
      {
        return usbd_ctap_min_error(ctap_pin_note_failure(), resp, resp_cap, resp_len);
      }
      if (ctap_client_pin_decrypt_new_pin(shared_secret, &parsed, new_pin, &new_pin_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_POLICY_VIOLATION, resp, resp_cap, resp_len);
      }
      ctap_pin_hash16_from_pin(new_pin, new_pin_len, stored_pin_hash);
      if (fido_store_client_pin_set_hash(stored_pin_hash) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_pin_note_success();
      resp[0] = CTAP_STATUS_OK;
      *resp_len = 1U;
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_PIN_SUBCMD_GET_PIN_TOKEN:
      if (fido_store_client_pin_is_set() == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_NOT_SET, resp, resp_cap, resp_len);
      }
      if (s_ctap_pin_power_cycle_blocked != 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_AUTH_BLOCKED, resp, resp_cap, resp_len);
      }
      if ((parsed.has_key_agreement == 0U) || (parsed.has_pin_hash_enc == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
      }
      if ((ctap_client_pin_get_shared_secret(&parsed, shared_secret) == 0U) ||
          (fido_store_client_pin_get_hash(stored_pin_hash) == 0U) ||
          (ctap_client_pin_decrypt_pin_hash(shared_secret, &parsed, provided_pin_hash) == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_INVALID_PARAMETER, resp, resp_cap, resp_len);
      }
      if (memcmp(stored_pin_hash, provided_pin_hash, CTAP_PIN_HASH_SIZE) != 0)
      {
        return usbd_ctap_min_error(ctap_pin_note_failure(), resp, resp_cap, resp_len);
      }
      ctap_pin_note_success();
      if (build_client_pin_token_response(shared_secret, resp, resp_cap, resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    default:
      return usbd_ctap_min_error(CTAP_ERR_INVALID_COMMAND, resp, resp_cap, resp_len);
  }
}

static uint8_t usbd_ctap_min_handle_cred_mgmt(const uint8_t *req,
                                              uint16_t req_len,
                                              uint8_t *resp,
                                              uint16_t resp_cap,
                                              uint16_t *resp_len)
{
  ctap_cred_mgmt_req_t parsed;
  fido_store_credential_t credential;
  uint32_t slot_index = 0U;
  uint8_t auth_status;

  ctap_diag_note_request(req[0], 0U, 0U, 0U);

  if (parse_cred_mgmt(req, req_len, &parsed) == 0U)
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
  }
  if ((parsed.has_subcmd == 0U) || (parsed.subcmd == 0U))
  {
    return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
  }

  auth_status = ctap_credman_verify_pin_auth(&parsed);
  if (auth_status != CTAP_STATUS_OK)
  {
    return usbd_ctap_min_error(auth_status, resp, resp_cap, resp_len);
  }

  switch (parsed.subcmd)
  {
    case CTAP_CRED_MGMT_SUBCMD_METADATA:
      if (build_credman_metadata_response(resp, resp_cap, resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_CRED_MGMT_SUBCMD_RP_BEGIN:
      s_ctap_credman_rp_total = ctap_credman_count_unique_rps();
      s_ctap_credman_rp_cursor = 0U;
      s_ctap_credman_rk_cursor = 0U;
      s_ctap_credman_rk_total = 0U;
      memset(s_ctap_credman_rp_hash, 0, sizeof(s_ctap_credman_rp_hash));
      if (s_ctap_credman_rp_total == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
      }
      if (ctap_credman_get_nth_rp(0U, &credential) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      memcpy(s_ctap_credman_rp_hash, credential.rp_id_hash, sizeof(s_ctap_credman_rp_hash));
      s_ctap_credman_rp_cursor = 1U;
      if (build_credman_rp_response(&credential,
                                    1U,
                                    s_ctap_credman_rp_total,
                                    resp,
                                    resp_cap,
                                    resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_CRED_MGMT_SUBCMD_RP_NEXT:
      if ((s_ctap_credman_rp_total == 0U) || (s_ctap_credman_rp_cursor >= s_ctap_credman_rp_total))
      {
        return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
      }
      if (ctap_credman_get_nth_rp(s_ctap_credman_rp_cursor, &credential) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      memcpy(s_ctap_credman_rp_hash, credential.rp_id_hash, sizeof(s_ctap_credman_rp_hash));
      s_ctap_credman_rp_cursor++;
      if (build_credman_rp_response(&credential, 0U, 0U, resp, resp_cap, resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_CRED_MGMT_SUBCMD_RK_BEGIN:
      if ((parsed.has_rp_id_hash == 0U) || (parsed.has_subcmd_params == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
      }
      memcpy(s_ctap_credman_rp_hash, parsed.rp_id_hash, sizeof(s_ctap_credman_rp_hash));
      s_ctap_credman_rk_total = ctap_credman_count_rks_for_rp(s_ctap_credman_rp_hash);
      s_ctap_credman_rk_cursor = 0U;
      if (s_ctap_credman_rk_total == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
      }
      if (ctap_credman_get_nth_rk_for_rp(s_ctap_credman_rp_hash, 0U, &credential, &slot_index) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      s_ctap_credman_rk_cursor = 1U;
      if (build_credman_rk_response(&credential,
                                    1U,
                                    s_ctap_credman_rk_total,
                                    resp,
                                    resp_cap,
                                    resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_CRED_MGMT_SUBCMD_RK_NEXT:
      if ((s_ctap_credman_rk_total == 0U) || (s_ctap_credman_rk_cursor >= s_ctap_credman_rk_total))
      {
        return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
      }
      if (ctap_credman_get_nth_rk_for_rp(s_ctap_credman_rp_hash,
                                         s_ctap_credman_rk_cursor,
                                         &credential,
                                         &slot_index) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      s_ctap_credman_rk_cursor++;
      if (build_credman_rk_response(&credential, 0U, 0U, resp, resp_cap, resp_len) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_CRED_MGMT_SUBCMD_DELETE:
      if ((parsed.has_credential_id == 0U) || (parsed.has_subcmd_params == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
      }
      if (fido_store_find_by_credential_id(parsed.credential_id,
                                           parsed.credential_id_len,
                                           &credential,
                                           &slot_index) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
      }
      if (fido_store_delete(slot_index) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      resp[0] = CTAP_STATUS_OK;
      *resp_len = 1U;
      ctap_credman_reset_state();
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    default:
      return usbd_ctap_min_error(CTAP_ERR_INVALID_COMMAND, resp, resp_cap, resp_len);
  }
}

static uint8_t usbd_ctap_min_handle_config(const uint8_t *req,
                                           uint16_t req_len,
                                           uint8_t *resp,
                                           uint16_t resp_cap,
                                           uint16_t *resp_len)
{
  ctap_config_req_t parsed;
  uint8_t auth_status;
  uint8_t always_uv = 0U;

  ctap_diag_note_request(CTAP_CMD_CONFIG, 0U, 0U, 0U);

  if (parse_config(req, req_len, &parsed) == 0U)
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
  }
  if ((parsed.has_subcmd == 0U) || (parsed.subcmd == 0U))
  {
    return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
  }

  auth_status = ctap_config_verify_pin_auth(&parsed);
  if (auth_status != CTAP_STATUS_OK)
  {
    return usbd_ctap_min_error(auth_status, resp, resp_cap, resp_len);
  }

  switch (parsed.subcmd)
  {
    case CTAP_CONFIG_SUBCMD_SET_MIN_PIN_LEN:
      if ((parsed.has_new_min_pin_len == 0U) && (parsed.has_force_change_pin == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
      }
      if ((parsed.has_new_min_pin_len != 0U) && (parsed.new_min_pin_len < CTAP_PIN_MIN_LEN))
      {
        return usbd_ctap_min_error(CTAP_ERR_PIN_POLICY_VIOLATION, resp, resp_cap, resp_len);
      }
      if ((parsed.has_new_min_pin_len != 0U) &&
          (fido_store_client_pin_set_min_len(parsed.new_min_pin_len) == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      if ((parsed.has_force_change_pin != 0U) &&
          (fido_store_client_pin_set_force_change(parsed.force_change_pin) == 0U))
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      resp[0] = CTAP_STATUS_OK;
      *resp_len = 1U;
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    case CTAP_CONFIG_SUBCMD_ALWAYS_UV:
      (void)fido_store_client_pin_get_always_uv(&always_uv);
      always_uv = (uint8_t)(always_uv == 0U ? 1U : 0U);
      if (fido_store_client_pin_set_always_uv(always_uv) == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
      }
      resp[0] = CTAP_STATUS_OK;
      *resp_len = 1U;
      ctap_diag_note_status(CTAP_STATUS_OK);
      return USBD_CTAP_MIN_DONE;

    default:
      return usbd_ctap_min_error(CTAP_ERR_INVALID_COMMAND, resp, resp_cap, resp_len);
  }
}

static uint8_t usbd_ctap_min_handle_make_credential(const uint8_t *req,
                                                    uint16_t req_len,
                                                    uint8_t *resp,
                                                    uint16_t resp_cap,
                                                    uint16_t *resp_len)
{
  ctap_make_credential_req_t parsed;
  uint8_t auto_confirm;
  uint8_t pin_uv_verified = 0U;
  uint8_t cred_protect_policy = 0U;

  ctap_diag_note_request(CTAP_CMD_MAKE_CREDENTIAL, 0U, 0U, 0U);

  if (parse_make_credential(req, req_len, &parsed) == 0U)
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
  }
  if ((parsed.has_client_data_hash == 0U) || (parsed.has_rp_id == 0U))
  {
    return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
  }
  if (parsed.es256_ok == 0U)
  {
    return usbd_ctap_min_error(CTAP_ERR_UNSUPPORTED_ALGORITHM, resp, resp_cap, resp_len);
  }
  if ((parsed.has_pin_uv_auth_protocol != 0U) && (parsed.pin_uv_auth_protocol != CTAP_PIN_PROTOCOL_ONE))
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_PARAMETER, resp, resp_cap, resp_len);
  }
  if (parsed.has_pin_uv_auth_param != 0U)
  {
    if (fido_store_client_pin_is_set() == 0U)
    {
      return usbd_ctap_min_error(CTAP_ERR_PIN_NOT_SET, resp, resp_cap, resp_len);
    }
    if ((parsed.has_pin_uv_auth_protocol == 0U) ||
        (ctap_verify_pin_uv_auth_param(parsed.client_data_hash,
                                       parsed.pin_uv_auth_protocol,
                                       parsed.pin_uv_auth_param) == 0U))
    {
      return usbd_ctap_min_error(CTAP_ERR_PIN_AUTH_INVALID, resp, resp_cap, resp_len);
    }
    pin_uv_verified = 1U;
  }
  cred_protect_policy = parsed.cred_protect_present != 0U ? parsed.cred_protect_policy : 0U;
  if ((cred_protect_policy == CTAP_CRED_PROTECT_UV_REQUIRED) && (pin_uv_verified == 0U))
  {
    cred_protect_policy = CTAP_CRED_PROTECT_UV_OR_CRED_ID_REQ;
  }
  {
    uint8_t rp_id_hash[FIDO_SHA256_SIZE];

    fido_crypto_sha256((const uint8_t *)parsed.rp_id, (uint32_t)strlen(parsed.rp_id), rp_id_hash);
    if (ctap_make_credential_matches_exclude(&parsed, rp_id_hash) != 0U)
    {
      return usbd_ctap_min_error(CTAP_ERR_CREDENTIAL_EXCLUDED, resp, resp_cap, resp_len);
    }
  }

  s_ctap_selection_count = 0U;
  s_ctap_selection_index = 0U;
  s_ctap_pending_cmd = CTAP_CMD_MAKE_CREDENTIAL;
  s_ctap_ui_state = USBD_CTAP_UI_WAIT_TOUCH;
  auto_confirm = (uint8_t)(ctap_request_matches_recent(CTAP_CMD_MAKE_CREDENTIAL, req, req_len) != 0U ? 1U : 0U);
  s_ctap_user_presence_latched = auto_confirm;
  g_a_usb_diag_runtime.fido_last_auto_confirm = auto_confirm;
  *resp_len = 0U;
  return USBD_CTAP_MIN_PENDING;
}

static uint8_t usbd_ctap_min_handle_get_assertion(const uint8_t *req,
                                                  uint16_t req_len,
                                                  uint8_t *resp,
                                                  uint16_t resp_cap,
                                                  uint16_t *resp_len)
{
  ctap_get_assertion_req_t parsed;
  uint8_t rp_id_hash[FIDO_SHA256_SIZE];
  uint8_t match_count;
  uint8_t auto_confirm;
  uint8_t pin_uv_verified = 0U;

  ctap_diag_note_request(CTAP_CMD_GET_ASSERTION, 0U, 0U, 0U);

  if (parse_get_assertion(req, req_len, &parsed) == 0U)
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
  }
  if ((parsed.has_client_data_hash == 0U) || (parsed.has_rp_id == 0U))
  {
    return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
  }
  if ((parsed.has_pin_uv_auth_protocol != 0U) && (parsed.pin_uv_auth_protocol != CTAP_PIN_PROTOCOL_ONE))
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_PARAMETER, resp, resp_cap, resp_len);
  }
  if (parsed.has_pin_uv_auth_param != 0U)
  {
    if (fido_store_client_pin_is_set() == 0U)
    {
      return usbd_ctap_min_error(CTAP_ERR_PIN_NOT_SET, resp, resp_cap, resp_len);
    }
    if ((parsed.has_pin_uv_auth_protocol == 0U) ||
        (ctap_verify_pin_uv_auth_param(parsed.client_data_hash,
                                       parsed.pin_uv_auth_protocol,
                                       parsed.pin_uv_auth_param) == 0U))
    {
      return usbd_ctap_min_error(CTAP_ERR_PIN_AUTH_INVALID, resp, resp_cap, resp_len);
    }
    pin_uv_verified = 1U;
  }
  fido_crypto_sha256((const uint8_t *)parsed.rp_id, (uint32_t)strlen(parsed.rp_id), rp_id_hash);
  match_count = ctap_collect_assertion_candidates(req, req_len, rp_id_hash, &parsed, pin_uv_verified);
  g_a_usb_diag_runtime.fido_last_allow_count = parsed.allow_credential_total;
  g_a_usb_diag_runtime.fido_last_match_count = match_count;
  if (match_count == 0U)
  {
    s_ctap_ui_state = USBD_CTAP_UI_IDLE;
    s_ctap_pending_cmd = 0U;
    return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
  }

  if ((parsed.option_up_present != 0U) && (parsed.option_up == 0U))
  {
    fido_store_credential_t credential;
    uint32_t slot_index = 0U;

    if ((s_ctap_selection_count == 0U) || (s_ctap_selection_index >= s_ctap_selection_count))
    {
      return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
    }

    credential = s_ctap_candidates[s_ctap_selection_index];
    slot_index = s_ctap_candidate_slots[s_ctap_selection_index];
    s_ctap_ui_state = USBD_CTAP_UI_IDLE;
    s_ctap_pending_cmd = 0U;
    s_ctap_selection_count = 0U;
    s_ctap_selection_index = 0U;
    if (build_get_assertion_response(rp_id_hash,
                                     &credential,
                                     slot_index,
                                     parsed.client_data_hash,
                                     0U,
                                     resp,
                                     resp_cap,
                                     resp_len) == 0U)
    {
      return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
    }
    ctap_diag_note_status(CTAP_STATUS_OK);
    return USBD_CTAP_MIN_DONE;
  }

  s_ctap_pending_cmd = CTAP_CMD_GET_ASSERTION;
  s_ctap_ui_state = USBD_CTAP_UI_WAIT_TOUCH;
  auto_confirm = (uint8_t)(ctap_request_matches_recent(CTAP_CMD_GET_ASSERTION, req, req_len) != 0U ? 1U : 0U);
  s_ctap_user_presence_latched = auto_confirm;
  g_a_usb_diag_runtime.fido_last_auto_confirm = auto_confirm;
  *resp_len = 0U;
  return USBD_CTAP_MIN_PENDING;
}

uint8_t usbd_ctap_min_handle_cbor(const uint8_t *req,
                                  uint16_t req_len,
                                  uint8_t *resp,
                                  uint16_t resp_cap,
                                  uint16_t *resp_len)
{
  ctap_ensure_boot_reference();

  if ((req == NULL) || (req_len == 0U) || (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }

  switch (req[0])
  {
    case CTAP_CMD_GET_INFO:
      ctap_diag_note_request(CTAP_CMD_GET_INFO, 0U, 0U, 0U);
      s_ctap_ui_state = USBD_CTAP_UI_IDLE;
      s_ctap_pending_cmd = 0U;
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
      ctap_credman_reset_state();
      return usbd_ctap_min_build_get_info(resp, resp_cap, resp_len);

    case CTAP_CMD_MAKE_CREDENTIAL:
      return usbd_ctap_min_handle_make_credential(req, req_len, resp, resp_cap, resp_len);

    case CTAP_CMD_GET_ASSERTION:
      return usbd_ctap_min_handle_get_assertion(req, req_len, resp, resp_cap, resp_len);

    case CTAP_CMD_CLIENT_PIN:
      s_ctap_ui_state = USBD_CTAP_UI_IDLE;
      s_ctap_pending_cmd = 0U;
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
      ctap_credman_reset_state();
      return usbd_ctap_min_handle_client_pin(req, req_len, resp, resp_cap, resp_len);

    case CTAP_CMD_CONFIG:
      s_ctap_ui_state = USBD_CTAP_UI_IDLE;
      s_ctap_pending_cmd = 0U;
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
      ctap_credman_reset_state();
      return usbd_ctap_min_handle_config(req, req_len, resp, resp_cap, resp_len);

    case CTAP_CMD_CRED_MGMT:
    case CTAP_CMD_CRED_MGMT_PRE:
      s_ctap_ui_state = USBD_CTAP_UI_IDLE;
      s_ctap_pending_cmd = 0U;
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
      return usbd_ctap_min_handle_cred_mgmt(req, req_len, resp, resp_cap, resp_len);

    case CTAP_CMD_RESET:
      ctap_diag_note_request(CTAP_CMD_RESET, 0U, 0U, 0U);
      if (req_len != 1U)
      {
        return usbd_ctap_min_error(CTAP_ERR_INVALID_LENGTH, resp, resp_cap, resp_len);
      }
      if (ctap_is_reset_allowed() == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_NOT_ALLOWED, resp, resp_cap, resp_len);
      }
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
      ctap_credman_reset_state();
      s_ctap_pending_cmd = CTAP_CMD_RESET;
      s_ctap_ui_state = USBD_CTAP_UI_WAIT_TOUCH;
      s_ctap_user_presence_latched = 0U;
      *resp_len = 0U;
      return USBD_CTAP_MIN_PENDING;

    default:
      s_ctap_ui_state = USBD_CTAP_UI_IDLE;
      s_ctap_pending_cmd = 0U;
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
      ctap_credman_reset_state();
      return usbd_ctap_min_error(CTAP_ERR_INVALID_COMMAND, resp, resp_cap, resp_len);
  }
}

uint8_t usbd_ctap_min_complete_pending(const uint8_t *req,
                                       uint16_t req_len,
                                       uint8_t confirmed,
                                       uint8_t *resp,
                                       uint16_t resp_cap,
                                       uint16_t *resp_len)
{
  uint8_t cmd = 0U;

  if ((req == NULL) || (req_len == 0U) || (resp == NULL) || (resp_len == NULL) || (resp_cap < 1U))
  {
    return 0U;
  }

  cmd = req[0];
  s_ctap_pending_cmd = 0U;

  if (confirmed == 0U)
  {
    s_ctap_ui_state = USBD_CTAP_UI_DENIED;
    s_ctap_selection_count = 0U;
    s_ctap_selection_index = 0U;
    resp[0] = CTAP_ERR_OPERATION_DENIED;
    *resp_len = 1U;
    return USBD_CTAP_MIN_DONE;
  }

  s_ctap_ui_state = USBD_CTAP_UI_CONFIRMED;
  s_ctap_user_presence_latched = 0U;

  if (cmd == CTAP_CMD_MAKE_CREDENTIAL)
  {
    ctap_make_credential_req_t parsed;
    fido_store_credential_t credential;
    uint8_t rp_id_hash[FIDO_SHA256_SIZE];
    uint8_t cred_protect_policy = 0U;

    if ((parse_make_credential(req, req_len, &parsed) == 0U) ||
        (parsed.has_client_data_hash == 0U) ||
        (parsed.has_rp_id == 0U) ||
        (parsed.es256_ok == 0U))
    {
      return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
    }

    fido_crypto_sha256((const uint8_t *)parsed.rp_id, (uint32_t)strlen(parsed.rp_id), rp_id_hash);
    cred_protect_policy = parsed.cred_protect_present != 0U ? parsed.cred_protect_policy : 0U;
    if ((cred_protect_policy == CTAP_CRED_PROTECT_UV_REQUIRED) &&
        (parsed.has_pin_uv_auth_param == 0U))
    {
      cred_protect_policy = CTAP_CRED_PROTECT_UV_OR_CRED_ID_REQ;
    }
    if ((fido_store_register(rp_id_hash,
                             parsed.rp_id,
                             parsed.client_data_hash,
                             cred_protect_policy,
                             parsed.user_id,
                             parsed.user_id_len,
                             parsed.user_name,
                             parsed.user_display_name,
                             &credential) == 0U) ||
        (build_make_credential_response(rp_id_hash,
                                        parsed.client_data_hash,
                                        &credential,
                                        (uint8_t)(cred_protect_policy != 0U),
                                        resp,
                                        resp_cap,
                                        resp_len) == 0U))
    {
      return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
    }
    ctap_remember_recent_approval(cmd, req, req_len);
    ctap_diag_note_status(CTAP_STATUS_OK);
    return USBD_CTAP_MIN_DONE;
  }

  if (cmd == CTAP_CMD_GET_ASSERTION)
  {
    ctap_get_assertion_req_t parsed;
    fido_store_credential_t credential;
    uint8_t rp_id_hash[FIDO_SHA256_SIZE];
    uint32_t slot_index = 0U;

    if ((parse_get_assertion(req, req_len, &parsed) == 0U) ||
        (parsed.has_client_data_hash == 0U) ||
        (parsed.has_rp_id == 0U))
    {
      return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
    }

    fido_crypto_sha256((const uint8_t *)parsed.rp_id, (uint32_t)strlen(parsed.rp_id), rp_id_hash);
    if ((s_ctap_selection_count != 0U) && (s_ctap_selection_index < s_ctap_selection_count))
    {
      credential = s_ctap_candidates[s_ctap_selection_index];
      slot_index = s_ctap_candidate_slots[s_ctap_selection_index];
    }
    else
    {
      uint8_t matched = 0U;
      uint8_t allow_index;

      if (parsed.allow_credential_count == 0U)
      {
        matched = fido_store_find(rp_id_hash, NULL, 0U, &credential, &slot_index);
      }
      else
      {
        for (allow_index = 0U; allow_index < parsed.allow_credential_count; ++allow_index)
        {
          if (fido_store_find(rp_id_hash,
                              parsed.allow_credential_ids[allow_index],
                              parsed.allow_credential_id_lens[allow_index],
                              &credential,
                              &slot_index) != 0U)
          {
            matched = 1U;
            break;
          }
        }
      }

      if (matched == 0U)
      {
        return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
      }
    }

    if (build_get_assertion_response(rp_id_hash,
                                     &credential,
                                     slot_index,
                                     parsed.client_data_hash,
                                     1U,
                                     resp,
                                     resp_cap,
                                     resp_len) == 0U)
    {
      return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
    }
    s_ctap_selection_count = 0U;
    s_ctap_selection_index = 0U;
    ctap_remember_recent_approval(cmd, req, req_len);
    ctap_diag_note_status(CTAP_STATUS_OK);
    return USBD_CTAP_MIN_DONE;
  }

  if (cmd == CTAP_CMD_RESET)
  {
    s_ctap_selection_count = 0U;
    s_ctap_selection_index = 0U;
    ctap_credman_reset_state();
    if (fido_store_clear() == 0U)
    {
      return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
    }
    ctap_pin_reset_retries();
    memset(s_ctap_pin_token, 0, sizeof(s_ctap_pin_token));
    s_ctap_pin_token_valid = 0U;
    resp[0] = CTAP_STATUS_OK;
    *resp_len = 1U;
    ctap_diag_note_status(CTAP_STATUS_OK);
    return USBD_CTAP_MIN_DONE;
  }

  return usbd_ctap_min_error(CTAP_ERR_INVALID_COMMAND, resp, resp_cap, resp_len);
}

void usbd_ctap_min_note_user_presence(void)
{
  s_ctap_user_presence_latched = 1U;
}

void usbd_ctap_min_note_user_denied(void)
{
  s_ctap_user_presence_latched = 2U;
}

void usbd_ctap_min_next_selection(void)
{
  if ((s_ctap_pending_cmd == CTAP_CMD_GET_ASSERTION) && (s_ctap_selection_count > 1U))
  {
    s_ctap_selection_index = (uint8_t)((s_ctap_selection_index + 1U) % s_ctap_selection_count);
  }
}

void usbd_ctap_min_prev_selection(void)
{
  if ((s_ctap_pending_cmd == CTAP_CMD_GET_ASSERTION) && (s_ctap_selection_count > 1U))
  {
    s_ctap_selection_index = (uint8_t)((s_ctap_selection_index + s_ctap_selection_count - 1U) % s_ctap_selection_count);
  }
}

void usbd_ctap_min_get_ui_status(usbd_ctap_min_ui_status_t *status)
{
  if (status == NULL)
  {
    return;
  }

  status->ui_state = s_ctap_ui_state;
  status->pending_cmd = s_ctap_pending_cmd;
  status->selection_count = s_ctap_selection_count;
  status->selection_index = s_ctap_selection_index;
  memset(status->selection_name, 0, sizeof(status->selection_name));
  if ((s_ctap_selection_count != 0U) && (s_ctap_selection_index < s_ctap_selection_count))
  {
    const char *src = s_ctap_candidates[s_ctap_selection_index].user_display_name;
    size_t n;

    if (src[0] == '\0')
    {
      src = s_ctap_candidates[s_ctap_selection_index].user_name;
    }
    n = strlen(src);
    if (n >= sizeof(status->selection_name))
    {
      n = sizeof(status->selection_name) - 1U;
    }
    if (n != 0U)
    {
      memcpy(status->selection_name, src, n);
      status->selection_name[n] = '\0';
    }
  }

  if ((s_ctap_ui_state == USBD_CTAP_UI_WAIT_TOUCH) && (s_ctap_user_presence_latched == 1U))
  {
    status->ui_state = USBD_CTAP_UI_CONFIRMED;
  }
  else if ((s_ctap_ui_state == USBD_CTAP_UI_WAIT_TOUCH) && (s_ctap_user_presence_latched == 2U))
  {
    status->ui_state = USBD_CTAP_UI_DENIED;
  }
}

void usbd_ctap_min_begin_external_wait(uint8_t pending_cmd)
{
  s_ctap_pending_cmd = pending_cmd;
  s_ctap_ui_state = USBD_CTAP_UI_WAIT_TOUCH;
  s_ctap_selection_count = 0U;
  s_ctap_selection_index = 0U;
  s_ctap_user_presence_latched = 0U;
}

void usbd_ctap_min_finish_external_wait(void)
{
  s_ctap_pending_cmd = 0U;
  s_ctap_ui_state = USBD_CTAP_UI_IDLE;
  s_ctap_selection_count = 0U;
  s_ctap_selection_index = 0U;
  s_ctap_user_presence_latched = 0U;
}
