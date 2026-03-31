#include "usbd_ctap_min.h"

#include <string.h>

#include "fido_crypto.h"
#include "fido_store.h"

#define CTAP_MC_KEY_CLIENT_DATA_HASH 0x01U
#define CTAP_MC_KEY_RP               0x02U
#define CTAP_MC_KEY_USER             0x03U
#define CTAP_MC_KEY_PUBKEY_PARAMS    0x04U

#define CTAP_GA_KEY_RP_ID            0x01U
#define CTAP_GA_KEY_CLIENT_DATA_HASH 0x02U
#define CTAP_GA_KEY_ALLOW_LIST       0x03U
#define CTAP_GA_ALLOW_LIST_MAX       8U

#define CTAP_FLAG_USER_PRESENT 0x01U
#define CTAP_FLAG_ATTESTED     0x40U

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
} ctap_make_credential_req_t;

typedef struct
{
  uint8_t client_data_hash[FIDO_SHA256_SIZE];
  char rp_id[96];
  uint8_t allow_credential_ids[CTAP_GA_ALLOW_LIST_MAX][FIDO_CREDENTIAL_ID_SIZE];
  uint16_t allow_credential_id_lens[CTAP_GA_ALLOW_LIST_MAX];
  uint8_t allow_credential_count;
  uint8_t has_client_data_hash;
  uint8_t has_rp_id;
} ctap_get_assertion_req_t;

static uint8_t s_ctap_user_presence_latched;
static uint8_t s_ctap_pending_cmd;
static uint8_t s_ctap_ui_state;
static uint8_t s_ctap_selection_count;
static uint8_t s_ctap_selection_index;
static fido_store_credential_t s_ctap_candidates[CTAP_GA_ALLOW_LIST_MAX];
static uint32_t s_ctap_candidate_slots[CTAP_GA_ALLOW_LIST_MAX];

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
                                uint8_t *cred_id_count)
{
  uint32_t item_count;
  uint32_t i;

  if ((cred_ids == NULL) || (cred_id_lens == NULL) || (cred_id_count == NULL) ||
      (cbor_enter_array(reader, &item_count) == 0U))
  {
    return 0U;
  }

  *cred_id_count = 0U;
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
        if (value.len > FIDO_CREDENTIAL_ID_SIZE)
        {
          return 0U;
        }
        memcpy(entry_id, value.ptr, value.len);
        entry_id_len = value.len;
        found = 1U;
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
                             &parsed->allow_credential_count) == 0U)
        {
          return 0U;
        }
        break;

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

static uint8_t ctap_collect_assertion_candidates(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                                 const ctap_get_assertion_req_t *parsed)
{
  uint32_t slot_index;

  s_ctap_selection_count = 0U;
  s_ctap_selection_index = 0U;

  if ((rp_id_hash == NULL) || (parsed == NULL))
  {
    return 0U;
  }

  if (parsed->allow_credential_count != 0U)
  {
    uint8_t allow_index;

    for (allow_index = 0U; allow_index < parsed->allow_credential_count; ++allow_index)
    {
      if (fido_store_find(rp_id_hash,
                          parsed->allow_credential_ids[allow_index],
                          parsed->allow_credential_id_lens[allow_index],
                          &s_ctap_candidates[s_ctap_selection_count],
                          &s_ctap_candidate_slots[s_ctap_selection_count]) != 0U)
      {
        s_ctap_selection_count = (uint8_t)(s_ctap_selection_count + 1U);
        if (s_ctap_selection_count >= CTAP_GA_ALLOW_LIST_MAX)
        {
          break;
        }
      }
    }

    return s_ctap_selection_count;
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
                                               uint8_t *auth_data,
                                               uint16_t auth_cap,
                                               uint16_t *auth_len)
{
  static const uint8_t k_aaguid[16] = {
      0x55U, 0x4CU, 0x54U, 0x52U, 0x41U, 0x4CU, 0x49U, 0x4EU,
      0x4BU, 0x2DU, 0x46U, 0x34U, 0x30U, 0x35U, 0x02U, 0x00U};
  uint8_t cose_key[96];
  uint16_t cose_key_len;
  uint16_t off = 0U;

  if ((rp_id_hash == NULL) || (credential == NULL) || (auth_data == NULL) || (auth_len == NULL))
  {
    return 0U;
  }
  if (build_cose_public_key(credential->public_key, cose_key, sizeof(cose_key), &cose_key_len) == 0U)
  {
    return 0U;
  }
  if ((uint16_t)(32U + 1U + 4U + 16U + 2U + credential->credential_id_len + cose_key_len) > auth_cap)
  {
    return 0U;
  }

  memcpy(&auth_data[off], rp_id_hash, FIDO_SHA256_SIZE);
  off = (uint16_t)(off + FIDO_SHA256_SIZE);
  auth_data[off++] = (uint8_t)(CTAP_FLAG_USER_PRESENT | CTAP_FLAG_ATTESTED);
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
  *auth_len = off;
  return 1U;
}

static uint8_t build_make_credential_response(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                              const fido_store_credential_t *credential,
                                              uint8_t *resp,
                                              uint16_t resp_cap,
                                              uint16_t *resp_len)
{
  uint8_t auth_data[256];
  uint16_t auth_len;
  uint16_t off = 0U;

  if ((resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }
  if (build_make_credential_auth_data(rp_id_hash, credential, auth_data, sizeof(auth_data), &auth_len) == 0U)
  {
    return 0U;
  }

  resp[off++] = CTAP_STATUS_OK;
  if ((cbor_write_map(3U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x01U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("none", resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x02U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(auth_data, auth_len, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x03U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_map(0U, resp, resp_cap, &off) == 0U))
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
                                            uint8_t *resp,
                                            uint16_t resp_cap,
                                            uint16_t *resp_len)
{
  uint8_t auth_data[37];
  uint8_t signature[80];
  uint16_t signature_len = 0U;
  uint16_t off = 0U;
  uint8_t include_user = 0U;

  if ((rp_id_hash == NULL) || (credential == NULL) || (client_data_hash == NULL) ||
      (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }

  memcpy(&auth_data[0], rp_id_hash, FIDO_SHA256_SIZE);
  auth_data[32] = CTAP_FLAG_USER_PRESENT;
  credential->sign_count += 1U;
  store_be32(&auth_data[33], credential->sign_count);
  include_user = (uint8_t)((credential->user_id_len != 0U) ||
                           (credential->user_name[0] != '\0') ||
                           (credential->user_display_name[0] != '\0'));

  if ((fido_crypto_sign_es256_der(credential->private_key,
                                  auth_data,
                                  sizeof(auth_data),
                                  client_data_hash,
                                  signature,
                                  sizeof(signature),
                                  &signature_len) == 0U) ||
      (fido_store_update_sign_count(slot_index, credential->sign_count) == 0U))
  {
    return 0U;
  }

  resp[off++] = CTAP_STATUS_OK;
  if ((cbor_write_map((uint32_t)(include_user != 0U ? 4U : 3U), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x01U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_map(2U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("type", resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("public-key", resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("id", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(credential->credential_id,
                        credential->credential_id_len,
                        resp,
                        resp_cap,
                        &off) == 0U) ||
      (cbor_write_uint(0x02U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(auth_data, sizeof(auth_data), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x03U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(signature, signature_len, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  if (include_user != 0U)
  {
    uint32_t user_map_items = 0U;

    if (credential->user_id_len != 0U)
    {
      user_map_items += 1U;
    }
    if (credential->user_name[0] != '\0')
    {
      user_map_items += 1U;
    }
    if (credential->user_display_name[0] != '\0')
    {
      user_map_items += 1U;
    }

    if ((cbor_write_uint(0x04U, resp, resp_cap, &off) == 0U) ||
        (cbor_write_map(user_map_items, resp, resp_cap, &off) == 0U))
    {
      return 0U;
    }
    if ((credential->user_id_len != 0U) &&
        ((cbor_write_text("id", resp, resp_cap, &off) == 0U) ||
         (cbor_write_bytes(credential->user_id, credential->user_id_len, resp, resp_cap, &off) == 0U)))
    {
      return 0U;
    }
    if ((credential->user_name[0] != '\0') &&
        ((cbor_write_text("name", resp, resp_cap, &off) == 0U) ||
         (cbor_write_text(credential->user_name, resp, resp_cap, &off) == 0U)))
    {
      return 0U;
    }
    if ((credential->user_display_name[0] != '\0') &&
        ((cbor_write_text("displayName", resp, resp_cap, &off) == 0U) ||
         (cbor_write_text(credential->user_display_name, resp, resp_cap, &off) == 0U)))
    {
      return 0U;
    }
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

  if ((resp == NULL) || (resp_len == NULL) || (resp_cap == 0U))
  {
    return 0U;
  }

  resp[off++] = CTAP_STATUS_OK;
  if ((cbor_write_map(4U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x01U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_type_value(4U, 1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("FIDO_2_0", resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x03U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(k_aaguid, sizeof(k_aaguid), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x04U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_map(3U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("rk", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(0U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("up", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("plat", resp, resp_cap, &off) == 0U) ||
      (cbor_write_bool(0U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x05U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(1024U, resp, resp_cap, &off) == 0U))
  {
    return 0U;
  }

  *resp_len = off;
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
  return 1U;
}

static uint8_t usbd_ctap_min_handle_make_credential(const uint8_t *req,
                                                    uint16_t req_len,
                                                    uint8_t *resp,
                                                    uint16_t resp_cap,
                                                    uint16_t *resp_len)
{
  ctap_make_credential_req_t parsed;

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

  s_ctap_selection_count = 0U;
  s_ctap_selection_index = 0U;
  s_ctap_pending_cmd = CTAP_CMD_MAKE_CREDENTIAL;
  s_ctap_ui_state = USBD_CTAP_UI_WAIT_TOUCH;
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

  if (parse_get_assertion(req, req_len, &parsed) == 0U)
  {
    return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
  }
  if ((parsed.has_client_data_hash == 0U) || (parsed.has_rp_id == 0U))
  {
    return usbd_ctap_min_error(CTAP_ERR_MISSING_PARAMETER, resp, resp_cap, resp_len);
  }

  fido_crypto_sha256((const uint8_t *)parsed.rp_id, (uint32_t)strlen(parsed.rp_id), rp_id_hash);
  if (ctap_collect_assertion_candidates(rp_id_hash, &parsed) == 0U)
  {
    s_ctap_ui_state = USBD_CTAP_UI_IDLE;
    s_ctap_pending_cmd = 0U;
    return usbd_ctap_min_error(CTAP_ERR_NO_CREDENTIALS, resp, resp_cap, resp_len);
  }

  s_ctap_pending_cmd = CTAP_CMD_GET_ASSERTION;
  s_ctap_ui_state = USBD_CTAP_UI_WAIT_TOUCH;
  *resp_len = 0U;
  return USBD_CTAP_MIN_PENDING;
}

uint8_t usbd_ctap_min_handle_cbor(const uint8_t *req,
                                  uint16_t req_len,
                                  uint8_t *resp,
                                  uint16_t resp_cap,
                                  uint16_t *resp_len)
{
  if ((req == NULL) || (req_len == 0U) || (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }

  switch (req[0])
  {
    case CTAP_CMD_GET_INFO:
      s_ctap_ui_state = USBD_CTAP_UI_IDLE;
      s_ctap_pending_cmd = 0U;
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
      return usbd_ctap_min_build_get_info(resp, resp_cap, resp_len);

    case CTAP_CMD_MAKE_CREDENTIAL:
      return usbd_ctap_min_handle_make_credential(req, req_len, resp, resp_cap, resp_len);

    case CTAP_CMD_GET_ASSERTION:
      return usbd_ctap_min_handle_get_assertion(req, req_len, resp, resp_cap, resp_len);

    default:
      s_ctap_ui_state = USBD_CTAP_UI_IDLE;
      s_ctap_pending_cmd = 0U;
      s_ctap_selection_count = 0U;
      s_ctap_selection_index = 0U;
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

    if ((parse_make_credential(req, req_len, &parsed) == 0U) ||
        (parsed.has_client_data_hash == 0U) ||
        (parsed.has_rp_id == 0U) ||
        (parsed.es256_ok == 0U))
    {
      return usbd_ctap_min_error(CTAP_ERR_INVALID_CBOR, resp, resp_cap, resp_len);
    }

    fido_crypto_sha256((const uint8_t *)parsed.rp_id, (uint32_t)strlen(parsed.rp_id), rp_id_hash);
    if ((fido_store_register(rp_id_hash,
                             parsed.client_data_hash,
                             parsed.user_id,
                             parsed.user_id_len,
                             parsed.user_name,
                             parsed.user_display_name,
                             &credential) == 0U) ||
        (build_make_credential_response(rp_id_hash, &credential, resp, resp_cap, resp_len) == 0U))
    {
      return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
    }
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
                                     resp,
                                     resp_cap,
                                     resp_len) == 0U)
    {
      return usbd_ctap_min_error(CTAP_ERR_INTERNAL, resp, resp_cap, resp_len);
    }
    s_ctap_selection_count = 0U;
    s_ctap_selection_index = 0U;
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
