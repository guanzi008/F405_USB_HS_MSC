#include "usbd_ctap_min.h"

#include <string.h>

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
  if ((cbor_write_type_value(5U, 4U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x01U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_type_value(4U, 1U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_text("FIDO_2_0", resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x03U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_bytes(k_aaguid, sizeof(k_aaguid), resp, resp_cap, &off) == 0U) ||
      (cbor_write_uint(0x04U, resp, resp_cap, &off) == 0U) ||
      (cbor_write_type_value(5U, 3U, resp, resp_cap, &off) == 0U) ||
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
      return usbd_ctap_min_build_get_info(resp, resp_cap, resp_len);

    case CTAP_CMD_MAKE_CREDENTIAL:
    case CTAP_CMD_GET_ASSERTION:
      if (resp_cap < 1U)
      {
        return 0U;
      }
      resp[0] = CTAP_ERR_OPERATION_DENIED;
      *resp_len = 1U;
      return 1U;

    default:
      if (resp_cap < 1U)
      {
        return 0U;
      }
      resp[0] = CTAP_ERR_INVALID_COMMAND;
      *resp_len = 1U;
      return 1U;
  }
}
