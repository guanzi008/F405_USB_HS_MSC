#include "usbd_hid_fido.h"

#include <string.h>

#include "usbd_conf.h"
#include "usbd_ctap_min.h"
#include "fido_crypto.h"
#include "fido_store.h"

__ALIGN_BEGIN static uint8_t k_fido_hid_report_desc[FIDO_HID_REPORT_DESC_SIZE] __ALIGN_END = {
    0x06U, 0xD0U, 0xF1U,
    0x09U, 0x01U,
    0xA1U, 0x01U,
    0x09U, 0x20U,
    0x15U, 0x00U,
    0x26U, 0xFFU, 0x00U,
    0x75U, 0x08U,
    0x95U, 0x40U,
    0x81U, 0x02U,
    0x09U, 0x21U,
    0x15U, 0x00U,
    0x26U, 0xFFU, 0x00U,
    0x75U, 0x08U,
    0x95U, 0x40U,
    0x91U, 0x02U,
    0xC0U};

static const uint8_t k_u2f_attest_private_key[FIDO_P256_PRIVATE_KEY_SIZE] = {
    0x45U, 0x1DU, 0xF4U, 0x44U, 0x9BU, 0xA2U, 0x90U, 0x11U,
    0xCDU, 0x3DU, 0xB0U, 0x2BU, 0xC2U, 0x62U, 0xD8U, 0x4FU,
    0xEAU, 0x7DU, 0x56U, 0xDDU, 0x87U, 0x64U, 0xD9U, 0x33U,
    0x55U, 0x4BU, 0x83U, 0xB2U, 0xF8U, 0x23U, 0xE8U, 0xC6U};

static const uint8_t k_u2f_attest_cert_der[] = {
    0x30U,0x82U,0x01U,0xDFU,0x30U,0x82U,0x01U,0x85U,0xA0U,0x03U,0x02U,0x01U,
    0x02U,0x02U,0x14U,0x58U,0xC4U,0xB9U,0xC3U,0xCFU,0x80U,0x0AU,0x18U,0xFCU,
    0xB8U,0x6BU,0xECU,0xE2U,0x66U,0x43U,0x71U,0x78U,0x3BU,0x2FU,0xE6U,0x30U,
    0x0AU,0x06U,0x08U,0x2AU,0x86U,0x48U,0xCEU,0x3DU,0x04U,0x03U,0x02U,0x30U,
    0x45U,0x31U,0x22U,0x30U,0x20U,0x06U,0x03U,0x55U,0x04U,0x03U,0x0CU,0x19U,
    0x55U,0x6CU,0x74U,0x72U,0x61U,0x4CU,0x69U,0x6EU,0x6BU,0x20U,0x55U,0x32U,
    0x46U,0x20U,0x41U,0x74U,0x74U,0x65U,0x73U,0x74U,0x61U,0x74U,0x69U,0x6FU,
    0x6EU,0x31U,0x12U,0x30U,0x10U,0x06U,0x03U,0x55U,0x04U,0x0AU,0x0CU,0x09U,
    0x55U,0x6CU,0x74U,0x72U,0x61U,0x4CU,0x69U,0x6EU,0x6BU,0x31U,0x0BU,0x30U,
    0x09U,0x06U,0x03U,0x55U,0x04U,0x06U,0x13U,0x02U,0x43U,0x4EU,0x30U,0x1EU,
    0x17U,0x0DU,0x32U,0x36U,0x30U,0x34U,0x30U,0x31U,0x31U,0x31U,0x31U,0x31U,
    0x30U,0x39U,0x5AU,0x17U,0x0DU,0x33U,0x36U,0x30U,0x33U,0x32U,0x39U,0x31U,
    0x31U,0x31U,0x31U,0x30U,0x39U,0x5AU,0x30U,0x45U,0x31U,0x22U,0x30U,0x20U,
    0x06U,0x03U,0x55U,0x04U,0x03U,0x0CU,0x19U,0x55U,0x6CU,0x74U,0x72U,0x61U,
    0x4CU,0x69U,0x6EU,0x6BU,0x20U,0x55U,0x32U,0x46U,0x20U,0x41U,0x74U,0x74U,
    0x65U,0x73U,0x74U,0x61U,0x74U,0x69U,0x6FU,0x6EU,0x31U,0x12U,0x30U,0x10U,
    0x06U,0x03U,0x55U,0x04U,0x0AU,0x0CU,0x09U,0x55U,0x6CU,0x74U,0x72U,0x61U,
    0x4CU,0x69U,0x6EU,0x6BU,0x31U,0x0BU,0x30U,0x09U,0x06U,0x03U,0x55U,0x04U,
    0x06U,0x13U,0x02U,0x43U,0x4EU,0x30U,0x59U,0x30U,0x13U,0x06U,0x07U,0x2AU,
    0x86U,0x48U,0xCEU,0x3DU,0x02U,0x01U,0x06U,0x08U,0x2AU,0x86U,0x48U,0xCEU,
    0x3DU,0x03U,0x01U,0x07U,0x03U,0x42U,0x00U,0x04U,0xF3U,0xC5U,0x6AU,0x6DU,
    0xC2U,0x51U,0xCAU,0xCEU,0x9FU,0x95U,0x05U,0x6BU,0x5BU,0x1CU,0xB2U,0xE5U,
    0x9FU,0xA0U,0x99U,0x5FU,0x2BU,0x1FU,0x0CU,0x92U,0x9AU,0x62U,0xC1U,0xCAU,
    0x78U,0x94U,0xE4U,0x4CU,0xF1U,0x8BU,0xE8U,0x33U,0x02U,0xF5U,0x47U,0x5FU,
    0x34U,0xC2U,0x65U,0x11U,0x07U,0xB5U,0xF7U,0x27U,0x1FU,0xA1U,0x2AU,0x45U,
    0xF6U,0x9FU,0x55U,0x30U,0xC3U,0x9BU,0xA5U,0xE8U,0x3AU,0xFBU,0xBCU,0x2BU,
    0xA3U,0x53U,0x30U,0x51U,0x30U,0x1DU,0x06U,0x03U,0x55U,0x1DU,0x0EU,0x04U,
    0x16U,0x04U,0x14U,0x56U,0xA0U,0x77U,0x0BU,0x47U,0x90U,0x05U,0x02U,0x9AU,
    0x5EU,0x31U,0x91U,0x43U,0xADU,0x66U,0xEFU,0xAAU,0xC9U,0xB0U,0xF9U,0x30U,
    0x1FU,0x06U,0x03U,0x55U,0x1DU,0x23U,0x04U,0x18U,0x30U,0x16U,0x80U,0x14U,
    0x56U,0xA0U,0x77U,0x0BU,0x47U,0x90U,0x05U,0x02U,0x9AU,0x5EU,0x31U,0x91U,
    0x43U,0xADU,0x66U,0xEFU,0xAAU,0xC9U,0xB0U,0xF9U,0x30U,0x0FU,0x06U,0x03U,
    0x55U,0x1DU,0x13U,0x01U,0x01U,0xFFU,0x04U,0x05U,0x30U,0x03U,0x01U,0x01U,
    0xFFU,0x30U,0x0AU,0x06U,0x08U,0x2AU,0x86U,0x48U,0xCEU,0x3DU,0x04U,0x03U,
    0x02U,0x03U,0x48U,0x00U,0x30U,0x45U,0x02U,0x20U,0x20U,0x45U,0x03U,0x8BU,
    0x61U,0xD8U,0xB2U,0x95U,0x3FU,0xFCU,0x73U,0x8AU,0x86U,0xF6U,0xDEU,0x29U,
    0x1EU,0x52U,0x1AU,0x4AU,0x2EU,0xA7U,0x25U,0x0AU,0x9DU,0x61U,0x05U,0x43U,
    0xA6U,0xEEU,0xA6U,0x62U,0x02U,0x21U,0x00U,0xCAU,0xF2U,0x2DU,0x37U,0x9AU,
    0xBFU,0x1FU,0x44U,0x76U,0x3AU,0x7AU,0xFBU,0x18U,0x16U,0x7FU,0x71U,0x85U,
    0xF9U,0x2FU,0xB0U,0x8CU,0x7BU,0x27U,0x5BU,0x0CU,0x11U,0xF8U,0xDBU,0xA9U,
    0x32U,0x9AU,0x5DU};

#define U2F_INS_REGISTER            0x01U
#define U2F_INS_AUTHENTICATE        0x02U
#define U2F_INS_VERSION             0x03U

#define U2F_AUTH_ENFORCE            0x03U
#define U2F_AUTH_CHECK_ONLY         0x07U
#define U2F_AUTH_DONT_ENFORCE       0x08U

#define U2F_SW_NO_ERROR             0x9000U
#define U2F_SW_WRONG_LENGTH         0x6700U
#define U2F_SW_CONDITIONS_NOT_SATISFIED 0x6985U
#define U2F_SW_WRONG_DATA           0x6A80U
#define U2F_SW_INS_NOT_SUPPORTED    0x6D00U
#define U2F_SW_CLA_NOT_SUPPORTED    0x6E00U

#define U2F_REGISTER_RESERVED_BYTE  0x05U
#define U2F_USER_PRESENCE_FLAG      0x01U

typedef struct
{
  uint8_t cla;
  uint8_t ins;
  uint8_t p1;
  uint8_t p2;
  const uint8_t *data;
  uint32_t lc;
} fido_u2f_apdu_t;

static void fido_start_tx(usbd_hid_fido_state_t *state, uint32_t cid, uint8_t cmd, uint16_t len);

static uint32_t fido_load_be32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static void fido_store_be32(uint8_t *p, uint32_t value)
{
  p[0] = (uint8_t)(value >> 24);
  p[1] = (uint8_t)(value >> 16);
  p[2] = (uint8_t)(value >> 8);
  p[3] = (uint8_t)value;
}

static void fido_store_be16(uint8_t *p, uint16_t value)
{
  p[0] = (uint8_t)(value >> 8);
  p[1] = (uint8_t)value;
}

static void fido_hex_encode(const uint8_t *src, uint16_t len, char *dst, uint16_t dst_cap)
{
  static const char hex_digits[] = "0123456789abcdef";
  uint16_t i;

  if ((src == NULL) || (dst == NULL) || (dst_cap == 0U))
  {
    return;
  }

  for (i = 0U; (i < len) && ((uint16_t)((i * 2U) + 1U) < dst_cap); ++i)
  {
    dst[i * 2U] = hex_digits[src[i] >> 4];
    dst[(i * 2U) + 1U] = hex_digits[src[i] & 0x0FU];
  }

  if ((uint16_t)(len * 2U) < dst_cap)
  {
    dst[len * 2U] = '\0';
  }
  else
  {
    dst[dst_cap - 1U] = '\0';
  }
}

static void fido_u2f_reply_status(usbd_hid_fido_state_t *state, uint32_t cid, uint16_t sw)
{
  state->tx_buf[0] = (uint8_t)(sw >> 8);
  state->tx_buf[1] = (uint8_t)sw;
  fido_start_tx(state, cid, FIDO_HID_CMD_MSG, 2U);
}

static uint8_t fido_parse_u2f_apdu(const usbd_hid_fido_state_t *state, fido_u2f_apdu_t *apdu)
{
  uint32_t lc;

  if ((state == NULL) || (apdu == NULL) || (state->rx_expected_len < 7U))
  {
    return 0U;
  }

  lc = ((uint32_t)state->rx_buf[4] << 16) |
       ((uint32_t)state->rx_buf[5] << 8) |
       (uint32_t)state->rx_buf[6];
  if ((uint32_t)state->rx_expected_len != (lc + 7U))
  {
    return 0U;
  }

  apdu->cla = state->rx_buf[0];
  apdu->ins = state->rx_buf[1];
  apdu->p1 = state->rx_buf[2];
  apdu->p2 = state->rx_buf[3];
  apdu->data = &state->rx_buf[7];
  apdu->lc = lc;
  return 1U;
}

static uint8_t fido_is_same_pending_u2f(const usbd_hid_fido_state_t *state)
{
  uint8_t req_hash[FIDO_SHA256_SIZE];

  if ((state == NULL) ||
      (state->wait_user_presence == 0U) ||
      (state->pending_req_valid == 0U) ||
      (state->rx_cmd != FIDO_HID_CMD_MSG) ||
      (state->pending_msg_len == 0U) ||
      (state->pending_msg_len != state->rx_expected_len))
  {
    return 0U;
  }

  fido_crypto_sha256(state->rx_buf, state->rx_expected_len, req_hash);
  return (uint8_t)(memcmp(req_hash, state->pending_req_hash, sizeof(req_hash)) == 0);
}

static void fido_diag_note_rx(const uint8_t *request, uint16_t request_len)
{
  g_a_usb_diag_runtime.fido_rx_count++;
  g_a_usb_diag_runtime.fido_last_req_len = request_len;
  g_a_usb_diag_runtime.fido_last_req_word0 = 0U;
  g_a_usb_diag_runtime.fido_last_req_word1 = 0U;
  if (request_len >= 4U)
  {
    g_a_usb_diag_runtime.fido_last_req_word0 = fido_load_be32(request);
  }
  if (request_len >= 8U)
  {
    g_a_usb_diag_runtime.fido_last_req_word1 = fido_load_be32(&request[4]);
  }
}

static void fido_diag_note_tx(const uint8_t *response, uint16_t response_len, uint8_t status)
{
  g_a_usb_diag_runtime.fido_tx_count++;
  g_a_usb_diag_runtime.fido_last_rsp_len = response_len;
  g_a_usb_diag_runtime.fido_last_rsp_word0 = 0U;
  g_a_usb_diag_runtime.fido_last_rsp_word1 = 0U;
  g_a_usb_diag_runtime.fido_last_status = status;
  if (response_len >= 4U)
  {
    g_a_usb_diag_runtime.fido_last_rsp_word0 = fido_load_be32(response);
  }
  if (response_len >= 8U)
  {
    g_a_usb_diag_runtime.fido_last_rsp_word1 = fido_load_be32(&response[4]);
  }
}

static void fido_diag_note_state(const usbd_hid_fido_state_t *state)
{
  if (state == NULL)
  {
    return;
  }

  g_a_usb_diag_runtime.fido_rx_expected_total = state->rx_expected_len;
  g_a_usb_diag_runtime.fido_rx_received_total = state->rx_received_len;
  g_a_usb_diag_runtime.fido_rx_seq_next = state->rx_seq;
  g_a_usb_diag_runtime.fido_rx_active = state->rx_active;
}

static void fido_reset_rx(usbd_hid_fido_state_t *state)
{
  state->rx_active = 0U;
  state->rx_received_len = 0U;
  state->rx_expected_len = 0U;
  state->rx_seq = 0U;
  fido_diag_note_state(state);
}

static void fido_start_tx(usbd_hid_fido_state_t *state, uint32_t cid, uint8_t cmd, uint16_t len)
{
  state->tx_cid = cid;
  state->tx_cmd = cmd;
  state->tx_len = len;
  state->tx_offset = 0U;
  state->tx_seq = 0U;
  state->tx_active = 1U;
}

static void fido_queue_error(usbd_hid_fido_state_t *state, uint32_t cid, uint8_t code)
{
  state->tx_buf[0] = code;
  fido_start_tx(state, cid, FIDO_HID_CMD_ERROR, 1U);
}

static uint8_t fido_is_same_pending_cbor(const usbd_hid_fido_state_t *state)
{
  uint8_t req_hash[FIDO_SHA256_SIZE];

  if ((state == NULL) ||
      (state->wait_user_presence == 0U) ||
      (state->pending_req_valid == 0U) ||
      (state->rx_cmd != FIDO_HID_CMD_CBOR) ||
      (state->pending_cbor_len == 0U) ||
      (state->pending_cbor_len != state->rx_expected_len))
  {
    return 0U;
  }

  fido_crypto_sha256(state->rx_buf, state->rx_expected_len, req_hash);
  return (uint8_t)(memcmp(req_hash, state->pending_req_hash, sizeof(req_hash)) == 0);
}

static uint16_t fido_emit_tx_packet(usbd_hid_fido_state_t *state,
                                    uint8_t *response,
                                    uint16_t response_cap)
{
  uint16_t copy_len;

  if ((state == NULL) || (response == NULL) || (response_cap < FIDO_HID_PACKET_SIZE) || (state->tx_active == 0U))
  {
    return 0U;
  }

  memset(response, 0, response_cap);
  fido_store_be32(response, state->tx_cid);

  if (state->tx_offset == 0U)
  {
    response[4] = (uint8_t)(0x80U | state->tx_cmd);
    response[5] = (uint8_t)(state->tx_len >> 8);
    response[6] = (uint8_t)(state->tx_len);
    copy_len = state->tx_len;
    if (copy_len > (FIDO_HID_PACKET_SIZE - 7U))
    {
      copy_len = FIDO_HID_PACKET_SIZE - 7U;
    }
    if (copy_len != 0U)
    {
      memcpy(&response[7], state->tx_buf, copy_len);
    }
  }
  else
  {
    response[4] = state->tx_seq++;
    copy_len = (uint16_t)(state->tx_len - state->tx_offset);
    if (copy_len > (FIDO_HID_PACKET_SIZE - 5U))
    {
      copy_len = FIDO_HID_PACKET_SIZE - 5U;
    }
    if (copy_len != 0U)
    {
      memcpy(&response[5], &state->tx_buf[state->tx_offset], copy_len);
    }
  }

  state->tx_offset = (uint16_t)(state->tx_offset + copy_len);
  if (state->tx_offset >= state->tx_len)
  {
    state->tx_active = 0U;
    state->tx_offset = 0U;
    state->tx_len = 0U;
    state->tx_seq = 0U;
  }

  fido_diag_note_tx(response, FIDO_HID_PACKET_SIZE, response[4]);
  return FIDO_HID_PACKET_SIZE;
}

static uint32_t fido_allocate_cid(usbd_hid_fido_state_t *state)
{
  uint32_t cid = state->next_cid;

  if ((cid == 0U) || (cid == FIDO_HID_BROADCAST_CID))
  {
    cid = 0x01000000U;
  }
  state->next_cid = cid + 1U;
  if ((state->next_cid == 0U) || (state->next_cid == FIDO_HID_BROADCAST_CID))
  {
    state->next_cid = 0x01000000U;
  }
  return cid;
}

static uint8_t fido_u2f_append_status(uint8_t *buf, uint16_t buf_cap, uint16_t *buf_len, uint16_t sw)
{
  if ((buf == NULL) || (buf_len == NULL) || ((uint16_t)(*buf_len + 2U) > buf_cap))
  {
    return 0U;
  }

  fido_store_be16(&buf[*buf_len], sw);
  *buf_len = (uint16_t)(*buf_len + 2U);
  return 1U;
}

static uint8_t fido_build_u2f_register_response(const uint8_t challenge_param[FIDO_SHA256_SIZE],
                                                const uint8_t app_param[FIDO_SHA256_SIZE],
                                                uint8_t *resp,
                                                uint16_t resp_cap,
                                                uint16_t *resp_len)
{
  fido_store_credential_t credential;
  char app_id_hex[(FIDO_SHA256_SIZE * 2U) + 1U];
  uint8_t sig_base[1U + FIDO_SHA256_SIZE + FIDO_SHA256_SIZE + 1U + FIDO_CREDENTIAL_ID_SIZE + 65U];
  uint8_t signature[80];
  uint16_t sig_len = 0U;
  uint16_t off = 0U;
  uint16_t sig_base_len = 0U;

  if ((challenge_param == NULL) || (app_param == NULL) || (resp == NULL) || (resp_len == NULL))
  {
    return 0U;
  }

  fido_hex_encode(app_param, FIDO_SHA256_SIZE, app_id_hex, sizeof(app_id_hex));
  if (fido_store_register(app_param,
                          app_id_hex,
                          challenge_param,
                          0U,
                          NULL,
                          0U,
                          NULL,
                          0U,
                          NULL,
                          NULL,
                          &credential) == 0U)
  {
    return 0U;
  }

  if ((uint32_t)resp_cap < (1U + 65U + 1U + credential.credential_id_len + sizeof(k_u2f_attest_cert_der) + 72U + 2U))
  {
    return 0U;
  }

  resp[off++] = U2F_REGISTER_RESERVED_BYTE;
  resp[off++] = 0x04U;
  memcpy(&resp[off], credential.public_key, FIDO_P256_PUBLIC_KEY_SIZE);
  off = (uint16_t)(off + FIDO_P256_PUBLIC_KEY_SIZE);
  resp[off++] = (uint8_t)credential.credential_id_len;
  memcpy(&resp[off], credential.credential_id, credential.credential_id_len);
  off = (uint16_t)(off + credential.credential_id_len);
  memcpy(&resp[off], k_u2f_attest_cert_der, sizeof(k_u2f_attest_cert_der));
  off = (uint16_t)(off + sizeof(k_u2f_attest_cert_der));

  sig_base[sig_base_len++] = 0x00U;
  memcpy(&sig_base[sig_base_len], app_param, FIDO_SHA256_SIZE);
  sig_base_len = (uint16_t)(sig_base_len + FIDO_SHA256_SIZE);
  memcpy(&sig_base[sig_base_len], challenge_param, FIDO_SHA256_SIZE);
  sig_base_len = (uint16_t)(sig_base_len + FIDO_SHA256_SIZE);
  sig_base[sig_base_len++] = (uint8_t)credential.credential_id_len;
  memcpy(&sig_base[sig_base_len], credential.credential_id, credential.credential_id_len);
  sig_base_len = (uint16_t)(sig_base_len + credential.credential_id_len);
  sig_base[sig_base_len++] = 0x04U;
  memcpy(&sig_base[sig_base_len], credential.public_key, FIDO_P256_PUBLIC_KEY_SIZE);
  sig_base_len = (uint16_t)(sig_base_len + FIDO_P256_PUBLIC_KEY_SIZE);

  if (fido_crypto_sign_p256_sha256_der(k_u2f_attest_private_key,
                                       sig_base,
                                       sig_base_len,
                                       signature,
                                       sizeof(signature),
                                       &sig_len) == 0U)
  {
    return 0U;
  }

  memcpy(&resp[off], signature, sig_len);
  off = (uint16_t)(off + sig_len);
  if (fido_u2f_append_status(resp, resp_cap, &off, U2F_SW_NO_ERROR) == 0U)
  {
    return 0U;
  }

  *resp_len = off;
  return 1U;
}

static uint8_t fido_build_u2f_authenticate_response(const uint8_t challenge_param[FIDO_SHA256_SIZE],
                                                    const uint8_t app_param[FIDO_SHA256_SIZE],
                                                    fido_store_credential_t *credential,
                                                    uint32_t slot_index,
                                                    uint8_t user_presence,
                                                    uint8_t *resp,
                                                    uint16_t resp_cap,
                                                    uint16_t *resp_len)
{
  uint8_t sig_base[FIDO_SHA256_SIZE + 1U + 4U + FIDO_SHA256_SIZE];
  uint8_t signature[80];
  uint16_t sig_len = 0U;
  uint16_t off = 0U;
  uint32_t next_sign_count;

  if ((challenge_param == NULL) || (app_param == NULL) || (credential == NULL) ||
      (resp == NULL) || (resp_len == NULL) || (resp_cap < (1U + 4U + 8U)))
  {
    return 0U;
  }

  next_sign_count = credential->sign_count + 1U;
  memcpy(sig_base, app_param, FIDO_SHA256_SIZE);
  sig_base[FIDO_SHA256_SIZE] = (uint8_t)((user_presence != 0U) ? U2F_USER_PRESENCE_FLAG : 0U);
  fido_store_be32(&sig_base[FIDO_SHA256_SIZE + 1U], next_sign_count);
  memcpy(&sig_base[FIDO_SHA256_SIZE + 5U], challenge_param, FIDO_SHA256_SIZE);

  if (fido_crypto_sign_p256_sha256_der(credential->private_key,
                                       sig_base,
                                       sizeof(sig_base),
                                       signature,
                                       sizeof(signature),
                                       &sig_len) == 0U)
  {
    return 0U;
  }

  resp[off++] = (uint8_t)((user_presence != 0U) ? U2F_USER_PRESENCE_FLAG : 0U);
  fido_store_be32(&resp[off], next_sign_count);
  off = (uint16_t)(off + 4U);
  memcpy(&resp[off], signature, sig_len);
  off = (uint16_t)(off + sig_len);
  if (fido_u2f_append_status(resp, resp_cap, &off, U2F_SW_NO_ERROR) == 0U)
  {
    return 0U;
  }

  (void)fido_store_update_sign_count(slot_index, next_sign_count);
  *resp_len = off;
  return 1U;
}

static uint8_t fido_complete_u2f_pending(usbd_hid_fido_state_t *state,
                                         uint8_t confirmed,
                                         uint16_t *resp_len)
{
  fido_u2f_apdu_t apdu;
  fido_store_credential_t credential;
  uint32_t slot_index = 0U;

  if ((state == NULL) || (resp_len == NULL))
  {
    return 0U;
  }
  if (state->pending_msg_len != 0U)
  {
    state->rx_expected_len = state->pending_msg_len;
  }
  if (fido_parse_u2f_apdu(state, &apdu) == 0U)
  {
    return 0U;
  }

  if (confirmed == 0U)
  {
    state->tx_buf[0] = (uint8_t)(U2F_SW_CONDITIONS_NOT_SATISFIED >> 8);
    state->tx_buf[1] = (uint8_t)U2F_SW_CONDITIONS_NOT_SATISFIED;
    *resp_len = 2U;
    return 1U;
  }

  if ((apdu.ins == U2F_INS_REGISTER) && (apdu.lc == (FIDO_SHA256_SIZE * 2U)))
  {
    return fido_build_u2f_register_response(&apdu.data[0],
                                            &apdu.data[FIDO_SHA256_SIZE],
                                            state->tx_buf,
                                            (uint16_t)sizeof(state->tx_buf),
                                            resp_len);
  }

  if ((apdu.ins == U2F_INS_AUTHENTICATE) &&
      (apdu.lc >= (FIDO_SHA256_SIZE * 2U + 1U)) &&
      (apdu.data[(FIDO_SHA256_SIZE * 2U)] != 0U))
  {
    uint8_t key_handle_len = apdu.data[FIDO_SHA256_SIZE * 2U];

    if ((uint32_t)key_handle_len != (apdu.lc - (FIDO_SHA256_SIZE * 2U + 1U)))
    {
      return 0U;
    }
    if (fido_store_find(apdu.data + FIDO_SHA256_SIZE,
                        &apdu.data[(FIDO_SHA256_SIZE * 2U) + 1U],
                        key_handle_len,
                        &credential,
                        &slot_index) == 0U)
    {
      return 0U;
    }

    return fido_build_u2f_authenticate_response(&apdu.data[0],
                                                &apdu.data[FIDO_SHA256_SIZE],
                                                &credential,
                                                slot_index,
                                                1U,
                                                state->tx_buf,
                                                (uint16_t)sizeof(state->tx_buf),
                                                resp_len);
  }

  return 0U;
}

static void fido_process_u2f_message(usbd_hid_fido_state_t *state)
{
  fido_u2f_apdu_t apdu;
  fido_store_credential_t credential;
  uint32_t slot_index = 0U;
  uint16_t resp_len = 0U;

  if ((state == NULL) || (fido_parse_u2f_apdu(state, &apdu) == 0U))
  {
    if (state != NULL)
    {
      fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_LENGTH);
    }
    return;
  }

  if (apdu.cla != 0x00U)
  {
    fido_u2f_reply_status(state, state->rx_cid, U2F_SW_CLA_NOT_SUPPORTED);
    return;
  }

  switch (apdu.ins)
  {
    case U2F_INS_VERSION:
      if (apdu.lc != 0U)
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_LENGTH);
        return;
      }
      memcpy(state->tx_buf, "U2F_V2", 6U);
      resp_len = 6U;
      (void)fido_u2f_append_status(state->tx_buf, (uint16_t)sizeof(state->tx_buf), &resp_len, U2F_SW_NO_ERROR);
      fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_MSG, resp_len);
      return;

    case U2F_INS_REGISTER:
      if (apdu.lc != (FIDO_SHA256_SIZE * 2U))
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_LENGTH);
        return;
      }
      state->wait_user_presence = 1U;
      state->pending_msg_len = state->rx_expected_len;
      state->pending_req_valid = 1U;
      fido_crypto_sha256(state->rx_buf, state->rx_expected_len, state->pending_req_hash);
      usbd_ctap_min_begin_external_wait(CTAP_CMD_MAKE_CREDENTIAL);
      state->last_keepalive_ms = HAL_GetTick();
      state->tx_buf[0] = FIDO_HID_KEEPALIVE_UPNEEDED;
      fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_KEEPALIVE, 1U);
      return;

    case U2F_INS_AUTHENTICATE:
      if ((apdu.lc < (FIDO_SHA256_SIZE * 2U + 1U)) ||
          (apdu.data[(FIDO_SHA256_SIZE * 2U)] == 0U) ||
          ((uint32_t)apdu.data[(FIDO_SHA256_SIZE * 2U)] != (apdu.lc - (FIDO_SHA256_SIZE * 2U + 1U))))
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_LENGTH);
        return;
      }
      if (fido_store_find(apdu.data + FIDO_SHA256_SIZE,
                          &apdu.data[(FIDO_SHA256_SIZE * 2U) + 1U],
                          apdu.data[(FIDO_SHA256_SIZE * 2U)],
                          &credential,
                          &slot_index) == 0U)
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_DATA);
        return;
      }
      if (apdu.p1 == U2F_AUTH_CHECK_ONLY)
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_CONDITIONS_NOT_SATISFIED);
        return;
      }
      if (apdu.p1 == U2F_AUTH_DONT_ENFORCE)
      {
        if (fido_build_u2f_authenticate_response(&apdu.data[0],
                                                 &apdu.data[FIDO_SHA256_SIZE],
                                                 &credential,
                                                 slot_index,
                                                 0U,
                                                 state->tx_buf,
                                                 (uint16_t)sizeof(state->tx_buf),
                                                 &resp_len) == 0U)
        {
          fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_DATA);
          return;
        }
        fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_MSG, resp_len);
        return;
      }
      if (apdu.p1 != U2F_AUTH_ENFORCE)
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_DATA);
        return;
      }
      state->wait_user_presence = 1U;
      state->pending_msg_len = state->rx_expected_len;
      state->pending_req_valid = 1U;
      fido_crypto_sha256(state->rx_buf, state->rx_expected_len, state->pending_req_hash);
      usbd_ctap_min_begin_external_wait(CTAP_CMD_GET_ASSERTION);
      state->last_keepalive_ms = HAL_GetTick();
      state->tx_buf[0] = FIDO_HID_KEEPALIVE_UPNEEDED;
      fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_KEEPALIVE, 1U);
      return;

    default:
      fido_u2f_reply_status(state, state->rx_cid, U2F_SW_INS_NOT_SUPPORTED);
      return;
  }
}

static void fido_process_message(usbd_hid_fido_state_t *state)
{
  uint16_t resp_len = 0U;

  if (state->rx_cmd == FIDO_HID_CMD_INIT)
  {
    uint8_t payload[17];
    uint32_t new_cid;

    if (state->rx_expected_len != 8U)
    {
      fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_INVALID_LEN);
      return;
    }

    new_cid = (state->rx_cid == FIDO_HID_BROADCAST_CID) ? fido_allocate_cid(state) : state->rx_cid;
    memcpy(payload, state->rx_buf, 8U);
    fido_store_be32(&payload[8], new_cid);
    payload[12] = 0x02U;
    payload[13] = 0x01U;
    payload[14] = 0x00U;
    payload[15] = 0x00U;
    payload[16] = 0x05U;
    memcpy(state->tx_buf, payload, sizeof(payload));
    fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_INIT, sizeof(payload));
    return;
  }

  if (state->rx_cmd == FIDO_HID_CMD_PING)
  {
    memcpy(state->tx_buf, state->rx_buf, state->rx_expected_len);
    fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_PING, state->rx_expected_len);
    return;
  }

  if (state->rx_cmd == FIDO_HID_CMD_WINK)
  {
    fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_WINK, 0U);
    return;
  }

  if (state->rx_cmd == FIDO_HID_CMD_MSG)
  {
    if ((state->wait_user_presence != 0U) && (fido_is_same_pending_u2f(state) != 0U))
    {
      state->last_keepalive_ms = HAL_GetTick();
      state->tx_buf[0] = FIDO_HID_KEEPALIVE_UPNEEDED;
      fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_KEEPALIVE, 1U);
      return;
    }
    else if (state->wait_user_presence != 0U)
    {
      fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_BUSY);
      return;
    }

    fido_process_u2f_message(state);
    return;
  }

  if (state->rx_cmd == FIDO_HID_CMD_CBOR)
  {
    if ((state->wait_user_presence != 0U) && (fido_is_same_pending_cbor(state) != 0U))
    {
      state->last_keepalive_ms = HAL_GetTick();
      state->tx_buf[0] = FIDO_HID_KEEPALIVE_UPNEEDED;
      fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_KEEPALIVE, 1U);
      return;
    }
    else if (state->wait_user_presence != 0U)
    {
      fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_BUSY);
      return;
    }

    {
      uint8_t result = usbd_ctap_min_handle_cbor(state->rx_buf,
                                                 state->rx_expected_len,
                                                 state->tx_buf,
                                                 (uint16_t)sizeof(state->tx_buf),
                                                 &resp_len);

      if (result == 0U)
      {
        fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_OTHER);
        return;
      }

      if (result == USBD_CTAP_MIN_PENDING)
      {
        state->wait_user_presence = 1U;
        state->pending_cbor_len = state->rx_expected_len;
        fido_crypto_sha256(state->rx_buf, state->rx_expected_len, state->pending_req_hash);
        state->pending_req_valid = 1U;
        state->last_keepalive_ms = HAL_GetTick();
        state->tx_buf[0] = FIDO_HID_KEEPALIVE_UPNEEDED;
        fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_KEEPALIVE, 1U);
        return;
      }

      fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_CBOR, resp_len);
      return;
    }
  }

  fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_INVALID_CMD);
}

uint16_t usbd_hid_fido_get_report_desc(const uint8_t **desc)
{
  if (desc != NULL)
  {
    *desc = k_fido_hid_report_desc;
  }
  return (uint16_t)sizeof(k_fido_hid_report_desc);
}

void usbd_hid_fido_init(usbd_hid_fido_state_t *state)
{
  if (state == NULL)
  {
    return;
  }

  memset(state, 0, sizeof(*state));
  state->next_cid = 0x01000000U;
}

uint16_t usbd_hid_fido_process(USBD_HandleTypeDef *pdev,
                               uint8_t class_id,
                               usbd_hid_fido_state_t *state,
                               const uint8_t *request,
                               uint16_t request_len,
                               uint8_t *response,
                               uint16_t response_cap)
{
  uint32_t cid;
  uint8_t tag;
  uint16_t copy_len;

  (void)pdev;
  (void)class_id;

  if ((state == NULL) || (request == NULL) || (response == NULL) || (request_len != FIDO_HID_PACKET_SIZE))
  {
    return 0U;
  }

  fido_diag_note_rx(request, request_len);
  fido_diag_note_state(state);

  cid = fido_load_be32(request);
  tag = request[4];

  if (state->tx_active != 0U)
  {
    fido_queue_error(state, cid, FIDO_HID_ERR_BUSY);
  }
  else if ((tag & 0x80U) != 0U)
  {
    state->rx_cid = cid;
    state->rx_cmd = (uint8_t)(tag & 0x7FU);
    state->rx_expected_len = (uint16_t)(((uint16_t)request[5] << 8) | request[6]);
    state->rx_received_len = 0U;
    state->rx_seq = 0U;
    state->rx_active = 0U;
    fido_diag_note_state(state);

    if (state->rx_expected_len > FIDO_HID_MSG_MAX)
    {
      fido_queue_error(state, cid, FIDO_HID_ERR_INVALID_LEN);
    }
    else if ((cid == FIDO_HID_BROADCAST_CID) && (state->rx_cmd != FIDO_HID_CMD_INIT))
    {
      fido_queue_error(state, cid, FIDO_HID_ERR_INVALID_CHANNEL);
    }
    else
    {
      copy_len = state->rx_expected_len;
      if (copy_len > (FIDO_HID_PACKET_SIZE - 7U))
      {
        copy_len = FIDO_HID_PACKET_SIZE - 7U;
      }
      if (copy_len != 0U)
      {
        memcpy(state->rx_buf, &request[7], copy_len);
      }
      state->rx_received_len = copy_len;
      fido_diag_note_state(state);
      if (state->rx_received_len >= state->rx_expected_len)
      {
        fido_process_message(state);
      }
      else
      {
        state->rx_active = 1U;
      }
    }
  }
  else if ((state->rx_active == 0U) || (cid != state->rx_cid) || (tag != state->rx_seq))
  {
    fido_queue_error(state, cid, FIDO_HID_ERR_INVALID_SEQ);
    fido_reset_rx(state);
  }
  else
  {
    uint16_t remain = (uint16_t)(state->rx_expected_len - state->rx_received_len);

    copy_len = remain;
    if (copy_len > (FIDO_HID_PACKET_SIZE - 5U))
    {
      copy_len = FIDO_HID_PACKET_SIZE - 5U;
    }
    if (copy_len != 0U)
    {
      memcpy(&state->rx_buf[state->rx_received_len], &request[5], copy_len);
    }
    state->rx_received_len = (uint16_t)(state->rx_received_len + copy_len);
    state->rx_seq = (uint8_t)(state->rx_seq + 1U);
    fido_diag_note_state(state);
    if (state->rx_received_len >= state->rx_expected_len)
    {
      state->rx_active = 0U;
      fido_process_message(state);
      state->rx_received_len = 0U;
      state->rx_expected_len = 0U;
      state->rx_seq = 0U;
      fido_diag_note_state(state);
    }
  }

  return fido_emit_tx_packet(state, response, response_cap);
}

uint16_t usbd_hid_fido_service(USBD_HandleTypeDef *pdev,
                               uint8_t class_id,
                               usbd_hid_fido_state_t *state,
                               uint8_t *response,
                               uint16_t response_cap,
                               uint32_t now_ms)
{
  uint16_t resp_len = 0U;
  usbd_ctap_min_ui_status_t ui;

  if ((pdev == NULL) || (state == NULL) || (response == NULL) || (response_cap < FIDO_HID_PACKET_SIZE))
  {
    return 0U;
  }

  if (state->wait_user_presence == 0U)
  {
    return 0U;
  }

  usbd_ctap_min_get_ui_status(&ui);
  if (ui.ui_state == USBD_CTAP_UI_CONFIRMED)
  {
    if ((state->tx_active != 0U) && (state->tx_cmd == FIDO_HID_CMD_KEEPALIVE))
    {
      state->tx_active = 0U;
      state->tx_len = 0U;
      state->tx_offset = 0U;
      state->tx_seq = 0U;
    }
    else if (state->tx_active != 0U)
    {
      return 0U;
    }

    if (state->rx_cmd == FIDO_HID_CMD_CBOR)
    {
      if (usbd_ctap_min_complete_pending(state->rx_buf,
                                         state->pending_cbor_len,
                                         1U,
                                         state->tx_buf,
                                         (uint16_t)sizeof(state->tx_buf),
                                         &resp_len) == 0U)
      {
        fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_OTHER);
      }
      else
      {
        fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_CBOR, resp_len);
      }
    }
    else if (state->rx_cmd == FIDO_HID_CMD_MSG)
    {
      if (fido_complete_u2f_pending(state, 1U, &resp_len) == 0U)
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_WRONG_DATA);
      }
      else
      {
        fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_MSG, resp_len);
      }
      usbd_ctap_min_finish_external_wait();
    }
    else
    {
      fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_OTHER);
    }
    state->wait_user_presence = 0U;
    state->pending_req_valid = 0U;
    state->pending_cbor_len = 0U;
    state->pending_msg_len = 0U;
  }
  else if (ui.ui_state == USBD_CTAP_UI_DENIED)
  {
    if ((state->tx_active != 0U) && (state->tx_cmd == FIDO_HID_CMD_KEEPALIVE))
    {
      state->tx_active = 0U;
      state->tx_len = 0U;
      state->tx_offset = 0U;
      state->tx_seq = 0U;
    }
    else if (state->tx_active != 0U)
    {
      return 0U;
    }

    if (state->rx_cmd == FIDO_HID_CMD_CBOR)
    {
      if (usbd_ctap_min_complete_pending(state->rx_buf,
                                         state->pending_cbor_len,
                                         0U,
                                         state->tx_buf,
                                         (uint16_t)sizeof(state->tx_buf),
                                         &resp_len) == 0U)
      {
        fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_OTHER);
      }
      else
      {
        fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_CBOR, resp_len);
      }
    }
    else if (state->rx_cmd == FIDO_HID_CMD_MSG)
    {
      if (fido_complete_u2f_pending(state, 0U, &resp_len) == 0U)
      {
        fido_u2f_reply_status(state, state->rx_cid, U2F_SW_CONDITIONS_NOT_SATISFIED);
      }
      else
      {
        fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_MSG, resp_len);
      }
      usbd_ctap_min_finish_external_wait();
    }
    else
    {
      fido_queue_error(state, state->rx_cid, FIDO_HID_ERR_OTHER);
    }
    state->wait_user_presence = 0U;
    state->pending_req_valid = 0U;
    state->pending_cbor_len = 0U;
    state->pending_msg_len = 0U;
  }
  else if (state->tx_active != 0U)
  {
    return 0U;
  }
  else if ((uint32_t)(now_ms - state->last_keepalive_ms) >= 250U)
  {
    state->last_keepalive_ms = now_ms;
    state->tx_buf[0] = FIDO_HID_KEEPALIVE_UPNEEDED;
    fido_start_tx(state, state->rx_cid, FIDO_HID_CMD_KEEPALIVE, 1U);
  }

  return fido_emit_tx_packet(state, response, response_cap);
}

uint16_t usbd_hid_fido_continue(usbd_hid_fido_state_t *state,
                                uint8_t *response,
                                uint16_t response_cap)
{
  return fido_emit_tx_packet(state, response, response_cap);
}
