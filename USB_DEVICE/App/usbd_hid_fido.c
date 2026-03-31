#include "usbd_hid_fido.h"

#include <string.h>

#include "usbd_conf.h"
#include "usbd_ctap_min.h"
#include "fido_crypto.h"

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

static void fido_reset_rx(usbd_hid_fido_state_t *state)
{
  state->rx_active = 0U;
  state->rx_received_len = 0U;
  state->rx_expected_len = 0U;
  state->rx_seq = 0U;
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
    payload[16] = 0x0CU;
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
    if (state->rx_received_len >= state->rx_expected_len)
    {
      state->rx_active = 0U;
      fido_process_message(state);
      state->rx_received_len = 0U;
      state->rx_expected_len = 0U;
      state->rx_seq = 0U;
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

  if ((state->wait_user_presence == 0U) || (state->tx_active != 0U))
  {
    return 0U;
  }

  usbd_ctap_min_get_ui_status(&ui);
  if (ui.ui_state == USBD_CTAP_UI_CONFIRMED)
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
    state->wait_user_presence = 0U;
    state->pending_req_valid = 0U;
    state->pending_cbor_len = 0U;
  }
  else if (ui.ui_state == USBD_CTAP_UI_DENIED)
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
    state->wait_user_presence = 0U;
    state->pending_req_valid = 0U;
    state->pending_cbor_len = 0U;
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
