#include "usbd_hid_cmsisdap.h"

#include <string.h>

#include "usbd_conf.h"

#define DAP_PACKET_SIZE 64U
#define DAP_PACKET_COUNT 1U

#define ID_DAP_INFO               0x00U
#define ID_DAP_HOST_STATUS        0x01U
#define ID_DAP_CONNECT            0x02U
#define ID_DAP_DISCONNECT         0x03U
#define ID_DAP_TRANSFER_CONFIGURE 0x04U
#define ID_DAP_TRANSFER           0x05U
#define ID_DAP_TRANSFER_BLOCK     0x06U
#define ID_DAP_TRANSFER_ABORT     0x07U
#define ID_DAP_WRITE_ABORT        0x08U
#define ID_DAP_DELAY              0x09U
#define ID_DAP_RESET_TARGET       0x0AU
#define ID_DAP_SWJ_PINS           0x10U
#define ID_DAP_SWJ_CLOCK          0x11U
#define ID_DAP_SWJ_SEQUENCE       0x12U
#define ID_DAP_SWD_CONFIGURE      0x13U

#define DAP_OK                    0x00U
#define DAP_ERROR                 0xFFU

#define DAP_PORT_AUTODETECT       0x00U
#define DAP_PORT_DISABLED         0x00U
#define DAP_PORT_SWD              0x01U
#define DAP_PORT_JTAG             0x02U

#define DAP_ID_VENDOR             0x01U
#define DAP_ID_PRODUCT            0x02U
#define DAP_ID_SER_NUM            0x03U
#define DAP_ID_DAP_FW_VER         0x04U
#define DAP_ID_DEVICE_VENDOR      0x05U
#define DAP_ID_DEVICE_NAME        0x06U
#define DAP_ID_BOARD_VENDOR       0x07U
#define DAP_ID_BOARD_NAME         0x08U
#define DAP_ID_PRODUCT_FW_VER     0x09U
#define DAP_ID_CAPABILITIES       0xF0U
#define DAP_ID_TIMESTAMP_CLOCK    0xF1U
#define DAP_ID_PACKET_COUNT       0xFEU
#define DAP_ID_PACKET_SIZE        0xFFU

#define DAP_TRANSFER_RNW          (1U << 1)
#define DAP_TRANSFER_MATCH_VALUE  (1U << 4)

typedef struct
{
  uint8_t connected;
  uint8_t active_port;
  uint8_t host_debugger_connected;
  uint8_t host_target_running;
  uint32_t swj_clock_hz;
} cmsis_dap_state_t;

static cmsis_dap_state_t s_dap_state = {
    0U, DAP_PORT_DISABLED, 0U, 0U, 1000000U};

static uint16_t cmsis_dap_reply_string(uint8_t *response,
                                       uint16_t response_cap,
                                       uint8_t cmd,
                                       const char *value)
{
  uint16_t len;

  if (response_cap < 2U)
  {
    return 0U;
  }

  response[0] = cmd;
  if (value == NULL)
  {
    response[1] = 0U;
    return 2U;
  }

  len = (uint16_t)strlen(value) + 1U;
  if ((uint16_t)(2U + len) > response_cap)
  {
    len = (uint16_t)(response_cap - 2U);
  }

  response[1] = (uint8_t)len;
  if (len != 0U)
  {
    memcpy(&response[2], value, len);
  }

  return (uint16_t)(2U + len);
}

static uint16_t cmsis_dap_reply_u8(uint8_t *response,
                                   uint16_t response_cap,
                                   uint8_t cmd,
                                   uint8_t value)
{
  if (response_cap < 3U)
  {
    return 0U;
  }
  response[0] = cmd;
  response[1] = 1U;
  response[2] = value;
  return 3U;
}

static uint16_t cmsis_dap_reply_u16(uint8_t *response,
                                    uint16_t response_cap,
                                    uint8_t cmd,
                                    uint16_t value)
{
  if (response_cap < 4U)
  {
    return 0U;
  }
  response[0] = cmd;
  response[1] = 2U;
  response[2] = (uint8_t)(value & 0xFFU);
  response[3] = (uint8_t)((value >> 8) & 0xFFU);
  return 4U;
}

static uint16_t cmsis_dap_reply_u32(uint8_t *response,
                                    uint16_t response_cap,
                                    uint8_t cmd,
                                    uint32_t value)
{
  if (response_cap < 6U)
  {
    return 0U;
  }
  response[0] = cmd;
  response[1] = 4U;
  response[2] = (uint8_t)(value & 0xFFU);
  response[3] = (uint8_t)((value >> 8) & 0xFFU);
  response[4] = (uint8_t)((value >> 16) & 0xFFU);
  response[5] = (uint8_t)((value >> 24) & 0xFFU);
  return 6U;
}

static uint16_t cmsis_dap_reply_status(uint8_t *response,
                                       uint16_t response_cap,
                                       uint8_t cmd,
                                       uint8_t status)
{
  if (response_cap < 2U)
  {
    return 0U;
  }
  response[0] = cmd;
  response[1] = status;
  return 2U;
}

static uint16_t cmsis_dap_reply_transfer_dummy(const uint8_t *request,
                                               uint16_t request_len,
                                               uint8_t *response,
                                               uint16_t response_cap,
                                               uint8_t cmd)
{
  uint16_t offset = 2U;
  uint8_t transfer_count;
  uint8_t request_value;

  if ((request == NULL) || (request_len < 2U) || (response_cap < 3U))
  {
    return 0U;
  }

  response[0] = cmd;
  transfer_count = request[1];

  while (transfer_count-- != 0U)
  {
    if (offset >= request_len)
    {
      break;
    }

    request_value = request[offset++];
    if ((request_value & DAP_TRANSFER_RNW) != 0U)
    {
      if ((request_value & DAP_TRANSFER_MATCH_VALUE) != 0U)
      {
        if ((uint16_t)(offset + 4U) > request_len)
        {
          offset = request_len;
          break;
        }
        offset = (uint16_t)(offset + 4U);
      }
    }
    else
    {
      if ((uint16_t)(offset + 4U) > request_len)
      {
        offset = request_len;
        break;
      }
      offset = (uint16_t)(offset + 4U);
    }
  }

  response[1] = 0U;
  response[2] = 0U;
  return 3U;
}

static uint16_t cmsis_dap_reply_transfer_block_dummy(const uint8_t *request,
                                                     uint16_t request_len,
                                                     uint8_t *response,
                                                     uint16_t response_cap,
                                                     uint8_t cmd)
{
  uint8_t request_value;

  (void)request_len;

  if ((request == NULL) || (response == NULL) || (response_cap < 4U))
  {
    return 0U;
  }

  response[0] = cmd;
  response[1] = 0U;
  response[2] = 0U;
  response[3] = 0U;

  if ((request_len >= 4U) && ((request[3] & DAP_TRANSFER_RNW) == 0U))
  {
    request_value = request[3];
    (void)request_value;
  }

  return 4U;
}

uint16_t usbd_hid_cmsisdap_process(USBD_HandleTypeDef *pdev,
                                   uint8_t class_id,
                                   const uint8_t *request,
                                   uint16_t request_len,
                                   uint8_t *response,
                                   uint16_t response_cap)
{
  const uint8_t *packet;
  uint16_t packet_len;
  uint8_t cmd;
  uint8_t arg0;

  (void)pdev;
  (void)class_id;

  if ((request == NULL) || (response == NULL) || (response_cap < DAP_PACKET_SIZE))
  {
    return 0U;
  }

  memset(response, 0, response_cap);

  g_a_usb_diag_runtime.cmsis_rx_count++;
  g_a_usb_diag_runtime.cmsis_last_req_len = request_len;
  g_a_usb_diag_runtime.cmsis_last_req_word0 = 0U;
  g_a_usb_diag_runtime.cmsis_last_req_word1 = 0U;
  if (request_len >= 1U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word0 |= (uint32_t)request[0];
  }
  if (request_len >= 2U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word0 |= ((uint32_t)request[1] << 8);
  }
  if (request_len >= 3U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word0 |= ((uint32_t)request[2] << 16);
  }
  if (request_len >= 4U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word0 |= ((uint32_t)request[3] << 24);
  }
  if (request_len >= 5U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word1 |= (uint32_t)request[4];
  }
  if (request_len >= 6U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word1 |= ((uint32_t)request[5] << 8);
  }
  if (request_len >= 7U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word1 |= ((uint32_t)request[6] << 16);
  }
  if (request_len >= 8U)
  {
    g_a_usb_diag_runtime.cmsis_last_req_word1 |= ((uint32_t)request[7] << 24);
  }

  if (request_len == 0U)
  {
    return 0U;
  }

  packet = request;
  packet_len = request_len;

  /* Some host stacks prepend Report ID 0 for unnumbered HID reports. */
  if ((request_len >= 3U) && (request[0] == 0x00U) && (request[1] == ID_DAP_INFO))
  {
    packet = &request[1];
    packet_len = (uint16_t)(request_len - 1U);
  }
  else if ((request_len >= 2U) &&
           (request[0] == 0x00U) &&
           (request[1] != ID_DAP_INFO) &&
           (request[1] <= ID_DAP_SWD_CONFIGURE))
  {
    packet = &request[1];
    packet_len = (uint16_t)(request_len - 1U);
  }

  cmd = packet[0];
  arg0 = (packet_len > 1U) ? packet[1] : 0U;

  switch (cmd)
  {
    case ID_DAP_INFO:
      switch (arg0)
      {
        case DAP_ID_VENDOR:
          goto done_string_ultralink;
        case DAP_ID_PRODUCT:
          goto done_string_product;
        case DAP_ID_SER_NUM:
          goto done_string_serial;
        case DAP_ID_DAP_FW_VER:
          goto done_string_dap_fw;
        case DAP_ID_DEVICE_VENDOR:
          goto done_string_ultralink;
        case DAP_ID_DEVICE_NAME:
          goto done_string_device;
        case DAP_ID_BOARD_VENDOR:
          goto done_string_ultralink;
        case DAP_ID_BOARD_NAME:
          goto done_string_ultralink;
        case DAP_ID_PRODUCT_FW_VER:
          goto done_string_product_fw;
        case DAP_ID_CAPABILITIES:
          goto done_capabilities;
        case DAP_ID_TIMESTAMP_CLOCK:
          goto done_timestamp_clock;
        case DAP_ID_PACKET_COUNT:
          goto done_packet_count;
        case DAP_ID_PACKET_SIZE:
          goto done_packet_size;
        default:
          response[0] = cmd;
          response[1] = 0U;
          goto done_return_2;
      }

    case ID_DAP_HOST_STATUS:
      if (request_len >= 3U)
      {
        if (arg0 == 0U)
        {
          s_dap_state.host_debugger_connected = request[2] & 0x01U;
        }
        else if (arg0 == 1U)
        {
          s_dap_state.host_target_running = request[2] & 0x01U;
        }
      }
      goto done_status_ok;

    case ID_DAP_CONNECT:
      if ((arg0 == DAP_PORT_AUTODETECT) || (arg0 == DAP_PORT_SWD))
      {
        s_dap_state.connected = 1U;
        s_dap_state.active_port = DAP_PORT_SWD;
      }
      else
      {
        s_dap_state.connected = 0U;
        s_dap_state.active_port = DAP_PORT_DISABLED;
      }
      goto done_status_port;

    case ID_DAP_DISCONNECT:
      s_dap_state.connected = 0U;
      s_dap_state.active_port = DAP_PORT_DISABLED;
      goto done_status_ok;

    case ID_DAP_TRANSFER_CONFIGURE:
      goto done_status_ok;

    case ID_DAP_DELAY:
      goto done_status_ok;

    case ID_DAP_RESET_TARGET:
      if (response_cap < 3U)
      {
        goto done_zero;
      }
      response[0] = cmd;
      response[1] = DAP_OK;
      response[2] = 0U;
      goto done_return_3;

    case ID_DAP_SWJ_PINS:
      if (response_cap < 2U)
      {
        goto done_zero;
      }
      response[0] = cmd;
      response[1] = 0x80U;
      goto done_return_2;

    case ID_DAP_SWJ_CLOCK:
      if (request_len >= 5U)
      {
        s_dap_state.swj_clock_hz = (uint32_t)request[1] |
                                   ((uint32_t)request[2] << 8) |
                                   ((uint32_t)request[3] << 16) |
                                   ((uint32_t)request[4] << 24);
      }
      goto done_status_ok;

    case ID_DAP_SWJ_SEQUENCE:
      goto done_status_ok;

    case ID_DAP_SWD_CONFIGURE:
      goto done_status_ok;

    case ID_DAP_TRANSFER_ABORT:
      goto done_zero;

    case ID_DAP_TRANSFER:
      {
        uint16_t ret = cmsis_dap_reply_transfer_dummy(packet,
                                                      packet_len,
                                                      response,
                                                      response_cap,
                                                      cmd);
        g_a_usb_diag_runtime.cmsis_tx_count++;
        g_a_usb_diag_runtime.cmsis_last_rsp_len = ret;
        g_a_usb_diag_runtime.cmsis_last_rsp_word0 = ((ret >= 1U) ? response[0] : 0U) |
                                                    ((ret >= 2U) ? ((uint32_t)response[1] << 8) : 0U) |
                                                    ((ret >= 3U) ? ((uint32_t)response[2] << 16) : 0U) |
                                                    ((ret >= 4U) ? ((uint32_t)response[3] << 24) : 0U);
        g_a_usb_diag_runtime.cmsis_last_rsp_word1 = ((ret >= 5U) ? response[4] : 0U) |
                                                    ((ret >= 6U) ? ((uint32_t)response[5] << 8) : 0U) |
                                                    ((ret >= 7U) ? ((uint32_t)response[6] << 16) : 0U) |
                                                    ((ret >= 8U) ? ((uint32_t)response[7] << 24) : 0U);
        return ret;
      }

    case ID_DAP_TRANSFER_BLOCK:
      {
        uint16_t ret = cmsis_dap_reply_transfer_block_dummy(packet,
                                                            packet_len,
                                                            response,
                                                            response_cap,
                                                            cmd);
        g_a_usb_diag_runtime.cmsis_tx_count++;
        g_a_usb_diag_runtime.cmsis_last_rsp_len = ret;
        g_a_usb_diag_runtime.cmsis_last_rsp_word0 = ((ret >= 1U) ? response[0] : 0U) |
                                                    ((ret >= 2U) ? ((uint32_t)response[1] << 8) : 0U) |
                                                    ((ret >= 3U) ? ((uint32_t)response[2] << 16) : 0U) |
                                                    ((ret >= 4U) ? ((uint32_t)response[3] << 24) : 0U);
        g_a_usb_diag_runtime.cmsis_last_rsp_word1 = 0U;
        return ret;
      }

    case ID_DAP_WRITE_ABORT:
      goto done_status_error;

    default:
      goto done_status_error;
  }

done_string_ultralink:
  {
    uint16_t ret = cmsis_dap_reply_string(response, response_cap, cmd, "UltraLink");
    goto done_finalize;
done_string_product:
    ret = cmsis_dap_reply_string(response, response_cap, cmd, "UltraLink CMSIS-DAP");
    goto done_finalize;
done_string_serial:
    ret = cmsis_dap_reply_string(response, response_cap, cmd, "UL-PRO-HS");
    goto done_finalize;
done_string_dap_fw:
    ret = cmsis_dap_reply_string(response, response_cap, cmd, "1.3.0");
    goto done_finalize;
done_string_device:
    ret = cmsis_dap_reply_string(response, response_cap, cmd, "Debug Probe");
    goto done_finalize;
done_string_product_fw:
    ret = cmsis_dap_reply_string(response, response_cap, cmd, "0.1.0");
    goto done_finalize;
done_capabilities:
    ret = cmsis_dap_reply_u8(response, response_cap, cmd, 0x01U);
    goto done_finalize;
done_timestamp_clock:
    ret = cmsis_dap_reply_u32(response, response_cap, cmd, 0U);
    goto done_finalize;
done_packet_count:
    ret = cmsis_dap_reply_u8(response, response_cap, cmd, DAP_PACKET_COUNT);
    goto done_finalize;
done_packet_size:
    ret = cmsis_dap_reply_u16(response, response_cap, cmd, DAP_PACKET_SIZE);
    goto done_finalize;
done_status_ok:
    ret = cmsis_dap_reply_status(response, response_cap, cmd, DAP_OK);
    goto done_finalize;
done_status_port:
    ret = cmsis_dap_reply_status(response, response_cap, cmd, s_dap_state.active_port);
    goto done_finalize;
done_status_error:
    ret = cmsis_dap_reply_status(response, response_cap, cmd, DAP_ERROR);
    goto done_finalize;
done_return_2:
    ret = 2U;
    goto done_finalize;
done_return_3:
    ret = 3U;
    goto done_finalize;
done_zero:
    ret = 0U;
done_finalize:
    g_a_usb_diag_runtime.cmsis_tx_count++;
    g_a_usb_diag_runtime.cmsis_last_rsp_len = ret;
    g_a_usb_diag_runtime.cmsis_last_rsp_word0 = ((ret >= 1U) ? response[0] : 0U) |
                                                ((ret >= 2U) ? ((uint32_t)response[1] << 8) : 0U) |
                                                ((ret >= 3U) ? ((uint32_t)response[2] << 16) : 0U) |
                                                ((ret >= 4U) ? ((uint32_t)response[3] << 24) : 0U);
    g_a_usb_diag_runtime.cmsis_last_rsp_word1 = ((ret >= 5U) ? response[4] : 0U) |
                                                ((ret >= 6U) ? ((uint32_t)response[5] << 8) : 0U) |
                                                ((ret >= 7U) ? ((uint32_t)response[6] << 16) : 0U) |
                                                ((ret >= 8U) ? ((uint32_t)response[7] << 24) : 0U);
    return ret;
  }
}
