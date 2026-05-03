#include "usbd_hid_km.h"

#include "usbd_composite_builder.h"
#include "usbd_ctlreq.h"
#include "usbd_hid.h"

#include <stdlib.h>
#include <string.h>

#define HID_KM_QUEUE_LEN 48u
#define HID_KM_LINE_LEN  96u
#define HID_KM_SEND_INTERVAL_MS 8u
#define HID_KM_MOD_LCTRL  0x01u
#define HID_KM_MOD_LSHIFT 0x02u
#define HID_KM_MOD_LALT   0x04u
#define HID_KM_MOD_LGUI   0x08u
#define HID_KM_TARGET_KEYBOARD 0u
#define HID_KM_TARGET_MOUSE    1u

typedef struct {
  uint8_t target;
  uint8_t len;
  uint8_t data[HID_KM_KEYBOARD_PACKET_SIZE];
} hid_km_frame_t;

typedef struct {
  const char *name;
  uint8_t usage;
} hid_km_key_name_t;

static uint8_t USBD_HID_KM_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_HID_KM_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_HID_KM_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
static uint8_t USBD_HID_KM_EP0_RxReady(USBD_HandleTypeDef *pdev);
static uint8_t USBD_HID_KM_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum);

USBD_ClassTypeDef USBD_HID_KM = {
    USBD_HID_KM_Init,
    USBD_HID_KM_DeInit,
    USBD_HID_KM_Setup,
    NULL,
    USBD_HID_KM_EP0_RxReady,
    USBD_HID_KM_DataIn,
    NULL,
    NULL,
    NULL,
    NULL,
#ifdef USE_USB_HS
    NULL,
#endif
    NULL,
    NULL,
    NULL,
#if (USBD_SUPPORT_USER_STRING_DESC == 1U)
    NULL,
#endif
};

__ALIGN_BEGIN static uint8_t s_keyboard_report_desc[] __ALIGN_END = {
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
    0x95, 0x08, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00,
    0x25, 0x65, 0x05, 0x07, 0x19, 0x00,
    0x29, 0x65, 0x81, 0x00, 0xC0,
};

__ALIGN_BEGIN static uint8_t s_mouse_report_desc[] __ALIGN_END = {
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01,
    0x09, 0x01, 0xA1, 0x00,
    0x05, 0x09, 0x19, 0x01, 0x29, 0x05,
    0x15, 0x00, 0x25, 0x01, 0x95, 0x05,
    0x75, 0x01, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x03, 0x81, 0x01,
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31,
    0x09, 0x38, 0x15, 0x81, 0x25, 0x7F,
    0x75, 0x08, 0x95, 0x03, 0x81, 0x06,
    0xC0, 0xC0,
};

static const hid_km_key_name_t s_key_names[] = {
    {"ENTER", 0x28u}, {"RET", 0x28u},
    {"ESC", 0x29u}, {"ESCAPE", 0x29u},
    {"BSP", 0x2Au}, {"BACKSPACE", 0x2Au},
    {"TAB", 0x2Bu}, {"SPACE", 0x2Cu},
    {"CAPS", 0x39u}, {"CAPSLOCK", 0x39u},
    {"F1", 0x3Au}, {"F2", 0x3Bu}, {"F3", 0x3Cu}, {"F4", 0x3Du},
    {"F5", 0x3Eu}, {"F6", 0x3Fu}, {"F7", 0x40u}, {"F8", 0x41u},
    {"F9", 0x42u}, {"F10", 0x43u}, {"F11", 0x44u}, {"F12", 0x45u},
    {"PRINT", 0x46u}, {"SCROLL", 0x47u}, {"PAUSE", 0x48u},
    {"INS", 0x49u}, {"INSERT", 0x49u},
    {"HOME", 0x4Au}, {"PGUP", 0x4Bu}, {"PAGEUP", 0x4Bu},
    {"DEL", 0x4Cu}, {"DELETE", 0x4Cu},
    {"END", 0x4Du}, {"PGDN", 0x4Eu}, {"PAGEDOWN", 0x4Eu},
    {"RIGHT", 0x4Fu}, {"LEFT", 0x50u}, {"DOWN", 0x51u}, {"UP", 0x52u},
};

__ALIGN_BEGIN static uint8_t s_hid_desc[USB_HID_DESC_SIZ] __ALIGN_END = {
    0x09, HID_DESCRIPTOR_TYPE, 0x11, 0x01, 0x00, 0x01, HID_REPORT_DESC, 0x00, 0x00,
};

static hid_km_frame_t s_queue[HID_KM_QUEUE_LEN];
static uint8_t s_q_head;
static uint8_t s_q_tail;
static uint8_t s_q_count;
static uint8_t s_mouse_buttons;
static uint8_t s_led_report;
static uint8_t s_keyboard_busy;
static uint8_t s_mouse_busy;
static uint8_t s_keyboard_protocol;
static uint8_t s_mouse_protocol;
static uint8_t s_keyboard_idle;
static uint8_t s_mouse_idle;
static uint8_t s_ctrl_report[HID_KM_KEYBOARD_PACKET_SIZE];
static uint8_t s_ctrl_report_len;
static uint8_t s_ctrl_report_target;
static uint32_t s_next_send_ms;
static char s_line[HID_KM_LINE_LEN];
static uint8_t s_line_len;
static usbd_hid_km_status_t s_status;

static uint8_t ascii_to_hid(char ch, uint8_t *modifier, uint8_t *usage);
static void hid_km_execute_line(const char *line);

void usbd_hid_km_init(void)
{
  s_q_head = 0u;
  s_q_tail = 0u;
  s_q_count = 0u;
  s_mouse_buttons = 0u;
  s_led_report = 0u;
  s_keyboard_busy = 0u;
  s_mouse_busy = 0u;
  s_keyboard_protocol = 1u;
  s_mouse_protocol = 1u;
  s_keyboard_idle = 0u;
  s_mouse_idle = 0u;
  s_ctrl_report_len = 0u;
  s_ctrl_report_target = HID_KM_TARGET_KEYBOARD;
  s_next_send_ms = 0u;
  s_line_len = 0u;
  memset(s_line, 0, sizeof(s_line));
  memset(&s_status, 0, sizeof(s_status));
  strncpy(s_status.last_cmd, "READY", sizeof(s_status.last_cmd) - 1u);
}

uint16_t usbd_hid_km_get_keyboard_report_desc(const uint8_t **desc)
{
  if (desc != NULL) {
    *desc = s_keyboard_report_desc;
  }
  return (uint16_t)sizeof(s_keyboard_report_desc);
}

uint16_t usbd_hid_km_get_mouse_report_desc(const uint8_t **desc)
{
  if (desc != NULL) {
    *desc = s_mouse_report_desc;
  }
  return (uint16_t)sizeof(s_mouse_report_desc);
}

static void set_last_cmd(const char *cmd)
{
  memset(s_status.last_cmd, 0, sizeof(s_status.last_cmd));
  if (cmd != NULL) {
    strncpy(s_status.last_cmd, cmd, sizeof(s_status.last_cmd) - 1u);
  }
}

static uint8_t queue_frame(uint8_t target, const uint8_t *data, uint8_t len)
{
  if ((data == NULL) || (len == 0u) || (len > sizeof(s_queue[0].data))) {
    return 0u;
  }
  if (s_q_count >= HID_KM_QUEUE_LEN) {
    s_status.dropped_reports++;
    return 0u;
  }

  s_queue[s_q_tail].target = target;
  s_queue[s_q_tail].len = len;
  memcpy(s_queue[s_q_tail].data, data, len);
  s_q_tail = (uint8_t)((s_q_tail + 1u) % HID_KM_QUEUE_LEN);
  s_q_count++;
  s_status.queue_depth = s_q_count;
  return 1u;
}

static void queue_key_release(void)
{
  uint8_t report[HID_KM_KEYBOARD_PACKET_SIZE] = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u};

  (void)queue_frame(HID_KM_TARGET_KEYBOARD, report, sizeof(report));
}

static uint8_t queue_key(uint8_t modifier, uint8_t usage)
{
  uint8_t report[HID_KM_KEYBOARD_PACKET_SIZE] = {modifier, 0u, usage, 0u, 0u, 0u, 0u, 0u};

  if (usage == 0u) {
    return 0u;
  }
  if (queue_frame(HID_KM_TARGET_KEYBOARD, report, sizeof(report)) == 0u) {
    return 0u;
  }
  queue_key_release();
  return 1u;
}

static uint8_t queue_text(const char *text)
{
  uint8_t any = 0u;

  while ((text != NULL) && (*text != '\0')) {
    uint8_t mod = 0u;
    uint8_t usage = 0u;

    if (ascii_to_hid(*text, &mod, &usage) != 0u) {
      any |= queue_key(mod, usage);
    }
    text++;
  }
  return any;
}

static int8_t clamp_i8(long value)
{
  if (value > 127) {
    return 127;
  }
  if (value < -127) {
    return -127;
  }
  return (int8_t)value;
}

static uint8_t queue_mouse(int8_t dx, int8_t dy, int8_t wheel, uint8_t buttons)
{
  uint8_t report[HID_KM_MOUSE_PACKET_SIZE];

  report[0] = (uint8_t)(buttons & 0x1Fu);
  report[1] = (uint8_t)dx;
  report[2] = (uint8_t)dy;
  report[3] = (uint8_t)wheel;
  return queue_frame(HID_KM_TARGET_MOUSE, report, sizeof(report));
}

static void queue_mouse_release(void)
{
  s_mouse_buttons = 0u;
  (void)queue_mouse(0, 0, 0, s_mouse_buttons);
}

void usbd_hid_km_feed_serial_byte(uint8_t byte)
{
  s_status.rx_bytes++;

  if ((byte == 0x03u) || (byte == 0x18u) || (byte == 0x1Bu)) {
    s_line_len = 0u;
    memset(s_line, 0, sizeof(s_line));
    set_last_cmd("CLEAR");
    return;
  }

  if ((byte == '\r') || (byte == '\n')) {
    if (s_line_len != 0u) {
      s_line[s_line_len] = '\0';
      hid_km_execute_line(s_line);
      s_line_len = 0u;
      memset(s_line, 0, sizeof(s_line));
    }
    return;
  }

  if (s_line_len < (sizeof(s_line) - 1u)) {
    s_line[s_line_len++] = (char)byte;
  } else {
    s_status.dropped_reports++;
    set_last_cmd("LINE TOO LONG");
    s_line_len = 0u;
  }
}

static uint8_t get_keyboard_ep(USBD_HandleTypeDef *pdev, uint8_t class_id)
{
  return pdev->tclasslist[class_id].Eps[0].add;
}

static uint8_t get_mouse_ep(USBD_HandleTypeDef *pdev, uint8_t class_id)
{
  return pdev->tclasslist[class_id].Eps[1].add;
}

void usbd_hid_km_service(USBD_HandleTypeDef *pdev, uint32_t now_ms)
{
  uint32_t class_id;
  hid_km_frame_t *frame;
  uint8_t ep;

  if ((pdev == NULL) || (s_q_count == 0u)) {
    return;
  }
  if ((int32_t)(now_ms - s_next_send_ms) < 0) {
    return;
  }

  class_id = USBD_CMPSIT_GetClassID(pdev, CLASS_TYPE_HID_KM, 0u);
  if (class_id == 0xFFu) {
    return;
  }

  frame = &s_queue[s_q_head];
  if ((frame->target == HID_KM_TARGET_KEYBOARD) && (s_keyboard_busy != 0u)) {
    return;
  }
  if ((frame->target == HID_KM_TARGET_MOUSE) && (s_mouse_busy != 0u)) {
    return;
  }

  if (frame->target == HID_KM_TARGET_MOUSE) {
    ep = get_mouse_ep(pdev, (uint8_t)class_id);
    s_mouse_busy = 1u;
    s_status.mouse_reports++;
  } else {
    ep = get_keyboard_ep(pdev, (uint8_t)class_id);
    s_keyboard_busy = 1u;
    s_status.key_reports++;
  }

  (void)USBD_LL_Transmit(pdev, ep, frame->data, frame->len);
  s_q_head = (uint8_t)((s_q_head + 1u) % HID_KM_QUEUE_LEN);
  s_q_count--;
  s_status.queue_depth = s_q_count;
  s_next_send_ms = now_ms + HID_KM_SEND_INTERVAL_MS;
}

void usbd_hid_km_get_status(usbd_hid_km_status_t *status)
{
  if (status != NULL) {
    *status = s_status;
    status->queue_depth = s_q_count;
    status->led_report = s_led_report;
  }
}

static uint8_t interface_target(USBD_HandleTypeDef *pdev, uint16_t if_num, uint8_t *target)
{
  if (if_num == pdev->tclasslist[pdev->classId].Ifs[0]) {
    *target = HID_KM_TARGET_KEYBOARD;
    return 1u;
  }
  if (if_num == pdev->tclasslist[pdev->classId].Ifs[1]) {
    *target = HID_KM_TARGET_MOUSE;
    return 1u;
  }
  return 0u;
}

static uint8_t *hid_desc_for_target(uint8_t target, uint16_t *len)
{
  uint16_t report_len = (uint16_t)sizeof(s_keyboard_report_desc);

  if (target == HID_KM_TARGET_MOUSE) {
    report_len = (uint16_t)sizeof(s_mouse_report_desc);
  }
  s_hid_desc[7] = (uint8_t)(report_len & 0xFFu);
  s_hid_desc[8] = (uint8_t)(report_len >> 8);
  *len = USB_HID_DESC_SIZ;
  return s_hid_desc;
}

static uint8_t *zero_report_for_target(uint8_t target, uint16_t *len)
{
  memset(s_ctrl_report, 0, sizeof(s_ctrl_report));
  *len = (target == HID_KM_TARGET_MOUSE) ? HID_KM_MOUSE_PACKET_SIZE : HID_KM_KEYBOARD_PACKET_SIZE;
  return s_ctrl_report;
}

static uint8_t USBD_HID_KM_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  uint8_t keyboard_ep;
  uint8_t mouse_ep;

  UNUSED(cfgidx);
  usbd_hid_km_init();
  keyboard_ep = get_keyboard_ep(pdev, (uint8_t)pdev->classId);
  mouse_ep = get_mouse_ep(pdev, (uint8_t)pdev->classId);

  if (pdev->dev_speed == USBD_SPEED_HIGH) {
    pdev->ep_in[keyboard_ep & 0xFU].bInterval = HID_HS_BINTERVAL;
    pdev->ep_in[mouse_ep & 0xFU].bInterval = HID_HS_BINTERVAL;
  } else {
    pdev->ep_in[keyboard_ep & 0xFU].bInterval = HID_FS_BINTERVAL;
    pdev->ep_in[mouse_ep & 0xFU].bInterval = HID_FS_BINTERVAL;
  }

  (void)USBD_LL_OpenEP(pdev, keyboard_ep, USBD_EP_TYPE_INTR, HID_KM_KEYBOARD_PACKET_SIZE);
  (void)USBD_LL_OpenEP(pdev, mouse_ep, USBD_EP_TYPE_INTR, HID_KM_MOUSE_PACKET_SIZE);
  pdev->ep_in[keyboard_ep & 0xFU].is_used = 1U;
  pdev->ep_in[mouse_ep & 0xFU].is_used = 1U;
  return (uint8_t)USBD_OK;
}

static uint8_t USBD_HID_KM_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  uint8_t keyboard_ep = get_keyboard_ep(pdev, (uint8_t)pdev->classId);
  uint8_t mouse_ep = get_mouse_ep(pdev, (uint8_t)pdev->classId);

  UNUSED(cfgidx);
  (void)USBD_LL_CloseEP(pdev, keyboard_ep);
  (void)USBD_LL_CloseEP(pdev, mouse_ep);
  pdev->ep_in[keyboard_ep & 0xFU].is_used = 0U;
  pdev->ep_in[mouse_ep & 0xFU].is_used = 0U;
  pdev->ep_in[keyboard_ep & 0xFU].bInterval = 0U;
  pdev->ep_in[mouse_ep & 0xFU].bInterval = 0U;
  return (uint8_t)USBD_OK;
}

static uint8_t USBD_HID_KM_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req)
{
  USBD_StatusTypeDef ret = USBD_OK;
  uint8_t target;
  uint8_t *pbuf = NULL;
  uint16_t len = 0u;
  uint16_t status_info = 0u;
  const uint8_t *report_desc = NULL;

  if (interface_target(pdev, req->wIndex, &target) == 0u) {
    USBD_CtlError(pdev, req);
    return (uint8_t)USBD_FAIL;
  }

  switch (req->bmRequest & USB_REQ_TYPE_MASK) {
    case USB_REQ_TYPE_CLASS:
      switch (req->bRequest) {
        case USBD_HID_REQ_SET_PROTOCOL:
          if (target == HID_KM_TARGET_MOUSE) {
            s_mouse_protocol = (uint8_t)req->wValue;
          } else {
            s_keyboard_protocol = (uint8_t)req->wValue;
          }
          break;
        case USBD_HID_REQ_GET_PROTOCOL:
          pbuf = (target == HID_KM_TARGET_MOUSE) ? &s_mouse_protocol : &s_keyboard_protocol;
          (void)USBD_CtlSendData(pdev, pbuf, 1u);
          break;
        case USBD_HID_REQ_SET_IDLE:
          if (target == HID_KM_TARGET_MOUSE) {
            s_mouse_idle = (uint8_t)(req->wValue >> 8);
          } else {
            s_keyboard_idle = (uint8_t)(req->wValue >> 8);
          }
          break;
        case USBD_HID_REQ_GET_IDLE:
          pbuf = (target == HID_KM_TARGET_MOUSE) ? &s_mouse_idle : &s_keyboard_idle;
          (void)USBD_CtlSendData(pdev, pbuf, 1u);
          break;
        case USBD_HID_REQ_GET_REPORT:
          pbuf = zero_report_for_target(target, &len);
          len = MIN(len, req->wLength);
          (void)USBD_CtlSendData(pdev, pbuf, len);
          break;
        case USBD_HID_REQ_SET_REPORT:
          s_ctrl_report_len = (uint8_t)MIN(req->wLength, (uint16_t)sizeof(s_ctrl_report));
          s_ctrl_report_target = target;
          if (s_ctrl_report_len != 0u) {
            (void)USBD_CtlPrepareRx(pdev, s_ctrl_report, s_ctrl_report_len);
          }
          break;
        default:
          USBD_CtlError(pdev, req);
          ret = USBD_FAIL;
          break;
      }
      break;

    case USB_REQ_TYPE_STANDARD:
      switch (req->bRequest) {
        case USB_REQ_GET_STATUS:
          if (pdev->dev_state == USBD_STATE_CONFIGURED) {
            (void)USBD_CtlSendData(pdev, (uint8_t *)&status_info, 2u);
          } else {
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
          }
          break;
        case USB_REQ_GET_DESCRIPTOR:
          if ((req->wValue >> 8) == HID_REPORT_DESC) {
            if (target == HID_KM_TARGET_MOUSE) {
              len = usbd_hid_km_get_mouse_report_desc(&report_desc);
            } else {
              len = usbd_hid_km_get_keyboard_report_desc(&report_desc);
            }
            len = MIN(len, req->wLength);
            (void)USBD_CtlSendData(pdev, (uint8_t *)report_desc, len);
          } else if ((req->wValue >> 8) == HID_DESCRIPTOR_TYPE) {
            pbuf = hid_desc_for_target(target, &len);
            len = MIN(len, req->wLength);
            (void)USBD_CtlSendData(pdev, pbuf, len);
          } else {
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
          }
          break;
        case USB_REQ_GET_INTERFACE:
          s_ctrl_report[0] = 0u;
          (void)USBD_CtlSendData(pdev, s_ctrl_report, 1u);
          break;
        case USB_REQ_SET_INTERFACE:
        case USB_REQ_CLEAR_FEATURE:
          break;
        default:
          USBD_CtlError(pdev, req);
          ret = USBD_FAIL;
          break;
      }
      break;

    default:
      USBD_CtlError(pdev, req);
      ret = USBD_FAIL;
      break;
  }
  return (uint8_t)ret;
}

static uint8_t USBD_HID_KM_EP0_RxReady(USBD_HandleTypeDef *pdev)
{
  UNUSED(pdev);
  if ((s_ctrl_report_target == HID_KM_TARGET_KEYBOARD) && (s_ctrl_report_len != 0u)) {
    s_led_report = s_ctrl_report[0];
    s_status.led_report = s_led_report;
  }
  s_ctrl_report_len = 0u;
  return (uint8_t)USBD_OK;
}

static uint8_t USBD_HID_KM_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
  uint8_t keyboard_ep = get_keyboard_ep(pdev, (uint8_t)pdev->classId);
  uint8_t mouse_ep = get_mouse_ep(pdev, (uint8_t)pdev->classId);

  if ((epnum & 0x7Fu) == (keyboard_ep & 0x7Fu)) {
    s_keyboard_busy = 0u;
  } else if ((epnum & 0x7Fu) == (mouse_ep & 0x7Fu)) {
    s_mouse_busy = 0u;
  }
  return (uint8_t)USBD_OK;
}

static uint8_t upper_char(char ch)
{
  if ((ch >= 'a') && (ch <= 'z')) {
    return (uint8_t)(ch - ('a' - 'A'));
  }
  return (uint8_t)ch;
}

static uint8_t token_equals(const char *a, const char *b)
{
  while ((a != NULL) && (b != NULL) && (*a != '\0') && (*b != '\0')) {
    if (upper_char(*a) != upper_char(*b)) {
      return 0u;
    }
    a++;
    b++;
  }
  return (uint8_t)((a != NULL) && (b != NULL) && (*a == '\0') && (*b == '\0'));
}

static uint8_t starts_with_token(const char *line, const char *token, const char **payload)
{
  uint32_t i = 0u;

  while ((line[i] != '\0') && (token[i] != '\0') && (upper_char(line[i]) == upper_char(token[i]))) {
    i++;
  }
  if (token[i] != '\0') {
    return 0u;
  }
  if ((line[i] != '\0') && (line[i] != ' ') && (line[i] != '\t') && (line[i] != ':')) {
    return 0u;
  }
  while ((line[i] == ' ') || (line[i] == '\t') || (line[i] == ':')) {
    i++;
  }
  if (payload != NULL) {
    *payload = &line[i];
  }
  return 1u;
}

static const char *skip_space(const char *p)
{
  while ((p != NULL) && ((*p == ' ') || (*p == '\t'))) {
    p++;
  }
  return p;
}

static uint8_t parse_mouse_button(const char *name, uint8_t *mask)
{
  if ((name == NULL) || (mask == NULL)) {
    return 0u;
  }
  if (token_equals(name, "LEFT") || token_equals(name, "L")) {
    *mask = 0x01u;
    return 1u;
  }
  if (token_equals(name, "RIGHT") || token_equals(name, "R")) {
    *mask = 0x02u;
    return 1u;
  }
  if (token_equals(name, "MIDDLE") || token_equals(name, "M")) {
    *mask = 0x04u;
    return 1u;
  }
  return 0u;
}

static uint8_t parse_named_key(const char *name, uint8_t *usage)
{
  uint32_t i;

  for (i = 0u; i < (sizeof(s_key_names) / sizeof(s_key_names[0])); ++i) {
    if (token_equals(name, s_key_names[i].name)) {
      *usage = s_key_names[i].usage;
      return 1u;
    }
  }
  return 0u;
}

static uint8_t parse_key_combo(const char *combo, uint8_t *modifier, uint8_t *usage)
{
  char token[18];
  uint8_t token_len = 0u;
  uint8_t found_key = 0u;

  *modifier = 0u;
  *usage = 0u;
  while (combo != NULL) {
    char ch = *combo;
    if ((ch == '+') || (ch == ' ') || (ch == '\t') || (ch == '\0')) {
      if (token_len != 0u) {
        token[token_len] = '\0';
        if (token_equals(token, "CTRL") || token_equals(token, "CONTROL")) {
          *modifier |= HID_KM_MOD_LCTRL;
        } else if (token_equals(token, "SHIFT")) {
          *modifier |= HID_KM_MOD_LSHIFT;
        } else if (token_equals(token, "ALT")) {
          *modifier |= HID_KM_MOD_LALT;
        } else if (token_equals(token, "GUI") || token_equals(token, "WIN") || token_equals(token, "META")) {
          *modifier |= HID_KM_MOD_LGUI;
        } else if (token_len == 1u) {
          uint8_t ascii_mod = 0u;
          uint8_t ascii_usage = 0u;

          if (ascii_to_hid(token[0], &ascii_mod, &ascii_usage) == 0u) {
            return 0u;
          }
          *modifier |= ascii_mod;
          *usage = ascii_usage;
          found_key = 1u;
        } else if (parse_named_key(token, usage) != 0u) {
          found_key = 1u;
        } else {
          return 0u;
        }
        token_len = 0u;
      }
      if (ch == '\0') {
        break;
      }
    } else if (token_len < (sizeof(token) - 1u)) {
      token[token_len++] = ch;
    } else {
      return 0u;
    }
    combo++;
  }

  return found_key;
}

static void hid_km_execute_line(const char *line)
{
  const char *payload;
  const char *tail;
  uint8_t mod;
  uint8_t usage;
  char *endptr;
  long mod_value;
  long usage_value;
  long dx;
  long dy;
  long wheel;
  long mask_value;
  uint8_t mask;

  line = skip_space(line);
  if ((line == NULL) || (*line == '\0')) {
    return;
  }
  s_status.cmd_count++;
  set_last_cmd(line);

  if ((starts_with_token(line, "t", &payload) != 0u) ||
      (starts_with_token(line, "type", &payload) != 0u)) {
    (void)queue_text(payload);
    return;
  }

  if ((starts_with_token(line, "key", &payload) != 0u) ||
      (starts_with_token(line, "k", &payload) != 0u)) {
    mod = 0u;
    usage = 0u;
    if (parse_key_combo(payload, &mod, &usage) != 0u) {
      (void)queue_key(mod, usage);
    }
    return;
  }

  if ((starts_with_token(line, "hid", &payload) != 0u) ||
      (starts_with_token(line, "usage", &payload) != 0u)) {
    mod_value = strtol(payload, &endptr, 0);
    payload = skip_space(endptr);
    usage_value = strtol(payload, NULL, 0);
    if ((usage_value > 0) && (usage_value <= 0xE7)) {
      (void)queue_key((uint8_t)(mod_value & 0xFF), (uint8_t)(usage_value & 0xFF));
    }
    return;
  }

  mod_value = strtol(line, &endptr, 0);
  if (endptr != line) {
    payload = skip_space(endptr);
    usage_value = strtol(payload, &endptr, 0);
    tail = skip_space(endptr);
    if ((endptr != payload) && (tail != NULL) && (*tail == '\0') &&
        (usage_value > 0) && (usage_value <= 0xE7)) {
      (void)queue_key((uint8_t)(mod_value & 0xFF), (uint8_t)(usage_value & 0xFF));
    }
    return;
  }

  if (starts_with_token(line, "m", &payload) != 0u) {
    dx = strtol(payload, &endptr, 0);
    payload = skip_space(endptr);
    dy = strtol(payload, &endptr, 0);
    payload = skip_space(endptr);
    wheel = 0;
    if ((payload != NULL) && (*payload != '\0')) {
      wheel = strtol(payload, NULL, 0);
    }
    (void)queue_mouse(clamp_i8(dx), clamp_i8(dy), clamp_i8(wheel), s_mouse_buttons);
    return;
  }

  if ((starts_with_token(line, "click", &payload) != 0u) ||
      (starts_with_token(line, "c", &payload) != 0u)) {
    if (parse_mouse_button(skip_space(payload), &mask) != 0u) {
      s_mouse_buttons = mask;
      (void)queue_mouse(0, 0, 0, s_mouse_buttons);
      queue_mouse_release();
    }
    return;
  }

  if ((starts_with_token(line, "btn", &payload) != 0u) ||
      (starts_with_token(line, "p", &payload) != 0u)) {
    mask_value = strtol(payload, NULL, 0);
    s_mouse_buttons = (uint8_t)(mask_value & 0x1Fu);
    (void)queue_mouse(0, 0, 0, s_mouse_buttons);
    return;
  }

  if ((token_equals(line, "r") != 0u) || (token_equals(line, "release") != 0u)) {
    queue_key_release();
    queue_mouse_release();
    return;
  }

  /* Keep the raw unknown line in last_cmd for serial diagnostics. */
}

static uint8_t ascii_to_hid(char ch, uint8_t *modifier, uint8_t *usage)
{
  *modifier = 0u;
  *usage = 0u;

  if ((ch >= 'a') && (ch <= 'z')) {
    *usage = (uint8_t)(0x04u + (uint8_t)(ch - 'a'));
    return 1u;
  }
  if ((ch >= 'A') && (ch <= 'Z')) {
    *modifier = HID_KM_MOD_LSHIFT;
    *usage = (uint8_t)(0x04u + (uint8_t)(ch - 'A'));
    return 1u;
  }
  if ((ch >= '1') && (ch <= '9')) {
    *usage = (uint8_t)(0x1Eu + (uint8_t)(ch - '1'));
    return 1u;
  }
  if (ch == '0') {
    *usage = 0x27u;
    return 1u;
  }

  switch (ch) {
    case '\b': *usage = 0x2Au; return 1u;
    case '\t': *usage = 0x2Bu; return 1u;
    case ' ': *usage = 0x2Cu; return 1u;
    case '-': *usage = 0x2Du; return 1u;
    case '_': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x2Du; return 1u;
    case '=': *usage = 0x2Eu; return 1u;
    case '+': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x2Eu; return 1u;
    case '[': *usage = 0x2Fu; return 1u;
    case '{': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x2Fu; return 1u;
    case ']': *usage = 0x30u; return 1u;
    case '}': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x30u; return 1u;
    case '\\': *usage = 0x31u; return 1u;
    case '|': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x31u; return 1u;
    case ';': *usage = 0x33u; return 1u;
    case ':': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x33u; return 1u;
    case '\'': *usage = 0x34u; return 1u;
    case '"': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x34u; return 1u;
    case '`': *usage = 0x35u; return 1u;
    case '~': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x35u; return 1u;
    case ',': *usage = 0x36u; return 1u;
    case '<': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x36u; return 1u;
    case '.': *usage = 0x37u; return 1u;
    case '>': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x37u; return 1u;
    case '/': *usage = 0x38u; return 1u;
    case '?': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x38u; return 1u;
    case '!': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x1Eu; return 1u;
    case '@': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x1Fu; return 1u;
    case '#': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x20u; return 1u;
    case '$': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x21u; return 1u;
    case '%': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x22u; return 1u;
    case '^': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x23u; return 1u;
    case '&': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x24u; return 1u;
    case '*': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x25u; return 1u;
    case '(': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x26u; return 1u;
    case ')': *modifier = HID_KM_MOD_LSHIFT; *usage = 0x27u; return 1u;
    default: return 0u;
  }
}
