#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path("/home/hao/link/A/F405_USB_HS_MSC")
OUT_C = ROOT / "Core/Src/lcd_zh.c"
FONT_FAMILY = "Noto Sans CJK SC"


ENTRIES = [
    ("LCD_ZH_MENU", "菜单", 12, 208),
    ("LCD_ZH_DEBUG", "调试", 12, 208),
    ("LCD_ZH_KEY", "安全", 12, 208),
    ("LCD_ZH_FLASH", "闪存", 12, 208),
    ("LCD_ZH_INPUT", "输入", 12, 208),
    ("LCD_ZH_WIPE", "清空", 12, 208),
    ("LCD_ZH_DELETE", "删除", 12, 208),
    ("LCD_ZH_MENU_USB_DEBUG", "USB调试", 12, 208),
    ("LCD_ZH_MENU_SECURITY_KEY", "安全密钥", 12, 208),
    ("LCD_ZH_MENU_SPI_FLASH", "SPI闪存", 12, 208),
    ("LCD_ZH_MENU_INPUT_DEV", "输入设备", 12, 208),
    ("LCD_ZH_MENU_WIPE_KEY", "清空密钥", 12, 208),
    ("LCD_ZH_MENU_DELETE_KEY", "删除密钥", 12, 208),
    ("LCD_ZH_SHORT_ENTER", "短按进入", 12, 208),
    ("LCD_ZH_LONG_BACK", "长按返回", 12, 208),
    ("LCD_ZH_WAIT_CONFIRM", "等待确认", 12, 208),
    ("LCD_ZH_BUTTON_CONFIRM", "按钮确认", 12, 208),
    ("LCD_ZH_PRESENT", "已连接", 12, 208),
    ("LCD_ZH_NOT_FOUND", "未找到", 12, 208),
    ("LCD_ZH_CHECK_SPI1", "检查SPI1", 12, 208),
    ("LCD_ZH_FIDO_CONFIRM", "FIDO确认", 12, 208),
    ("LCD_ZH_MAKE_CRED", "创建凭证", 12, 208),
    ("LCD_ZH_GET_ASSERT", "身份验证", 12, 208),
    ("LCD_ZH_GET_INFO", "读取信息", 12, 208),
    ("LCD_ZH_SHORT_OK", "短按确认", 12, 208),
    ("LCD_ZH_LONG_CANCEL", "长按取消", 12, 208),
    ("LCD_ZH_KNOB_SELECT", "旋钮选择", 12, 208),
    ("LCD_ZH_ACCOUNT", "账号", 12, 208),
    ("LCD_ZH_CLEAR_STORE", "清空密钥库", 12, 208),
    ("LCD_ZH_ERASING", "正在清空", 12, 208),
    ("LCD_ZH_PLEASE_WAIT", "请稍候", 12, 208),
    ("LCD_ZH_SHORT_ERASE", "短按清空", 12, 208),
    ("LCD_ZH_SHORT_DELETE", "短按删除", 12, 208),
    ("LCD_ZH_DONE", "完成", 12, 208),
    ("LCD_ZH_ERASE_FAIL", "清空失败", 12, 208),
    ("LCD_ZH_DELETE_FAIL", "删除失败", 12, 208),
    ("LCD_ZH_REREGISTER", "重新注册", 12, 208),
    ("LCD_ZH_NO_KEY", "没有密钥", 12, 208),
    ("LCD_ZH_MENU_USB_DEBUG_S", "USB调试", 8, 190),
    ("LCD_ZH_MENU_SECURITY_KEY_S", "安全密钥", 8, 190),
    ("LCD_ZH_MENU_SPI_FLASH_S", "SPI闪存", 8, 190),
    ("LCD_ZH_MENU_INPUT_DEV_S", "输入设备", 8, 190),
    ("LCD_ZH_MENU_WIPE_KEY_S", "清空密钥", 8, 190),
    ("LCD_ZH_MENU_DELETE_KEY_S", "删除密钥", 8, 190),
]


def parse_ppm(data: bytes) -> tuple[int, int, bytes]:
    header, rest = data.split(b"\n", 1)
    if header.strip() != b"P6":
        raise RuntimeError(f"unexpected header: {header!r}")

    tokens = []
    i = 0
    while len(tokens) < 3:
        while i < len(rest) and rest[i] in b" \t\r\n":
            i += 1
        if rest[i : i + 1] == b"#":
            while i < len(rest) and rest[i] != 10:
                i += 1
            continue
        j = i
        while j < len(rest) and rest[j] not in b" \t\r\n":
            j += 1
        tokens.append(int(rest[i:j]))
        i = j

    while i < len(rest) and rest[i] in b" \t\r\n":
        i += 1

    width, height, _maxv = tokens
    return width, height, rest[i:]


def render_bitmap(text: str, size: int, threshold: int) -> tuple[int, int, list[int]]:
    with tempfile.TemporaryDirectory() as td:
        png = Path(td) / "src.png"
        subprocess.run(
            [
                "pango-view",
                "--no-display",
                "--pixels",
                f"--font={FONT_FAMILY} {size}",
                "--hinting=full",
                "--antialias=gray",
                "--margin=2",
                "--background=white",
                "--foreground=black",
                f"--output={png}",
                "-t",
                text,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ppm = subprocess.check_output(["pngtopnm", str(png)])

    width, height, pixels = parse_ppm(ppm)
    rows = []
    for y in range(height):
        row = []
        for x in range(width):
            off = (y * width + x) * 3
            r, g, b = pixels[off : off + 3]
            lum = (r + g + b) // 3
            row.append(1 if lum < threshold else 0)
        rows.append(row)

    xs = [x for y, row in enumerate(rows) for x, v in enumerate(row) if v]
    ys = [y for y, row in enumerate(rows) for x, v in enumerate(row) if v]
    if not xs:
        return 0, 0, []

    x0, x1 = min(xs), max(xs)
    y0, y1 = min(ys), max(ys)
    cropped = [row[x0 : x1 + 1] for row in rows[y0 : y1 + 1]]
    out_w = len(cropped[0])
    out_h = len(cropped)
    row_bytes = (out_w + 7) // 8
    packed: list[int] = []
    for row in cropped:
        for chunk in range(row_bytes):
            byte = 0
            for bit in range(8):
                idx = chunk * 8 + bit
                byte <<= 1
                if idx < out_w and row[idx]:
                    byte |= 1
            packed.append(byte)

    return out_w, out_h, packed


def emit_array(name: str, data: list[int]) -> str:
    chunks = []
    for i in range(0, len(data), 12):
        group = ", ".join(f"0x{b:02X}" for b in data[i : i + 12])
        chunks.append(f"    {group}")
    body = ",\n".join(chunks) if chunks else "    0x00"
    return f"static const uint8_t {name}_data[] = {{\n{body}\n}};\n"


def main() -> None:
    lines = [
        '#include "lcd_zh.h"\n',
        "\n",
        "/* Generated by tools/gen_lcd_zh.py */\n",
        "\n",
    ]
    table_names = []
    for name, text, size, threshold in ENTRIES:
        width, height, packed = render_bitmap(text, size, threshold)
        lines.append(emit_array(name, packed))
        lines.append(
            f"static const lcd_zh_bitmap_t {name}_bmp = {{ {width}, {height}, {name}_data }};\n\n"
        )
        table_names.append(f"    &{name}_bmp,\n")

    lines.append(f"static const lcd_zh_bitmap_t *const k_lcd_zh_table[LCD_ZH_COUNT] = {{\n")
    lines.extend(table_names)
    lines.append("};\n\n")
    lines.append("const lcd_zh_bitmap_t *lcd_zh_get(lcd_zh_id_t id)\n{\n")
    lines.append("    if ((unsigned)id >= LCD_ZH_COUNT) {\n")
    lines.append("        return 0;\n")
    lines.append("    }\n")
    lines.append("    return k_lcd_zh_table[id];\n")
    lines.append("}\n")

    OUT_C.write_text("".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
