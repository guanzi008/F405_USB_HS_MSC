# UltraLink F405 USB HS MSC

基于 STM32F405RG 的 UltraLink 固件工程，当前集成了：

- `CMSIS-DAP HID`
- `FIDO HID`
- `USB HID Keyboard`
- `USB HID Mouse`
- `MSC`
- LCD 中文菜单与设备侧交互
- SPI Flash 凭证存储
- UART4 串口控制的键盘 / 鼠标输入

当前 USB 枚举为：

- `VID:PID = cafe:4009`
- `Product = UltraLink CMSIS-DAP FIDO MSC`

当前复合 USB 接口：

- `CMSIS-DAP HID`：调试通道
- `FIDO HID`：CTAP1/U2F 与 CTAP2
- `MSC`：保留的大容量存储接口
- `HID Keyboard`：串口驱动的键盘输入
- `HID Mouse`：串口驱动的鼠标输入

## 当前状态

已经打通：

- `webauthn.io` 注册与认证
- `CTAP1/U2F VERSION / REGISTER / AUTHENTICATE`
- `CTAP2 makeCredential / getAssertion`
- `CTAP2 getNextAssertion`
- `CTAPHID CANCEL`
- `CTAPHID LOCK`
- USB HID 键盘 / 鼠标枚举
- UART4 全局串口命令输入，不需要先进入 LCD 的输入设备页面

补充行为：

- 当 `alwaysUv = true` 时，设备会按规范禁用 `CTAP1/U2F REGISTER / AUTHENTICATE`
- 此时 `getInfo.versions` 不再返回 `U2F_V2`
- `authenticatorGetInfo`
  - 已按 canonical CBOR 输出嵌套 `options` map
  - 已补 `Windows/libfido2` 预检兼容字段与顺序问题
- `ClientPIN`
  - `getRetries`
  - `getKeyAgreement`
  - `setPIN`
  - `changePIN`
  - `getPINToken`
- `Bio Enrollment Preview`
  - 已补最小 `0x40` `getInfo` 兼容响应
  - 当前仅用于主机预检兼容，不提供真实生物录入能力
- `authenticatorConfig`
  - `toggleAlwaysUv`
  - `setMinPINLength`
  - `forcePINChange`
- `credProtect`
- `hmac-secret`
- `credBlob`
- `largeBlobKey`
- `authenticatorLargeBlobs`
- 更完整的 `credMgmt`
  - metadata
  - enumerate RPs
  - enumerate credentials
  - delete credential
  - update user information
- 板上 `删除密钥 / 清空密钥`
- `HID Keyboard / Mouse`
  - 键盘 8 字节 boot/report 协议报文
  - 鼠标 4 字节相对移动报文
  - UART4 中断接收环形缓冲
  - 命令队列与自动按键释放
  - 支持 `key`、`hid`、裸 HID usage、`type`、`m`、`click`、`btn`、`release`
  - 每条非空命令行返回 `AKM OK ...` 状态行，便于上位机确认

当前仍在继续补全：

- Windows Hello 账户登录场景的进一步兼容
- Windows 预触摸探测链的剩余兼容细节

## 目录

- `Core/`：主循环、LCD、编码器、板级输入输出
- `USB_DEVICE/App/`：FIDO、U2F、凭证存储、密码学
- `cmake/`：CMake 与 ARM GCC toolchain
- `tools/`：字模生成等辅助脚本

## 依赖安装

### 1. 基础构建依赖

Debian / Ubuntu / Deepin：

```bash
sudo apt update
sudo apt install -y cmake build-essential git pkg-config libusb-1.0-0-dev
```

### 2. ARM GCC 工具链

本工程使用 `arm-none-eabi-gcc`，要求可执行文件在 `PATH` 中。

如果你使用 xPack 版本，可以像下面这样加入环境变量：

```bash
export PATH="$HOME/.local/tools/xpack-arm-none-eabi-gcc-15.2.1-1.1/bin:$PATH"
```

验证：

```bash
arm-none-eabi-gcc --version
```

### 3. probe-rs 烧录工具

如果本机已经有 `probe-rs`，确保它在 `PATH` 中；例如：

```bash
export PATH="$HOME/.local/tools/probe-rs-tools-x86_64-unknown-linux-gnu/bin:$PATH"
probe-rs --version
```

如果没有，可以按 probe-rs 官方方式安装，或者使用预编译包。

### 4. 可选：FIDO 调试工具

Linux 下建议安装 `libfido2` 相关工具，便于验证 `PIN / getInfo / credMgmt`：

```bash
sudo apt install -y libfido2-1 libfido2-dev
```

如果发行版提供 `fido2-token`，可一并安装对应工具包。

## 编译

首次配置：

```bash
cd /home/hao/link/A/F405_USB_HS_MSC
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
```

编译：

```bash
cmake --build build -j4
```

产物：

- `build/F405_DEBUG.elf`

## 烧录

### 1. 查看探针

```bash
probe-rs list
```

### 2. 烧录命令

当前开发中使用的 ST-LINK 例子：

```bash
probe-rs download build/F405_DEBUG.elf \
  --chip STM32F405RGTx \
  --probe 0483:3748:2B4907 \
  --speed 950
```

### 3. 复位启动

```bash
probe-rs reset \
  --chip STM32F405RGTx \
  --probe 0483:3748:2B4907
```

如果你更换了探针序列号，把 `--probe` 换成你自己的设备即可。

## 常用验证命令

### USB 枚举

```bash
lsusb -d cafe:4009
```

### Linux 输入设备枚举

插入设备后应能看到键盘和鼠标事件节点：

```bash
ls -l /dev/input/by-id | grep -i ultralink
```

典型结果会包含：

- `...if02-event-kbd`
- `...if03-event-mouse`

### FIDO 信息

```bash
fido2-token -I /dev/hidrawX
```

### 设置 PIN

```bash
fido2-token -S /dev/hidrawX
```

### 设置最小 PIN 长度

```bash
fido2-token -S -l 6 /dev/hidrawX
```

### 开启 alwaysUv

```bash
fido2-token -S -u /dev/hidrawX
```

### hmac-secret 注册与认证

```bash
fido2-cred -M -h -i cred_param /dev/hidrawX es256
fido2-cred -V -h -i cred_out -o cred_pub es256
fido2-assert -G -h -p -i assert_param /dev/hidrawX
fido2-assert -V -h -i assert_out cred_pub es256
```

### largeBlobKey 注册与认证

```bash
fido2-cred -M -b -i cred_param /dev/hidrawX es256
fido2-assert -G -b -p -i assert_param /dev/hidrawX
```

### authenticatorLargeBlobs 原生命令面

```bash
fido2-token -I /dev/hidrawX
```

预期会看到：

- `extension strings: ... largeBlobKey`
- `transport strings: usb`
- `algorithms: es256 (public-key)`
- `maxcredcntlst: 64`
- `maxcredlen: 32`
- `maxlargeblob: 3824`

## UART HID 键盘鼠标

UART4 用于控制 USB HID 键盘 / 鼠标。当前命令解析在主循环全局启用，不依赖 LCD 当前页面；即使没有进入 `输入设备` 页面，也会接收串口命令。

### 串口参数

- `UART4`
- `115200`
- `8N1`
- TX：`PA0`
- RX：`PC11`
- 行结束：`\r`、`\n` 或 `\r\n`

建议上位机每条命令前发送一次 `0x18`，用于清掉可能残留的半行命令。固件收到 `0x03`、`0x18` 或 `0x1B` 会清空当前输入行。

### 回包

每解析一条非空命令行，设备会返回状态行：

```text
AKM OK RX=35 CMD=2 KEY=1 MOU=1 Q=2 DROP=0 LAST=hid 0 4
```

字段含义：

- `RX`：串口累计接收字节
- `CMD`：累计解析命令数
- `KEY`：累计发送键盘 report 数
- `MOU`：累计发送鼠标 report 数
- `Q`：待发送 HID report 队列深度
- `DROP`：队列满或命令过长导致的丢弃次数
- `LAST`：最后一条命令摘要

### 键盘命令

按键组合：

```text
key a
key SHIFT+a
key CTRL+ALT+DEL
key ENTER
key ESC
key F8
```

短别名：

```text
k a
k SHIFT+UP
```

输入一段 ASCII 文本：

```text
type hello-123
t hello
```

直接发送 HID usage：

```text
hid 0 4
usage 0 4
0 4
```

其中 `hid 0 4` 和裸格式 `0 4` 都表示修饰键 `0x00`、usage `0x04`，即 `a` 键。

常用修饰键位：

- `CTRL`
- `SHIFT`
- `ALT`
- `GUI` / `WIN` / `META`

常用功能键名：

- `ENTER` / `RET`
- `ESC` / `ESCAPE`
- `BACKSPACE` / `BSP`
- `TAB`
- `SPACE`
- `UP`、`DOWN`、`LEFT`、`RIGHT`
- `HOME`、`END`、`PGUP`、`PGDN`
- `INS`、`DEL`
- `F1` 到 `F12`

释放键盘和鼠标状态：

```text
release
r
```

### 鼠标命令

相对移动：

```text
m 20 0 0
m -10 5 0
m 0 0 1
```

格式为：

```text
m <dx> <dy> <wheel>
```

单次点击：

```text
click left
click right
click middle
c l
```

设置鼠标按钮位：

```text
btn 1
btn 0
p 1
p 0
```

按钮位定义：

- `1`：左键
- `2`：右键
- `4`：中键

### 上位机工具

Qt/DTK 串口键鼠工具当前在仓库外部：

```text
/home/hao/link/A/ui
```

它会选择串口后发送上述命令。该目录不是本 firmware 仓库的一部分，如果需要一起发布，需要单独纳入仓库或创建独立仓库。

## 板上交互

- 旋钮：菜单选择
- 短按：确认 / 删除 / 清空 / FIDO 确认
- 长按：返回

板上提供：

- `安全密钥`
- `删除密钥`
- `清空密钥`
- `SPI 闪存`
- `输入设备`
- `USB 调试`

`输入设备` 页面用于查看 UART HID 键鼠状态，不是串口接收的开关。串口命令在设备启动后全局可用。

## 已知边界

- Windows Hello 的 `PIN / reset` 管理链已经推进，`getInfo` 与 `bio preview getInfo` 的预检兼容也已补；但“直接作为 Windows 账户登录密钥”的兼容还没有完全收口。当前 Windows 仍可能提示“无法读取你的安全密钥，请重试”。
- `authenticatorLargeBlobs` 命令面已经实现，当前 `maxlargeblob = 3824`。
- 更完整的 `credMgmt`、更完整的 CTAP2.1 扩展仍在继续补。
- 当前文档以 Linux 开发和调试流程为主。
