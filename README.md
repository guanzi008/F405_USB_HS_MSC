# UltraLink F405 USB HS MSC

基于 STM32F405RG 的 UltraLink 固件工程，当前集成了：

- `CMSIS-DAP HID`
- `FIDO HID`
- `MSC`
- LCD 中文菜单与设备侧交互
- SPI Flash 凭证存储

当前 USB 枚举为：

- `VID:PID = cafe:4009`
- `Product = UltraLink CMSIS-DAP FIDO MSC`

## 当前状态

已经打通：

- `webauthn.io` 注册与认证
- `CTAP1/U2F VERSION / REGISTER / AUTHENTICATE`
- `CTAP2 makeCredential / getAssertion`
- `ClientPIN`
  - `getRetries`
  - `getKeyAgreement`
  - `setPIN`
  - `changePIN`
  - `getPINToken`
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

当前仍在继续补全：

- Windows Hello 账户登录场景的进一步兼容

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

## 已知边界

- Windows Hello 的 `PIN / reset` 管理链已经推进，但“直接作为 Windows 账户登录密钥”的兼容还没有完全收口。
- `authenticatorLargeBlobs` 命令面已经实现，当前 `maxlargeblob = 3824`。
- 更完整的 `credMgmt`、更完整的 CTAP2.1 扩展仍在继续补。
- 当前文档以 Linux 开发和调试流程为主。
