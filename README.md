# EgisTec EH577 (ET300) Linux 指纹驱动

> ⚠️ **重要提示：仅供日常使用，请谨慎使用**
>
> 本项目仅面向**日常便利场景**（桌面锁屏解锁、登录等），**不适合高安全性场景**。
> 受限于传感器面积极小（约 5×4 mm）和主机侧匹配算法，识别准确性**无法保证**，
> 存在**误接受（其他手指/区域被接受）**和**误拒绝（本人被拒绝）**的可能。
> 请自行评估风险；如需高安全性，请使用密码、硬件密钥或其他认证方式。
> 作者不对因误识别造成的任何损失承担责任。

适用于 USB ID `1c7a:0577` 的 Egis Technology EH577 指纹传感器（常见于部分笔记本电源键/小面积按压式传感器）。

这是一个 **libfprint 驱动**，配合 `fprintd` 使用，支持：

- 指纹录入（enroll）
- 指纹验证 / 识别（verify / identify）
- KDE Plasma 锁屏指纹解锁（通过 PAM）
- SDDM 登录界面指纹认证（通过 PAM，需手动触发）
- 自定义主机的匹配算法（见下文）

> 已在 Arch/EndeavourOS + KDE Plasma 6.8.2 (Wayland) + fprintd 1.94.5 上测试。

---

## 为什么需要专用驱动

1. **图像解码**：一次采集是 3990 字节，实际是 **70×57** 的灰度图（不是常见的 114×7 分条）。姿势不对会把图像彻底打碎。
2. **传感器很小**（约 5×4 mm），NBIS/Bozorth3 每次只能提取 3–9 个细节点，低于 Bozorth3 的硬性下限 10，因此内置的 NBIS 匹配不可用。
3. 因此驱动实现了自己的**分块（patch）匹配器**：
   - 16×16 归一化块，步长 4
   - 小角度旋转搜索（±20°，步长 5°）
   - 同时要求 **匹配块数量** 和 **空间平移一致性投票（consensus）**，以兼容“部分重叠”，并拒绝不同手指/区域。

---

## 仓库内容

```
drivers/et577.c                驱动源码
drivers/et577_calib_data.h     3990 字节设备校准数据（设备校准，不是生物特征）
patches/0001-register-et577-driver.patch   把驱动注册进 libfprint/meson
patches/0002-meson-foreach-dict.patch     新版 Meson 的 dict foreach 兼容修复
docs/PROTOCOL.md               USB 协议笔记
```

本仓库**不包含**任何指纹图像、USB 抓包、日志或个人信息。

---

## 编译安装

以 Arch 为例（其他发行版路径可能不同）。请选择与系统 `fprintd` 匹配的 libfprint 源码版本。

```bash
# 1. 获取 libfprint 源码
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
cd libfprint

# 2. 放入驱动
cp /path/to/repo/drivers/et577.c          libfprint/drivers/
cp /path/to/repo/drivers/et577_calib_data.h libfprint/drivers/

# 3. 应用注册补丁
git apply /path/to/repo/patches/0001-register-et577-driver.patch

# 如果 Meson 报错 "Foreach expects exactly 2 variables ... dict"：
git apply /path/to/repo/patches/0002-meson-foreach-dict.patch

# 4. 编译
meson setup builddir
ninja -C builddir

# 5. 安装（二选一）
sudo ninja -C builddir install
# 或者仅替换库（Arch 的 fprintd 使用 /usr/lib/libfprint-2.so.2.0.0）：
sudo cp builddir/libfprint/libfprint-2.so.2.0.0 /usr/lib/

sudo systemctl restart fprintd
```

### 录入指纹

```bash
fprintd-enroll -f right-index-finger "$USER"
fprintd-verify -f right-index-finger "$USER"
```

也可以在 KDE 系统设置的“指纹”页面录入。

---

## PAM 配置（锁屏 / 登录）

**不要**把 `pam_fprintd.so` 加到 `/etc/pam.d/system-auth`，否则可能影响 `sudo`。

### KDE 锁屏

1. Plasma 6.8 升级后锁屏指纹默认被禁用，需要开启：

```bash
kwriteconfig6 --file kscreenlockerrc --group Authenticators --key Fingerprint true
```

2. 让指纹在锁屏期间持续等待（发行版通常把 `kde-fingerprint` 放在 `/usr/lib/pam.d/`，用 `/etc/pam.d/` 覆盖即可）：

```pam
# /etc/pam.d/kde-fingerprint
auth       required   pam_shells.so
auth       requisite  pam_nologin.so
auth       requisite  pam_faillock.so preauth
-auth      required   pam_fprintd.so timeout=-1
auth       optional   pam_permit.so
auth       required   pam_env.so

account    include    system-local-login
password   required   pam_deny.so
session    include    system-local-login
```

> Plasma 的锁屏默认只显示壁纸/时钟，需要按任意键或移动鼠标后才显示解锁界面并启动指纹。这是上游设计，没有“锁屏后立即开始扫描”的官方开关。

### SDDM 登录

```pam
# /etc/pam.d/sddm（在 auth 段最前面）
auth        sufficient  pam_fprintd.so timeout=10
auth        include     system-login
```

SDDM 没有原生指纹 UI：在登录界面**保持密码为空按回车**即可触发指纹扫描；超时后回退到密码。KDE 设置里显示“暂不支持使用指纹登录系统”是 KCM 对 SDDM 的限制提示，不影响 PAM 层的指纹认证。

---

## 匹配参数与安全

驱动顶部的常量：

```c
#define ET577_MATCH_THRESHOLD 20.0   /* 空间一致性投票最小值 */
#define ET577_RAW_MIN         40.0   /* 原始匹配块最小值 */
#define ET577_PATCH           16
#define ET577_PATCH_STRIDE     4
#define ET577_PATCH_GOOD       0.75
#define ET577_ANGLE_RANGE     20.0
#define ET577_ANGLE_STEP       5.0
```

实测（同一设备）：

- 同一手指：consensus 39–104，raw 53–159 → 通过
- 不同手指：consensus/raw 0–2 → 拒绝

阈值调高更安全但更容易误拒；调低更易用但可能误接受。

---

## 已知限制 / 注意

- 传感器面积极小，录入和验证时手指位置/角度差异会造成部分重叠；建议录入 5–6 次以覆盖更大区域。
- 设备固件较脆弱：**不要**长时间连续采集。驱动使用官方的轮询命令检测手指，仅在检测到手指后做短脉冲采集，并带有 25 秒看门狗。
- 不要对设备执行 USB reset / authorized 循环，可能导致固件挂死（需要完全断电恢复）。
- 若设备完全无响应（`libusb_open` 返回 EIO / 传输超时），断电重启可恢复。

---

## 隐私说明

- 仓库不包含指纹图像、USB 抓包、日志或用户配置。
- `et577_calib_data.h` 是从厂商驱动的 USB 通信中提取的**设备校准数据**，不是生物特征数据。
- 请勿把自己的指纹采集文件、`.pcapng`、调试图像提交到公开仓库。

---

## 许可证

LGPL-2.1-or-later（与 libfprint 一致）。见 `LICENSE`。
