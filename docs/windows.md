# Windows 使用手册

## 安装和启动

在“设置 → 系统 → 系统信息”查看系统类型，双击对应的 MSI 安装包。安装位置为当前用户的 `%LOCALAPPDATA%\Programs\PeerTTY`。0.3.1 的 MSI 尚无发行者签名。[x64 安装包](../dist/installers/0.3.1/PeerTTY-Windows-x64.msi) · [ARM64 安装包](../dist/installers/0.3.1/PeerTTY-Windows-ARM64.msi)

在开始菜单搜索 **PeerTTY** 即可打开终端菜单。也可以关闭已有的 Windows Terminal 和 PowerShell 窗口，重新打开后输入以下命令。

```powershell
peertty
```

首次启动会在 `%APPDATA%\PeerTTY\device.key` 保存当前用户的设备私钥。设备身份会随邀请或回执发送。输入 `0` 退出。

## 用 Windows 控制另一台设备

1. 两端安装 0.3.1，请对方选 `2` 并把邀请私发给你。在 Windows Terminal 或 PowerShell 中粘贴邀请并回车，也可用 `/paste` 读取剪贴板。收到文件时选 `1` 并输入文件路径。
2. 回车采用邀请中的账号，把回执发回同一私聊。如果屏幕提示“回车使用本次授权登录”，对方核对设备并输入 `y` 后即可直接登录。要使用已有 SSH 凭据，可在账号栏输入 `/ssh`。
3. 在新窗口运行 `peertty link`，可以同时打开多个终端。输入 `exit` 关闭当前窗口。脚本可执行 `peertty link -- hostname`。

## 让对方控制这台 Windows 设备

1. 选 `2 允许被控制`。已有回环 SSH 服务时直接进入配对。若 22 关闭，按菜单提示检查临时服务。选“在管理员窗口打开 PeerTTY”后，完成 Windows 授权，再在新窗口选 `2`，原设备身份会随窗口保留。
2. 缺少 OpenSSH Server 时，选菜单中的安装项。Windows 安装组件时可能创建系统防火墙规则。首次使用且缺少系统配置时，菜单可打开 Windows 服务管理器，管理员可启动 **OpenSSH SSH Server** 完成初始化，系统服务会按本机配置监听。关闭管理器后从菜单复查。[Windows OpenSSH 配置](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)
3. 选择 **1–24 小时**，直接回车为 1 小时。把邀请通过私聊发给对方。邀请会尝试自动复制，也可输入 `c` 复制或 `v` 显示。
4. 粘贴回执或输入 `p`，核对请求控制的设备和账号，再输入 `y`。对方可在有效期内打开多个 SSH 终端。
5. 关闭菜单后授权继续计时。重新运行 `peertty` 可看到状态与终端数，`/host` 回到被控面板。面板中按 `q`，或在任意终端运行 `peertty revoke`，可撤销并断开全部窗口。

普通本地账号能否使用本次公钥登录，取决于本机 Windows OpenSSH 的有效配置。管理员窗口、域账号或集中管理公钥的策略使用已有 SSH 凭据。[Windows OpenSSH 账号配置](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)

Windows 被控端按 Windows 账号和 UAC 策略处理管理员操作。用 Windows 控制 Linux 或 macOS 时，可以从 PowerShell 运行 `peertty link -t -- sudo -l` 查看远端账号允许的命令。如果目标机提示验证，就在这个终端输入密码。[交互终端和 Agent 的用法](../README.md#用普通账号运行管理员命令)

## 两端都在私网时

两端各选 `4 网络自检`。如映射为 0，可在主菜单 `3 连接设置` 更换当前网络可达的 STUN 地址，再选 `4`。双方批准配对后可看到实际连接路径。[双 NAT 常见提示](../README.md#两端都在私网时)

## 升级和卸载

先用 `peertty revoke` 结束活动授权并退出菜单，双击同架构的新版 `.msi`，重新打开终端运行 `peertty --version`。卸载可在“设置 → 应用 → 已安装的应用”中找到 **PeerTTY** 并选择“卸载”。设备密钥保存在当前用户的 `%APPDATA%\PeerTTY`，重装后可沿用原指纹。
