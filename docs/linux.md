# Linux 使用手册

## 通过 APT 安装

Debian 12、Ubuntu 22.04 及更新版本可添加 PeerTTY 软件源，支持 amd64 和 arm64。首次安装运行以下命令。

```sh
curl -fsSLo peertty.sources https://chiway-luo.github.io/PeerTTY/peertty.sources &&
sudo install -m 0644 peertty.sources /etc/apt/sources.list.d/peertty.sources &&
sudo apt update &&
sudo apt install peertty
```

软件源签名公钥指纹为 `CA3D 08AE 398A 9873 A155  6DA9 0CDE C356 2B01 5AED`。

## 安装和启动

安装完成后，在任意终端运行以下命令即可打开菜单。

```sh
peertty
```

输入 `1` 控制设备，`2` 允许被控制，`5` 单独检查本机被控条件，`0` 退出。每次配对时临时生成会话密钥，同一镜像复制的设备也能互连。

取得安装包后，用系统软件管理器打开对应文件。[获取安装包](install.md#获取安装包)

| 系统 | 安装包 |
| --- | --- |
| Debian / Ubuntu | `peertty_amd64.deb` · `peertty_arm64.deb` |
| Fedora / RHEL | `peertty.x86_64.rpm` · `peertty.aarch64.rpm` |

<details>
<summary>无桌面的服务器或其他发行版如何安装</summary>

在下载目录安装。Debian / Ubuntu 使用 `sudo apt install "./peertty_$(dpkg --print-architecture).deb"`，Fedora / RHEL 使用 `sudo dnf install "./peertty.$(uname -m).rpm"`。

其他 64 位发行版可取单文件程序。x86-64 运行 `sudo install -m 0755 peertty-linux-amd64 /usr/local/bin/peertty`，ARM64 将文件名改为 `peertty-linux-arm64`。[构建单文件程序](install.md#构建安装包)

</details>

## 用 Linux 控制另一台设备

1. 两端安装 0.5.0 或兼容新版，请对方选 `2` 并把邀请私发给你。粘贴邀请并回车，或输入 `/paste` 读取剪贴板。收到文件时选 `1` 并输入文件路径。
2. 输入单独收到的一次性配对码，核对被控设备名，回车采用邀请中的账号，把回执发回同一私聊。如果屏幕提示“回车使用本次授权登录”，对方核对设备并输入 `y` 后即可直接登录。要使用已有 SSH 凭据，可在账号栏输入 `/ssh`。
3. 在新窗口运行 `peertty link` 可同时打开多个终端，运行 `peertty cp` / `peertty sftp` 可传输文件。输入 `exit` 关闭当前窗口。脚本可执行 `peertty link -- hostname`。

## 允许对方控制这台 Linux 设备

1. 选 `2 允许被控制`，PeerTTY 自动检查本机 SSH。已有 SSH 服务时直接进入配对。22 关闭时，程序检查临时服务需要的配置、主机密钥和权限。
2. 如显示待处理项，选 `1` 执行屏幕列出的操作。例如使用系统提示验证管理员权限、生成缺失的主机密钥，或在 Debian / Ubuntu 上创建缺少的运行目录。完成后程序自动复查。SSH 服务使用其他端口时选 `3 修改本机 SSH 端口`。
3. 选择 **1–24 小时** 或如 `30m`，直接回车为 1 小时。把邀请通过私聊发给对方，再通过电话或另一条已核实身份的渠道单独交付配对码。邀请会尝试自动复制，也可输入 `c` 复制或 `v` 显示。
4. 粘贴回执或输入 `p`，核对控制设备名和授权范围，再输入 `y`。使用临时密钥时可登录页面列出的账号。选择系统 SSH 时，可登录账号由本机 SSH 策略决定。对方可在有效期内打开多个 SSH 终端或传输文件。
5. 关闭菜单后授权继续计时。重新运行 `peertty` 可看到状态与终端数，`/host` 回到被控面板。面板中按 `q`，或在任意终端运行 `peertty revoke`，可撤销并断开全部窗口。

桌面 Linux 使用 Wayland 或 X11 的系统剪贴板。无桌面时，终端可能需要允许 OSC 52 复制。也可以输入 `v` 显示凭证，或发送邀请文件。

同一设备同一时间只能占用一个角色。已有被控授权时，再选 `2` 可回到原邀请。要换控制方或切换角色，先执行 `peertty revoke`。

在连接中输入 `sudo -l` 可查看该账号获准的命令。执行命令时若 sudo 提示验证，在这个 SSH 窗口输入密码。[交互终端和 Agent 的用法](usage.md#用普通账号运行管理员命令)

## 双私网诊断

两端各选 `4 网络自检`。如果显示“未取得 STUN 映射”，可在主菜单 `3 连接设置` 中更换 STUN 服务，再选 `4` 复查。批准回执后可查看最终的直连路径。[双 NAT 常见提示](usage.md#两端都在私网时) · [双 Linux 靶机复现](../lab/README.md)

## 升级和卸载

先用 `peertty revoke` 结束活动授权并退出菜单。使用 APT 软件源时运行 `sudo apt update && sudo apt install --only-upgrade peertty`。使用本地安装包时，在新版安装包目录重新执行对应的安装命令，再用 `peertty --version` 核对版本。卸载时，Debian / Ubuntu 运行 `sudo apt remove peertty`，Fedora / RHEL 运行 `sudo dnf remove peertty`。双方升级到兼容版本后发起新授权。

单文件安装沿用相同的 `install` 命令覆盖程序，卸载时运行 `sudo rm /usr/local/bin/peertty`。
