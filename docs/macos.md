# macOS 使用手册

## 安装和启动

Apple 芯片和 Intel 共用一个安装包。双击 `PeerTTY-macOS.pkg` 并按 macOS 提示授权，完成后打开“终端”。0.4.0 安装包尚无 Apple 开发者签名和公证。[获取安装包](install.md#获取安装包)

```sh
peertty
```

每次配对时临时生成会话密钥，同一镜像复制的设备也能互连。

仅给当前用户安装时，将 [用户安装脚本](../packaging/install-macos-user.sh) 与同一版本的 `.pkg` 放在一起，在该目录运行 `sh install-macos-user.sh`。程序会安装到 `~/.local/bin/peertty`。如果终端提示找不到命令，可直接运行 `"$HOME/.local/bin/peertty"`。要在每个新终端输入短命令，使用默认 zsh 的用户可将 `export PATH="$HOME/.local/bin:$PATH"` 加入自己的 `~/.zprofile`，然后重新打开终端。

## 在 Mac 上控制另一台设备

1. 两端安装 0.5.0 或兼容新版，请对方选 `2` 并把邀请私发给你。按 **⌘V，再按回车**，也可以输入 `/paste` 从 Mac 剪贴板读取邀请。收到文件时选 `1` 并输入文件路径。
2. 输入单独收到的一次性配对码，核对被控设备名，回车采用邀请中的账号，把回执发回同一私聊。如果屏幕提示“回车使用本次授权登录”，对方核对设备并输入 `y` 后即可直接登录。要使用已有 SSH 凭据，可在账号栏输入 `/ssh`。
3. 在新窗口运行 `peertty link` 可同时打开多个终端，运行 `peertty cp` / `peertty sftp` 可传输文件。输入 `exit` 关闭当前窗口。脚本可执行 `peertty link -- hostname`。

## 让对方控制这台 Mac

1. 选 `2 允许被控制`。绿色勾表示回环端口已响应 SSH。22 关闭时，黄色空心圆表示临时 SSH 配置已通过检查。若要使用系统 SSH，前往“系统设置 → 通用 → 共享 → 远程登录”，打开开关并允许登录账号。停在检查页时选 `2` 复查，也可从主菜单选 `5`。若提示“本次授权账号的临时 SSH 配置检查通过”，控制方应采用邀请中的账号。
2. 选择 **1–24 小时** 或如 `30m`，直接回车为 1 小时。填写时终端会更新端口状态，回车后会复查一次。把邀请通过私聊发给对方，再通过电话或另一条已核实身份的渠道单独交付配对码。邀请会尝试自动复制，也可输入 `c` 复制或 `v` 显示。
3. 粘贴回执或输入 `p`，核对控制设备名和授权范围，再输入 `y`。使用临时密钥时可登录页面列出的账号。选择系统 SSH 时，可登录账号由本机 SSH 策略决定。对方可在有效期内打开多个 SSH 终端或传输文件。
4. 关闭菜单后授权继续计时。重新运行 `peertty` 可看到状态与终端数，`/host` 回到被控面板。面板中按 `q`，或在任意终端运行 `peertty revoke`，可撤销并断开全部窗口。

如果选择系统 SSH 登录，账号须具有本机“远程登录”权限。[Apple 远程登录说明](https://support.apple.com/guide/mac-help/allow-a-remote-computer-to-access-your-mac-mchlp1066/mac)

在已连接的终端输入 `sudo -l` 可查看权限，sudo 要求验证时在该窗口输入密码。[从单条命令调用 sudo](usage.md#用普通账号运行管理员命令)

## 两边都在路由器后面

两端各选 `4 网络自检`。如果显示“未取得 STUN 映射”，在主菜单 `3 连接设置` 更换可达的 STUN 后再选 `4`。实际连接路径在批准回执后显示。[双 NAT 常见提示](usage.md#两端都在私网时)

## 升级和卸载

先用 `peertty revoke` 结束活动授权并退出菜单，按首次使用的安装方式升级或卸载。升级后用 `peertty --version` 核对版本。双方升级到兼容版本后发起新授权。

| 命令位置 | 升级 | 卸载 |
| --- | --- | --- |
| `/usr/local/bin/peertty` | 双击新版 `.pkg` | 删除系统命令入口和程序，然后移除两份安装收据，见下方命令。 |
| `~/.local/bin/peertty` | 在新版安装包目录运行 `sh install-macos-user.sh` | 运行 `rm "$HOME/.local/bin/peertty"` |

<details>
<summary>卸载系统安装版</summary>

```sh
sudo rm /usr/local/bin/peertty /Library/PeerTTY/peertty
sudo rmdir /Library/PeerTTY
sudo pkgutil --forget io.peertty.cli
sudo pkgutil --forget io.peertty.core
```

如果曾在当前用户版的菜单里加装系统版，完整卸载时按表中两行分别移除。设备身份保存在用户目录。

</details>
