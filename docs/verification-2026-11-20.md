# 首版验证记录

2026-11-20，使用 Go 1.27.4 构建。

| 平台 | 本轮验证 |
| --- | --- |
| macOS arm64 | 本机运行 CLI、原生 SSH 和竞态检测，作为工程师端连接 Linux VPS |
| Linux amd64 | VPS 运行被控端，接入已有 SSH 服务，分配真实 PTY 并正常退出 |
| Linux arm64 | 交叉编译为静态 ELF |
| Windows amd64 | 交叉编译为 PE32+ 控制台程序，原生双端实测待完成 |

## Mac 与 VPS 的终端会话

双方生成本轮设备密钥，用管理 SSH 交换签名文件。被测 SSH 客户端使用 PeerTTY 的 `connect` 作为 ProxyCommand，关闭 SSH 连接复用，沿用已有的 SSH 主机密钥校验。VPS 上的 PeerTTY 以普通用户权限运行。两端均选中 `udp host/host`，这组网络无需 STUN。

远端命令先用 `test -t 0` 确认分配了 PTY，再输出约定标记和内核名称。本机收到 `PEERTTY_VPS_PTY_OK` 和 `Linux`。本机 SSH 与远端 PeerTTY 被控进程退出码均为 0。

本轮临时目录和测试文件已删除。随后独立查询得到 `test_paths=0`、`test_processes=0`。VPS 的 `xray.service` 为 `active`，进入活动状态的时间早于本次测试，systemd 报告 `NRestarts=0`。

## 本地回归

- `go test -race ./...`、`go vet ./...` 和 `go mod verify` 通过。
- 会话测试覆盖签名篡改、身份错配、跨会话回执、授权前禁止接入本机 SSH、已连接会话到期、控制端断开和 TCP 半关闭后的双向完整性。受控 STUN 测试核对了外部映射地址进入邀请文件。
- 原生 OpenSSH 在正常退出时会向 ProxyCommand 发出挂断信号。为最后的 SSH 数据和关闭确认保留了最多 3 秒，授权截止仍然生效。对应回归连续运行 8 次通过。[回归用例](../cmd/peertty/proxy_test.go)
- `govulncheck` 针对本机目标的生产入口报告 0 个可达的已知漏洞。扫描器另列出依赖模块中未被该入口调用的公告。

首版的公网实测来自上述 Mac 与 VPS 网络组合。Windows 原生运行、校园网及不同 NAT 环境的直连成功率仍待验证。

## 纯终端菜单验证

2026-11-20，在 macOS arm64 构建终端菜单版，重新生成 macOS arm64、Linux amd64、Linux arm64 和 Windows amd64 产物。Windows 产物为 PE32+ 控制台程序，原生登录与退出待在 Windows 上验证。

- **Mac 终端。** 两个菜单同时首次启动，读取到相同的设备指纹。分别以 `lsof` 查询两个空闲进程，网络套接字均为 0。在 macOS 伪终端中粘贴一份 3911 字节的分行签名邀请，控制端完成校验并进入 SSH 用户名提示。
- **双机 SSH。** 在 `extreme --nat` 下运行 `./lab/ctl menu-check --binary dist/peertty-linux-arm64`。两台 Ubuntu ARM64 机器粘贴邀请、通过文件批准回执，通过 `udp srflx/srflx` 直连。远端返回 `PTY_OK`、`lima-device`、`ptlab`。输入 `exit` 后双方返回菜单。控制方随后切换为被控方，生成新邀请并用 `q` 撤销。[双机测试脚本](../lab/menu_check.py)
- **授权互斥与回收。** 在两台机器上分别用第二个进程、同一密钥申请相反角色，两次均被拒绝。菜单退出后两端的会话临时目录已清除。Go 测试另覆盖等待批准时到期、过期后继续读取菜单输入和控制菜单消失后回收代理。[终端回归](../internal/console/console_test.go) · [身份锁回归](../internal/grant/grant_test.go)
- **弱网观测。** 另一次使用同一最终构建的尝试中，控制端在测试等待的 65 秒内未报告已连接。当次记录不足以定位握手阶段。上述成功记录来自相同网络参数下重新发起的新授权。
- **工程检查。** `go test -race -count=1 ./...`、`go vet ./...` 和 `go mod verify` 均通过。本轮菜单测试使用本机与本地虚拟机，未在 VPS 部署或运行。

## 22 端口自动启动的双机实测

2026-11-20，在引用对话指定的两台独立 Ubuntu 22.04 ARM64 靶机上，使用同一个 Linux ARM64 发布文件完成三次终端测试。业务网络维持 `extreme nat`，双向注入的丢包率分别为 12% 和 22%。三次都选中了 `udp srflx/srflx` 并返回真实终端标记 `PTY_OK`。[复现命令](../lab/README.md) · [测试脚本](../lab/menu_check.py)

| 原始状态 | 实际登录 | 会话结束时的观测 |
| --- | --- | --- |
| `device` 已有回环 SSH 监听 | `engineer → device`，主机 `lima-device`，用户 `ptlab` | 输入 `exit` 后原服务继续监听，前后 PID 均为 `1984` |
| `engineer` 的 22 关闭 | `device → engineer`，主机 `lima-engineer`，用户 `chiway` | 批准前监听数为 0，连接时看到本机 22 的已建立连接，输入 `exit` 后监听和已建立连接均为 0 |
| `engineer` 的 22 再次关闭 | `device → engineer`，同一普通系统账号 | 已经进入远端 shell 时被控方输入 `q`，控制方返回菜单，22 的监听和已建立连接均为 0 |

关闭端口的场景使用普通用户启动 PeerTTY 菜单，由靶机既有的本机 sudo 权限运行专用启动进程。测试用 SSH 策略只在被控进程的挂载命名空间内生效。三次均验证了同一密钥申请相反角色时被拒绝。测试结束后独立复查，两台靶机的本轮临时目录计数均为 0，`device` 原服务为 `active`。

该 ELF 的 SHA-256 为 `dddfe177915e2c5d451a800add9bc761d7117b116f26f3f192396890d6d0ed11`。macOS 上通过竞态测试、静态检查和模块完整性校验，Windows x64 目标也通过交叉编译与静态检查。macOS 和 Windows 系统服务关闭时的原生联调仍待验证。本轮未连接 VPS。

## 双私网打洞验收

两台 Ubuntu 22.04 ARM64 靶机各有独立内核。控制端业务接口只有 `10.77.1.2`，被控端只有 `10.77.2.2`，反向测试时交换角色。两个网关各自维护 NAT 与入站状态，实验 WAN 使用 `198.18.0.0/30`。STUN 在各自网关外的观测点运行。Lima 管理通道传递签名邀请与回执，登录数据走 ICE 选中的 UDP 通道。

```sh
./lab/ctl punch-check --binary dist/peertty-linux-arm64
```

### 已建立的 SSH 会话

| 网关与操作 | 观察结果 |
| --- | --- |
| 两个独立 NAT，第一项 STUN 无服务，收到回执后再等 40 秒批准 | 第二项 STUN 提供映射。直接在主菜单粘贴邀请，双方均选中 `udp srflx/srflx`，登录得到 `PTY_OK`、`lima-device`、`ptlab`。 |
| 两端同时改写 UDP 源端口 | 两端签名凭证中的映射端口均等于本地端口按位异或 256，符合独立网关规则。通过映射地址登录同一目标，原有 SSH 服务 PID 保持 1984。 |
| 极端弱网，控制方登录已有 SSH 服务 | 工程师方向模拟 300 ± 80 ms 延迟、12% 丢包、256 kbit/s，反向 650 ± 150 ms、22%、96 kbit/s。两端通过 `udp srflx/srflx` 登录，核对了 PTY、主机名和普通账号。 |
| 同一弱网，机器互换角色，目标 22 关闭 | 批准前 22 关闭。反向登录 `lima-engineer` 后，被控方撤销，临时回环 SSH 连接和监听均回到 0。 |

延迟批准曾在相同的常规双 NAT、备用 STUN 和 40 秒等待条件下失败。两个签名凭证都有映射，批准后 60 秒仍然超时。仅向 STUN 服务器保活不足以保留网关面向对端的放行状态。修正后，在等待人工交换时，原 UDP 套接字每 15 秒向 STUN 与签名描述中的对端映射发送 Binding Indication，连接建立、撤销或到期即结束该阶段。重复相同测试后连接成功。[传输实现](../internal/transport/mapping.go) · [可复现的双机测试](../lab/menu_check.py)

本次沿用 Pion 的多服务器收集与 ICE 连通性检查，在本项目的人工交换阶段补充保活。诊断参考 Tailscale netcheck，把本机地址发现与两台机器真正选中的路径分别呈现。自检的地址计数按 UDP 数据组件统计，去除回环和同一套接字的 RTCP 副本。[Pion ICE 收集](https://github.com/pion/ice/blob/main/gather.go) · [Pion WebRTC 设置](https://github.com/pion/webrtc/blob/main/settingengine.go) · [Tailscale netcheck](https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go)

### STUN 有映射但对端不可达

两侧网关为发往 STUN 和发往对端的 UDP 使用互不重叠的端口范围，并仅接受已有状态的回包。两份签名凭证均包含观测点实际返回的映射，经过本机批准后，PeerTTY 在 60 秒建链窗口结束时报出两端的映射计数。控制方未进入 SSH，目标的 22 端口保持关闭。该场景与“网络完全禁止 UDP”可从两端的映射计数区分。

### 双向封锁 UDP

两台网关丢弃 UDP 后，邀请和回执均只包含接口候选，STUN 映射计数均为 0。批准后建链按时超时，SSH 未启动，授权释放。六个场景均完成，验收命令退出码为 0。结束后独立复查，两台靶机均已恢复 `extreme nat`，本轮临时目录、PeerTTY 进程和已建立的 22 连接均为 0。`engineer` 的 22 关闭，`device` 原有服务继续监听 `127.0.0.1:22`。

### 构建与平台范围

macOS arm64 上运行了原生菜单、自检、设备指纹核验及本机 OpenSSH 客户端回归。`go test -race -count=1 ./...`、本机与 Windows x64 目标的 `go vet ./...` 以及 `go mod verify` 通过。macOS、Linux、Windows 均生成 amd64 和 arm64 产物。上述双 NAT 登录在两台 Linux ARM64 机器上运行。本轮 Linux ARM64 验收产物的 SHA-256 为 `5782ebd499d7bb715714f1619ba6ccfc32baa5ed02862096ddb900775449b74c`。

本轮未连接 VPS。两家实际运营商之间的双 NAT 会话和 Windows 原生 SSH 会话尚待实测。本机在沙箱内向默认公网 STUN 自检时未取得映射。自动审批因会向第三方服务发送出口 IP 和端口，拒绝了沙箱外的公网复测。表中的映射与登录来自隔离实验网自己的 STUN。

## 安装包与终端启动

交付版本为 0.1.0。升级测试使用单独构建的 0.1.1，仅存放在测试目录。七个安装包和 macOS 用户安装脚本均通过 SHA-256 清单校验。[发布清单](../dist/installers/0.1.0/SHA256SUMS)

| 对象 | 本轮结果 |
| --- | --- |
| macOS ARM64 | 本机以普通用户安装到 `~/.local/bin/peertty`。登录 shell 解析到该路径并输出 `PeerTTY 0.1.0`。另在临时目录用用户安装脚本执行安装、打开菜单、升级和卸载，设备指纹一致。 |
| macOS 通用 PKG | 核对标识、版本和 `/usr/local/bin` 安装位置。包内程序含 Intel、ARM64，两个架构的代码签名完整性检查通过。已安装的用户版与包内程序逐字节一致。本机系统级安装需要管理员认证，此轮验证的是用户安装路径。 |
| Linux ARM64 DEB | 在独立 Ubuntu 靶机的临时包数据库内，用 dpkg 安装 0.1.0，无参数进入菜单，升级到 0.1.1 后卸载。程序已移除，设备私钥哈希一致，测试目录已清理。 |
| Linux ARM64 RPM | 在同一台 Ubuntu 靶机上，用发行版的 rpm 和 rpmdb 在隔离的安装根目录及数据库中执行了相同流程。版本、菜单、升级与卸载后的设备身份检查均通过，临时工具及测试目录已清理。 |
| Linux 两种架构 | 解包核对 amd64、arm64 的全部 DEB 和 RPM。包内 `/usr/bin/peertty` 与对应的发布程序逐字节一致。 |
| Windows x64 / ARM64 MSI | 分别解包并核对 PE 文件、目标架构、产品版本、升级标识、每用户 PATH 和开始菜单快捷方式。两个 MSI 均待在原生 Windows 运行完整安装、升级与卸载。 |

`go vet ./...` 和 `go test -race -count=1 ./...` 均通过。[安装、升级与卸载测试](../.github/workflows/installers.yml) · [Linux 复现脚本](../packaging/check-linux.sh) · [Windows 复现脚本](../packaging/check-windows.ps1)

## 菜单检查与准备 SSH

0.1.1 在选择控制或被控角色时检查本机 SSH。主菜单 `5` 可以独立检查被控条件。[菜单实现](../internal/console/ssh.go) · [回环检查](../internal/localssh/check.go)

| 场景 | 观察结果 |
| --- | --- |
| 已有 SSH 服务 | 两台独立 Linux ARM64 靶机先选 `5`，再通过 `2` 签发邀请。经双 NAT 直连登录成功，原 SSH 服务 PID 保持 1984。 |
| 22 关闭 | 互换两端角色后，选 `5` 检查通过，选 `2` 签发邀请。批准前未监听 22，批准并直连后完成 SSH 登录。撤销后临时连接和监听均已回收。 |
| 新机缺少主机密钥和运行目录 | 在 Linux 靶机隔离的挂载与网络命名空间内测试。选 `0` 返回时两项仍缺失。两次选择屏幕上的修复操作后，生成了主机密钥并建立了权限为 0755 的运行目录，复查通过。整个准备过程无监听、无邀请。 |
| 当前 Mac 的用户版 | 本机普通进程绑定回环 22 返回权限不足。`peertty` 已更新为 0.1.1，菜单 `2` 和 `5` 均给出系统安装选项，选 `0` 正常返回。系统安装器已识别命令入口和程序两个组件。系统级安装、密码授权和 macOS 临时 SSH 登录仍待本机管理员实际操作。 |
| Windows | x64、ARM64 已构建。组件安装、UAC 重开菜单与临时 SSH 登录尚待原生 Windows 验证。 |

Linux 集成可用 `./lab/ctl menu-check --binary dist/peertty-linux-arm64` 及同一命令追加 `--closed-ssh --revoke` 复现。三端 0.1.1 安装包已通过清单校验。[发布清单](../dist/installers/0.1.1/SHA256SUMS)

## 0.2.0 两段配对与 Mac 粘贴

| 场景 | 实际结果 |
| --- | --- |
| macOS 旧版复现 | 在本机伪终端向 0.1.1 主菜单发送带终端粘贴标记的完整邀请，菜单连续报告无效选择。先选 `1` 后粘贴时，邀请被当作错误的设备指纹。 |
| macOS 0.2.0 | 当前用户安装版在主菜单和控制菜单接受普通与带边界标记的粘贴。六组输入覆盖 CR、LF、CRLF、没有末尾换行及 14 KB 以上的选区。均完成签名校验、显示设备名，并可回车采用邀请中的账号。原生 SSH 代理生成回执后，被控菜单接受回执，等待本机批准，并可在批准前重选和撤销。 |
| 两台 Linux ARM64 靶机 | 在两个独立私网双向完成真实交互式 SSH 登录。每端只发送一份凭证，脚本检查两份签名凭证中的主机名。目标原有 SSH 服务的 PID 保持 1984。反向测试中，粘贴回执后 22 仍关闭，输入 `y` 后建立回环连接，撤销后回收。 |
| Linux 同一身份打开两个菜单 | 在 0.2.0 的第一个窗口生成邀请后，第二个窗口连续两次选 `2` 并输入 `60`，均提示已有授权。两次尝试后磁盘上只有第一个窗口的邀请。在第一个窗口输入 `q` 后原文件被回收，第二个窗口随即签发了新邀请。 |
| 校验与安装包 | 修改签名字段、更换签发人、跨邀请或跨版本回放、过期回执均被拒绝。旧版定向邀请继续检查接收设备。三端安装包均通过清单校验。Windows 两种 MSI 已解包，程序与对应架构的发布程序一致，原生 Windows 交互尚待验证。 |

[终端回归用例](../internal/console/console_test.go) · [签名与回执绑定测试](../internal/grant/grant_test.go) · [双靶机复现](../lab/README.md#单独检查链路和终端) · [0.2.0 安装包清单](../dist/installers/0.2.0/SHA256SUMS)
