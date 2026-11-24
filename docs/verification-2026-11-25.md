# PeerTTY 0.6.0 双协议验证 · 2026-11-25

在两台本地 Ubuntu 22.04 ARM64 虚拟机上，工程师从 `engineer` 控制 `device`，登录账号为 `ptlab`。配对材料经 Lima 管理通道传递，终端流量走两台虚拟机的独立业务网络。普通 SSH 对照使用相同的账号和已固定的主机公钥，在被控机业务接口上临时监听一个端口，测试后即回收。

## 双向封锁 UDP

| 唯一可接收入站 TCP 的一端 | 普通 SSH 从控制端直拨被控端 | PeerTTY 控制端所见 |
| --- | --- | --- |
| 被控端 | 成功，返回 `lima-device` 和 `ptlab` | 等待 40 秒后批准，通过 `tcp host/host` 登录 |
| 控制端 | TCP 连接超时 | 被控端主动拨出，通过 `tcp host/prflx` 登录 |

两轮均在业务网上向两个方向各发送 24 个 UDP 包，各收到 0 个。两端的 ICE 状态均显示 TCP，工程师虚拟机的 `ss` 显示已建立的套接字匹配允许入站一端的签名监听地址。登录后核对了远端主机名、系统账号和交互式终端。

第一轮两端预置同一份旧设备密钥。本机批准前，PeerTTY 没有接入 SSH。批准后打开两个终端，同名第三配置提交错误配对码或另一份回执均未获得连接，原终端继续工作。被控方撤销后，两个终端关闭，新 `link` 被拒绝，双方的临时 TCP 监听回收。

第二轮保持两个 TCP 终端打开，直到 180 秒授权自然到期。两个终端均断开，新登录被拒绝，监听端口回收。两轮均能从设备读回断开前写入的两行内容，原有回环 SSH 服务继续运行。

单次命令行模式另用 `peertty host` 和 OpenSSH 的 `ProxyCommand=peertty connect …` 复测。双方仍配置了实验用 STUN，双向 UDP 全部丢弃，只有被控端允许入站 TCP。两端分别报告 `tcp host/prflx` 和 `tcp host/host`，SSH 返回 `lima-device` 和 `ptlab`。测试结束后，两台虚拟机均恢复原有的 `extreme nat` 配置。

## UDP 优先与旧版互通

| 双端版本与网络 | 控制端和被控端报告 | 原生 SSH |
| --- | --- | --- |
| 0.6.0 ↔ 0.6.0，可路由网络 | `udp host/host` | 两个交互终端 |
| 0.6.0 ↔ 0.6.0，双方各自位于 NAT 后 | `udp srflx/srflx` | 两个交互终端 |
| 0.5.0 控制 0.6.0，可路由网络 | `udp host/host` | 两个交互终端 |
| 0.6.0 控制 0.5.0，可路由网络 | `udp host/host` | 两个交互终端 |

双向 UDP 封锁且两个 NAT 都拒绝新入站 TCP 时，批准后两端均未建立直连。被控机的测试 SSH 端口在整个用例中保持关闭。

## 复测构建

| Linux ARM64 程序 | SHA-256 |
| --- | --- |
| 0.6.0 双协议构建 | `893c8a21caa952c27c5cd7f7a1c1a95d886f8abf0ddc63170607b768a34ac5c7` |
| 0.5.0 UDP 互通对照 | `a3418eb5df101705865189d2932431080e489e3ce1bf0eb3d1438526fc2d374a` |

每轮在两个临时目录校验对应二进制摘要。Go 1.27.4 在 macOS ARM64 上通过全部 10 个包的 `go test -race -count=1 ./...` 和 `go vet ./...`。本机测试覆盖单次命令行连接及多终端授权的 TCP 数据通道。Windows x64 完成交叉编译，双机网络测试使用 Linux IPv4。[复测命令](../lab/README.md#复测-udp-和-tcp-直连)

本次测试的单文件程序按版本保存在本机 `dist/versions/`，每个版本目录附 `SHA256SUMS`。在项目根目录可使用同一对 Linux 构建复测。

```sh
./lab/ctl transport-check --binary dist/versions/0.6.0/peertty-linux-arm64 --udp-only-binary dist/versions/0.5.0/peertty-linux-arm64
```
