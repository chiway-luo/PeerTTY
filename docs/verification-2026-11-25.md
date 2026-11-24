# PeerTTY 0.6.0 双协议与 0.6.1 授权验证 · 2026-11-25

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

## 0.6.1 授权时钟与旧邀请

| 场景 | 结果 |
| --- | --- |
| 运行中先向前校时，再将日期拨回一天 | 到达已缩短的剩余时限时，终端准入检查返回已到期。恢复原来的读数也无法重新激活授权。 |
| 授权 1 小时，模拟休眠 2 小时，同时回拨日期 | 空闲授权自动关闭。 |
| SSH 数据已排队，转发前授权结束 | 本机端点收到 0 字节。 |
| 已用邀请记录经过清理，再回拨到原到期时间之前 | 控制端拒绝旧邀请。 |
| 8 个任务并发领取同一份新邀请 | 只有一个成功。 |
| 完成授权并撤销，在同一配置下启动新的控制端进程 | 即使原邀请仍在签名有效期内，新进程使用原邀请和配对码也无法建立授权。 |

回拨和休眠通过测试专用时钟注入。macOS ARM64 通过全部 10 个包的竞态检查和静态检查，Ubuntu ARM64 通过授权包、独立后台进程和临时 SSH 辅助进程回收用例。Windows x64 完成交叉编译。[时钟用例](../internal/grant/lifetime_test.go) · [邀请复用用例](../internal/grant/replay_test.go) · [后台进程用例](../internal/active/worker_test.go)

两台虚拟机运行同一份 0.6.1 Linux ARM64 程序，SHA-256 为 `651d623f753589b0145279a2dfc34cf620d63d6f74a7818be24d467c25d09dff`。双 NAT 下两个 SSH 终端通过 `udp srflx/srflx` 登录。180 秒测试授权结束后，两个终端断开，新 `link` 被拒绝，断开前写入的两行内容均能读回。虚拟机内的独立采样显示，控制端的启动计时已到截止点，系统日期仍比签名截止时间早约 3.5 秒。

双向封锁 UDP 时，每端探测均收到 0/24 个包。仅被控端可以接收入站 TCP 时，普通 SSH 直拨、PeerTTY 菜单和 `ProxyCommand` 均能登录。两端预置相同旧设备密钥后仍能配对，第三个同名配置提交错误配对码或另一份回执均被拒绝，原来的两个 shell 继续工作。仅控制端可以接收入站 TCP 时，普通 SSH 直拨超时，PeerTTY 通过被控端主动建立的 TCP 连接打开了两个终端。

这条反向建立的 TCP 连接在 180 秒授权到期后断开了两个终端，新的 `link` 被拒绝。控制端独立采样到的经过时间已越过截止点 25 毫秒，此时系统日期距签名截止时间仍有约 3.8 秒。两端释放了授权锁和临时 TCP 监听，交换角色后能发起新邀请并撤销。

开放 UDP 时，可路由网络使用 `udp host/host`，双 NAT 使用 `udp srflx/srflx`。同时封锁 UDP 且两侧 NAT 都拒绝入站 TCP 时，直连失败，测试 SSH 端口保持关闭。测试结束后已恢复两台机器原有的 `extreme nat` 网络配置。

```sh
./lab/ctl menu-check --binary dist/versions/0.6.1/peertty-linux-arm64 --expire
./lab/ctl transport-check --binary dist/versions/0.6.1/peertty-linux-arm64
```

Linux 使用 `CLOCK_BOOTTIME`，macOS 使用映射到 `mach_continuous_time` 的 `CLOCK_MONOTONIC_RAW`，Windows 使用 `GetTickCount64`。这些计时来源独立于用户设置的日期。[Linux 内核](https://www.kernel.org/doc/html/latest/core-api/timekeeping.html) · [Apple 实现](https://github.com/apple-oss-distributions/Libc/blob/main/gen/clock_gettime.c) · [Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)

如果两端同时恢复一份包含磁盘和运行内存的旧虚拟机快照，授权进程和本地使用记录也可能随之恢复。识别这种整机回滚需要快照之外的可信状态。
