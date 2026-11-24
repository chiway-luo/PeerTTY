# PeerTTY 双机网络测试

工程师和客户设备各占一台 Ubuntu 22.04 ARM64 虚拟机。每台配置 1 vCPU、1 GiB 内存和 8 GiB 稀疏磁盘，有独立的内核、文件系统和设备密钥。在项目根目录运行下列命令。

## 复现两端都没有公网 IP 的打洞

```sh
./lab/ctl punch-check --binary dist/peertty-linux-arm64
```

两台机器的业务接口各只有一个私网地址，分别是 `10.77.1.2`、`10.77.2.2`。各自网关只转发到对侧 WAN 和模拟 STUN 观测点，入站只放行已有连接的回包。Lima 管理通道只负责测试操作和传递签名凭证。SSH 登录数据必须走选中的 ICE 数据通道。

| 场景 | 验收条件 |
| --- | --- |
| 常规双 NAT，首个 STUN 无服务，延迟 40 秒批准 | 两端邀请和回执中都有正确的映射。控制方从主菜单直接粘贴邀请，等待批准后获得真实 SSH 终端。 |
| 双 NAT 同时改写源端口 | 两端签名凭证中的映射端口均与本地端口不同，且符合网关的固定转换；完成登录。 |
| 极端双 NAT，两端互换角色 | 正向接入已有服务，反向在 22 关闭时临时接入；撤销后回环连接归零。 |
| 两个网关均按目的地改写端口 | 两端都能取得 STUN 映射，但对端方向的映射落在其他端口范围。期望直连超时，SSH 保持关闭。 |
| 双侧封锁 UDP，两个 NAT 都拒绝新入站 TCP | 两端 STUN 映射均为 0，批准后报告未建立直连，SSH 保持关闭。 |

成功用例同时检查两端选中的 UDP 候选对、交互式 PTY、远端主机名和账号。完整运行需数分钟，两个失败场景各自等待直连超时和授权释放。套件在各机独立临时目录运行，结束后恢复进入测试时的网关模式和链路条件。整个测试使用实验网自己的 STUN。

## 复测 UDP 和 TCP 直连

在两台项目虚拟机已启动时，从仓库根目录运行以下命令。传入待测的 Linux ARM64 二进制。

```sh
./lab/ctl transport-check --binary dist/peertty-linux-arm64
```

加上 `--udp-only-binary /path/to/peertty-0.5.0-linux-arm64` 可验证 0.5.0 分别作为控制端和被控端。套件在可路由网络和双 NAT 下检查 UDP。随后双向封锁 UDP，轮流只允许一端接收入站 TCP，比较普通 SSH 与 PeerTTY，并核对实际 TCP 套接字、交互终端、撤销及到期。最后验证两端均无 TCP 入口时 SSH 保持关闭，恢复原实验网络。[实测记录](../docs/verification-2026-11-25.md)

## 单独检查链路和终端

```sh
./lab/ctl status
./lab/ctl probe
./lab/ctl ssh-check
./lab/ctl menu-check --binary dist/peertty-linux-arm64
```

`probe` 在两个方向各发送 24 个 UDP 包，分别显示收包、重复和乱序计数。`ssh-check` 用测试身份交换签名邀请和回执，通过 PeerTTY 登录客户设备。成功时返回主机名 `lima-device` 和普通用户名 `ptlab`。

`menu-check` 在两台机器上运行终端菜单，先选 `5` 检查被控条件，再选 `2` 生成邀请。脚本从被控终端单独交付本次配对码，双方交换签名邀请和回执。脚本核对凭证中的两台主机名，并在被控端输入 `y` 批准。登录后核对交互式 SSH 终端返回的 `PTY_OK`、主机名和账号。它还会关闭被控菜单、重新打开并核对状态，再用 `peertty link` 打开第二个原生 SSH 终端。正常退出场景会在所有窗口关闭后运行一次远端命令。撤销场景会在两个窗口仍打开时收回授权，并验证后续连接被拒绝和角色锁释放。需要在 22 关闭时接受控制的靶机用管理员所有的临时目录模拟系统安装，菜单仍以普通账号运行。测试程序和本次身份在结束时清理。省略 `--binary` 会使用两端已安装的 `peertty`。

验证 22 端口关闭时的行为，在项目根目录运行以下命令。

```sh
./lab/ctl menu-check --closed-ssh --binary dist/peertty-linux-arm64
./lab/ctl menu-check --closed-ssh --revoke --binary dist/peertty-linux-arm64
```

两条命令均由 `device` 控制 `engineer`，后者的业务网络初始没有 SSH 监听。第一条在 SSH 窗口全部退出后，用 `peertty link -- id -un` 核对远端账号再撤销。第二条在两个远端 shell 同时打开时由被控方撤销。测试分别检查批准前、登录时和结束后的 TCP 22 状态。独立挂载命名空间只给本轮被控进程提供测试 SSH 策略，默认登录账号使用本次控制端生成的临时密钥。被控端批准后才将回执中的公钥交给单连接 OpenSSH 实例。原有靶机 SSH 服务和 Lima 管理通道可继续使用。

给 `menu-check` 加 `--check-sudo` 可验证远端账号权限。默认被控账号 `ptlab` 没有测试命令的 sudo 权限，指定 `--closed-ssh` 后另一台机器的普通测试账号已有该权限。两种场景都分别用 `link --` 和 `link -t --` 查询有效用户 ID，并核对退出码。当 sudo 报告需要密码时，脚本还会在交互式 SSH 窗口等到密码提示，再取消并检查退出码。

### 检查撤销、到期和已完成的修改

```sh
./lab/ctl menu-check --binary dist/peertty-linux-arm64 --revoke --check-sudo
./lab/ctl menu-check --binary dist/peertty-linux-arm64 --closed-ssh --expire
```

两个 SSH 窗口各向被控机上的同一个测试文件写入一行。第一轮由被控方主动撤销，第二轮等待签名邀请的 180 秒测试期限自然结束。脚本检查两个窗口均已断开、两端均已释放授权、新的 `peertty link` 被拒绝，再通过虚拟机管理通道读回两行内容。最后由测试夹具清理该文件。

### 检查同名第三身份

在两台靶机运行时，从项目根目录执行以下命令。

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o lab/.lima/peertty-identity-linux-arm64 ./cmd/peertty
./lab/ctl menu-check --binary lab/.lima/peertty-identity-linux-arm64 --check-identity --revoke
./lab/ctl menu-check --binary lab/.lima/peertty-identity-linux-arm64 --check-identity --revoke --closed-ssh
```

测试把同一份旧设备密钥复制给两台虚拟机及第三个独立配置，验证前两者能打开两个 SSH 终端。第三个配置使用相同主机名和账号，输错配对码时无法生成回执。即使得到正确配对码，也无法替换已批准的回执或打开终端。脚本核对原来两个 shell 的 PID，反向测试还分别检查 SFTP 访问。结束授权后，新一轮会生成不同的会话密钥和配对码，并拒绝旧回执。

## 验证换网后沿用原授权

先启动两台靶机，在项目根目录构建并运行。

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o lab/.lima/peertty-roam-linux-arm64 ./cmd/peertty
./lab/ctl roam-check --binary lab/.lima/peertty-roam-linux-arm64
./lab/ctl roam-check --binary lab/.lima/peertty-roam-linux-arm64 --before-connect
```

`roam-check` 先打开两个 SSH 窗口。被控端移除 `eth0` 的旧地址，切换到 `roam0`、新子网和独立 NAT 出口。测试在两窗读回原 shell PID，再通过新的 SSH 登录检查设备地址。随后控制端断网 26 秒并换网，测试核对双方后台监听端口及邀请、回执文件的哈希，最后撤销授权并检查新登录被拒绝。

加上 `--before-connect` 后，测试在被控端批准前断开旧网，等到批准满一分钟才接入新网，随后验证首次 SSH 登录和原授权自然到期。测试网关允许外部地址联系本机已经使用过的 UDP 映射。两种测试退出时都会恢复原实验网络。

## 切换网络

```sh
./lab/ctl profile extreme
./lab/ctl probe
./lab/ctl exec engineer ping -c 10 10.77.2.2
```

| 场景 | 工程师 → 设备 | 设备 → 工程师 |
| --- | --- | --- |
| `clean` | 正常转发 | 正常转发 |
| `extreme` | 延迟 300 ± 80 ms，丢包 12%，限速 256 kbit/s，重复 1%，乱序 4% | 延迟 650 ± 150 ms，丢包 22%，限速 96 kbit/s，重复 2%，乱序 8% |
| `one-way` | 正常转发 | 丢包 100% |
| `udp-blocked` | 丢弃 UDP，允许 TCP 和 ICMP | 同左 |
| `offline` | 丢包 100% | 丢包 100% |

每种场景都可以叠加两侧独立的有状态 NAT。启用后，`probe` 向对侧的模拟公网观测点发包，显示转换后的来源地址。`ssh-check` 使用实验网内的 STUN 服务发现映射，实际尝试端到端登录。

```sh
./lab/ctl profile clean --nat
./lab/ctl probe
./lab/ctl ssh-check
./lab/ctl profile extreme --nat
```

用 `./lab/ctl profile clean --remap-ports` 模拟源端口被重写但对各目的地保持一致。用 `./lab/ctl profile clean --dependent-ports` 模拟 STUN 和对端使用不同外部端口的情形。恢复常用的弱网双 NAT 场景用 `./lab/ctl profile extreme --nat`。[nftables 地址与端口转换](https://netfilter.org/projects/nftables/manpage.html)

## 进入两台机器

分别在两个终端执行一条命令。这里启动的程序使用各自的测试网卡，Lima 的管理连接在业务断网时仍可使用。

```sh
./lab/ctl exec engineer
./lab/ctl exec device
```

| 角色 | 测试 IP | 网关的模拟公网 IP | 本端使用的远端 STUN 服务 |
| --- | --- | --- | --- |
| 工程师 `engineer` | `10.77.1.2` | `198.18.0.1` | `stun:198.19.2.2:3478` |
| 客户设备 `device` | `10.77.2.2` | `198.18.0.2` | `stun:198.19.1.2:3478` |

每台机器内部有一个业务网络和一个虚拟网关，两台网关通过 VXLAN 相连。模拟公网观测点有各自的 IP，负责 STUN 和 NAT 探测。`tc netem` 作用于各自网关的出口。测试网络使用 IPv4，MTU 为 1400，路由范围限于实验网段。[Lima 虚拟网络](https://lima-vm.io/docs/config/network/user-v2/) · [tc netem 手册](https://man7.org/linux/man-pages/man8/tc-netem.8.html)

设备端的测试 SSH 服务监听 `127.0.0.1:22`。`ptlab` 使用公钥认证。工程师端的登录私钥位于 `~/.ssh/peertty-lab`，固定的设备 SSH 主机公钥位于 `~/.ssh/peertty-lab-known-hosts`。`ssh-check` 首次运行时在两台机器各自生成 `~/.local/share/peertty-lab/identity.key`。

## 启停与重新构建

在 Apple Silicon Mac 上使用 Lima 2.x 和 Python 3。新工作区按顺序执行以下两条命令。构建使用 Go 1.25 或更高版本，本工作区已准备本地工具链。

```sh
./lab/ctl up
./lab/ctl build
```

`up` 会创建或启动两台机器，恢复上次保存的网络场景，首次默认为 `extreme --nat`。`build` 将当前源码构建为 Linux ARM64 程序，安装到两台机器，并启动本地 STUN 服务。

测试结束时使用 `./lab/ctl stop` 同时关闭两台虚拟机，保留磁盘和身份。运行状态保存在本工作区的 `lab/.lima/`。
