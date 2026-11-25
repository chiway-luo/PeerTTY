<p align="center">
  <img src="assets/peertty-icon.png" width="80" height="80" alt="">
</p>
<h1 align="center">PeerTTY</h1>
<p align="center"><strong>双端私网的 SSH 内网穿透 · 不在同一局域网，也能尝试点对点直连</strong></p>
<p align="center">
  <a href="#为什么用-peertty">项目价值</a> ·
  <a href="docs/install.md">安装</a> ·
  <a href="#首次连接">首次连接</a> ·
  <a href="docs/usage.md">使用手册</a> ·
  <a href="docs/usage.md#两端都在私网时">连接排查</a> ·
  <a href="CHANGELOG.md">版本记录</a>
</p>
<p align="center">
  <a href="docs/testing.md"><img src="assets/coverage.svg" alt="macOS 上测得的 Go 单元测试语句覆盖率"></a>
</p>

你在宿舍，待调试的设备在实验室。两端不在同一个局域网，各自在路由器后面，也没有公网 IP 或入站端口可供对方直接访问。普通 SSH 连不上时，**PeerTTY 在双方明确授权后尝试建立点对点通道，再用原生 OpenSSH 登录或传输文件**。直连成功时，不必在公网开放 SSH 22 端口，也不需要公网跳板机转发终端流量。

<p align="center">
  <img src="assets/peertty-menu.png" width="720" alt="PeerTTY 终端主菜单：查看当前授权，选择控制设备或允许被控制">
</p>

## 为什么用 PeerTTY

- **通过 UDP 或 TCP 直连。** PeerTTY 优先尝试 UDP，可用 STUN 发现出口映射，也可通过支持 UPnP 的网关临时映射 UDP 端口。UDP 暂未连通时，只要一端能访问另一端凭证中的 TCP 监听地址，就能尝试通过 TCP 承载原生 SSH、SFTP 和 SCP。
- **每次连接由被控方授权。** 两端按本次配对生成签名密钥。被控方通过独立渠道交付一次性配对码，再在本机批准一份回执。一次授权支持多个 SSH 终端和文件传输，到期或撤销时一起断开。

> 如果 UDP 打洞失败，两个网关又都拦截入站 TCP，双方需要先取得一条可达路径，例如接入同一个可路由的专网。PeerTTY 只使用直连。[排查直连失败](docs/usage.md#两端都在私网时)

两台 Ubuntu ARM64 虚拟机验证了双 NAT 下的 UDP 打洞，也验证了双向封锁 UDP、仅一端允许入站 TCP 时的 SSH 登录。[双协议验证](docs/verification-2026-11-25.md) · [早期双私网实测](docs/verification-2026-11-21.md#双私网实测)

## 首次连接

两端使用 0.6.3 可自动选择 UDP 或 TCP，并防止回拨系统时钟延长授权。一端仍为 0.5.0 时使用 UDP。安装后，两端都在终端运行 `peertty`。[下载安装包](docs/install.md#获取安装包) · [macOS](docs/macos.md#安装和启动) · [Windows](docs/windows.md#安装和启动) · [Linux](docs/linux.md#安装和启动) · [从源码安装](docs/install.md#从源码安装)

1. **被控方发邀请。** 选 `2 允许被控制`，设置授权时长（支持 `1–24` 小时或如 `30m`，默认 1 小时），把邀请私发给控制方，再通过电话或另一条已确认身份的渠道单独交付配对码。
2. **控制方回执。** 在主菜单粘贴邀请，输入配对码并确认登录账号，把生成的回执发回同一私聊。在回执页可直接回车或输入 `c` 再复制，也可在主菜单输入 `/receipt` 重开回执页。
3. **被控方批准。** 粘贴回执，核对请求的设备名和登录账号，输入 `y`。控制方随即按目标设备的 SSH 登录策略进入终端。

授权有效时，在控制端另开窗口运行 `peertty link` 可再开终端，`peertty cp` / `peertty sftp` 可直接传输文件，无需重新配对。输入 `exit` 只关当前窗口；要结束整份授权，在任一端运行 `peertty revoke`。

使用 UDP 时，任一端换网后，只要一方还能联系到另一方的已知 UDP 地址并收到回包，支持换网恢复的两端就会沿用原授权。[换网后继续使用终端](docs/usage.md#换网后继续使用终端)

若配对已批准却连不上，先在两端运行 `peertty doctor` 检查每个 STUN 连通性、NAT 映射类型与路由器 UPnP 支持，再按[网络自检结果](docs/usage.md#两端都在私网时)排查。

## 深入使用

| 想做什么 | 从这里开始 |
| --- | --- |
| 更换安装方式或自行打包 | [安装与构建指南](docs/install.md) |
| 查看授权状态、重开终端、传文件或撤销 | [管理一次授权](docs/usage.md#重开终端查看状态和撤销) |
| 在脚本中使用 PeerTTY | [命令行示例](docs/usage.md#脚本用法) |
| 复测覆盖率或验证网络行为 | [单元测试与覆盖率](docs/testing.md) · [双机网络实验](lab/README.md) |
