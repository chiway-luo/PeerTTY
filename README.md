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
  <a href="docs/usage.md#两端都在私网时">连接排查</a>
</p>
<p align="center">
  <a href="docs/testing.md"><img src="assets/coverage.svg" alt="macOS 上测得的 Go 单元测试语句覆盖率"></a>
</p>

你在宿舍，待调试的设备在实验室。两端不在同一个局域网，各自在路由器后面，也没有公网 IP 或入站端口可供对方直接访问。普通 SSH 连不上时，**PeerTTY 在双方明确授权后尝试建立点对点通道，再用原生 OpenSSH 登录**。直连成功时，不必在公网开放 SSH 22 端口，也不需要公网跳板机转发终端流量。

<p align="center">
  <img src="assets/peertty-menu.png" width="720" alt="PeerTTY 终端主菜单：查看当前授权，选择控制设备或允许被控制">
</p>

## 为什么用 PeerTTY

- **解决的是双端私网的 SSH 可达性。** 双方通过已有私聊交换签名邀请与回执。PeerTTY 用 **STUN** 发现各端的公网地址映射，用 **ICE** 检查候选路径；网络允许时，通过 **双向 UDP 打洞** 建立直连，再在通道内传输原生 SSH。STUN 不转发 SSH 流量。
- **直连不等于开放远程访问权限。** 被控方在本机核对控制设备和登录账号后批准。一次授权支持多个 SSH 终端，到期或主动撤销会一起断开。

> **网络边界：** 双端 NAT 不一定能打通，拿到 STUN 映射也不代表直连成功。如果网络封锁 UDP 或 NAT 的映射方式不兼容，连接会失败。当前没有中继回退，也不会更改防火墙或路由器配置。[排查直连失败](docs/usage.md#两端都在私网时)

**实测：** 两台各自位于独立 NAT 后的 Ubuntu ARM64 虚拟机，在四种场景下直连成功，均验证了原生 SSH、交互终端和远端登录账号。不兼容的 NAT 映射与 UDP 封锁也已验证会导致连接失败。[查看双私网实测记录](docs/verification-2026-11-21.md#双私网实测)

## 首次连接

两台设备都需要安装 PeerTTY：[macOS](docs/macos.md#安装和启动) · [Windows](docs/windows.md#安装和启动) · [Linux](docs/linux.md#安装和启动)。也可以[从源码安装](docs/install.md#从源码安装)。安装后，两端都在终端运行 `peertty`。

1. **被控方发邀请。** 选 `2 允许被控制`，设置授权时长（默认 1 小时），把邀请私发给控制方。
2. **控制方回执。** 在主菜单粘贴邀请，确认要登录的账号，把生成的回执发回同一私聊。
3. **被控方批准。** 粘贴回执，核对设备和账号，输入 `y`。控制方随即按目标设备的 SSH 登录策略进入终端。

授权有效时，在控制端另开一个窗口运行 `peertty link` 即可再开终端，无需重新配对。输入 `exit` 只关当前窗口；要结束整份授权，在任一端运行 `peertty revoke`。

若配对已批准却连不上，先在两端运行 `peertty doctor`，再按[网络自检结果](docs/usage.md#两端都在私网时)排查。

## 深入使用

| 想做什么 | 从这里开始 |
| --- | --- |
| 更换安装方式或自行打包 | [安装与构建指南](docs/install.md) |
| 查看授权状态、重开终端或撤销权限 | [管理一次授权](docs/usage.md#重开终端查看状态和撤销) |
| 在脚本中使用 PeerTTY | [命令行示例](docs/usage.md#脚本用法) |
| 复测覆盖率或验证网络行为 | [单元测试与覆盖率](docs/testing.md) · [双机网络实验](lab/README.md) |
