# <img src="assets/peertty-icon.png" alt="" width="48" height="48" align="middle"> PeerTTY

[![Go 单元测试覆盖率（macOS）](assets/coverage.svg)](docs/testing.md)

PeerTTY 让两台设备通过限时授权建立加密的 SSH 直连。双方通过已有的聊天渠道交换邀请和回执，被控方确认后，控制方就能打开一个或多个终端。支持 macOS、Windows 和 Linux。

- [安装 PeerTTY](docs/install.md) · [首次配对](docs/usage.md#打开一次远程终端) · [重连、查看状态和撤销授权](docs/usage.md#重开终端查看状态和撤销)
- [使用手册](docs/usage.md) · [脚本用法](docs/usage.md#脚本用法) · [私网连接排查](docs/usage.md#两端都在私网时)
- [运行测试与查看覆盖率](docs/testing.md) · [复现双机网络实验](lab/README.md)
