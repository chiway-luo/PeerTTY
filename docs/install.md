# 安装 PeerTTY

控制设备和被控设备各安装一次。两端使用同一个 `peertty` 命令。

## 从源码安装

准备 Go 1.25 或更新版本，并使用有仓库访问权的账号。在 macOS、Linux 或 Windows PowerShell 中克隆项目并安装。

```sh
git clone https://github.com/chiway-luo/PeerTTY.git
cd PeerTTY
go install ./cmd/peertty
peertty
```

若系统找不到命令，将 `go env GOBIN` 指向的目录加入用户的 `PATH`。该值为空时，命令位于 `go env GOPATH` 输出目录下的 `bin` 子目录。项目根目录也可直接运行 `go run ./cmd/peertty`。启动后选 `1` 控制设备，选 `2` 允许被控制。[首次配对](usage.md#打开一次远程终端)

## 获取安装包

在仓库 Actions 中打开 **Check native installers**。成功完成构建的运行会在 **Artifacts** 中提供 `installers` 下载。解压后按平台手册安装或升级。[安装包构建记录](https://github.com/chiway-luo/PeerTTY/actions/workflows/installers.yml)

| 平台 | 安装包 | 操作说明 |
| --- | --- | --- |
| macOS | `PeerTTY-macOS.pkg`，Apple 芯片和 Intel 通用 | [系统安装或仅为当前用户安装](macos.md#安装和启动) |
| Windows | x64 或 ARM64 的 `.msi` | [安装与启动](windows.md#安装和启动) |
| Linux | Debian / Ubuntu 用 `.deb`，Fedora / RHEL 用 `.rpm` | [桌面、服务器与单文件安装](linux.md#安装和启动) |

## 构建安装包

在配有 Apple 命令行工具、Go 和 Python 3 的 Mac 上，从项目根目录执行打包命令。

```sh
brew install nfpm msitools
python3 packaging/build.py
```

`VERSION` 决定安装包的版本。单文件程序写入 `dist/`，安装包与 `SHA256SUMS` 写入 `dist/installers/<版本>/`。可加 `--target macos`、`--target windows` 或 `--target linux` 只打一个平台。在安装包目录运行 `shasum -a 256 -c SHA256SUMS` 校验文件。[打包脚本](../packaging/build.py)
