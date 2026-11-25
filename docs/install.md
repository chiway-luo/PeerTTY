# 安装 PeerTTY

控制设备和被控设备各安装一次。两端使用同一个 `peertty` 命令。

## 从源码安装

准备 Go 1.25 或更新版本，在 macOS、Linux 或 Windows PowerShell 中克隆项目并安装。

```sh
git clone https://github.com/chiway-luo/PeerTTY.git
cd PeerTTY
go install -ldflags "-X main.version=$(cat VERSION)" ./cmd/peertty
peertty --version
peertty
```

若系统找不到命令，将 `go env GOBIN` 指向的目录加入用户的 `PATH`。该值为空时，命令位于 `go env GOPATH` 输出目录下的 `bin` 子目录。项目根目录也可直接运行 `go run ./cmd/peertty`。启动后选 `1` 控制设备，选 `2` 允许被控制。[首次配对](usage.md#打开一次远程终端)

## 获取安装包

打开 Releases，下载对应平台和架构的安装包及同版 `SHA256SUMS`。macOS 可用 `shasum -a 256 文件名`、Linux 可用 `sha256sum 文件名`、Windows PowerShell 可用 `Get-FileHash -Algorithm SHA256 文件名`，将结果与清单中同名文件的摘要核对。[PeerTTY Releases](https://github.com/chiway-luo/PeerTTY/releases)

仓库 Actions 中的 **Check native installers** 提供安装与升级回归使用的构建产物。Fedora / RHEL 用户从正式 Release 下载带发行签名的 RPM 和 `peertty-rpm.asc`。[安装包构建记录](https://github.com/chiway-luo/PeerTTY/actions/workflows/installers.yml)

| 平台 | 安装包 | 操作说明 |
| --- | --- | --- |
| macOS | `PeerTTY-macOS.pkg`，Apple 芯片和 Intel 通用 | [系统安装或仅为当前用户安装](macos.md#安装和启动) |
| Windows | x64 或 ARM64 的 `.msi` | [安装与启动](windows.md#安装和启动) |
| Linux | Debian / Ubuntu 用 APT 软件源或 `.deb`，Fedora / RHEL 用 `.rpm` | [通过 APT 安装](linux.md#通过-apt-安装) · [本地安装包](linux.md#安装和启动) |

## 构建安装包

在配有 Apple 命令行工具、Go 和 Python 3 的 Mac 上，从项目根目录执行打包命令。

```sh
brew install nfpm msitools
python3 packaging/build.py
```

`VERSION` 决定安装包的版本。单文件程序写入 `dist/`，安装包与 `SHA256SUMS` 写入 `dist/installers/<版本>/`。可加 `--target macos`、`--target windows` 或 `--target linux` 只打一个平台。在安装包目录运行 `shasum -a 256 -c SHA256SUMS` 校验文件。[打包脚本](../packaging/build.py)

## 为 Release 草稿签署 RPM

1. 在版本标签上运行 **Check native installers**。用该次运行的 `installers` 附件建立同一标签的 Release 草稿，记下运行 ID。
2. 在 `main` 上运行 **Sign draft RPMs**，填写标签和安装包运行 ID。仓库负责人在 `rpm-release` 环境审核该任务。[RPM 签名工作流](../.github/workflows/sign-rpms.yml)
3. 工作流从标签对应的构建中取回两份 RPM，签名后核对包内容，更新草稿中的 RPM、发行公钥和 `SHA256SUMS`。Fedora 任务验证两种架构的签名，并运行安装后的程序。签名完成后由维护者决定何时公开草稿。

发行认证主钥保存在维护者的本机钥匙串。轮换签名子钥时，更新仓库内的发行公钥和受保护环境中的 `RPM_SIGNING_SUBKEY`。该密钥项使用 GnuPG 的 `--export-secret-subkeys` 导出，只包含签名子钥的私有部分。安装包升级测试使用独立的临时测试密钥。[发行公钥](../packaging/keys/peertty-rpm.asc)
