#!/bin/sh
# Install the CLI from the adjacent offline package for the current user.
set -eu
if [ "$#" -gt 1 ]; then
    echo "用法: sh install-macos-user.sh [PeerTTY-macOS.pkg]" >&2
    exit 2
fi
pkg=${1:-"$(dirname "$0")/PeerTTY-macOS.pkg"}
bin_dir=${PEERTTY_BIN_DIR:-"$HOME/.local/bin"}
dest="$bin_dir/peertty"
if [ -L "$dest" ] || [ -d "$dest" ]; then
    echo "安装路径已被目录或符号链接占用: $dest" >&2
    exit 1
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
/usr/sbin/pkgutil --expand-full "$pkg" "$work/package"
binary="$work/package/core.pkg/Payload/peertty"
if [ ! -f "$binary" ]; then
    binary="$work/package/Payload/peertty"
fi
/usr/bin/codesign --verify --all-architectures "$binary"
mkdir -p "$bin_dir"
/usr/bin/install -S -m 0755 "$binary" "$dest"
"$dest" --version
echo "已安装到 $dest"
if [ "$(command -v peertty || true)" = "$dest" ]; then
    echo "在终端输入 peertty 即可启动。"
else
    echo "现在可以运行 \"$dest\"。要在终端输入 peertty 启动，请将 $bin_dir 放在 PATH 首位。"
fi
