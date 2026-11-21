#!/bin/sh
# Exercise a native install, upgrade, and removal inside a disposable package root.
set -eu
if [ "$#" -ne 2 ] || [ "$(id -u)" -ne 0 ]; then
    echo "Usage: sudo sh packaging/check-linux.sh OLD_PACKAGE NEW_PACKAGE" >&2
    exit 2
fi
first=$1
second=$2
case "$first,$second" in
    *.deb,*.deb) format=deb ;;
    *.rpm,*.rpm) format=rpm ;;
    *) echo "Choose two DEB files or two RPM files for this machine." >&2; exit 2 ;;
esac

umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
root=$work/root
export XDG_CONFIG_HOME="$work/config"
mkdir -p "$root"
rpm_in_root() {
    rpm --root "$root" --dbpath /var/lib/rpm "$@"
}
if [ "$format" = deb ]; then
    mkdir -p "$root/var/lib/dpkg"
    touch "$root/var/lib/dpkg/status"
else
    mkdir -p "$root/var/lib/rpm"
    rpmdb --root "$root" --dbpath /var/lib/rpm --initdb
fi
PATH="$root/usr/bin:$PATH"
export PATH

install_and_start() {
    if [ "$format" = deb ]; then
        version=$(dpkg-deb -f "$1" Version)
        version=${version%-*}
        dpkg --root="$root" --install "$1"
    else
        version=$(rpm_in_root -qp --queryformat '%{VERSION}' "$1")
        rpm_in_root --upgrade "$1"
    fi
    [ "$(command -v peertty)" = "$root/usr/bin/peertty" ]
    [ "$(peertty --version)" = "PeerTTY $version" ]
    printf '0\n' | peertty > "$work/menu"
    grep -Fq '允许被控制' "$work/menu"
}

install_and_start "$first"
old_version=$version
sha256sum "$XDG_CONFIG_HOME/PeerTTY/device.key" > "$work/identity.sha256"
install_and_start "$second"
[ "$version" != "$old_version" ]
sha256sum --status -c "$work/identity.sha256"
if [ "$format" = deb ]; then
    dpkg --root="$root" --remove peertty
else
    rpm_in_root --erase peertty
fi
[ ! -e "$root/usr/bin/peertty" ]
sha256sum --status -c "$work/identity.sha256"
echo "$format $old_version -> $version: install, menu, upgrade, identity and uninstall passed"
