#!/bin/sh
# Run in a fresh Fedora container with only the release files mounted.
set -eu
dir=$1
version=$2
key=$3
for arch in x86_64 aarch64; do
    if rpmkeys --define '_pkgverify_level all' --checksig "$dir/peertty.$arch.rpm"; then
        echo "RPM unexpectedly trusted before importing the project key" >&2
        exit 1
    fi
done
rpmkeys --import "$key"
for arch in x86_64 aarch64; do
    package="$dir/peertty.$arch.rpm"
    rpmkeys --define '_pkgverify_level all' --checksig "$package"
    test "$(rpm -qp --queryformat '%{NAME} %{VERSION} %{ARCH}' "$package")" = "peertty $version $arch"
done
dnf -y --disable-repo='*' --setopt=localpkg_gpgcheck=1 install "$dir/peertty.$(uname -m).rpm"
test "$(peertty --version)" = "PeerTTY $version"
printf '0\n' | peertty menu -state-dir /tmp/peertty-check -stun none
dnf -y --disable-repo='*' remove peertty
! command -v peertty
