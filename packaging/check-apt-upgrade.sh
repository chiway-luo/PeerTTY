#!/usr/bin/env bash
# Exercise a public APT upgrade on a fresh Debian-family CI runner.
set -euo pipefail

previous=${1:?supply the previous upstream version}
current=$(cat VERSION)
arch=$(dpkg --print-architecture)
for version in "$previous" "$current"; do
    [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
done
dpkg --compare-versions "$previous" lt "$current"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
chmod 755 "$work"
name="peertty_${arch}.deb"
releases=https://github.com/chiway-luo/PeerTTY/releases/download
pages=https://chiway-luo.github.io/PeerTTY
fetch() {
    curl --fail --silent --show-error --location --retry 3 "$1" --output "$2"
}
check_release_digest() {
    local package=$1 manifest=$2 expected
    expected=$(awk -v name="$name" '$2 == name { print $1 }' "$manifest")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]]
    printf '%s  %s\n' "$expected" "$package" | sha256sum --check --strict
}

fetch "$releases/v$previous/$name" "$work/previous.deb"
fetch "$releases/v$previous/SHA256SUMS" "$work/previous.sha256"
check_release_digest "$work/previous.deb" "$work/previous.sha256"
sudo dpkg -i "$work/previous.deb"
test "$(peertty --version)" = "PeerTTY $previous"

fetch "$pages/peertty.sources" "$work/peertty.sources"
cmp docs/peertty.sources "$work/peertty.sources"
source_file=/etc/apt/sources.list.d/peertty.sources
sudo install -m 0644 "$work/peertty.sources" "$source_file"
options=(-o "Dir::Etc::sourcelist=$source_file" -o Dir::Etc::sourceparts=-)
sudo apt-get "${options[@]}" update --error-on=any
candidate=$(LC_ALL=C apt-cache "${options[@]}" policy peertty | awk '/Candidate:/ {print $2}')
dpkg --compare-versions "$candidate" gt "$(dpkg-query -W -f='${Version}' peertty)"
fetch "$releases/v$current/SHA256SUMS" "$work/current.sha256"
(cd "$work" && apt-get "${options[@]}" download "peertty=$candidate")
downloaded=("$work"/peertty_*_"$arch".deb)
test "${#downloaded[@]}" = 1
check_release_digest "${downloaded[0]}" "$work/current.sha256"

sudo apt-get "${options[@]}" install -y --only-upgrade peertty
test "$(dpkg-query -W -f='${Version}' peertty)" = "$candidate"
test "$(peertty --version)" = "PeerTTY $current"
printf '%s upgraded from %s to %s through the signed APT repository\n' "$arch" "$previous" "$candidate"
