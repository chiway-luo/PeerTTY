#!/bin/sh
# Sign staged RPMs with the signing subkey bound to the supplied public key.
set -eu
if [ "$#" -lt 2 ]; then
    echo "Usage: sh sign-rpms.sh PUBLIC_KEY RPM..." >&2
    exit 2
fi
public_key=$1
shift
primary=$(gpg --batch --with-colons --show-keys "$public_key" |
    awk -F: '$1=="pub" {next_fpr=1} $1=="fpr" && next_fpr {print $10; next_fpr=0}')
case "$primary" in ''|*[!0-9A-F]*) echo "Expected one OpenPGP public key." >&2; exit 1;; esac
signer=$(gpg --batch --with-colons --list-secret-keys "$primary" |
    awk -F: '$1=="ssb" {usable=($2 !~ /^[redi]$/ && $12 ~ /s/ && $15=="+")}
             $1=="fpr" && usable {print $10; usable=0}')
case "$signer" in ''|*[!0-9A-F]*) echo "Expected one available signing subkey for $primary." >&2; exit 1;; esac

db=$(mktemp -d)
trap 'rm -rf -- "$db"' EXIT
rpm --dbpath "$db" --initdb
rpmkeys --dbpath "$db" --import "$public_key"
for package in "$@"; do
    rpmsign --define "_gpg_name $signer!" --define "_openpgp_sign_id $signer!" \
        --define "_openpgp_sign gpg" --define "_gpg_digest_algo sha256" \
        --define "__gpg $(command -v gpg)" --addsign "$package"
done
rpmkeys --dbpath "$db" --define '_pkgverify_level all' --checksig "$@"
