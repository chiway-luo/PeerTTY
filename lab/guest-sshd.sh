#!/usr/bin/env bash
# Provide PeerTTY with a loopback SSH target inside the device's test network.
set -euo pipefail
[[ $(hostname -s) == lima-device && $1 == ssh-ed25519\ * ]]
dir=/etc/peertty-lab
install -d -m 0755 "$dir"
if ! id ptlab >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash ptlab
fi
printf '%s\n' "$1" > "$dir/authorized_keys"
chmod 0644 "$dir/authorized_keys"
cat > "$dir/sshd_config" <<'CONFIG'
Port 22
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile /etc/peertty-lab/authorized_keys
AllowUsers ptlab
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
DisableForwarding yes
PidFile /run/peertty-lab/sshd.pid
CONFIG
/usr/sbin/sshd -t -f "$dir/sshd_config"
if ! systemctl is-active --quiet peertty-lab-sshd; then
    systemd-run --quiet --collect --unit=peertty-lab-sshd \
        --property=NetworkNamespacePath=/run/netns/pt-app --property=Restart=on-failure \
        /usr/sbin/sshd -D -e -f "$dir/sshd_config"
fi
awk '{print "peertty-device", $1, $2}' /etc/ssh/ssh_host_ed25519_key.pub
