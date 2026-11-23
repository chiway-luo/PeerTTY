#!/usr/bin/env bash
# Runs inside one of the two dedicated guests, via the Lima management channel.
set -euo pipefail

action=$1
role=$2
shift 2
case "$role" in
    engineer) side=1; other=2 ;;
    device)   side=2; other=1 ;;
    *) exit 2 ;;
esac
[[ $(hostname -s) == "lima-$role" ]] || { echo "Unexpected guest for $role" >&2; exit 1; }

app=pt-app
gw=pt-gw
svc=pt-svc
state=/run/peertty-lab
lan="10.77.$side"
peer_lan="10.77.$other"
wan="198.18.0.$side"
peer_wan="198.18.0.$other"
mkdir -p "$state"

setup() {
    local local_ip=$1 peer_ip=$2 dev
    install -d -m 0755 "/etc/netns/$app"
    cat > "/etc/netns/$app/hosts" <<'HOSTS'
127.0.0.1 localhost
::1 localhost ip6-localhost
10.77.1.2 lima-engineer engineer
10.77.2.2 lima-device device
HOSTS
    if [[ -f $state/underlay && $(<"$state/underlay") == "$local_ip $peer_ip" ]] &&
        ip -n "$gw" link show wan0 >/dev/null && ip -n "$app" link show eth0 >/dev/null; then
        return
    fi
    if [[ -e /run/netns/$app && -n $(ip netns pids "$app") ]]; then
        echo "Test network changed while applications are running on $role" >&2
        return 1
    fi
    # Recover only this lab's interfaces after an interrupted first setup.
    if [[ -e /run/netns/$svc ]]; then ip netns del "$svc"; fi
    if [[ -e /run/netns/$gw ]]; then ip netns del "$gw"; fi
    if [[ -e /run/netns/$app ]]; then ip netns del "$app"; fi
    if ip link show pt-xlink >/dev/null 2>&1; then ip link del pt-xlink; fi
    rm -f "$state/underlay" "$state/profile" "$state/zone"
    dev=$(ip -4 route get "$peer_ip" | awk 'NR==1 {for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}')
    ip netns add "$app"
    ip netns add "$gw"
    # VXLAN keeps its UDP socket in the management namespace. Its Ethernet
    # interface belongs to the isolated router on the corresponding machine.
    ip link add pt-xlink type vxlan id 4777 local "$local_ip" remote "$peer_ip" dev "$dev" dstport 4789 nolearning
    ip link set pt-xlink netns "$gw"
    ip -n "$gw" link set pt-xlink name wan0
    ip -n "$gw" link set wan0 address "02:50:54:77:00:0$side" mtu 1400 up
    ip -n "$gw" addr add "$wan/30" dev wan0
    # A simulated single-direction cut must not depend on ARP in the return direction.
    ip -n "$gw" neigh replace "$peer_wan" lladdr "02:50:54:77:00:0$other" nud permanent dev wan0
    ip -n "$gw" link add lan0 type veth peer name eth0 netns "$app"
    ip -n "$gw" link set lo up
    ip -n "$gw" link set lan0 mtu 1400 up
    ip -n "$gw" addr add "$lan.1/24" dev lan0
    ip -n "$gw" route add "$peer_lan.0/24" via "$peer_wan"
    ip -n "$app" link set lo up
    ip -n "$app" link set eth0 mtu 1400 up
    ip -n "$app" addr add "$lan.2/24" dev eth0
    ip -n "$app" route add default via "$lan.1"
    ip netns exec "$gw" sysctl -q -w net.ipv4.ip_forward=1
    echo "$local_ip $peer_ip" > "$state/underlay"
}

setup_observer() {
    # Each simulated public observer has one address. Wildcard UDP services
    # consequently reply from the same address the clients contacted.
    if ! ip -n "$svc" link show eth0 >/dev/null 2>&1; then
        if [[ ! -e /run/netns/$svc ]]; then ip netns add "$svc"; fi
        ip -n "$gw" link add svc0 type veth peer name eth0 netns "$svc"
    fi
    ip -n "$gw" link set svc0 mtu 1400 up
    ip -n "$gw" addr replace "198.19.$side.1/30" dev svc0
    ip -n "$svc" link set lo up
    ip -n "$svc" link set eth0 mtu 1400 up
    ip -n "$svc" addr replace "198.19.$side.2/30" dev eth0
    ip -n "$svc" route replace default via "198.19.$side.1"
    ip -n "$gw" route replace "198.19.$other.0/30" via "$peer_wan" dev wan0
}

apply_profile() {
    local profile=$1 mode=$2 zone=1 last="" udp_rule="" forward_rules nat_rule="" input_rule="" udp_nat=""
    shift 2
    [[ -f $state/underlay ]] || { echo "Run lab/ctl up first" >&2; return 1; }
    [[ ! -f $state/zone ]] || read -r zone last < "$state/zone"
    # New NAT modes get fresh connection tracking, including reused UDP ports.
    if [[ $last != "$mode" ]]; then zone=$((zone % 65535 + 1)); fi
    if [[ $profile == udp-blocked ]]; then udp_rule='meta l4proto udp counter drop'; fi
    case "$mode" in
        routed)
            forward_rules='iifname "lan0" oifname "wan0" accept
                           iifname "wan0" oifname "lan0" accept'
            ;;
        nat|nat-remap|nat-dependent)
            forward_rules="iifname \"lan0\" oifname \"wan0\" ip daddr { 198.18.0.0/30, 198.19.$other.2 } accept
                           iifname \"wan0\" oifname \"lan0\" ct state established,related accept"
            case "$mode" in
                nat-remap)
                    # A stable, non-port-preserving mapping for every UDP socket.
                    udp_nat="oifname \"wan0\" ip saddr $lan.0/24 udp sport >= 1024 snat to $wan : udp sport ^ 256;"
                    ;;
                nat-dependent)
                    # Disjoint mapped port ranges at STUN and at the other peer.
                    # Established-only inbound filtering still applies on each side.
                    udp_nat="oifname \"wan0\" ip saddr $lan.0/24 ip daddr 198.19.$other.2 meta l4proto udp snat to $wan : (udp sport & 16383) | 16384;
                             oifname \"wan0\" ip saddr $lan.0/24 ip daddr $peer_wan meta l4proto udp snat to $wan : (udp sport & 16383) | 49152;"
                    ;;
            esac
            nat_rule="chain post { type nat hook postrouting priority srcnat; $udp_nat oifname \"wan0\" ip saddr $lan.0/24 snat to $wan; }"
            # An unsolicited datagram at a closed WAN port must be dropped before
            # conntrack confirms it; otherwise it can collide with a later mapping.
            input_rule="chain input {
                type filter hook input priority filter; policy accept;
                iifname \"wan0\" ip daddr $wan ct state established,related accept
                iifname \"wan0\" ip daddr $wan icmp type echo-request accept
                iifname \"wan0\" ip daddr $wan counter drop
            }"
            ;;
        *) return 2 ;;
    esac
    echo "updating $profile $mode" > "$state/profile"
    ip netns exec "$gw" nft add table ip peertty
    ip netns exec "$gw" nft -f - <<RULES
delete table ip peertty
table ip peertty {
    chain track_in { type filter hook prerouting priority raw; ct zone set $zone; }
    chain track_out { type filter hook output priority raw; ct zone set $zone; }
    chain switching { type filter hook postrouting priority 110; oifname "wan0" drop; }
    chain forward {
        type filter hook forward priority filter; policy drop;
        $udp_rule
        iifname "wan0" oifname "svc0" ip daddr 198.19.$side.2 accept
        iifname "svc0" oifname "wan0" ip saddr 198.19.$side.2 accept
        $forward_rules
    }
    $nat_rule
    $input_rule
}
RULES
    # netem retains omitted rate/reorder parameters on an in-place change.
    # Gate test traffic while replacing the queue. Management stays reachable.
    if [[ $(ip netns exec "$gw" tc qdisc show dev wan0) == "qdisc netem "* ]]; then
        ip netns exec "$gw" tc qdisc del dev wan0 root
    fi
    ip netns exec "$gw" tc qdisc add dev wan0 root handle 1: netem limit 150 "$@"
    ip netns exec "$gw" nft flush chain ip peertty switching
    echo "$zone $mode" > "$state/zone"
    echo "$profile $mode" > "$state/profile"
}

roam_prepare() {
    [[ $(<"$state/profile") == "clean routed" ]]
    ip -n "$gw" link add roamlan type veth peer name roam0 netns "$app"
    ip -n "$gw" link set roamlan mtu 1400 up
    ip -n "$gw" addr add "10.78.$side.1/24" dev roamlan
    ip -n "$gw" addr add "198.18.1.$side/32" dev wan0
    ip -n "$gw" route add "198.18.1.$other/32" via "$peer_wan"
    ip netns exec "$gw" nft insert rule ip peertty forward iifname roamlan oifname wan0 accept
    ip netns exec "$gw" nft insert rule ip peertty forward iifname wan0 oifname roamlan accept
    # A different egress IP, with endpoint-independent inbound filtering for
    # UDP ports that this endpoint actually used. The new LAN is not routed
    # across the WAN. Count translated UDP packets on the wire.
    ip netns exec "$gw" nft -f - <<RULES
table ip peertty_roam {
    set ports { type inet_service; flags dynamic,timeout; timeout 2m; }
    counter translated {}
    chain outbound { type filter hook forward priority mangle; iifname "roamlan" ip saddr != 10.78.$side.2 drop; iifname "roamlan" oifname "wan0" meta l4proto udp update @ports { udp sport timeout 2m }; }
    chain post { type nat hook postrouting priority srcnat; oifname "wan0" ip saddr 10.78.$side.2 snat to 198.18.1.$side; }
    chain pre { type nat hook prerouting priority dstnat; iifname "wan0" ip daddr 198.18.1.$side udp dport @ports dnat to 10.78.$side.2; }
    chain observe { type filter hook postrouting priority 115; oifname "wan0" ip saddr 198.18.1.$side meta l4proto udp counter name translated; }
}
RULES
}

roam_cut() {
    ip -n "$app" addr del "$lan.2/24" dev eth0
    ip -n "$app" link set eth0 down
}

roam_join() {
    ip -n "$app" link set roam0 mtu 1400 up
    ip -n "$app" addr add "10.78.$side.2/24" dev roam0
    ip -n "$app" route replace default via "10.78.$side.1" dev roam0
}

roam_restore() {
    ip -n "$app" link set eth0 up
    ip -n "$app" addr replace "$lan.2/24" dev eth0
    ip -n "$app" route replace default via "$lan.1" dev eth0
    if ip -n "$gw" link show roamlan >/dev/null 2>&1; then ip -n "$gw" link del roamlan; fi
    if ip netns exec "$gw" nft list table ip peertty_roam >/dev/null 2>&1; then
        ip netns exec "$gw" nft delete table ip peertty_roam
    fi
    if [[ -n $(ip -n "$gw" route show "198.18.1.$other/32") ]]; then
        ip -n "$gw" route del "198.18.1.$other/32" via "$peer_wan"
    fi
    if [[ -n $(ip -n "$gw" -4 addr show dev wan0 to "198.18.1.$side/32") ]]; then
        ip -n "$gw" addr del "198.18.1.$side/32" dev wan0
    fi
}

case "$action" in
    setup)
        setup "$@"
        setup_observer
        ;;
    profile) apply_profile "$@" ;;
    roam-prepare) roam_prepare ;;
    roam-cut) roam_cut ;;
    roam-join) roam_join ;;
    roam-count) ip netns exec "$gw" nft list counter ip peertty_roam translated ;;
    roam-restore) roam_restore ;;
    stun)
        server=/usr/local/lib/peertty-lab/stun-only-server
        [[ -x $server ]] || exit 0
        if systemctl is-active --quiet peertty-lab-stun; then
            pid=$(systemctl show -p MainPID --value peertty-lab-stun)
            if [[ ! /proc/$pid/exe -ef $server ]]; then systemctl restart peertty-lab-stun; fi
        else
            systemd-run --quiet --collect --unit=peertty-lab-stun \
                --property=NetworkNamespacePath=/run/netns/pt-svc \
                --property=DynamicUser=yes --property=NoNewPrivileges=yes \
                --property=Restart=on-failure \
                "$server" -public-ip "198.19.$side.2"
        fi
        ;;
    status)
        cat /etc/machine-id /proc/sys/kernel/random/boot_id
        if [[ -f $state/profile ]]; then
            cat "$state/profile"
            ip netns exec "$gw" tc qdisc show dev wan0
        else
            echo "unconfigured"
        fi
        ;;
    *) exit 2 ;;
esac
