#!/bin/sh
set -eu
umask 077

# Runs only inside the disposable OpenWrt integration VM.
output=$1
manager_pid=$2
core_pid=$3
csrf_token=$4
api=http://192.168.111.1:9091/api/v1
cookie_jar=/tmp/boxctl-integration-cookies
root=/opt/boxctl
restart_pid=

cleanup() {
	set +e
	kill -CONT "$manager_pid" "$core_pid" 2>/dev/null
	[ -z "$restart_pid" ] || wait "$restart_pid"
	BOXCTL_ROOT="$root" "$root/bin/boxctl" fw guard-off >/dev/null 2>&1
	ip netns del bgr-client
	ip netns del bgr-origin
	ip link del bgr-lan
	ip link del bgr-wan
	ip link del bgr-new
	ip -6 address del fd41:1::1/64 dev br-lan
	for chain in input forward; do
		while :; do
			handle=$(nft -a list chain inet fw4 "$chain" 2>/dev/null | awk '/comment "boxctl-guard-integration"/ { print $NF; exit }')
			[ -n "$handle" ] || break
			nft delete rule inet fw4 "$chain" handle "$handle" >/dev/null 2>&1 || break
		done
	done
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

put_setting() {
	curl --fail --silent --show-error --max-time 15 --cookie "$cookie_jar" \
		-H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf_token" \
		-X PUT --data "$1" "$api/settings"
}

allow_fixture() {
	nft insert rule inet fw4 input iifname "$1" meta l4proto ipv6-icmp accept comment "boxctl-guard-integration"
	nft insert rule inet fw4 forward iifname br-lan oifname "$1" accept comment "boxctl-guard-integration"
	nft insert rule inet fw4 forward iifname "$1" oifname br-lan accept comment "boxctl-guard-integration"
}

ping_origin() {
	ip netns exec bgr-client ping -c 1 -W 1 192.0.2.2 &&
		ip netns exec bgr-client ping -6 -c 1 -W 1 fd41:2::2
}

wait_origin() {
    baseline_remaining=10
    until ping_origin; do
        baseline_remaining=$((baseline_remaining - 1))
        [ "$baseline_remaining" -gt 0 ] || return 1
        sleep 1
    done
}

blocked_origin() {
	! ip netns exec bgr-client ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1 &&
		! ip netns exec bgr-client ping -6 -c 1 -W 1 fd41:2::2 >/dev/null 2>&1
}

ip netns add bgr-client
ip netns add bgr-origin
ip link add bgr-lan type veth peer name bgr-client
ip link set bgr-client netns bgr-client
ip link set bgr-lan master br-lan
ip link set bgr-lan up
ip netns exec bgr-client ip link set lo up
ip netns exec bgr-client ip link set bgr-client up
ip netns exec bgr-client ip address add 192.168.111.102/24 dev bgr-client
ip netns exec bgr-client ip route add default via 192.168.111.1
ip -6 address add fd41:1::1/64 dev br-lan nodad
ip netns exec bgr-client ip -6 address add fd41:1::2/64 dev bgr-client nodad
ip netns exec bgr-client ip -6 route add default via fd41:1::1
ip link add bgr-wan type veth peer name bgr-origin
ip link set bgr-origin netns bgr-origin
ip link set bgr-wan up
ip address add 192.0.2.1/24 dev bgr-wan
ip -6 address add fd41:2::1/64 dev bgr-wan nodad
ip netns exec bgr-origin ip link set lo up
ip netns exec bgr-origin ip link set bgr-origin up
ip netns exec bgr-origin ip address add 192.0.2.2/24 dev bgr-origin
ip netns exec bgr-origin ip -6 address add fd41:2::2/64 dev bgr-origin nodad
ip netns exec bgr-origin ip route add default via 192.0.2.1
ip netns exec bgr-origin ip -6 route add default via fd41:2::1
allow_fixture bgr-wan
sysctl net.ipv6.conf.all.forwarding
ip -6 route show
ip -6 address show dev br-lan
ip -6 address show dev bgr-wan
wait_origin

put_setting '{"coreRestartGuard":true}' >"$output/restart-guard-settings.json"
jq -e '.data.coreRestartGuard == true' "$output/restart-guard-settings.json" >/dev/null
if nft list table inet boxctl_guard >/dev/null 2>&1; then exit 1; fi

# Delay the old core's graceful exit to observe the guard before replacement.
kill -STOP "$core_pid"
curl --fail --silent --show-error --max-time 150 --cookie "$cookie_jar" \
	-H "X-CSRF-Token: $csrf_token" -X POST "$api/service/restart" >"$output/restart-guard-result.json" &
restart_pid=$!
remaining=10
while ! nft list table inet boxctl_guard >"$output/restart-guard.nft" 2>/dev/null; do
	[ "$remaining" -gt 0 ] || exit 1
	sleep 1
	remaining=$((remaining - 1))
done
curl --fail --silent --max-time 3 --cookie "$cookie_jar" "$api/status" >"$output/restart-guard-active.json"
jq -e '.data.restartGuard.active == true' "$output/restart-guard-active.json" >/dev/null
kill -STOP "$manager_pid"
blocked_origin
ip netns exec bgr-client ping -c 1 -W 1 192.168.111.1 >/dev/null
ip netns exec bgr-client ping -6 -c 1 -W 1 fd41:1::1 >/dev/null
/etc/init.d/firewall reload >"$output/restart-guard-fw4-reload.log" 2>&1
allow_fixture bgr-wan
blocked_origin
# A renamed/new egress is still blocked without a WAN-list update.
ip link set bgr-wan down
ip link set bgr-wan name bgr-new
ip link set bgr-new up
ip -6 address replace fd41:2::1/64 dev bgr-new nodad
allow_fixture bgr-new
blocked_origin
kill -CONT "$manager_pid" "$core_pid"
wait "$restart_pid"
restart_pid=
if nft list table inet boxctl_guard >/dev/null 2>&1; then exit 1; fi
wait_origin

# Replay the exact rendered rule with a short lease while no lifecycle owns
# it. Expiry must restore IPv4/IPv6 forwarding without manager cleanup.
sed -E 's/timeout [0-9][^[:space:];,}]*/timeout 3s/g; s/ expires [0-9][^[:space:];,}]*//g' "$output/restart-guard.nft" >"$output/restart-guard-expiry.nft"
nft -c -f "$output/restart-guard-expiry.nft"
nft -f "$output/restart-guard-expiry.nft"
blocked_origin
sleep 3
wait_origin
put_setting '{"coreRestartGuard":false}' >"$output/restart-guard-disabled.json"
if nft list table inet boxctl_guard >/dev/null 2>&1; then exit 1; fi
printf 'restart guard: IPv4/IPv6 restart, router access, fw4 reload, new egress and kernel expiry passed\n'
