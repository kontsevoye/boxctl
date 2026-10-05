#!/bin/sh
set -eu
umask 077

[ "$#" -eq 3 ] || exit 2
output=$1 cookie_jar=$2 csrf=$3
api=http://192.168.111.1:9091/api/v1
mkdir -p "$output"
client=boxctl-dot-client origin=boxctl-dot-origin
client_host=bdc-host origin_host=bdo-host
tcp_pid='' udp_pid=''
settings_changed=false

save() {
	curl --fail --silent --show-error --max-time 90 --cookie "$cookie_jar" \
		-H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
		-X PUT --data "$1" "$api/settings" >"$output/save-$2.json"
	remaining=45
	while [ "$remaining" -gt 0 ]; do
		if curl --fail --silent --max-time 2 --cookie "$cookie_jar" "$api/status" >"$output/status-$2.json" &&
			jq -e '.data.healthy and .data.core.state == "running" and (.data.transition // "") == ""' "$output/status-$2.json" >/dev/null; then return; fi
		sleep 1
		remaining=$((remaining - 1))
	done
	return 1
}

cleanup() (
	set +e
	for pid in "$tcp_pid" "$udp_pid"; do [ -z "$pid" ] || kill "$pid" 2>/dev/null; done
	for pid in "$tcp_pid" "$udp_pid"; do [ -z "$pid" ] || wait "$pid" 2>/dev/null; done
	ip netns del "$client" 2>/dev/null
	ip netns del "$origin" 2>/dev/null
	ip link del "$client_host" 2>/dev/null
	ip link del "$origin_host" 2>/dev/null
	while :; do
		handle=$(nft -a list chain inet fw4 forward 2>/dev/null | awk '/comment "boxctl-dot-test"/ { print $NF; exit }')
		[ -n "$handle" ] || break
		nft delete rule inet fw4 forward handle "$handle" || break
	done
	[ "$settings_changed" = false ] || save '{"blockDoT":false,"bypassSources":[],"bypassTCPPorts":[],"bypassUDPPorts":[],"proxyOnlyTCPPorts":[],"proxyOnlyUDPPorts":[],"captureMode":"tproxy","tunStack":"system"}' cleanup
)
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ip netns add "$client"
ip netns add "$origin"
ip link add "$client_host" type veth peer name bdc-peer
ip link set bdc-peer netns "$client"
ip link set "$client_host" master br-lan
ip link set "$client_host" up
ip netns exec "$client" ip link set lo up
ip netns exec "$client" ip link set bdc-peer up
ip netns exec "$client" ip address add 192.168.111.100/24 dev bdc-peer
ip netns exec "$client" ip address add 192.168.111.101/24 dev bdc-peer
ip netns exec "$client" ip route add default via 192.168.111.1
ip link add "$origin_host" type veth peer name bdo-peer
ip link set bdo-peer netns "$origin"
ip address add 9.9.9.1/24 dev "$origin_host"
ip link set "$origin_host" up
ip netns exec "$origin" ip link set lo up
ip netns exec "$origin" ip link set bdo-peer up
ip netns exec "$origin" ip address add 9.9.9.11/24 dev bdo-peer
ip netns exec "$origin" ip route add 192.168.111.0/24 via 9.9.9.1
nft insert rule inet fw4 forward iifname br-lan oifname "$origin_host" accept comment 'boxctl-dot-test'
nft insert rule inet fw4 forward iifname "$origin_host" oifname br-lan ct state established,related accept comment 'boxctl-dot-test'
ip netns exec "$origin" socat -d -d -T1 TCP4-LISTEN:853,reuseaddr,fork EXEC:cat >"$output/tcp-server.log" 2>&1 & tcp_pid=$!
sleep 1
kill -0 "$tcp_pid"

probe() {
	protocol=$1 source=$2 label=$3 expected=$4
	if [ "$protocol" = UDP4 ]; then
		# A fresh one-datagram receiver avoids shared/forked UDP sockets and
		# checks ingress delivery directly rather than relying on echo replies.
		ip netns exec "$origin" socat -d -d -u UDP4-RECVFROM:853,reuseaddr,so-rcvtimeo=2 \
			"OPEN:$output/$label.txt,creat,trunc" >"$output/$label-server.log" 2>&1 & udp_pid=$!
		sleep 1
		udp_address=UDP4-SENDTO:9.9.9.11:853
		if [ "$source" = router ]; then
			printf boxctl-dot-probe | socat -u - "$udp_address" 2>"$output/$label.err"
		else
			printf boxctl-dot-probe | ip netns exec "$client" socat -u - "$udp_address,bind=$source" 2>"$output/$label.err"
		fi
		# RECVFROM waits for its first peer before socat's transfer timeout
		# applies. End a blocked receiver explicitly after the delivery window.
		sleep 1
		kill "$udp_pid" 2>/dev/null || true
		wait "$udp_pid" || true
		udp_pid=''
	else
	address="$protocol:9.9.9.11:853,bind=$source"
	[ "$protocol" != TCP4 ] || address="$address,connect-timeout=1"
	if [ "$source" = router ]; then
		router_address="$protocol:9.9.9.11:853"
		[ "$protocol" != TCP4 ] || router_address="$router_address,connect-timeout=1"
		printf boxctl-dot-probe | socat -d -d -T2 - "$router_address" >"$output/$label.txt" 2>"$output/$label.err" || true
	else
		printf boxctl-dot-probe | ip netns exec "$client" socat -d -d -T2 - "$address" >"$output/$label.txt" 2>"$output/$label.err" || true
	fi
	fi
	if [ "$expected" = delivered ]; then
		[ "$(cat "$output/$label.txt")" = boxctl-dot-probe ] || { printf 'expected delivery: %s\n' "$label" >&2; return 1; }
	else
		[ ! -s "$output/$label.txt" ] || { printf 'expected blocking: %s\n' "$label" >&2; return 1; }
	fi
}

for protocol in TCP4 UDP4; do probe "$protocol" 192.168.111.100 "$protocol-off" delivered; done
settings_changed=true
# Enforce DoT even when capture is selective, 853 is bypassed by port, and the
# proxy-only port list excludes 853. Source bypass must still take precedence.
save '{"blockDoT":true,"bypassSources":["192.168.111.101"],"bypassTCPPorts":[853],"bypassUDPPorts":[853],"proxyOnlyTCPPorts":[443],"proxyOnlyUDPPorts":[443]}' dot-on
nft list chain inet clash dot_block >"$output/dot-chain.txt"
for protocol in TCP4 UDP4; do
	probe "$protocol" 192.168.111.100 "$protocol-blocked" blocked
	probe "$protocol" 192.168.111.101 "$protocol-source-bypass" delivered
	probe "$protocol" router "$protocol-router-output" delivered
done
save '{"blockDoT":false,"bypassSources":[],"bypassTCPPorts":[],"bypassUDPPorts":[],"proxyOnlyTCPPorts":[],"proxyOnlyUDPPorts":[]}' dot-off
if nft list chain inet clash dot_block >/dev/null 2>&1; then exit 1; fi
for protocol in TCP4 UDP4; do probe "$protocol" 192.168.111.100 "$protocol-restored" delivered; done
cleanup
settings_changed=false
trap - EXIT
printf 'dot_tcp=true\ndot_udp=true\ndot_source_bypass=true\ndot_router_output=true\ndot_disable_restores=true\n' >"$output/result.txt"
