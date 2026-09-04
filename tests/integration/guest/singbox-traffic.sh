#!/bin/sh
set -eu
umask 077

[ "$#" -eq 3 ] || { printf 'usage: singbox-traffic.sh OUTPUT MANAGER_PID CORE_PID\n' >&2; exit 2; }
output=$1
manager_pid=$2
core_pid=$3
root=/opt/boxctl
source_ip=192.168.111.101
destination_ip=9.9.9.12
destination_port=5212
client_namespace=bxs-client
origin_namespace=bxs-origin
client_host=bxs-ch
client_peer=bxs-cp
origin_host=bxs-oh
origin_peer=bxs-op
server_pid=
client_pid=
cleanup_done=false

delete_test_rules() {
	while :; do
		handle=$(nft -a list chain inet fw4 forward 2>/dev/null | awk '/comment "boxctl-integration-singbox"/ { print $NF; exit }')
		[ -n "$handle" ] || break
		nft delete rule inet fw4 forward handle "$handle" >/dev/null 2>&1 || break
	done
}

cleanup() {
	[ "$cleanup_done" = false ] || return 0
	cleanup_done=true
	set +e
	[ -z "$client_pid" ] || kill "$client_pid" 2>/dev/null
	[ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null
	[ -z "$client_pid" ] || wait "$client_pid" 2>/dev/null
	[ -z "$server_pid" ] || wait "$server_pid" 2>/dev/null
	delete_test_rules
	ip netns del "$client_namespace" >/dev/null 2>&1
	ip netns del "$origin_namespace" >/dev/null 2>&1
	ip link del "$client_host" >/dev/null 2>&1
	ip link del "$origin_host" >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for pid in "$manager_pid" "$core_pid"; do
	case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
	[ -d "/proc/${pid}" ] || exit 1
done
[ "$(readlink "/proc/${core_pid}/exe")" = "$root/engines/sing-box/sing-box" ] || exit 1
[ -f "$root/.boxctl/sing-box-controller-secret" ] || exit 1
controller_secret=$(tr -d '\r\n' <"$root/.boxctl/sing-box-controller-secret")
[ -n "$controller_secret" ] || exit 1

ip netns add "$client_namespace"
ip netns add "$origin_namespace"
ip link add "$client_host" type veth peer name "$client_peer"
ip link set "$client_peer" netns "$client_namespace"
ip link set "$client_host" master br-lan
ip link set "$client_host" up
ip netns exec "$client_namespace" ip link set lo up
ip netns exec "$client_namespace" ip link set "$client_peer" up
ip netns exec "$client_namespace" ip address add "${source_ip}/24" dev "$client_peer"
ip netns exec "$client_namespace" ip route add default via 192.168.111.1

ip link add "$origin_host" type veth peer name "$origin_peer"
ip link set "$origin_peer" netns "$origin_namespace"
ip address add 9.9.9.1/24 dev "$origin_host"
ip link set "$origin_host" up
ip netns exec "$origin_namespace" ip link set lo up
ip netns exec "$origin_namespace" ip link set "$origin_peer" up
ip netns exec "$origin_namespace" ip address add 9.9.9.2/24 dev "$origin_peer"
ip netns exec "$origin_namespace" ip address add "${destination_ip}/32" dev "$origin_peer"
ip netns exec "$origin_namespace" ip route add 192.168.111.0/24 via 9.9.9.1

nft insert rule inet fw4 forward iifname "br-lan" oifname "$origin_host" accept comment "boxctl-integration-singbox"
nft insert rule inet fw4 forward iifname "$origin_host" oifname "br-lan" ct state established,related accept comment "boxctl-integration-singbox"
nft list chain inet clash mark_traffic | grep -Fq 'meta l4proto tcp meta mark set 0x00000001' || exit 1

ip netns exec "$origin_namespace" iperf3 -s -B "$destination_ip" -p "$destination_port" >"${output}/singbox-server.log" 2>&1 & server_pid=$!
sleep 1
kill -0 "$server_pid"
ip netns exec "$client_namespace" iperf3 -c "$destination_ip" -p "$destination_port" -t 6 -P 2 -J \
	>"${output}/singbox-traffic.json" 2>"${output}/singbox-traffic.err" & client_pid=$!

observed=false
iteration=1
while [ "$iteration" -le 5 ]; do
	sleep 1
	connections="${output}/singbox-connections-${iteration}.json"
	if curl --fail --silent --max-time 5 --header "Authorization: Bearer ${controller_secret}" \
		http://127.0.0.1:9090/connections >"$connections"; then
		jq -e --arg source "$source_ip" --arg destination "$destination_ip" --arg port "$destination_port" '
			any(.connections[]?;
				.metadata.sourceIP == $source and
				.metadata.destinationIP == $destination and
				(.metadata.destinationPort | tostring) == $port)
		' "$connections" >/dev/null && observed=true || true
	fi
	iteration=$((iteration + 1))
done

client_status=0
wait "$client_pid" || client_status=$?
client_pid=
sent_bytes=$(jsonfilter -i "${output}/singbox-traffic.json" -e '@.end.sum_sent.bytes' 2>/dev/null || printf 0)
case "$sent_bytes" in ''|*[!0-9]*) sent_bytes=0 ;; esac
printf 'exit\tsent_bytes\tcontroller_observation\n%s\t%s\t%s\n' \
	"$client_status" "$sent_bytes" "$observed" >"${output}/singbox-traffic.tsv"
[ "$client_status" -eq 0 ] && [ "$sent_bytes" -ge 1048576 ] || exit 1
[ "$observed" = true ] || exit 1

cleanup
! nft -a list chain inet fw4 forward 2>/dev/null | grep -Fq 'boxctl-integration-singbox' || exit 1
! ip netns list | awk '{ print $1 }' | grep -Fxq "$client_namespace" || exit 1
! ip netns list | awk '{ print $1 }' | grep -Fxq "$origin_namespace" || exit 1
exit 0
