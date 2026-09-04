#!/bin/sh
set -eu
umask 077

[ "$#" -eq 3 ] || { printf 'usage: traffic.sh OUTPUT MANAGER_PID CORE_PID\n' >&2; exit 2; }
output=$1
manager_pid=$2
core_pid=$3
captured_ip=9.9.9.10
direct_ip=9.9.9.11
client_namespace=boxctl-client
origin_namespace=boxctl-origin
client_host=bxc-host
client_peer=bxc-peer
origin_host=bxo-host
origin_peer=bxo-peer
captured_server_pid=
direct_server_pid=
captured_client_pid=
direct_client_pid=
mode_before=rule
mode_changed=false
capture_added=false
cleanup_done=false

delete_test_rules() {
	while :; do
		handle=$(nft -a list chain inet fw4 forward 2>/dev/null | awk '/comment "boxctl-integration-traffic"/ { print $NF; exit }')
		[ -n "$handle" ] || break
		nft delete rule inet fw4 forward handle "$handle" >/dev/null 2>&1 || break
	done
}

cleanup() {
	[ "$cleanup_done" = false ] || return 0
	cleanup_done=true
	set +e
	for pid in "$captured_client_pid" "$direct_client_pid" "$captured_server_pid" "$direct_server_pid"; do [ -z "$pid" ] || kill "$pid" 2>/dev/null; done
	for pid in "$captured_client_pid" "$direct_client_pid" "$captured_server_pid" "$direct_server_pid"; do [ -z "$pid" ] || wait "$pid" 2>/dev/null; done
	[ "$mode_changed" = false ] || curl --silent --max-time 10 -X PATCH -H 'Content-Type: application/json' --data "{\"mode\":\"${mode_before}\"}" http://127.0.0.1:9090/configs >/dev/null 2>&1
	[ "$capture_added" = false ] || nft delete element inet clash capture4 "{ ${captured_ip} }" >/dev/null 2>&1
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

resources="${output}/resources.tsv"
printf 'phase\trole\trss_kb\tthreads\tcpu_ticks\n' >"$resources"
sample_process() {
	phase=$1 role=$2 pid=$3
	rss=$(awk '$1 == "VmRSS:" { print $2; exit }' "/proc/${pid}/status")
	threads=$(awk '$1 == "Threads:" { print $2; exit }' "/proc/${pid}/status")
	ticks=$(awk '{ closing=index($0, ") "); rest=substr($0, closing+2); split(rest, field, " "); print field[12]+field[13] }' "/proc/${pid}/stat")
	printf '%s\t%s\t%s\t%s\t%s\n' "$phase" "$role" "$rss" "$threads" "$ticks" >>"$resources"
}
sample_pair() { sample_process "$1" manager "$manager_pid"; sample_process "$1" mihomo "$core_pid"; }

! nft get element inet clash capture4 "{ ${captured_ip} }" >/dev/null 2>&1 || exit 1
! nft get element inet clash capture4 "{ ${direct_ip} }" >/dev/null 2>&1 || exit 1

ip netns add "$client_namespace"
ip netns add "$origin_namespace"
ip link add "$client_host" type veth peer name "$client_peer"
ip link set "$client_peer" netns "$client_namespace"
ip link set "$client_host" master br-lan
ip link set "$client_host" up
ip netns exec "$client_namespace" ip link set lo up
ip netns exec "$client_namespace" ip link set "$client_peer" up
ip netns exec "$client_namespace" ip address add 192.168.111.100/24 dev "$client_peer"
ip netns exec "$client_namespace" ip route add default via 192.168.111.1

ip link add "$origin_host" type veth peer name "$origin_peer"
ip link set "$origin_peer" netns "$origin_namespace"
ip address add 9.9.9.1/24 dev "$origin_host"
ip link set "$origin_host" up
ip netns exec "$origin_namespace" ip link set lo up
ip netns exec "$origin_namespace" ip link set "$origin_peer" up
ip netns exec "$origin_namespace" ip address add 9.9.9.2/24 dev "$origin_peer"
ip netns exec "$origin_namespace" ip address add "${captured_ip}/32" dev "$origin_peer"
ip netns exec "$origin_namespace" ip address add "${direct_ip}/32" dev "$origin_peer"
ip netns exec "$origin_namespace" ip route add 192.168.111.0/24 via 9.9.9.1

nft insert rule inet fw4 forward iifname "br-lan" oifname "$origin_host" accept comment "boxctl-integration-traffic"
nft insert rule inet fw4 forward iifname "$origin_host" oifname "br-lan" ct state established,related accept comment "boxctl-integration-traffic"

curl --fail --silent --max-time 10 http://127.0.0.1:9090/configs >"${output}/core-mode-before.json"
mode_before=$(jsonfilter -i "${output}/core-mode-before.json" -e '@.mode' 2>/dev/null || true)
case "$mode_before" in rule|global|direct) ;; *) mode_before=rule ;; esac
curl --fail --silent --max-time 10 -X PATCH -H 'Content-Type: application/json' --data '{"mode":"direct"}' http://127.0.0.1:9090/configs >/dev/null
mode_changed=true
nft add element inet clash capture4 "{ ${captured_ip} }"
capture_added=true

ip netns exec "$origin_namespace" iperf3 -s -B "$captured_ip" -p 5210 >"${output}/captured-server.log" 2>&1 & captured_server_pid=$!
ip netns exec "$origin_namespace" iperf3 -s -B "$direct_ip" -p 5211 >"${output}/direct-server.log" 2>&1 & direct_server_pid=$!
sleep 1
kill -0 "$captured_server_pid"
kill -0 "$direct_server_pid"
sample_pair idle

ip netns exec "$client_namespace" iperf3 -c "$captured_ip" -p 5210 -t 8 -P 2 -b 50M -J >"${output}/captured.json" 2>"${output}/captured.err" & captured_client_pid=$!
ip netns exec "$client_namespace" iperf3 -c "$direct_ip" -p 5211 -t 8 -P 2 -b 50M -J >"${output}/direct.json" 2>"${output}/direct.err" & direct_client_pid=$!

tproxy_observed=false
direct_observed=false
iteration=1
while [ "$iteration" -le 7 ]; do
	sleep 1
	sample_pair "load-${iteration}"
	connections="${output}/connections-${iteration}.json"
	if curl --fail --silent --max-time 5 http://127.0.0.1:9090/connections >"$connections"; then
		jq -e --arg source '192.168.111.100' --arg destination "$captured_ip" --arg port '5210' 'any(.connections[]?; .metadata.sourceIP == $source and .metadata.destinationIP == $destination and .metadata.destinationPort == $port and .metadata.type == "TProxy" and .metadata.network == "tcp")' "$connections" >/dev/null && tproxy_observed=true || true
		jq -e --arg source '192.168.111.100' --arg destination "$direct_ip" --arg port '5211' 'any(.connections[]?; .metadata.sourceIP == $source and .metadata.destinationIP == $destination and .metadata.destinationPort == $port and .metadata.network == "tcp")' "$connections" >/dev/null && direct_observed=true || true
	fi
	iteration=$((iteration + 1))
done

captured_status=0 direct_status=0
wait "$captured_client_pid" || captured_status=$?
wait "$direct_client_pid" || direct_status=$?
captured_bytes=$(jsonfilter -i "${output}/captured.json" -e '@.end.sum_sent.bytes' 2>/dev/null || printf 0)
direct_bytes=$(jsonfilter -i "${output}/direct.json" -e '@.end.sum_sent.bytes' 2>/dev/null || printf 0)
case "$captured_bytes" in ''|*[!0-9]*) captured_bytes=0 ;; esac
case "$direct_bytes" in ''|*[!0-9]*) direct_bytes=0 ;; esac
printf 'path\texit\tsent_bytes\tmihomo_observation\n' >"${output}/traffic.tsv"
printf 'captured\t%s\t%s\t%s\n' "$captured_status" "$captured_bytes" "$tproxy_observed" >>"${output}/traffic.tsv"
printf 'direct\t%s\t%s\t%s\n' "$direct_status" "$direct_bytes" "$direct_observed" >>"${output}/traffic.tsv"

[ "$captured_status" -eq 0 ] && [ "$captured_bytes" -ge 52428800 ] || exit 1
[ "$direct_status" -eq 0 ] && [ "$direct_bytes" -ge 52428800 ] || exit 1
[ "$tproxy_observed" = true ] || exit 1
[ "$direct_observed" = false ] || exit 1

cleanup
! nft -a list chain inet fw4 forward 2>/dev/null | grep -Fq 'boxctl-integration-traffic' || exit 1
! ip netns list | awk '{ print $1 }' | grep -Fxq "$client_namespace" || exit 1
! ip netns list | awk '{ print $1 }' | grep -Fxq "$origin_namespace" || exit 1
exit 0
