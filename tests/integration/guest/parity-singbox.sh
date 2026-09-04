#!/bin/sh
set -eu
umask 077

[ "$#" -eq 1 ] || { printf 'usage: parity-singbox.sh OUTPUT\n' >&2; exit 2; }
input=/mnt/integration-input
output=$1
root=/opt/boxctl
manager_binary=$root/bin/boxctl
sing_box_binary=$root/engines/sing-box/sing-box
process_state=$root/.boxctl/mihomo-process.json
api=http://192.168.111.1:9091/api/v1
integration_password=integration-password
cookie_jar=/tmp/parity-singbox-cookies
csrf_token=
controller_secret=
client_namespace=parity-client
origin_namespace=parity-origin
proxy_namespace=parity-proxy
client_host=psc-host
client_peer=psc-peer
origin_host=pso-host
origin_peer=pso-peer
proxy_host=psp-host
proxy_peer=psp-peer
dns_baseline=/tmp/parity-singbox-dns-baseline.uci
fixture_dns_pid=
web_origin_pid=
local_proxy_pid=
remote_proxy_pid=
server_pid=
client_pid=
cleanup_done=false

note() { printf 'PARITY-SINGBOX-PHASE: %s\n' "$*"; }

delete_forward_rules() {
	while :; do
		handle=$(nft -a list chain inet fw4 forward 2>/dev/null | awk '/comment "parity-singbox"/ { print $NF; exit }')
		[ -n "$handle" ] || break
		nft delete rule inet fw4 forward handle "$handle" >/dev/null 2>&1 || break
	done
}

capture_diagnostics() {
	ps w >"${output}/processes.txt" 2>&1 || true
	ss -H -lnpt >"${output}/listeners-tcp.txt" 2>&1 || true
	ss -H -lnpu >"${output}/listeners-udp.txt" 2>&1 || true
	nft list ruleset >"${output}/nft-ruleset.txt" 2>&1 || true
	ip -N -4 rule show >"${output}/ip-rules.txt" 2>&1 || true
	ip -N -4 route show table 100 >"${output}/ip-routes-100.txt" 2>&1 || true
	if [ -n "$controller_secret" ]; then
		curl --silent --show-error --max-time 3 --header "Authorization: Bearer ${controller_secret}" \
			http://127.0.0.1:9090/version >"${output}/controller-version-diagnostic.json" 2>&1 || true
		curl --silent --show-error --max-time 3 --header "Authorization: Bearer ${controller_secret}" \
			http://127.0.0.1:9090/connections >"${output}/controller-connections-diagnostic.json" 2>&1 || true
	fi
	diagnostic_cookie=/tmp/parity-singbox-diagnostic-cookies
	curl --silent --show-error --max-time 5 "$api/setup" >"${output}/diagnostic-setup.json" 2>&1 || true
	if jq -e '.data.required == true' "${output}/diagnostic-setup.json" >/dev/null 2>&1; then
		curl --silent --show-error --max-time 10 --header 'Content-Type: application/json' \
			--data "{\"password\":\"${integration_password}\"}" "$api/setup" >"${output}/diagnostic-setup-result.json" 2>&1 || true
	fi
	curl --silent --show-error --max-time 10 --cookie-jar "$diagnostic_cookie" --header 'Content-Type: application/json' \
		--data "{\"password\":\"${integration_password}\"}" "$api/auth/login" >"${output}/diagnostic-login.json" 2>&1 || true
	curl --silent --show-error --max-time 5 --cookie "$diagnostic_cookie" "$api/status" >"${output}/diagnostic-status.json" 2>&1 || true
	curl --silent --show-error --max-time 5 --cookie "$diagnostic_cookie" "$api/logs/system?limit=200" >"${output}/diagnostic-system-logs.json" 2>&1 || true
	[ ! -f "$process_state" ] || cp "$process_state" "${output}/process-state-diagnostic.json" 2>/dev/null || true
	logread >"${output}/logread.log" 2>&1 || true
}

cleanup() {
	[ "$cleanup_done" = false ] || return 0
	cleanup_done=true
	set +e
	/etc/init.d/boxctl stop >/dev/null 2>&1
	for pid in "$client_pid" "$server_pid" "$remote_proxy_pid" "$local_proxy_pid" "$web_origin_pid" "$fixture_dns_pid"; do
		[ -z "$pid" ] || kill "$pid" 2>/dev/null
	done
	for pid in "$client_pid" "$server_pid" "$remote_proxy_pid" "$local_proxy_pid" "$web_origin_pid" "$fixture_dns_pid"; do
		[ -z "$pid" ] || wait "$pid" 2>/dev/null
	done
	nft delete table inet parity_singbox >/dev/null 2>&1
	delete_forward_rules
	for namespace in "$client_namespace" "$origin_namespace" "$proxy_namespace"; do
		ip netns del "$namespace" >/dev/null 2>&1
	done
	for link in "$client_host" "$origin_host" "$proxy_host"; do ip link del "$link" >/dev/null 2>&1; done
	for namespace in "$client_namespace" "$origin_namespace" "$proxy_namespace"; do rm -rf "/etc/netns/${namespace}" >/dev/null 2>&1; done
}

die() {
	printf 'PARITY-SINGBOX-ERROR: %s\n' "$*" >&2
	capture_diagnostics
	exit 1
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

find_interface() {
	wanted=$1
	for address_file in /sys/class/net/*/address; do
		[ -f "$address_file" ] || continue
		interface=$(basename "$(dirname "$address_file")")
		[ -e "/sys/class/net/${interface}/device" ] || continue
		[ "$(tr 'A-F' 'a-f' <"$address_file")" = "$wanted" ] || continue
		printf '%s\n' "$interface"
		return 0
	done
	return 1
}

write_managed_dns_state() {
	state_path=$1
	uci -q export dhcp | awk '
		$1 == "config" { if (dnsmasq) exit; dnsmasq = ($2 == "dnsmasq"); next }
		dnsmasq && ($1 == "option" || $1 == "list") && ($2 == "cachesize" || $2 == "noresolv" || $2 == "server") {
			print $1 ":" $2 ":" $3
		}
	' | LC_ALL=C sort >"$state_path"
}

exact_pid() {
	expected=$1
	for executable in /proc/[0-9]*/exe; do
		[ -L "$executable" ] || continue
		resolved=$(readlink "$executable" 2>/dev/null || true)
		case "$resolved" in "$expected"|"$expected (deleted)") basename "$(dirname "$executable")"; return 0 ;; esac
	done
	return 1
}

has_owned_listener() {
	listener_protocol=$1
	listener_pid=$2
	listener_port=$3
	if command -v ss >/dev/null 2>&1; then
		case "$listener_protocol" in
			tcp) ss -H -lnpt 2>/dev/null ;;
			udp) ss -H -lnpu 2>/dev/null ;;
			*) return 1 ;;
		esac | awk -v port="$listener_port" -v owner="pid=${listener_pid}," '
			$0 ~ (":" port "[[:space:]]") && index($0, owner) { found=1 }
			END { exit(found ? 0 : 1) }
		'
		return
	fi
	case "$listener_protocol" in
		tcp) netstat -lntp 2>/dev/null ;;
		udp) netstat -lnup 2>/dev/null ;;
		*) return 1 ;;
	esac | awk -v port="$listener_port" -v owner="${listener_pid}/" '
		$4 ~ (":" port "$") && index($NF, owner) == 1 { found=1 }
		END { exit(found ? 0 : 1) }
	'
}

controller_get() {
	controller_path=$1
	controller_output=$2
	curl --fail --silent --show-error --max-time 5 \
		--header "Authorization: Bearer ${controller_secret}" \
		"http://127.0.0.1:9090${controller_path}" >"$controller_output"
}

wait_active() {
	remaining=90
	while [ "$remaining" -gt 0 ]; do
		manager_pid=$(exact_pid "$manager_binary" 2>/dev/null || true)
		core_pid=$(exact_pid "$sing_box_binary" 2>/dev/null || true)
		if [ -f "$root/.boxctl/sing-box-controller-secret" ]; then
			controller_secret=$(tr -d '\r\n' <"$root/.boxctl/sing-box-controller-secret")
		fi
		if [ -n "$manager_pid" ] && [ -n "$core_pid" ] && [ -n "$controller_secret" ] && \
			nft list table inet clash >/dev/null 2>&1 && \
			has_owned_listener tcp "$core_pid" 7894 && has_owned_listener udp "$core_pid" 7894 && \
			has_owned_listener udp "$core_pid" 7874 && has_owned_listener tcp "$core_pid" 9090 && \
			curl --fail --silent --max-time 2 --header "Authorization: Bearer ${controller_secret}" \
				http://127.0.0.1:9090/version >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	return 1
}

assert_policy() {
	ip -N -4 rule show | grep -Eq '^1000:.*fwmark 0x1.*lookup 100.*proto 196' || die 'owned TPROXY policy rule is absent'
	ip -N -4 route show table 100 | grep -Eq '^(local|2) default dev lo.*proto 196' || die 'owned TPROXY policy route is absent'
}

assert_runtime_contract() {
	phase=$1
	core_pid=$(exact_pid "$sing_box_binary") || die "$phase sing-box process is absent"
	[ "$(readlink "/proc/${core_pid}/exe")" = "$sing_box_binary" ] || die "$phase sing-box executable identity changed"
	for listener in 'tcp 7894' 'udp 7894' 'udp 7874' 'tcp 9090'; do
		listener_protocol=${listener%% *}
		listener_port=${listener#* }
		has_owned_listener "$listener_protocol" "$core_pid" "$listener_port" || \
			die "$phase sing-box does not own ${listener_protocol}/${listener_port}"
	done
	nft list table inet clash >"${output}/nft-${phase}.txt"
	grep -Fq 'managed-by=boxctl/v1' "${output}/nft-${phase}.txt" || die "$phase nft ownership marker is absent"
	assert_policy
	[ "$(uci -q get 'dhcp.@dnsmasq[0].cachesize')" = 0 ] || die "$phase dnsmasq cache is not disabled"
	[ "$(uci -q get 'dhcp.@dnsmasq[0].noresolv')" = 1 ] || die "$phase dnsmasq resolver ownership is absent"
	[ "$(uci -q get 'dhcp.@dnsmasq[0].server')" = '127.0.0.1#7874' ] || die "$phase dnsmasq upstream differs from sing-box"
	cp "$root/.boxctl/active-gateway.json" "${output}/active-gateway-${phase}.json"
	jq -e '
		.version == 1 and .engine == "sing-box" and
		.capture.TCP.Method == "tproxy" and .capture.TCP.Port == 7894 and
		.capture.UDP.Method == "tproxy" and .capture.UDP.Port == 7894 and
		.capture.LoopMark == 2 and .plan.Mode == "tproxy" and
		.plan.Table == "clash" and .plan.Owner == "boxctl/v1" and
		.plan.DNSMode == "upstream" and .plan.DNSPort == 7874 and
		.plan.TProxyMark == 1 and .plan.LoopMark == 2 and
		.plan.CaptureCIDRsConfigured == false and (.plan.CaptureCIDRs | length) == 0
	' "${output}/active-gateway-${phase}.json" >/dev/null || die "$phase active gateway generation is inconsistent"
	[ -f "$process_state" ] && [ ! -L "$process_state" ] || die "$phase process state is missing or unsafe"
	runtime=$(jq -r '.prepared.runtimeConfigPath // empty' "$process_state")
	case "$runtime" in /tmp/boxctl-sing-box-*/sing-box-runtime.json) ;; *) die "$phase runtime path is not private sing-box state" ;; esac
	[ -f "$runtime" ] && [ ! -L "$runtime" ] || die "$phase runtime config is missing or unsafe"
	jq 'del(.experimental.clash_api.secret)' "$runtime" | jq -S . >"${output}/runtime-${phase}-sanitized.json"
	jq -e '
		([.inbounds[] | select(.type == "tproxy" and .listen_port == 7894)] | length) == 1 and
		([.inbounds[] | select(.type == "direct" and .listen_port == 7874)] | length) == 1 and
		.experimental.clash_api.external_controller == "127.0.0.1:9090"
	' "$runtime" >/dev/null || die "$phase managed inbounds/controller are inconsistent"
}

assert_stopped() {
	remaining=30
	while [ "$remaining" -gt 0 ] && [ -n "$(exact_pid "$manager_binary" 2>/dev/null || true)" ]; do
		sleep 1
		remaining=$((remaining - 1))
	done
	[ -z "$(exact_pid "$manager_binary" 2>/dev/null || true)" ] || die 'manager survived service stop'
	[ -z "$(exact_pid "$sing_box_binary" 2>/dev/null || true)" ] || die 'managed sing-box survived service stop'
	! nft list table inet clash >/dev/null 2>&1 || die 'owned nft table survived service stop'
	! ip -N -4 rule show | grep -Eq '^1000:.*proto 196' || die 'owned policy rule survived service stop'
	! ip -N -4 route show table 100 | grep -Eq '(^|[[:space:]])proto 196([[:space:]]|$)' || \
		die 'owned policy route survived service stop'
	restored=/tmp/parity-singbox-dns-restored.uci
	write_managed_dns_state "$restored"
	cmp "$dns_baseline" "$restored" >/dev/null || die 'dnsmasq settings were not restored exactly'
}

authenticate_management() {
	curl --fail --silent --show-error --max-time 5 "$api/setup" >"${output}/setup.json" || return 1
	if jq -e '.data.required == true' "${output}/setup.json" >/dev/null; then
		curl --fail --silent --show-error --max-time 10 --header 'Content-Type: application/json' \
			--data "{\"password\":\"${integration_password}\"}" \
			"$api/setup" >"${output}/setup-result.json" || return 1
	fi
	curl --fail --silent --show-error --max-time 10 --cookie-jar "$cookie_jar" --header 'Content-Type: application/json' \
		--data "{\"password\":\"${integration_password}\"}" \
		"$api/auth/login" >"${output}/login.json" || return 1
	csrf_token=$(jq -r '.data.csrfToken // empty' "${output}/login.json") || return 1
	[ -n "$csrf_token" ]
}

dns_answer() {
	query_name=$1
	query_output=$2
	ip netns exec "$client_namespace" nslookup -type=a "$query_name" 192.168.111.1 >"$query_output" 2>&1 || return 1
	awk '$1 == "Address:" && $2 !~ /:/ { answer=$2 } END { print answer }' "$query_output"
}

connection_for_port() {
	port=$1
	response=$2
	controller_get /connections "$response" || return 1
	jq -c --arg source 192.168.111.100 --arg port "$port" '
		[.connections[]? | select(
			.metadata.sourceIP == $source and
			(.metadata.destinationPort | tostring) == $port and
			(.metadata.type | startswith("tproxy")) and .metadata.network == "tcp"
		)][0] // empty
	' "$response"
}

start_flow_server() {
	label=$1
	bind_ip=$2
	port=$3
	ip netns exec "$origin_namespace" iperf3 -s -1 -B "$bind_ip" -p "$port" >"${output}/flow-${label}-server.log" 2>&1 &
	server_pid=$!
	sleep 1
	kill -0 "$server_pid" 2>/dev/null || die "$label origin server did not start"
}

run_flow() {
	label=$1
	target=$2
	bind_ip=$3
	port=$4
	rule_fragment=$5
	action_fragment=$6
	chain_proxy=$7
	chain_selector=$8
	expected_host=$9
	start_flow_server "$label" "$bind_ip" "$port"
	ip netns exec "$client_namespace" iperf3 -c "$target" -p "$port" -t 8 -b 20M -J \
		>"${output}/flow-${label}.json" 2>"${output}/flow-${label}.stderr" &
	client_pid=$!
	connection_raw="${output}/flow-${label}-connection-raw.json"
	: >"$connection_raw"
	iteration=1
	while [ "$iteration" -le 7 ]; do
		sleep 1
		candidate="${output}/flow-${label}-connections-${iteration}.json"
		matched=$(connection_for_port "$port" "$candidate" 2>/dev/null || true)
		if [ -n "$matched" ] && [ ! -s "$connection_raw" ]; then printf '%s\n' "$matched" >"$connection_raw"; fi
		curl --fail --silent --show-error --max-time 3 --cookie "$cookie_jar" \
			"$api/core/connections" >"${output}/flow-${label}-manager-connections-${iteration}.json" 2>/dev/null || true
		iteration=$((iteration + 1))
	done
	client_status=0
	wait "$client_pid" || client_status=$?
	client_pid=
	server_status=0
	wait "$server_pid" || server_status=$?
	server_pid=
	bytes=$(jq -r '.end.sum_sent.bytes // 0' "${output}/flow-${label}.json" 2>/dev/null || printf 0)
	case "$bytes" in ''|*[!0-9]*) bytes=0 ;; esac
	[ "$client_status" -eq 0 ] && [ "$server_status" -eq 0 ] && [ "$bytes" -ge 1048576 ] || \
		die "$label flow failed (client=$client_status server=$server_status bytes=$bytes)"
	[ -s "$connection_raw" ] || die "$label flow was not observed by sing-box"
	actual_rule=$(jq -r '.rule // ""' "$connection_raw")
	case "$actual_rule" in *"$rule_fragment"*"$action_fragment"*) ;; *) die "$label matched unexpected rule: $actual_rule" ;; esac
	[ "$(jq -r '.rulePayload // ""' "$connection_raw")" = '' ] || die "$label native rulePayload is not empty"
	if [ -n "$chain_proxy" ]; then
		jq -e --arg chain "$chain_proxy" '.chains | index($chain) != null' "$connection_raw" >/dev/null || \
			die "$label did not use expected chain $chain_proxy"
	fi
	if [ -n "$chain_selector" ]; then
		jq -e --arg chain "$chain_selector" '.chains | index($chain) != null' "$connection_raw" >/dev/null || \
			die "$label did not use expected chain $chain_selector"
	fi
	if [ -n "$expected_host" ]; then
		[ "$(jq -r '.metadata.host // ""' "$connection_raw")" = "$expected_host" ] || die "$label reverse-mapped host differs"
	fi
	jq -S --argjson bytes "$bytes" '{
		observed: true, dataplaneBytesAtLeast1MiB: ($bytes >= 1048576),
		rule: (.rule // ""), rulePayload: (.rulePayload // ""), chains: (.chains // []),
		sourceIP: (.metadata.sourceIP // ""), destinationIP: (.metadata.destinationIP // ""),
		destinationPort: (.metadata.destinationPort // ""), host: (.metadata.host // ""),
		dnsMode: (.metadata.dnsMode // ""), type: (.metadata.type // ""), network: (.metadata.network // "")
	}' "$connection_raw" >"${output}/flow-${label}-contract.json"
}

run_bypass_flow() {
	label=$1
	target=$2
	bind_ip=$3
	port=$4
	start_flow_server "$label" "$bind_ip" "$port"
	ip netns exec "$client_namespace" iperf3 -c "$target" -p "$port" -t 5 -b 20M -J \
		>"${output}/flow-${label}.json" 2>"${output}/flow-${label}.stderr" &
	client_pid=$!
	observed=false
	valid_snapshots=0
	iteration=1
	while [ "$iteration" -le 4 ]; do
		sleep 1
		candidate="${output}/flow-${label}-connections-${iteration}.json"
		matched=$(connection_for_port "$port" "$candidate" 2>/dev/null || true)
		if jq -e 'type == "object" and has("connections") and (.connections | type) == "array"' "$candidate" >/dev/null 2>&1; then
			valid_snapshots=$((valid_snapshots + 1))
		fi
		[ -z "$matched" ] || observed=true
		iteration=$((iteration + 1))
	done
	client_status=0; wait "$client_pid" || client_status=$?; client_pid=
	server_status=0; wait "$server_pid" || server_status=$?; server_pid=
	bytes=$(jq -r '.end.sum_sent.bytes // 0' "${output}/flow-${label}.json" 2>/dev/null || printf 0)
	case "$bytes" in ''|*[!0-9]*) bytes=0 ;; esac
	[ "$client_status" -eq 0 ] && [ "$server_status" -eq 0 ] && [ "$bytes" -ge 1048576 ] || die "$label bypass flow failed"
	[ "$valid_snapshots" -ge 3 ] || die "$label did not obtain enough valid controller snapshots"
	[ "$observed" = false ] || die "$label bypass unexpectedly entered sing-box"
	jq -S -n --argjson bytes "$bytes" '{observed:false,liveControllerSnapshotsAtLeast3:true,dataplaneBytesAtLeast1MiB:($bytes >= 1048576),rule:null,rulePayload:null,chains:[]}' \
		>"${output}/flow-${label}-contract.json"
}

run_rejected_flow() {
	label=$1
	target=$2
	bind_ip=$3
	port=$4
	start_flow_server "$label" "$bind_ip" "$port"
	set +e
	ip netns exec "$client_namespace" iperf3 -c "$target" -p "$port" -t 3 -b 20M -J \
		>"${output}/flow-${label}.json" 2>"${output}/flow-${label}.stderr"
	client_status=$?
	set -e
	[ "$client_status" -ne 0 ] || die "$label unexpectedly reached the origin"
	kill -0 "$server_pid" 2>/dev/null || die "$label origin accepted a rejected connection"
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
	server_pid=
	controller_get /rules "${output}/routing-rules-reject.json" || die 'sing-box rules endpoint is unavailable'
	jq -e 'any(.rules[]?; (.payload | contains("9.9.9.16/32")) and (.proxy | contains("reject")))' \
		"${output}/routing-rules-reject.json" >/dev/null || die 'native reject rule is absent'
	jq -S -n --argjson client_exit "$client_status" \
		'{clientExit:$client_exit,originAccepted:false,nativeRulePresent:true}' >"${output}/flow-${label}-contract.json"
}

lan_device=$(find_interface '52:54:00:11:00:01') || die 'LAN NIC not found'
wan_device=$(find_interface '52:54:00:12:00:01') || die 'WAN NIC not found'
prep_device=$(find_interface '52:54:00:13:00:01') || die 'preparation NIC not found'

note 'installing test dependencies'
ip link set "$prep_device" up
ip address flush dev "$prep_device"
ip address add 192.168.113.15/24 dev "$prep_device"
ip route replace default via 192.168.113.2 dev "$prep_device"
mkdir -p /tmp/resolv.conf.d
printf 'nameserver 192.168.113.3\n' >/tmp/resolv.conf.d/resolv.conf.auto
{
	apk update
	apk add ip-full kmod-inet-diag kmod-nft-tproxy nftables-json curl ca-bundle kmod-veth iperf3 jq microsocks uhttpd openssl-util
} >"${output}/apk.log" 2>&1 || die 'package installation failed'
/usr/sbin/uhttpd -h >"${output}/uhttpd-help.txt" 2>&1 || true
grep -q -- '-s \[addr:\]port' "${output}/uhttpd-help.txt" || die 'installed uhttpd does not expose HTTPS listener support'

note 'isolating package network'
ip route del default via 192.168.113.2 dev "$prep_device" 2>/dev/null || true
ip address flush dev "$prep_device"
ip link set "$prep_device" down
: >/tmp/resolv.conf.d/resolv.conf.auto
prep_pci=$(readlink -f "/sys/class/net/${prep_device}/device")
case "$(basename "$prep_pci")" in virtio*) prep_pci=$(dirname "$prep_pci") ;; esac
[ -w "${prep_pci}/remove" ] || die 'preparation NIC is not removable'
printf '1\n' >"${prep_pci}/remove"
printf 'INTEGRATION-ISOLATE-REQUEST\n'
IFS= read -r isolation || die 'isolation acknowledgement missing'
[ "$isolation" = INTEGRATION-ISOLATED ] || die 'host did not isolate preparation NIC'
[ ! -e "/sys/class/net/${prep_device}" ] || die 'preparation NIC survived isolation'

note 'configuring synthetic OpenWrt topology'
uci -q delete network.lan || true
uci -q delete network.wan || true
uci -q delete network.br_lan || true
if [ "$(uci -q get 'network.@device[0].name')" = br-lan ]; then uci -q delete 'network.@device[0]'; fi
uci set network.br_lan=device
uci set network.br_lan.name='br-lan'
uci set network.br_lan.type='bridge'
uci add_list network.br_lan.ports="$lan_device"
uci set network.lan=interface
uci set network.lan.device='br-lan'
uci set network.lan.proto='static'
uci set network.lan.ipaddr='192.168.111.1'
uci set network.lan.netmask='255.255.255.0'
uci set network.wan=interface
uci set network.wan.device="$wan_device"
uci set network.wan.proto='static'
uci set network.wan.ipaddr='192.168.112.15'
uci set network.wan.netmask='255.255.255.0'
uci set network.wan.gateway='192.168.112.2'
uci set network.wan.peerdns='0'
uci commit network
if uci -q get 'firewall.@zone[0]' >/dev/null 2>&1; then
	uci set 'firewall.@zone[0].name=lan'
	uci -q delete 'firewall.@zone[0].network' || true
	uci add_list 'firewall.@zone[0].network=lan'
fi
if uci -q get 'firewall.@zone[1]' >/dev/null 2>&1; then
	uci set 'firewall.@zone[1].name=wan'
	uci -q delete 'firewall.@zone[1].network' || true
	uci add_list 'firewall.@zone[1].network=wan'
fi
uci commit firewall
/etc/init.d/network restart >"${output}/network.log" 2>&1
sleep 3
/etc/init.d/firewall restart >>"${output}/network.log" 2>&1
ip -4 address show dev br-lan | grep -q 'inet 192\.168\.111\.1/24' || die 'LAN bridge is unavailable'

note 'creating isolated client, origin, and SOCKS5 namespaces'
ip netns add "$client_namespace"
ip netns add "$origin_namespace"
ip netns add "$proxy_namespace"
ip link add "$client_host" type veth peer name "$client_peer"
ip link set "$client_peer" netns "$client_namespace"
ip link set "$client_host" master br-lan
ip link set "$client_host" up
ip netns exec "$client_namespace" ip link set lo up
ip netns exec "$client_namespace" ip link set "$client_peer" up
ip netns exec "$client_namespace" ip address add 192.168.111.100/24 dev "$client_peer"
ip netns exec "$client_namespace" ip route add default via 192.168.111.1
mkdir -p "/etc/netns/${client_namespace}"
printf 'nameserver 192.168.111.1\n' >"/etc/netns/${client_namespace}/resolv.conf"

ip link add "$origin_host" type veth peer name "$origin_peer"
ip link set "$origin_peer" netns "$origin_namespace"
ip address add 9.9.9.1/24 dev "$origin_host"
ip link set "$origin_host" up
ip netns exec "$origin_namespace" ip link set lo up
ip netns exec "$origin_namespace" ip link set "$origin_peer" up
ip netns exec "$origin_namespace" ip address add 9.9.9.2/24 dev "$origin_peer"
for address in 9.9.9.10 9.9.9.11 9.9.9.12 9.9.9.13 9.9.9.14 9.9.9.15 9.9.9.16 192.0.2.10; do
	ip netns exec "$origin_namespace" ip address add "${address}/32" dev "$origin_peer"
done
ip netns exec "$origin_namespace" ip route add 192.168.111.0/24 via 9.9.9.1
ip netns exec "$origin_namespace" ip route add 10.254.0.0/24 via 9.9.9.1
ip route add 192.0.2.0/24 via 9.9.9.2 dev "$origin_host"

ip link add "$proxy_host" type veth peer name "$proxy_peer"
ip link set "$proxy_peer" netns "$proxy_namespace"
ip address add 10.254.0.1/24 dev "$proxy_host"
ip link set "$proxy_host" up
ip netns exec "$proxy_namespace" ip link set lo up
ip netns exec "$proxy_namespace" ip link set "$proxy_peer" up
ip netns exec "$proxy_namespace" ip address add 10.254.0.2/24 dev "$proxy_peer"
ip netns exec "$proxy_namespace" ip route add default via 10.254.0.1

nft insert rule inet fw4 forward iifname "br-lan" oifname "$origin_host" accept comment "parity-singbox"
nft insert rule inet fw4 forward iifname "$origin_host" oifname "br-lan" ct state established,related accept comment "parity-singbox"
nft insert rule inet fw4 forward iifname "$proxy_host" oifname "$origin_host" accept comment "parity-singbox"
nft insert rule inet fw4 forward iifname "$origin_host" oifname "$proxy_host" ct state established,related accept comment "parity-singbox"

ip netns exec "$proxy_namespace" /usr/bin/microsocks -i 10.254.0.2 -p 1080 >"${output}/proxy-local.log" 2>&1 &
local_proxy_pid=$!
ip netns exec "$proxy_namespace" /usr/bin/microsocks -i 10.254.0.2 -p 1081 >"${output}/proxy-remote.log" 2>&1 &
remote_proxy_pid=$!
sleep 1
for pid in "$local_proxy_pid" "$remote_proxy_pid"; do kill -0 "$pid" 2>/dev/null || die 'a SOCKS5 origin did not start'; done
ip netns exec "$proxy_namespace" netstat -lnt | grep -Eq '10\.254\.0\.2:1080[[:space:]]' || die 'local SOCKS5 listener is absent'
ip netns exec "$proxy_namespace" netstat -lnt | grep -Eq '10\.254\.0\.2:1081[[:space:]]' || die 'remote SOCKS5 listener is absent'

note 'starting hermetic DNS, rule-set, and TLS profile origins'
dnsmasq --no-daemon --conf-file=/dev/null --port=5353 \
	--listen-address=192.168.112.15 --bind-interfaces --no-resolv --no-hosts \
	--address=/fake.parity.integration/9.9.9.10 --address=/real.parity.integration/9.9.9.11 \
	--address=/local-rule.parity.integration/9.9.9.12 --address=/remote-rule.parity.integration/9.9.9.13 \
	--address=/remote-profile.parity.integration/9.9.9.15 --address=/#/9.9.9.9 \
	--log-queries=extra --pid-file=/tmp/parity-singbox-dns.pid >"${output}/dns-origin.log" 2>&1 &
fixture_dns_pid=$!
web_root=/tmp/parity-singbox-origin
tls_root=/tmp/parity-singbox-tls
mkdir -p "$web_root" "$tls_root"
chmod 755 "$web_root"
chmod 700 "$tls_root"
cp "$input/fixtures/parity-singbox-remote-rule-set.json" "$web_root/"
cp "$input/fixtures/parity-singbox-remote-profile.json" "$web_root/"
chmod 644 "$web_root/parity-singbox-remote-rule-set.json" "$web_root/parity-singbox-remote-profile.json"
cat >"$tls_root/ca.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=boxctl parity CA
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
cat >"$tls_root/server.cnf" <<'EOF'
[req]
distinguished_name=dn
prompt=no
[dn]
CN=192.168.112.15
EOF
cat >"$tls_root/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:192.168.112.15
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$tls_root/ca.cnf" \
	-keyout "$tls_root/ca.key" -out "$tls_root/ca.crt" >"${output}/openssl-ca.log" 2>&1 || die 'test CA generation failed'
openssl req -new -newkey rsa:2048 -nodes -config "$tls_root/server.cnf" \
	-keyout "$tls_root/server.key" -out "$tls_root/server.csr" >"${output}/openssl-server.log" 2>&1 || die 'test server CSR generation failed'
openssl x509 -req -days 2 -in "$tls_root/server.csr" -CA "$tls_root/ca.crt" -CAkey "$tls_root/ca.key" \
	-CAcreateserial -extfile "$tls_root/server.ext" -out "$tls_root/server.crt" >>"${output}/openssl-server.log" 2>&1 || die 'test server certificate signing failed'
chmod 600 "$tls_root/ca.key" "$tls_root/server.key"
chmod 644 "$tls_root/ca.crt" "$tls_root/server.crt"
cat "$tls_root/ca.crt" >>/etc/ssl/certs/ca-certificates.crt
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt "$tls_root/server.crt" >"${output}/tls-verify.txt" 2>&1 || die 'test TLS chain is not trusted'
/etc/init.d/uhttpd stop >/dev/null 2>&1 || true
/usr/sbin/uhttpd -f -h "$web_root" -p 192.168.112.15:18080 -s 192.168.112.15:18443 \
	-C "$tls_root/server.crt" -K "$tls_root/server.key" >"${output}/web-origin.log" 2>&1 &
web_origin_pid=$!
sleep 1
for pid in "$fixture_dns_pid" "$web_origin_pid"; do kill -0 "$pid" 2>/dev/null || die 'a hermetic content origin did not start'; done
curl --fail --silent --show-error --max-time 5 \
	http://192.168.112.15:18080/parity-singbox-remote-rule-set.json >"${output}/remote-rule-http.json" || die 'HTTP rule-set origin is unavailable'
curl --fail --silent --show-error --max-time 5 \
	https://192.168.112.15:18443/parity-singbox-remote-profile.json >"${output}/remote-profile-https.json" || die 'trusted HTTPS profile origin is unavailable'
cmp "$input/fixtures/parity-singbox-remote-profile.json" "${output}/remote-profile-https.json" >/dev/null || die 'HTTPS profile origin changed bytes'

uci set 'dhcp.@dnsmasq[0].cachesize=37'
uci set 'dhcp.@dnsmasq[0].noresolv=1'
uci -q delete 'dhcp.@dnsmasq[0].server' || true
uci add_list 'dhcp.@dnsmasq[0].server=192.168.112.15#5353'
uci commit dhcp
/etc/init.d/dnsmasq restart >>"${output}/network.log" 2>&1
sleep 1
write_managed_dns_state "$dns_baseline"

note 'checking kernel capabilities and installing runtime'
modprobe nft_tproxy >/dev/null 2>&1 || true
cat >"${output}/tproxy-probe.nft" <<'EOF'
table inet boxctl_parity_probe {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		meta l4proto tcp tproxy to :9
	}
}
EOF
nft -f "${output}/tproxy-probe.nft" >/dev/null 2>&1 || die 'nft TPROXY probe failed'
nft delete table inet boxctl_parity_probe
ip route add local default dev lo table 32000 protocol 196
ip rule add pref 32000 fwmark 0x7fff lookup 32000 protocol 196
ip rule del pref 32000 fwmark 0x7fff lookup 32000 protocol 196
ip route flush table 32000 protocol 196

mkdir -p "$root/bin" "$root/engines/sing-box" "$root/engines/mihomo" "$root/.boxctl" "$root/configs"
chmod 700 "$root" "$root/bin" "$root/engines/sing-box" "$root/engines/mihomo" "$root/.boxctl" "$root/configs"
cp "$input/boxctl" "$manager_binary"
cp "$input/sing-box" "$sing_box_binary"
cp "$input/fixtures/parity-singbox-local.json" "$root/configs/ParityLocal.json"
cp "$input/fixtures/parity-singbox-local.json" "$root/config.json"
cp "$input/fixtures/parity-singbox-local-rule-set.json" "$root/parity-singbox-local-rule-set.json"
cp "$input/fixtures/parity-singbox-remote-rule-set-initial.json" "$root/parity-singbox-remote-rule-set-initial.json"
cp "$input/fixtures/parity-singbox-settings" "$root/.boxctl/settings"
printf '{"name":"ParityLocal","engine":"sing-box"}\n' >"$root/.boxctl/active-profile"
chmod 700 "$manager_binary" "$sing_box_binary"
chmod 600 "$root/configs/ParityLocal.json" "$root/config.json" "$root/parity-singbox-local-rule-set.json" \
	"$root/parity-singbox-remote-rule-set-initial.json" "$root/.boxctl/settings" "$root/.boxctl/active-profile"
cp "$input/openwrt-files/etc/init.d/boxctl" /etc/init.d/boxctl
cp "$input/openwrt-files/etc/hotplug.d/iface/40-boxctl" /etc/hotplug.d/iface/40-boxctl
cp "$input/openwrt-files/etc/hotplug.d/net/99-boxctl-tun" /etc/hotplug.d/net/99-boxctl-tun
chmod 700 /etc/init.d/boxctl /etc/hotplug.d/iface/40-boxctl /etc/hotplug.d/net/99-boxctl-tun
{
	"$manager_binary" version
	"$sing_box_binary" version
} >"${output}/versions.txt" 2>&1
grep -Eq '^sing-box version 1\.14\.[0-9]+([[:space:]]|$)' "${output}/versions.txt" || die 'sing-box is outside supported 1.14.x'
"$manager_binary" config validate --engine sing-box --file "$root/configs/ParityLocal.json" \
	>"${output}/config-validate-local.txt" 2>&1 || die 'boxctl rejected the local sing-box profile before service start'

note 'starting local sing-box profile'
/etc/init.d/boxctl enable
/etc/init.d/boxctl start
wait_active || die 'local sing-box service did not become ready'
authenticate_management || die 'management authentication failed'
assert_runtime_contract local
controller_get /version "${output}/core-version.json"
controller_get /providers/proxies "${output}/native-proxy-providers.json"
controller_get /providers/rules "${output}/native-rule-providers.json"
jq -e '.providers == {}' "${output}/native-proxy-providers.json" >/dev/null || die 'sing-box unexpectedly exposes native proxy providers'
jq -e '.providers == []' "${output}/native-rule-providers.json" >/dev/null || die 'sing-box unexpectedly exposes native rule providers'

curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" "$api/core/capabilities" >"${output}/capabilities.json"
jq -e '
	.data.coreName == "sing-box" and .data.features.proxyProviders == false and .data.features.ruleProviders == false and
	.data.actions.updateProxyProvider == false and .data.actions.updateRuleProvider == false and
	.data.features.groups == true and .data.features.selection == true and .data.features.rules == true and .data.features.connections == true
' "${output}/capabilities.json" >/dev/null || die 'sing-box API capabilities are inaccurate'
for provider_kind in proxy rule; do
	provider_status=$(curl --silent --show-error --max-time 5 --output "${output}/manager-${provider_kind}-providers-unsupported.json" \
		--write-out '%{http_code}' --cookie "$cookie_jar" "$api/core/providers/${provider_kind}")
	[ "$provider_status" = 501 ] || die "$provider_kind provider API did not return 501"
	jq -e '.error.code == "unsupported"' "${output}/manager-${provider_kind}-providers-unsupported.json" >/dev/null || die "$provider_kind provider API error is not explicit"
done
curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" "$api/engines" >"${output}/engines.json"
jq -e 'any(.data[]; .id == "sing-box" and .selected == true and .running == true and .management.remoteProfiles == true and .management.proxySubscriptions == false and .management.localRuleLists == false and .management.fakeIPCapture == false)' \
	"${output}/engines.json" >/dev/null || die 'engine catalog overclaims sing-box resource management'

controller_get /proxies "${output}/native-proxies-local.json"
curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" "$api/core/proxies" >"${output}/manager-proxies-local-before.json"
jq -e 'any(.data[]; .name == "parity-local-selector" and (.options | map(.name) | index("parity-local-proxy")) != null and (.options | map(.name) | index("parity-direct")) != null)' \
	"${output}/manager-proxies-local-before.json" >/dev/null || die 'local selector/outbounds are absent'
for selected in parity-direct parity-local-proxy; do
	curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" --header 'Content-Type: application/json' \
		--header "X-CSRF-Token: ${csrf_token}" --data "{\"proxy\":\"${selected}\"}" -X PUT \
		"$api/core/proxies/parity-local-selector" >"${output}/select-local-${selected}.json"
	done
curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" "$api/core/proxies" >"${output}/manager-proxies-local-after.json"
jq -e 'any(.data[]; .name == "parity-local-selector" and .selected == "parity-local-proxy")' \
	"${output}/manager-proxies-local-after.json" >/dev/null || die 'local selector did not retain proxy choice'

note 'installing hermetic outbound enforcement counters'
nft add table inet parity_singbox
nft 'add counter inet parity_singbox local_proxy'
nft 'add counter inet parity_singbox remote_proxy'
nft 'add counter inet parity_singbox direct_block'
nft 'add chain inet parity_singbox output { type filter hook output priority filter; policy accept; }'
nft add rule inet parity_singbox output ip daddr 10.254.0.2 tcp dport 1080 counter name local_proxy accept
nft add rule inet parity_singbox output ip daddr 10.254.0.2 tcp dport 1081 counter name remote_proxy accept
nft add rule inet parity_singbox output ip daddr 9.9.9.14 tcp dport 5214 counter name direct_block reject
nft add rule inet parity_singbox output ip daddr 9.9.9.15 tcp dport 5215 counter name direct_block reject
nft list table inet parity_singbox >"${output}/outbound-enforcement-initial.txt"

note 'checking fake and real DNS plus local/remote native rule sets'
fake_answer=$(dns_answer fake.parity.integration "${output}/dns-fake.txt") || die 'fake-IP DNS query failed'
real_answer=$(dns_answer real.parity.integration "${output}/dns-real.txt") || die 'real-IP DNS query failed'
case "$fake_answer" in 198.18.*|198.19.*) ;; *) die "unexpected fake-IP answer: $fake_answer" ;; esac
[ "$real_answer" = 9.9.9.11 ] || die "unexpected real-IP answer: $real_answer"
run_flow fake-dns fake.parity.integration 9.9.9.10 5210 'fake.parity.integration' 'route(parity-direct)' parity-direct '' fake.parity.integration
run_flow real-dns real.parity.integration 9.9.9.11 5211 'final' '' parity-direct '' real.parity.integration
run_flow local-rule local-rule.parity.integration 9.9.9.12 5212 'rule_set=parity-local-rules' 'route(parity-direct)' parity-direct '' local-rule.parity.integration
run_flow remote-rule remote-rule.parity.integration 9.9.9.13 5213 'rule_set=parity-remote-rules' 'route(parity-direct)' parity-direct '' remote-rule.parity.integration
run_flow local-proxy 9.9.9.14 9.9.9.14 5214 'ip_cidr=9.9.9.14/32' 'route(parity-local-selector)' parity-local-proxy parity-local-selector ''
run_bypass_flow reserved-bypass 192.0.2.10 192.0.2.10 5216
nft add element inet clash bypass4 '{ 9.9.9.16 }'
run_bypass_flow reject-control 9.9.9.16 9.9.9.16 5217
nft delete element inet clash bypass4 '{ 9.9.9.16 }'
run_rejected_flow reject-rule 9.9.9.16 9.9.9.16 5217
grep -Fq 'fake.parity.integration' "${output}/dns-origin.log" || die 'fake flow was not resolved by isolated real DNS'
grep -Fq 'real.parity.integration' "${output}/dns-origin.log" || die 'real query did not reach isolated DNS'
controller_get /rules "${output}/native-rules-local.json"
curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" "$api/core/rules" >"${output}/manager-rules-local.json"
jq -e '
	any(.rules[]?; .payload | contains("parity-local-rules")) and
	any(.rules[]?; .payload | contains("parity-remote-rules")) and
	any(.rules[]?; (.payload | contains("9.9.9.16/32")) and (.proxy | contains("reject")))
' "${output}/native-rules-local.json" >/dev/null || die 'native routes do not expose local, remote, and reject rules'

note 'creating and activating HTTPS-backed sing-box remote profile'
remote_profile_request=/tmp/parity-singbox-remote-profile-request.json
jq -n '{name:"ParityRemote",engine:"sing-box",sourceUrl:"https://192.168.112.15:18443/parity-singbox-remote-profile.json",updateIntervalHours:24}' \
	>"$remote_profile_request"
curl --fail --silent --show-error --max-time 45 --cookie "$cookie_jar" --header 'Content-Type: application/json' \
	--header "X-CSRF-Token: ${csrf_token}" --data-binary "@${remote_profile_request}" \
	"$api/profiles" >"${output}/remote-profile-create.json"
remote_profile_id=$(jq -r '.data.id // empty' "${output}/remote-profile-create.json")
[ "$remote_profile_id" = 'sing-box:ParityRemote' ] || die "unexpected remote profile id: $remote_profile_id"
jq -e '.data.engine == "sing-box" and .data.sourceKind == "remote" and .data.hasSource == true and .data.sourceEnabled == true and .data.updateIntervalHours == 24' \
	"${output}/remote-profile-create.json" >/dev/null || die 'remote profile metadata is incomplete'
! grep -Fq '192.168.112.15' "${output}/remote-profile-create.json" || die 'remote profile API leaked source URL'
curl --fail --silent --show-error --max-time 45 --cookie "$cookie_jar" --header 'Content-Type: application/json' \
	--header "X-CSRF-Token: ${csrf_token}" --data '{}' \
	"$api/profiles/${remote_profile_id}/refresh" >"${output}/remote-profile-refresh.json"
jq -e '
	.data.id == "sing-box:ParityRemote" and .data.engine == "sing-box" and
	.data.sourceKind == "remote" and .data.hasSource == true and .data.sourceEnabled == true and
	.data.updateIntervalHours == 24 and (.data.lastError // "") == "" and
	(.data.lastCheckedAt | type == "string" and length > 0) and
	(.data.fingerprint | type == "string" and length == 64)
' \
	"${output}/remote-profile-refresh.json" >/dev/null || die 'remote profile refresh failed'
remote_profile_fingerprint=$(jq -r '.data.fingerprint' "${output}/remote-profile-refresh.json")
case "$remote_profile_fingerprint" in *[!0-9a-f]*) die 'remote profile fingerprint is not lowercase SHA-256' ;; esac
curl --fail --silent --show-error --max-time 10 --cookie "$cookie_jar" \
	"$api/profiles/${remote_profile_id}/config" >"${output}/remote-profile-config.json"
jq -rj '.data.content' "${output}/remote-profile-config.json" >"${output}/remote-profile-downloaded.json"
cmp "$input/fixtures/parity-singbox-remote-profile.json" "${output}/remote-profile-downloaded.json" >/dev/null || die 'boxctl-downloaded remote profile differs from HTTPS source'
remote_source_sha256=$(openssl dgst -sha256 "$input/fixtures/parity-singbox-remote-profile.json" | awk '{print $NF}')
remote_https_sha256=$(openssl dgst -sha256 "${output}/remote-profile-https.json" | awk '{print $NF}')
remote_download_sha256=$(openssl dgst -sha256 "${output}/remote-profile-downloaded.json" | awk '{print $NF}')
[ "$remote_source_sha256" = "$remote_https_sha256" ] && [ "$remote_source_sha256" = "$remote_download_sha256" ] && \
	[ "$remote_source_sha256" = "$remote_profile_fingerprint" ] || die 'remote profile source/fetch/API fingerprints differ'
printf 'source_sha256=%s\nhttps_sha256=%s\nmanager_config_sha256=%s\napi_fingerprint=%s\n' \
	"$remote_source_sha256" "$remote_https_sha256" "$remote_download_sha256" "$remote_profile_fingerprint" \
	>"${output}/remote-profile-content-sha256.txt"
curl --fail --silent --show-error --max-time 90 --cookie "$cookie_jar" --header 'Content-Type: application/json' \
	--header "X-CSRF-Token: ${csrf_token}" --data '{"confirmRestart":true}' \
	"$api/profiles/${remote_profile_id}/activate" >"${output}/remote-profile-activate.json"
jq -e '.data.id == "sing-box:ParityRemote" and .data.active == true' "${output}/remote-profile-activate.json" >/dev/null || die 'remote profile did not activate'
wait_active || die 'remote sing-box profile did not become ready'
assert_runtime_contract remote
jq -e '.name == "ParityRemote" and .engine == "sing-box"' "$root/.boxctl/active-profile" >/dev/null || die 'active remote profile marker is inconsistent'

curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" "$api/core/proxies" >"${output}/manager-proxies-remote.json"
jq -e 'any(.data[]; .name == "parity-remote-profile-selector" and (.options | map(.name) | index("parity-remote-profile-proxy")) != null)' \
	"${output}/manager-proxies-remote.json" >/dev/null || die 'remote-profile selector/proxy is absent'
curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" --header 'Content-Type: application/json' \
	--header "X-CSRF-Token: ${csrf_token}" --data '{"proxy":"parity-remote-profile-proxy"}' -X PUT \
	"$api/core/proxies/parity-remote-profile-selector" >"${output}/select-remote-profile-proxy.json"
run_flow remote-profile 9.9.9.15 9.9.9.15 5215 'ip_cidr=9.9.9.15/32' 'route(parity-remote-profile-selector)' parity-remote-profile-proxy parity-remote-profile-selector ''

note 'proving native dynamic provider API is unsupported'
subscription_status=$(curl --silent --show-error --max-time 10 --output "${output}/sing-proxy-subscription-unsupported.json" \
	--write-out '%{http_code}' --cookie "$cookie_jar" --header 'Content-Type: application/json' \
	--header "X-CSRF-Token: ${csrf_token}" --data '{"engine":"sing-box","name":"Unsupported","sourceUrl":"https://192.168.112.15:18443/parity-singbox-remote-profile.json"}' \
	"$api/proxy-subscriptions")
[ "$subscription_status" = 409 ] || die "sing-box proxy subscription returned HTTP $subscription_status, want 409"
jq -e '.error.code == "subscription_engine_unsupported"' "${output}/sing-proxy-subscription-unsupported.json" >/dev/null || die 'sing-box proxy subscription error is not explicit'

nft list counter inet parity_singbox local_proxy >"${output}/counter-local-proxy.txt"
nft list counter inet parity_singbox remote_proxy >"${output}/counter-remote-proxy.txt"
nft list counter inet parity_singbox direct_block >"${output}/counter-direct-block.txt"
local_proxy_packets=$(awk '/packets/ { for (i=1;i<=NF;i++) if ($i == "packets") { print $(i+1); exit } }' "${output}/counter-local-proxy.txt")
remote_proxy_packets=$(awk '/packets/ { for (i=1;i<=NF;i++) if ($i == "packets") { print $(i+1); exit } }' "${output}/counter-remote-proxy.txt")
direct_block_packets=$(awk '/packets/ { for (i=1;i<=NF;i++) if ($i == "packets") { print $(i+1); exit } }' "${output}/counter-direct-block.txt")
case "$local_proxy_packets:$remote_proxy_packets:$direct_block_packets" in *[!0-9:]*|:*|*::*) die 'could not parse hermetic outbound counters' ;; esac
[ "$local_proxy_packets" -gt 0 ] || die 'local SOCKS5 path was not traversed'
[ "$remote_proxy_packets" -gt 0 ] || die 'remote-profile SOCKS5 path was not traversed'
[ "$direct_block_packets" -eq 0 ] || die 'a tested proxy flow attempted direct egress'
nft list table inet parity_singbox >"${output}/outbound-enforcement-final.txt"

note 'writing observable and semantic contracts'
jq -S -n \
	--arg fake_answer "$fake_answer" --arg real_answer "$real_answer" \
	--argjson local_proxy_packets "$local_proxy_packets" --argjson remote_proxy_packets "$remote_proxy_packets" \
	--argjson direct_block_packets "$direct_block_packets" \
	--slurpfile version "${output}/core-version.json" \
	--slurpfile local_gateway "${output}/active-gateway-local.json" \
	--slurpfile remote_gateway "${output}/active-gateway-remote.json" \
	--slurpfile fake_flow "${output}/flow-fake-dns-contract.json" \
	--slurpfile real_flow "${output}/flow-real-dns-contract.json" \
	--slurpfile local_rule "${output}/flow-local-rule-contract.json" \
	--slurpfile remote_rule "${output}/flow-remote-rule-contract.json" \
	--slurpfile local_proxy "${output}/flow-local-proxy-contract.json" \
	--slurpfile remote_proxy "${output}/flow-remote-profile-contract.json" \
	--slurpfile bypass "${output}/flow-reserved-bypass-contract.json" \
	--slurpfile reject_control "${output}/flow-reject-control-contract.json" \
	--slurpfile reject "${output}/flow-reject-rule-contract.json" '
	{
		schema:1,
		engine:"sing-box",
		stimuli:{
			fakeDNS:{domain:"fake.parity.integration",originIP:"9.9.9.10",port:5210},
			realDNS:{domain:"real.parity.integration",originIP:"9.9.9.11",port:5211},
			localRule:{domain:"local-rule.parity.integration",originIP:"9.9.9.12",port:5212},
			remoteRule:{domain:"remote-rule.parity.integration",originIP:"9.9.9.13",port:5213},
			localProxy:{originIP:"9.9.9.14",port:5214},
			remoteProxy:{originIP:"9.9.9.15",port:5215},
			reservedBypass:{originIP:"192.0.2.10",port:5216},
			reject:{originIP:"9.9.9.16",port:5217}
		},
		engineContract:{
			controllerVersion:$version[0], listeners:["tcp:7894","tcp:9090","udp:7874","udp:7894"],
			nftOwner:"boxctl/v1", policy:{priority:1000,mark:1,table:100,protocol:196,route:"local default dev lo"},
			dnsmasqUpstream:"127.0.0.1#7874",
			fakeGateway:($local_gateway[0] | {mode:.plan.Mode,captureCIDRsConfigured:.plan.CaptureCIDRsConfigured,captureCIDRs:.plan.CaptureCIDRs,tproxyPort:.plan.TProxyPort,dnsPort:.plan.DNSPort}),
			routingGateway:($remote_gateway[0] | {mode:.plan.Mode,captureCIDRsConfigured:.plan.CaptureCIDRsConfigured,captureCIDRs:.plan.CaptureCIDRs,tproxyPort:.plan.TProxyPort,dnsPort:.plan.DNSPort})
		},
		dns:{fakeAnswer:$fake_answer,realAnswer:$real_answer,fakeFlow:$fake_flow[0],realFlow:$real_flow[0]},
		ruleProviders:{
			local:{name:"parity-local-rules",type:"RuleSet",vehicleType:"File",behavior:"domain",format:"source",ruleCount:1,native:true},
			remote:{name:"parity-remote-rules",type:"RuleSet",vehicleType:"HTTP",behavior:"domain",format:"source",ruleCount:1,native:true}
		},
		proxyProviders:{
			local:{name:"parity-local-proxy",type:"Socks",vehicleType:"NativeOutbound",count:1,proxies:[{name:"parity-local-proxy",type:"Socks",alive:true}],dynamicSupported:false,apiUnsupported:true},
			remote:{name:"ParityRemote",type:"Profile",vehicleType:"HTTPSRemoteProfile",count:1,proxies:[{name:"parity-remote-profile-proxy",type:"Socks",alive:true}],dynamicSupported:false,apiUnsupported:true}
		},
		routing:{
			localRule:$local_rule[0],remoteRule:$remote_rule[0],
			localProxy:{manager:$local_proxy[0],upstreamSOCKS5:{observed:($local_proxy_packets > 0)}},
			remoteProxy:{manager:$remote_proxy[0],upstreamSOCKS5:{observed:($remote_proxy_packets > 0)}},
			reservedBypass:$bypass[0],rejectControl:$reject_control[0],rejectRule:$reject[0],directLeak:($direct_block_packets > 0)
		}
	}
' >"${output}/contract.json"

jq -S -n \
	--arg fake_answer "$fake_answer" --arg real_answer "$real_answer" \
	--slurpfile full "${output}/contract.json" '
	{
		schema:1,
		common:{
			fakeDNS:($fake_answer | startswith("198.18.") or startswith("198.19.")), realDNS:($real_answer == "9.9.9.11"),
			localRuleMatched:$full[0].routing.localRule.observed,
			remoteRuleMatched:$full[0].routing.remoteRule.observed,
			localProxyPath:$full[0].routing.localProxy.upstreamSOCKS5.observed,
			remoteProxyPath:$full[0].routing.remoteProxy.upstreamSOCKS5.observed,
			reservedDirectBypass:($full[0].routing.reservedBypass.observed == false and $full[0].routing.reservedBypass.dataplaneBytesAtLeast1MiB),
			rejectRule:($full[0].routing.rejectRule.nativeRulePresent and ($full[0].routing.rejectRule.originAccepted == false) and ($full[0].routing.rejectControl.observed == false) and $full[0].routing.rejectControl.dataplaneBytesAtLeast1MiB),
			dataplane:{
				nftOwner:($full[0].engineContract.nftOwner == "boxctl/v1"),
				policy:($full[0].engineContract.policy == {priority:1000,mark:1,table:100,protocol:196,route:"local default dev lo"}),
				dnsUpstream:($full[0].engineContract.dnsmasqUpstream == "127.0.0.1#7874"),
				listeners:($full[0].engineContract.listeners == ["tcp:7894","tcp:9090","udp:7874","udp:7894"]),
				allTransferred:([$full[0].dns.fakeFlow,$full[0].dns.realFlow,$full[0].routing.localRule,$full[0].routing.remoteRule,$full[0].routing.localProxy.manager,$full[0].routing.remoteProxy.manager] | all(.dataplaneBytesAtLeast1MiB)),
				noDirectLeak:($full[0].routing.directLeak == false)
			}
		},
		expectedDifferences:{captureScope:"broad",nativeDynamicProxyProvider:false,remoteProxyMechanism:"https-remote-profile",nativeRulePayloadField:"empty"}
	}
' >"${output}/semantic-contract.json"

note 'checking final cleanup'
/etc/init.d/boxctl stop
assert_stopped
printf 'singbox_parity_contract=true\nsemantic_contract=true\ncleanup=true\n' >"${output}/result.txt"
note 'all sing-box parity checks passed'
