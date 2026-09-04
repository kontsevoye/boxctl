#!/bin/sh
set -eu
umask 077

[ "$#" -eq 1 ] || { printf 'usage: parity-mihomo.sh OUTPUT\n' >&2; exit 2; }
input=/mnt/integration-input
output=$1
root=/opt/boxctl
manager_binary=$root/bin/boxctl
mihomo_binary=$root/engines/mihomo/mihomo
upstream_binary=/tmp/parity-upstream-mihomo
client_namespace=parity-client
origin_namespace=parity-origin
client_host=pmc-host
client_peer=pmc-peer
origin_host=pmo-host
origin_peer=pmo-peer
dns_baseline=/tmp/parity-mihomo-dns-baseline.uci
fixture_dns_pid=
provider_http_pid=
health_http_pid=
upstream_pid=
server_pid=
client_pid=
cleanup_done=false

note() { printf 'PARITY-MIHOMO-PHASE: %s\n' "$*"; }

delete_forward_rules() {
	while :; do
		handle=$(nft -a list chain inet fw4 forward 2>/dev/null | awk '/comment "parity-mihomo"/ { print $NF; exit }')
		[ -n "$handle" ] || break
		nft delete rule inet fw4 forward handle "$handle" >/dev/null 2>&1 || break
	done
}

capture_diagnostics() {
	ubus call service list '{"name":"boxctl"}' >"${output}/service.json" 2>&1 || true
	/etc/init.d/boxctl status >"${output}/service-status.txt" 2>&1 || true
	ps w >"${output}/processes.txt" 2>&1 || true
	netstat -lntp >"${output}/listeners-tcp.txt" 2>&1 || true
	netstat -lnup >"${output}/listeners-udp.txt" 2>&1 || true
	nft list ruleset >"${output}/nft-ruleset.txt" 2>&1 || true
	ip -N -4 rule show >"${output}/ip-rules.txt" 2>&1 || true
	ip -N -4 route show table 100 >"${output}/ip-routes-100.txt" 2>&1 || true
	curl --silent --show-error --max-time 3 http://127.0.0.1:9090/version >"${output}/controller-version-diagnostic.json" 2>&1 || true
	curl --silent --show-error --max-time 3 http://127.0.0.1:9090/providers/rules >"${output}/rule-providers-diagnostic.json" 2>&1 || true
	curl --silent --show-error --max-time 3 http://127.0.0.1:9090/providers/proxies >"${output}/proxy-providers-diagnostic.json" 2>&1 || true
	"$manager_binary" doctor --root "$root" --json >"${output}/doctor-diagnostic.json" 2>&1 || true
	find "$root" -maxdepth 4 -type f -o -type l >"${output}/root-files-diagnostic.txt" 2>&1 || true
	cp "$root/.boxctl/mihomo-process.json" "${output}/process-state-diagnostic.json" 2>/dev/null || true
	cp "$root/.boxctl/active-gateway.json" "${output}/active-gateway-diagnostic.json" 2>/dev/null || true
	manager_pid=$(exact_pid "$manager_binary" 2>/dev/null || true)
	if [ -n "$manager_pid" ]; then
		tr '\000' ' ' <"/proc/${manager_pid}/cmdline" >"${output}/manager-cmdline.txt" 2>/dev/null || true
	fi
	logread >"${output}/logread.log" 2>&1 || true
}

cleanup() {
	[ "$cleanup_done" = false ] || return 0
	cleanup_done=true
	set +e
	/etc/init.d/boxctl stop >/dev/null 2>&1
	for pid in "$client_pid" "$server_pid" "$upstream_pid" "$health_http_pid" "$provider_http_pid" "$fixture_dns_pid"; do
		[ -z "$pid" ] || kill "$pid" 2>/dev/null
	done
	for pid in "$client_pid" "$server_pid" "$upstream_pid" "$health_http_pid" "$provider_http_pid" "$fixture_dns_pid"; do
		[ -z "$pid" ] || wait "$pid" 2>/dev/null
	done
	delete_forward_rules
	ip netns del "$client_namespace" >/dev/null 2>&1
	ip netns del "$origin_namespace" >/dev/null 2>&1
	ip link del "$client_host" >/dev/null 2>&1
	ip link del "$origin_host" >/dev/null 2>&1
	rm -rf "/etc/netns/${client_namespace}" >/dev/null 2>&1
}

die() {
	printf 'PARITY-MIHOMO-ERROR: %s\n' "$*" >&2
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

wait_active() {
	remaining=60
	while [ "$remaining" -gt 0 ]; do
		manager_pid=$(exact_pid "$manager_binary" 2>/dev/null || true)
		core_pid=$(exact_pid "$mihomo_binary" 2>/dev/null || true)
		if [ -n "$manager_pid" ] && [ -n "$core_pid" ] && \
			nft list table inet clash >/dev/null 2>&1 && \
			has_owned_listener tcp "$core_pid" 7894 && \
			has_owned_listener udp "$core_pid" 7894 && \
			has_owned_listener udp "$core_pid" 7874 && \
			has_owned_listener tcp "$core_pid" 9090 && \
			curl --fail --silent --max-time 2 http://127.0.0.1:9090/version >/dev/null 2>&1; then
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
	core_pid=$(exact_pid "$mihomo_binary") || die "$phase Mihomo process is absent"
	[ "$(readlink "/proc/${core_pid}/exe")" = "$mihomo_binary" ] || die "$phase Mihomo executable identity changed"
	has_owned_listener tcp "$core_pid" 7894 || die "$phase Mihomo does not own TCP/7894"
	has_owned_listener udp "$core_pid" 7894 || die "$phase Mihomo does not own UDP/7894"
	has_owned_listener udp "$core_pid" 7874 || die "$phase Mihomo does not own UDP/7874"
	has_owned_listener tcp "$core_pid" 9090 || die "$phase Mihomo does not own TCP/9090"
	nft list table inet clash >"${output}/nft-${phase}.txt"
	grep -Fq 'managed-by=boxctl/v1' "${output}/nft-${phase}.txt" || die "$phase nft ownership marker is absent"
	assert_policy
	[ "$(uci -q get 'dhcp.@dnsmasq[0].cachesize')" = 0 ] || die "$phase dnsmasq cache is not disabled"
	[ "$(uci -q get 'dhcp.@dnsmasq[0].noresolv')" = 1 ] || die "$phase dnsmasq resolver ownership is absent"
	[ "$(uci -q get 'dhcp.@dnsmasq[0].server')" = '127.0.0.1#7874' ] || die "$phase dnsmasq upstream differs from Mihomo"
	cp "$root/.boxctl/active-gateway.json" "${output}/active-gateway-${phase}.json"
	jq -e '
		.version == 1 and .engine == "mihomo" and
		.capture.TCP.Method == "tproxy" and .capture.TCP.Port == 7894 and
		.capture.UDP.Method == "tproxy" and .capture.UDP.Port == 7894 and
		.capture.LoopMark == 2 and .plan.Mode == "tproxy" and
		.plan.Table == "clash" and .plan.Owner == "boxctl/v1" and
		.plan.DNSMode == "upstream" and .plan.DNSPort == 7874 and
		.plan.TProxyMark == 1 and .plan.LoopMark == 2
	' "${output}/active-gateway-${phase}.json" >/dev/null || die "$phase active gateway generation is inconsistent"
}

assert_core_stopped() {
	[ -z "$(exact_pid "$mihomo_binary" 2>/dev/null || true)" ] || die 'managed Mihomo survived service stop'
	! nft list table inet clash >/dev/null 2>&1 || die 'owned nft table survived service stop'
	! ip -N -4 rule show | grep -Eq '^1000:.*proto 196' || die 'owned policy rule survived service stop'
	! ip -N -4 route show table 100 | grep -Eq '(^|[[:space:]])proto 196([[:space:]]|$)' || \
		die 'owned policy route survived service stop'
	restored=/tmp/parity-mihomo-dns-restored.uci
	write_managed_dns_state "$restored"
	cmp "$dns_baseline" "$restored" >/dev/null || die 'dnsmasq settings were not restored exactly'
}

assert_stopped() {
	remaining=30
	while [ "$remaining" -gt 0 ] && [ -n "$(exact_pid "$manager_binary" 2>/dev/null || true)" ]; do
		sleep 1
		remaining=$((remaining - 1))
	done
	[ -z "$(exact_pid "$manager_binary" 2>/dev/null || true)" ] || die 'manager survived service stop'
	assert_core_stopped
}

configure_phase() {
	configuration=$1
	phase=$2
	cp "$configuration" "$root/config.yaml"
	chmod 600 "$root/config.yaml"
	/etc/init.d/boxctl start
	wait_active || die "$phase service did not become ready"
	assert_runtime_contract "$phase"
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
	curl --fail --silent --max-time 3 http://127.0.0.1:9090/connections >"$response" || return 1
	jq -c --arg source 192.168.111.100 --arg port "$port" '
		[.connections[]? | select(
			.metadata.sourceIP == $source and
			(.metadata.destinationPort | tostring) == $port and
			.metadata.type == "TProxy" and .metadata.network == "tcp"
		)][0] // empty
	' "$response"
}

upstream_connection_for_port() {
	port=$1
	response=$2
	curl --fail --silent --max-time 3 http://127.0.0.1:19090/connections >"$response" || return 1
	jq -c --arg port "$port" '
		[.connections[]? | select(
			(.metadata.destinationPort | tostring) == $port and
			.metadata.network == "tcp"
		)][0] // empty
	' "$response"
}

assert_rule_kind() {
	actual=$1
	expected=$2
	case "$expected:$actual" in
		Domain:Domain|Domain:DOMAIN|RuleSet:RuleSet|RuleSet:RULE-SET|IPCIDR:IPCIDR|IPCIDR:IP-CIDR) return 0 ;;
	esac
	return 1
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
	expect_observed=$5
	expected_rule=$6
	expected_payload=$7
	expected_chain_a=$8
	expected_chain_b=$9
	start_flow_server "$label" "$bind_ip" "$port"
	ip netns exec "$client_namespace" iperf3 -c "$target" -p "$port" -t 8 -b 20M -J \
		>"${output}/flow-${label}.json" 2>"${output}/flow-${label}.stderr" &
	client_pid=$!
	connection_raw="${output}/flow-${label}-connection-raw.json"
	upstream_connection_raw="${output}/flow-${label}-upstream-connection-raw.json"
	: >"$connection_raw"
	: >"$upstream_connection_raw"
	manager_snapshot_count=0
	iteration=1
	while [ "$iteration" -le 7 ]; do
		sleep 1
		candidate="${output}/flow-${label}-connections-${iteration}.json"
		matched=
		if matched=$(connection_for_port "$port" "$candidate" 2>/dev/null) && \
			jq -e 'type == "object" and has("connections") and
				(.connections == null or (.connections | type == "array"))' \
				"$candidate" >/dev/null 2>&1; then
			manager_snapshot_count=$((manager_snapshot_count + 1))
		fi
		if [ -n "$matched" ] && [ ! -s "$connection_raw" ]; then
			printf '%s\n' "$matched" >"$connection_raw"
		fi
		upstream_candidate="${output}/flow-${label}-upstream-connections-${iteration}.json"
		upstream_matched=$(upstream_connection_for_port "$port" "$upstream_candidate" 2>/dev/null || true)
		if [ -n "$upstream_matched" ] && [ ! -s "$upstream_connection_raw" ]; then
			printf '%s\n' "$upstream_matched" >"$upstream_connection_raw"
		fi
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
	if [ "$expect_observed" = true ]; then
		[ -s "$connection_raw" ] || die "$label flow was not observed by Mihomo"
		actual_rule=$(jq -r '.rule // ""' "$connection_raw")
		assert_rule_kind "$actual_rule" "$expected_rule" || die "$label matched unexpected rule $actual_rule"
		[ "$(jq -r '.rulePayload // ""' "$connection_raw")" = "$expected_payload" ] || \
			die "$label matched unexpected rule payload"
		jq -e --arg chain "$expected_chain_a" '.chains | index($chain) != null' "$connection_raw" >/dev/null || \
			die "$label did not use expected chain $expected_chain_a"
		if [ -n "$expected_chain_b" ]; then
			jq -e --arg chain "$expected_chain_b" '.chains | index($chain) != null' "$connection_raw" >/dev/null || \
				die "$label did not use expected chain $expected_chain_b"
			[ -s "$upstream_connection_raw" ] || die "$label was not observed at the auxiliary SOCKS5 hop"
			[ "$(jq -r '.metadata.destinationIP // ""' "$upstream_connection_raw")" = "$bind_ip" ] || \
				die "$label auxiliary SOCKS5 hop used an unexpected destination"
			jq -S '{
				observed: true,
				sourceIP: (.metadata.sourceIP // ""), destinationIP: (.metadata.destinationIP // ""),
				destinationPort: (.metadata.destinationPort // ""),
				chains: (.chains // []), type: (.metadata.type // ""), network: (.metadata.network // "")
			}' "$upstream_connection_raw" >"${output}/flow-${label}-upstream-contract.json"
		fi
		jq -S '{
			observed: true,
			dataplaneBytesAtLeast1MiB: true,
			rule: (.rule // ""), rulePayload: (.rulePayload // ""), chains: (.chains // []),
			sourceIP: (.metadata.sourceIP // ""), destinationIP: (.metadata.destinationIP // ""),
			destinationPort: (.metadata.destinationPort // ""), host: (.metadata.host // ""),
			dnsMode: (.metadata.dnsMode // ""), type: (.metadata.type // ""), network: (.metadata.network // "")
		}' "$connection_raw" >"${output}/flow-${label}-contract.json"
	else
		[ "$manager_snapshot_count" -ge 3 ] || die "$label did not obtain enough live controller snapshots"
		[ ! -s "$connection_raw" ] || die "$label bypass flow unexpectedly entered Mihomo"
		jq -S -n \
			'{observed:false,liveControllerSnapshotsAtLeast3:true,dataplaneBytesAtLeast1MiB:true,rule:null,rulePayload:null,chains:[]}' \
			>"${output}/flow-${label}-contract.json"
	fi
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
	[ "$client_status" -ne 0 ] || die "$label unexpectedly reached the origin through MATCH,REJECT"
	kill -0 "$server_pid" 2>/dev/null || die "$label origin accepted a connection despite MATCH,REJECT"
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
	server_pid=
	curl --fail --silent --max-time 3 http://127.0.0.1:9090/rules >"${output}/routing-rules.json" || \
		die 'Mihomo routing rules endpoint is unavailable'
	last_rule=$(jq -c '.rules[-1] // empty' "${output}/routing-rules.json")
	[ -n "$last_rule" ] || die 'Mihomo did not expose the fallback rule'
	last_rule_type=$(printf '%s\n' "$last_rule" | jq -r '.type // ""')
	case "$last_rule_type" in Match|MATCH) ;; *) die "unexpected fallback rule type $last_rule_type" ;; esac
	[ "$(printf '%s\n' "$last_rule" | jq -r '.proxy // ""')" = REJECT ] || \
		die 'loaded fallback rule does not route to REJECT'
	printf 'client_exit=%s\n' "$client_status" >"${output}/flow-${label}-result.txt"
	printf '%s\n' "$last_rule" | jq -S '{
		clientFailed: true,
		originAccepted: false,
		rule: {type: (.type // ""), payload: (.payload // ""), proxy: (.proxy // "")}
	}' >"${output}/flow-${label}-contract.json"
}

wait_provider_contract() {
	remaining=60
	while [ "$remaining" -gt 0 ]; do
		curl --silent --show-error --max-time 10 --output "${output}/rule-provider-refresh-response.json" \
			--write-out '%{http_code}' -X PUT \
			http://127.0.0.1:9090/providers/rules/parity-remote-rules \
			>"${output}/rule-provider-refresh-status.txt" 2>"${output}/rule-provider-refresh.stderr" || true
		curl --silent --show-error --max-time 10 --output "${output}/proxy-provider-refresh-response.json" \
			--write-out '%{http_code}' -X PUT \
			http://127.0.0.1:9090/providers/proxies/parity-remote-proxies \
			>"${output}/proxy-provider-refresh-status.txt" 2>"${output}/proxy-provider-refresh.stderr" || true
		curl --silent --max-time 3 -X PUT http://127.0.0.1:9090/providers/proxies/parity-local-proxies/healthcheck >/dev/null 2>&1 || true
		curl --silent --max-time 3 -X PUT http://127.0.0.1:9090/providers/proxies/parity-remote-proxies/healthcheck >/dev/null 2>&1 || true
		if curl --fail --silent --max-time 3 http://127.0.0.1:9090/providers/rules >"${output}/rule-providers.json" 2>/dev/null && \
			curl --fail --silent --max-time 3 http://127.0.0.1:9090/providers/proxies >"${output}/proxy-providers.json" 2>/dev/null && \
			jq -e '
				.providers["parity-local-rules"].ruleCount == 1 and
				.providers["parity-remote-rules"].ruleCount == 1
			' "${output}/rule-providers.json" >/dev/null && \
			jq -e '
				(.providers["parity-local-proxies"].proxies | length) == 1 and
				(.providers["parity-remote-proxies"].proxies | length) == 1 and
				.providers["parity-local-proxies"].proxies[0].name == "parity-local-node" and
				.providers["parity-remote-proxies"].proxies[0].name == "parity-remote-node" and
				.providers["parity-local-proxies"].proxies[0].alive == true and
				.providers["parity-remote-proxies"].proxies[0].alive == true
			' "${output}/proxy-providers.json" >/dev/null; then
			return 0
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	return 1
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
	apk add ip-full kmod-tun kmod-inet-diag kmod-nft-tproxy nftables-json curl ca-bundle kmod-veth iperf3 jq
} >"${output}/apk.log" 2>&1 || die 'package installation failed'

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

note 'creating isolated client and origin'
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
mkdir -p "/etc/netns/${client_namespace}"
printf 'nameserver 192.168.111.1\n' >"/etc/netns/${client_namespace}/resolv.conf"

ip link add "$origin_host" type veth peer name "$origin_peer"
ip link set "$origin_peer" netns "$origin_namespace"
ip address add 9.9.9.1/24 dev "$origin_host"
ip link set "$origin_host" up
ip netns exec "$origin_namespace" ip link set lo up
ip netns exec "$origin_namespace" ip link set "$origin_peer" up
ip netns exec "$origin_namespace" ip address add 9.9.9.2/24 dev "$origin_peer"
for address in 9.9.9.10 9.9.9.11 9.9.9.12 9.9.9.13 9.9.9.14 9.9.9.15 9.9.9.16 9.9.9.20 9.9.9.21 192.0.2.10; do
	ip netns exec "$origin_namespace" ip address add "${address}/32" dev "$origin_peer"
done
ip netns exec "$origin_namespace" ip route add 192.168.111.0/24 via 9.9.9.1
ip route add 192.0.2.0/24 via 9.9.9.2 dev "$origin_host"
nft insert rule inet fw4 forward iifname "br-lan" oifname "$origin_host" accept comment "parity-mihomo"
nft insert rule inet fw4 forward iifname "$origin_host" oifname "br-lan" ct state established,related accept comment "parity-mihomo"

note 'starting hermetic DNS and provider origins'
dnsmasq --no-daemon --conf-file=/dev/null --port=5353 \
	--listen-address=192.168.112.15 --bind-interfaces --no-resolv --no-hosts \
	--address=/fake.parity.integration/9.9.9.10 --address=/real.parity.integration/9.9.9.11 \
	--address=/local-rule.parity.integration/9.9.9.12 --address=/remote-rule.parity.integration/9.9.9.13 \
	--address=/remote-profile.parity.integration/9.9.9.15 \
	--address=/#/9.9.9.9 --log-queries=extra --pid-file=/tmp/parity-mihomo-dns.pid \
	>"${output}/dns-origin.log" 2>&1 &
fixture_dns_pid=$!
mkdir -p /tmp/parity-mihomo-provider-origin /tmp/parity-mihomo-health
cp "$input/fixtures/parity-mihomo-remote-rules.yaml" /tmp/parity-mihomo-provider-origin/
cp "$input/fixtures/parity-mihomo-remote-proxies.yaml" /tmp/parity-mihomo-provider-origin/
printf 'ok\n' >/tmp/parity-mihomo-health/health
chmod 755 /tmp/parity-mihomo-provider-origin /tmp/parity-mihomo-health
chmod 644 /tmp/parity-mihomo-provider-origin/* /tmp/parity-mihomo-health/health
ip netns exec "$origin_namespace" /usr/sbin/uhttpd -f -p 9.9.9.21:18080 -h /tmp/parity-mihomo-provider-origin \
	>"${output}/provider-origin.log" 2>&1 &
provider_http_pid=$!
ip netns exec "$origin_namespace" /usr/sbin/uhttpd -f -p 9.9.9.20:18081 -h /tmp/parity-mihomo-health \
	>"${output}/health-origin.log" 2>&1 &
health_http_pid=$!
sleep 1
for pid in "$fixture_dns_pid" "$provider_http_pid" "$health_http_pid"; do
	kill -0 "$pid" 2>/dev/null || die 'a hermetic origin did not start'
done
ip route get 9.9.9.21 >"${output}/provider-origin-route.txt" 2>&1 || die 'provider origin route is unavailable'
curl --fail --silent --show-error --max-time 3 \
	http://9.9.9.21:18080/parity-mihomo-remote-rules.yaml \
	>"${output}/provider-origin-probe.yaml" 2>"${output}/provider-origin-probe.stderr" || \
	die 'remote provider origin is unavailable'
curl --fail --silent --show-error --max-time 3 \
	http://9.9.9.21:18080/parity-mihomo-remote-proxies.yaml \
	>"${output}/provider-origin-proxy-probe.yaml" 2>"${output}/provider-origin-proxy-probe.stderr" || \
	die 'remote proxy provider origin is unavailable'
ip netns exec "$origin_namespace" curl --fail --silent --show-error --max-time 3 \
	http://9.9.9.20:18081/health >"${output}/health-origin-probe.txt" 2>"${output}/health-origin-probe.stderr" || \
	die 'proxy health-check origin is unavailable'

uci set 'dhcp.@dnsmasq[0].cachesize=37'
uci set 'dhcp.@dnsmasq[0].noresolv=1'
uci -q delete 'dhcp.@dnsmasq[0].server' || true
uci add_list 'dhcp.@dnsmasq[0].server=192.168.112.15#5353'
uci commit dhcp
/etc/init.d/dnsmasq restart >>"${output}/network.log" 2>&1
sleep 1
write_managed_dns_state "$dns_baseline"

note 'checking kernel capabilities'
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

note 'installing manager and Mihomo instances'
mkdir -p "$root/bin" "$root/engines/mihomo" "$root/engines/sing-box" "$root/.boxctl" \
	"$root/local-rules" "$root/rule-providers" "$root/proxy-providers" /tmp/parity-upstream-home
chmod 700 "$root" "$root/bin" "$root/engines/mihomo" "$root/engines/sing-box" "$root/.boxctl" \
	"$root/local-rules"
cp "$input/boxctl" "$manager_binary"
cp "$input/mihomo" "$mihomo_binary"
cp "$input/mihomo" "$upstream_binary"
cp "$input/fixtures/parity-mihomo-settings" "$root/.boxctl/settings"
cp "$input/fixtures/parity-mihomo-local-rules.yaml" "$root/rule-providers/"
cp "$input/fixtures/parity-mihomo-capture-ipcidr.txt" "$root/local-rules/fakeip-whitelist-ipcidr.txt"
cp "$input/fixtures/parity-mihomo-local-proxies.yaml" "$root/proxy-providers/"
cp "$input/fixtures/parity-mihomo-upstream.yaml" /tmp/parity-upstream-home/config.yaml
chmod 700 "$manager_binary" "$mihomo_binary" "$upstream_binary"
chmod 600 "$root/.boxctl/settings" "$root/rule-providers/parity-mihomo-local-rules.yaml" \
	"$root/local-rules/fakeip-whitelist-ipcidr.txt" \
	"$root/proxy-providers/parity-mihomo-local-proxies.yaml" /tmp/parity-upstream-home/config.yaml
cp "$input/openwrt-files/etc/init.d/boxctl" /etc/init.d/boxctl
cp "$input/openwrt-files/etc/hotplug.d/iface/40-boxctl" /etc/hotplug.d/iface/40-boxctl
cp "$input/openwrt-files/etc/hotplug.d/net/99-boxctl-tun" /etc/hotplug.d/net/99-boxctl-tun
chmod 700 /etc/init.d/boxctl /etc/hotplug.d/iface/40-boxctl /etc/hotplug.d/net/99-boxctl-tun
{
	"$manager_binary" version
	"$mihomo_binary" -v
} >"${output}/versions.txt" 2>&1

"$upstream_binary" -d /tmp/parity-upstream-home -f /tmp/parity-upstream-home/config.yaml \
	>"${output}/upstream-mihomo.log" 2>&1 &
upstream_pid=$!
remaining=30
while [ "$remaining" -gt 0 ]; do
	if curl --fail --silent --max-time 2 http://127.0.0.1:19090/version >/dev/null 2>&1; then break; fi
	sleep 1
	remaining=$((remaining - 1))
done
curl --fail --silent --max-time 2 http://127.0.0.1:19090/version >"${output}/upstream-version.json" || \
	die 'auxiliary SOCKS5 Mihomo did not become ready'

note 'checking fake-IP and real-IP DNS behavior'
/etc/init.d/boxctl enable
[ ! -e "$root/proxy-providers/parity-mihomo-remote-proxies-cache.yaml" ] || \
	die 'remote proxy provider cache exists before startup'
[ ! -e "$root/rule-providers/parity-mihomo-remote-rules-cache.yaml" ] || \
	die 'remote rule provider cache exists before startup'
configure_phase "$input/fixtures/parity-mihomo-fake.yaml" fake
jq -e '
	.plan.CaptureCIDRsConfigured == true and
	(.plan.CaptureCIDRs | index("198.18.0.0/15")) != null and
	(.plan.CaptureCIDRs | index("9.9.9.0/24")) != null
' "${output}/active-gateway-fake.json" >/dev/null || die 'expected fake-IP and fixture capture ranges are absent'
grep -Fq '198.18.0.0/15' "${output}/nft-fake.txt" || die 'fake-IP capture range is absent from nftables'
grep -Fq '9.9.9.0/24' "${output}/nft-fake.txt" || die 'fixture capture range is absent from nftables'
curl --fail --silent --show-error --max-time 3 \
	http://9.9.9.21:18080/parity-mihomo-remote-rules.yaml >"${output}/provider-origin-post-start-rules.yaml" || \
	die 'post-start remote rule provider origin is unavailable'
curl --fail --silent --show-error --max-time 3 \
	http://9.9.9.21:18080/parity-mihomo-remote-proxies.yaml >"${output}/provider-origin-post-start-proxies.yaml" || \
	die 'post-start remote proxy provider origin is unavailable'
cmp "$input/fixtures/parity-mihomo-remote-rules.yaml" "${output}/provider-origin-post-start-rules.yaml" >/dev/null || \
	die 'post-start remote rule response differs from its fixture'
cmp "$input/fixtures/parity-mihomo-remote-proxies.yaml" "${output}/provider-origin-post-start-proxies.yaml" >/dev/null || \
	die 'post-start remote proxy response differs from its fixture'
wait_provider_contract || die 'local and remote providers did not become healthy'
case "$(cat "${output}/rule-provider-refresh-status.txt"):$(cat "${output}/proxy-provider-refresh-status.txt")" in
	200:200|200:204|204:200|204:204) ;;
	*) die 'explicit remote provider refresh endpoints did not succeed' ;;
esac
[ -f "$root/proxy-providers/parity-mihomo-remote-proxies-cache.yaml" ] || \
	die 'remote proxy provider cache was not materialized'
cmp "$input/fixtures/parity-mihomo-remote-proxies.yaml" \
	"$root/proxy-providers/parity-mihomo-remote-proxies-cache.yaml" >/dev/null || \
	die 'remote proxy provider cache differs from the HTTP fixture'
[ -f "$root/rule-providers/parity-mihomo-remote-rules-cache.yaml" ] || \
	die 'remote rule provider cache was not materialized'
cmp "$input/fixtures/parity-mihomo-remote-rules.yaml" \
	"$root/rule-providers/parity-mihomo-remote-rules-cache.yaml" >/dev/null || \
	die 'remote rule provider cache differs from the HTTP fixture'
fake_answer=$(dns_answer fake.parity.integration "${output}/dns-fake.txt") || die 'fake-IP DNS query failed'
real_answer=$(dns_answer real.parity.integration "${output}/dns-real.txt") || die 'real-IP DNS query failed'
case "$fake_answer" in 198.18.*|198.19.*) ;; *) die "unexpected fake-IP DNS answer: $fake_answer" ;; esac
[ "$real_answer" = 9.9.9.11 ] || die "unexpected real-IP DNS answer: $real_answer"
run_flow fake-dns fake.parity.integration 9.9.9.10 5210 true Domain fake.parity.integration DIRECT ''
run_flow real-dns real.parity.integration 9.9.9.11 5211 true Domain real.parity.integration DIRECT ''
grep -Fq 'fake.parity.integration' "${output}/dns-origin.log" || die 'fake DNS query did not reach the isolated upstream'
grep -Fq 'real.parity.integration' "${output}/dns-origin.log" || die 'real DNS query did not reach the isolated upstream'
curl --fail --silent --max-time 3 http://127.0.0.1:9090/version | jq -S . >"${output}/core-version.json"

jq -S '{
	local: (.providers["parity-local-rules"] | {
		name, type, vehicleType, behavior, format, ruleCount
	}),
	remote: (.providers["parity-remote-rules"] | {
		name, type, vehicleType, behavior, format, ruleCount
	})
}' "${output}/rule-providers.json" >"${output}/rule-provider-contract.json"
jq -S '{
	local: (.providers["parity-local-proxies"] | {
		name, type, vehicleType,
		count: (.proxies | length),
		proxies: [.proxies[] | {name, type, alive}]
	}),
	remote: (.providers["parity-remote-proxies"] | {
		name, type, vehicleType,
		count: (.proxies | length),
		proxies: [.proxies[] | {name, type, alive}]
	})
}' "${output}/proxy-providers.json" >"${output}/proxy-provider-contract.json"

run_flow local-rule local-rule.parity.integration 9.9.9.12 5212 true RuleSet parity-local-rules DIRECT ''
run_flow remote-rule remote-rule.parity.integration 9.9.9.13 5213 true RuleSet parity-remote-rules DIRECT ''
run_flow local-proxy 9.9.9.14 9.9.9.14 5214 true IPCIDR 9.9.9.14/32 PARITY-LOCAL-PROXY parity-local-node
run_flow remote-proxy 9.9.9.15 9.9.9.15 5215 true IPCIDR 9.9.9.15/32 PARITY-REMOTE-PROXY parity-remote-node
run_flow reserved-bypass 192.0.2.10 192.0.2.10 5216 false none '' '' ''
nft add element inet clash proxy_servers4 '{ 9.9.9.16 }'
run_flow reject-control 9.9.9.16 9.9.9.16 5217 false none '' '' ''
nft delete element inet clash proxy_servers4 '{ 9.9.9.16 }'
run_rejected_flow fallback-reject 9.9.9.16 9.9.9.16 5217

note 'writing normalized observable contract'
jq -S -n \
	--arg fake_answer "$fake_answer" --arg real_answer "$real_answer" \
	--slurpfile version "${output}/core-version.json" \
	--slurpfile gateway "${output}/active-gateway-fake.json" \
	--slurpfile fake_flow "${output}/flow-fake-dns-contract.json" \
	--slurpfile real_flow "${output}/flow-real-dns-contract.json" \
	--slurpfile rule_providers "${output}/rule-provider-contract.json" \
	--slurpfile proxy_providers "${output}/proxy-provider-contract.json" \
	--slurpfile local_rule "${output}/flow-local-rule-contract.json" \
	--slurpfile remote_rule "${output}/flow-remote-rule-contract.json" \
	--slurpfile local_proxy "${output}/flow-local-proxy-contract.json" \
	--slurpfile local_proxy_hop "${output}/flow-local-proxy-upstream-contract.json" \
	--slurpfile remote_proxy "${output}/flow-remote-proxy-contract.json" \
	--slurpfile remote_proxy_hop "${output}/flow-remote-proxy-upstream-contract.json" \
	--slurpfile bypass "${output}/flow-reserved-bypass-contract.json" \
	--slurpfile reject_control "${output}/flow-reject-control-contract.json" \
	--slurpfile fallback_reject "${output}/flow-fallback-reject-contract.json" '
	{
		schema: 1,
		engine: "mihomo",
		stimuli: {
			fakeDNS: {domain:"fake.parity.integration",originIP:"9.9.9.10",port:5210},
			realDNS: {domain:"real.parity.integration",originIP:"9.9.9.11",port:5211},
			localRule: {domain:"local-rule.parity.integration",originIP:"9.9.9.12",port:5212},
			remoteRule: {domain:"remote-rule.parity.integration",originIP:"9.9.9.13",port:5213},
			localProxy: {originIP:"9.9.9.14",port:5214},
			remoteProxy: {originIP:"9.9.9.15",port:5215},
			reservedBypass: {originIP:"192.0.2.10",port:5216},
			reject: {originIP:"9.9.9.16",port:5217}
		},
		engineContract: {
			controllerVersion: $version[0],
			listeners: ["tcp:7894", "tcp:9090", "udp:7874", "udp:7894"],
			nftOwner: "boxctl/v1",
			policy: {priority: 1000, mark: 1, table: 100, protocol: 196, route: "local default dev lo"},
			dnsmasqUpstream: "127.0.0.1#7874",
			captureScope: "selective-fake-plus-fixture-cidr",
			combinedGateway: ($gateway[0] | {
				mode: .plan.Mode, captureCIDRsConfigured: .plan.CaptureCIDRsConfigured,
				captureCIDRs: .plan.CaptureCIDRs, tproxyPort: .plan.TProxyPort, dnsPort: .plan.DNSPort
			})
		},
		dns: {
			fakeAnswer: $fake_answer,
			realAnswer: $real_answer,
			fakeFlow: $fake_flow[0],
			realFlow: $real_flow[0]
		},
		ruleProviders: $rule_providers[0],
		proxyProviders: $proxy_providers[0],
		routing: {
			localRule: $local_rule[0],
			remoteRule: $remote_rule[0],
			localProxy: {manager: $local_proxy[0], upstreamSOCKS5: $local_proxy_hop[0]},
			remoteProxy: {manager: $remote_proxy[0], upstreamSOCKS5: $remote_proxy_hop[0]},
			reservedBypass: $bypass[0],
			rejectControl: $reject_control[0],
			fallbackReject: $fallback_reject[0]
		}
	}
' >"${output}/contract.json"

jq -S -n \
	--arg fake_answer "$fake_answer" --arg real_answer "$real_answer" \
	--slurpfile full "${output}/contract.json" '
	{
		schema: 1,
		common: {
			fakeDNS: (($fake_answer | startswith("198.18.")) or ($fake_answer | startswith("198.19."))),
			realDNS: ($real_answer == "9.9.9.11"),
			localRuleMatched: $full[0].routing.localRule.observed,
			remoteRuleMatched: $full[0].routing.remoteRule.observed,
			localProxyPath: $full[0].routing.localProxy.upstreamSOCKS5.observed,
			remoteProxyPath: $full[0].routing.remoteProxy.upstreamSOCKS5.observed,
			reservedDirectBypass: (
				$full[0].routing.reservedBypass.observed == false and
				$full[0].routing.reservedBypass.dataplaneBytesAtLeast1MiB
			),
			rejectRule: (
				$full[0].routing.fallbackReject.clientFailed and
				$full[0].routing.fallbackReject.originAccepted == false and
				$full[0].routing.fallbackReject.rule.proxy == "REJECT" and
				$full[0].routing.rejectControl.observed == false and
				$full[0].routing.rejectControl.dataplaneBytesAtLeast1MiB
			),
			dataplane: {
				nftOwner: ($full[0].engineContract.nftOwner == "boxctl/v1"),
				policy: ($full[0].engineContract.policy == {priority:1000,mark:1,table:100,protocol:196,route:"local default dev lo"}),
				dnsUpstream: ($full[0].engineContract.dnsmasqUpstream == "127.0.0.1#7874"),
				listeners: ($full[0].engineContract.listeners == ["tcp:7894","tcp:9090","udp:7874","udp:7894"]),
				allTransferred: ([
					$full[0].dns.fakeFlow,$full[0].dns.realFlow,
					$full[0].routing.localRule,$full[0].routing.remoteRule,
					$full[0].routing.localProxy.manager,$full[0].routing.remoteProxy.manager
				] | all(.dataplaneBytesAtLeast1MiB)),
				noDirectLeak: (
					$full[0].routing.localProxy.upstreamSOCKS5.observed and
					$full[0].routing.remoteProxy.upstreamSOCKS5.observed
				)
			}
		},
		expectedDifferences: {
			captureScope: "selective-fake-plus-fixture-cidr",
			nativeDynamicProxyProvider: true,
			remoteProxyMechanism: "native-proxy-provider",
			nativeRulePayloadField: "typed-payload"
		}
	}
' >"${output}/semantic-contract.json"

note 'checking final cleanup'
/etc/init.d/boxctl stop
assert_stopped
printf 'mihomo_parity_contract=true\nsemantic_contract=true\ncleanup=true\n' >"${output}/result.txt"
note 'all Mihomo parity checks passed'
