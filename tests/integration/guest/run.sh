#!/bin/sh
set -eu
umask 077

input=/mnt/integration-input
output=$1
root=/opt/boxctl
api=http://192.168.111.1:9091/api/v1
integration_password=integration-password
cookie_jar=/tmp/boxctl-integration-cookies
csrf_token=
mihomo_binary=$root/engines/mihomo/mihomo
sing_box_binary=$root/engines/sing-box/sing-box
process_state=$root/.boxctl/mihomo-process.json
dns_baseline_uci=/tmp/boxctl-integration-dhcp-before.uci

die() { printf 'INTEGRATION-ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf 'INTEGRATION-PHASE: %s\n' "$*"; }

write_managed_dns_state() {
	state_path=$1
	uci -q export dhcp | awk '
		$1 == "config" { if (dnsmasq) exit; dnsmasq = ($2 == "dnsmasq"); next }
		dnsmasq && ($1 == "option" || $1 == "list") && ($2 == "cachesize" || $2 == "noresolv" || $2 == "server") {
			print $1 ":" $2 ":" $3
		}
	' | LC_ALL=C sort >"$state_path"
}

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

note 'isolating the package network'
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

note 'starting hermetic DNS upstream'
dnsmasq --no-daemon --conf-file=/dev/null --port=5353 \
	--listen-address=192.168.112.15 --bind-interfaces --no-resolv --no-hosts \
	--address=/#/9.9.9.9 --log-queries=extra \
	--pid-file=/tmp/boxctl-integration-dns.pid \
	>"${output}/dns-upstream.log" 2>&1 &
fixture_dns_pid=$!
sleep 1
kill -0 "$fixture_dns_pid" 2>/dev/null || die 'hermetic DNS upstream did not start'
uci set 'dhcp.@dnsmasq[0].cachesize=37'
uci set 'dhcp.@dnsmasq[0].noresolv=1'
uci -q delete 'dhcp.@dnsmasq[0].server' || true
uci add_list 'dhcp.@dnsmasq[0].server=192.168.112.15#5353'
uci commit dhcp
/etc/init.d/dnsmasq restart >>"${output}/network.log" 2>&1
sleep 1
kill -0 "$fixture_dns_pid" 2>/dev/null || die 'hermetic DNS upstream did not survive the baseline dnsmasq restart'
write_managed_dns_state "$dns_baseline_uci"
nslookup -type=a preflight.boxctl.integration 127.0.0.1 >"${output}/dns-preflight.txt" 2>&1 || die 'baseline DNS query failed'
grep -Fq '9.9.9.9' "${output}/dns-preflight.txt" || die 'baseline DNS query did not reach the hermetic upstream'

note 'checking kernel capabilities'
modprobe tun >/dev/null 2>&1 || true
modprobe nft_tproxy >/dev/null 2>&1 || true
[ -c /dev/net/tun ] || die '/dev/net/tun is unavailable'
cat >"${output}/tproxy-probe.nft" <<'EOF'
table inet boxctl_integration_probe {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		meta l4proto tcp tproxy to :9
	}
}
EOF
nft -f "${output}/tproxy-probe.nft" >/dev/null 2>&1 || die 'nft TPROXY probe failed'
nft delete table inet boxctl_integration_probe
ip route add local default dev lo table 32000 protocol 196
ip rule add pref 32000 fwmark 0x7fff lookup 32000 protocol 196
ip rule del pref 32000 fwmark 0x7fff lookup 32000 protocol 196
ip route flush table 32000 protocol 196

note 'installing boxctl and both engine test instances'
mkdir -p "$root/bin" "$root/engines/mihomo" "$root/engines/sing-box" "$root/.boxctl"
chmod 700 "$root" "$root/bin" "$root/engines/mihomo" "$root/engines/sing-box" "$root/.boxctl"
cp "$input/boxctl" "$root/bin/boxctl"
cp "$input/mihomo" "$mihomo_binary"
cp "$input/sing-box" "$sing_box_binary"
cp "$input/fixtures/config.yaml" "$root/config.yaml"
cp "$input/fixtures/settings" "$root/.boxctl/settings"
chmod 700 "$root/bin/boxctl" "$mihomo_binary" "$sing_box_binary"
chmod 600 "$root/config.yaml" "$root/.boxctl/settings"
cp "$input/openwrt-files/etc/init.d/boxctl" /etc/init.d/boxctl
cp "$input/openwrt-files/etc/hotplug.d/iface/40-boxctl" /etc/hotplug.d/iface/40-boxctl
cp "$input/openwrt-files/etc/hotplug.d/net/99-boxctl-tun" /etc/hotplug.d/net/99-boxctl-tun
chmod 700 /etc/init.d/boxctl /etc/hotplug.d/iface/40-boxctl /etc/hotplug.d/net/99-boxctl-tun
{
	"$root/bin/boxctl" version
	"$mihomo_binary" -v
	"$sing_box_binary" version
} >"${output}/versions.txt" 2>&1
grep -Eq '^sing-box version 1\.14\.[0-9]+([[:space:]]|$)' "${output}/versions.txt" || die 'sing-box is outside the supported 1.14.x range'

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

assert_owned_listeners() {
	listener_pid=$1
	listener_label=$2
	has_owned_listener tcp "$listener_pid" 7894 || die "$listener_label does not own the TCP TPROXY listener"
	has_owned_listener udp "$listener_pid" 7894 || die "$listener_label does not own the UDP TPROXY listener"
	has_owned_listener udp "$listener_pid" 7874 || die "$listener_label does not own the DNS listener"
	has_owned_listener tcp "$listener_pid" 9090 || die "$listener_label does not own the controller listener"
}

wait_active() {
	remaining=60
	while [ "$remaining" -gt 0 ]; do
		manager_pid=$(exact_pid "$root/bin/boxctl" 2>/dev/null || true)
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

wait_managed_engine() {
	wait_engine=$1
	wait_binary=$2
	wait_profile=$3
	case "$wait_engine" in
		mihomo) wait_other_binary=$sing_box_binary ;;
		sing-box) wait_other_binary=$mihomo_binary ;;
		*) return 1 ;;
	esac
	wait_status=/tmp/boxctl-integration-engine-status.json
	wait_remaining=60
	while [ "$wait_remaining" -gt 0 ]; do
		manager_pid=$(exact_pid "$root/bin/boxctl" 2>/dev/null || true)
		core_pid=$(exact_pid "$wait_binary" 2>/dev/null || true)
		other_pid=$(exact_pid "$wait_other_binary" 2>/dev/null || true)
		if [ -n "$manager_pid" ] && [ -n "$core_pid" ] && [ -z "$other_pid" ] && \
			nft list table inet clash >/dev/null 2>&1 && \
			has_owned_listener tcp "$core_pid" 7894 && \
			has_owned_listener udp "$core_pid" 7894 && \
			has_owned_listener udp "$core_pid" 7874 && \
			has_owned_listener tcp "$core_pid" 9090 && \
			curl --fail --silent --max-time 2 --cookie "$cookie_jar" "$api/status" >"$wait_status" 2>/dev/null && \
			jq -e --arg engine "$wait_engine" --arg profile "$wait_profile" '
				.data.healthy == true and .data.core.state == "running" and
				.data.selectedEngine == $engine and .data.runningEngine == $engine and
				.data.activeProfile.id == $profile and .data.activeProfile.engine == $engine and
				(.data.transition // "") == ""
			' "$wait_status" >/dev/null; then
			cp "$wait_status" "${output}/status-${wait_engine}.json"
			return 0
		fi
		sleep 1
		wait_remaining=$((wait_remaining - 1))
	done
	return 1
}

wait_replacement_manager() {
	replaced_manager_pid=$1
	replacement_remaining=60
	while [ "$replacement_remaining" -gt 0 ]; do
		replacement_manager_pid=$(exact_pid "$root/bin/boxctl" 2>/dev/null || true)
		if [ -n "$replacement_manager_pid" ] && [ "$replacement_manager_pid" != "$replaced_manager_pid" ]; then
			manager_pid=$replacement_manager_pid
			return 0
		fi
		sleep 1
		replacement_remaining=$((replacement_remaining - 1))
	done
	return 1
}

assert_process_identity() {
	identity_engine=$1
	identity_binary=$2
	identity_pid=$3
	identity_label=$4
	[ "$(readlink "/proc/${identity_pid}/exe")" = "$identity_binary" ] || die "$identity_label executable identity changed"
	[ -f "$process_state" ] && [ ! -L "$process_state" ] || die "$identity_label process state is missing or unsafe"
	identity_runtime=$(jq -r '.prepared.runtimeConfigPath // empty' "$process_state")
	case "$identity_engine:$identity_runtime" in
		mihomo:/tmp/boxctl-mihomo-*/mihomo-runtime.yaml) ;;
		sing-box:/tmp/boxctl-sing-box-*/sing-box-runtime.json) ;;
		*) die "$identity_label runtime path is not engine-owned" ;;
	esac
	[ -f "$identity_runtime" ] && [ ! -L "$identity_runtime" ] || die "$identity_label runtime config is missing or unsafe"
	[ "$(find "$identity_runtime" -prune -type f -perm 0600 -print)" = "$identity_runtime" ] || die "$identity_label runtime config is not private"
	identity_runtime_dir=$(dirname "$identity_runtime")
	[ "$(find "$identity_runtime_dir" -prune -type d -perm 0700 -print)" = "$identity_runtime_dir" ] || die "$identity_label runtime directory is not private"
	jq -e --arg engine "$identity_engine" --arg binary "$identity_binary" \
		--arg root "$root" --arg runtime "$identity_runtime" --argjson pid "$identity_pid" '
		.version == 2 and .engine == $engine and .pid == $pid and
		.executable == $binary and (.identity | type) == "string" and (.identity | length) > 0 and
		.prepared.engine == $engine and .prepared.binaryPath == $binary and
		.prepared.runtimeConfigPath == $runtime and
		(if $engine == "mihomo" then
			.argv == [$binary, "-d", $root, "-f", $runtime] and
			.prepared.args == ["-d", $root, "-f", $runtime]
		else
			.argv == [$binary, "run", "-D", $root, "-c", $runtime] and
			.prepared.args == ["run", "-D", $root, "-c", $runtime]
		end)
	' "$process_state" >/dev/null || die "$identity_label persisted process identity is inconsistent"
	tr '\000' '\n' <"/proc/${identity_pid}/cmdline" >"${output}/argv-${identity_label}.txt"
	jq -r '.argv[]' "$process_state" >"${output}/argv-${identity_label}-persisted.txt"
	cmp "${output}/argv-${identity_label}.txt" "${output}/argv-${identity_label}-persisted.txt" >/dev/null || die "$identity_label live argv differs from process state"
	cp "$process_state" "${output}/process-state-${identity_label}.json"
	assert_owned_listeners "$identity_pid" "$identity_label"
}

assert_engine_dataplane() {
	dataplane_engine=$1
	dataplane_label=$2
	[ ! -e "$root/.boxctl/profile-transition.v1.json" ] || die "$dataplane_label profile transition journal survived"
	jq -e --arg engine "$dataplane_engine" '
		.version == 1 and .engine == $engine and
		.capture.TCP.Method == "tproxy" and .capture.TCP.Port == 7894 and
		.capture.UDP.Method == "tproxy" and .capture.UDP.Port == 7894 and
		.capture.LoopMark == 2 and
		.plan.Mode == "tproxy" and .plan.Table == "clash" and
		.plan.Owner == "boxctl/v1" and .plan.TProxyPort == 7894 and
		.plan.DNSMode == "upstream" and .plan.DNSPort == 7874 and
		.plan.TProxyMark == 1 and .plan.LoopMark == 2
	' "$root/.boxctl/active-gateway.json" >/dev/null || die "$dataplane_label active gateway generation is inconsistent"
	nft list table inet clash >"${output}/nft-${dataplane_label}.txt"
	grep -Fq 'managed-by=boxctl/v1' "${output}/nft-${dataplane_label}.txt" || die "$dataplane_label nft ownership marker is absent"
	assert_policy
	"$root/bin/boxctl" fw diagnose >"${output}/diagnose-${dataplane_label}.json"
}

assert_dns_upstream() {
	dns_label=$1
	[ "$(uci -q get 'dhcp.@dnsmasq[0].cachesize')" = 0 ] || die "$dns_label dnsmasq cache ownership is absent"
	[ "$(uci -q get 'dhcp.@dnsmasq[0].noresolv')" = 1 ] || die "$dns_label dnsmasq noresolv ownership is absent"
	[ "$(uci -q get 'dhcp.@dnsmasq[0].server')" = '127.0.0.1#7874' ] || die "$dns_label dnsmasq upstream is not exactly the core"
	write_managed_dns_state "${output}/dns-uci-${dns_label}.txt"
	printf "list:server:'127.0.0.1#7874'\noption:cachesize:'0'\noption:noresolv:'1'\n" \
		>"${output}/dns-uci-${dns_label}-expected.txt"
	cmp "${output}/dns-uci-${dns_label}-expected.txt" "${output}/dns-uci-${dns_label}.txt" >/dev/null || \
		die "$dns_label dnsmasq managed option kinds or values are inconsistent"
	kill -0 "$fixture_dns_pid" 2>/dev/null || die "$dns_label hermetic DNS upstream exited"
	nslookup -type=a "${dns_label}.boxctl.integration" 127.0.0.1 >"${output}/dns-${dns_label}.txt" 2>&1 || die "$dns_label DNS query failed"
	grep -Fq '9.9.9.9' "${output}/dns-${dns_label}.txt" || die "$dns_label DNS response did not traverse the explicit upstream"
}

assert_dns_restored() {
	restored_label=$1
	restored_uci="${output}/dns-restored-${restored_label}.uci"
	write_managed_dns_state "$restored_uci"
	cmp "$dns_baseline_uci" "$restored_uci" >/dev/null || die "$restored_label dnsmasq UCI was not restored exactly"
	kill -0 "$fixture_dns_pid" 2>/dev/null || die "$restored_label hermetic DNS upstream exited"
	nslookup -type=a "${restored_label}.boxctl.integration" 127.0.0.1 >"${output}/dns-restored-${restored_label}.txt" 2>&1 || \
		die "$restored_label restored DNS query failed"
	grep -Fq '9.9.9.9' "${output}/dns-restored-${restored_label}.txt" || \
		die "$restored_label restored DNS did not reach the original upstream"
}

capture_service_diagnostics() {
	ubus call service list '{"name":"boxctl"}' >"${output}/service.json" 2>&1 || true
	ps w >"${output}/processes.txt" 2>&1 || true
	netstat -lntp >"${output}/listeners.txt" 2>&1 || true
	netstat -lnup >"${output}/listeners-udp.txt" 2>&1 || true
	if command -v ss >/dev/null 2>&1; then
		ss -H -lnpt >"${output}/ss-tcp.txt" 2>&1 || true
		ss -H -lnpu >"${output}/ss-udp.txt" 2>&1 || true
	fi
	curl --silent --show-error --max-time 5 http://127.0.0.1:9090/version >"${output}/controller-version.json" 2>"${output}/controller-version.stderr" || true
	/etc/init.d/boxctl status >"${output}/service-status.txt" 2>&1 || true
	"$root/bin/boxctl" doctor --root "$root" --json >"${output}/doctor.json" 2>"${output}/doctor.stderr" || true
	nft list ruleset >"${output}/nft-ruleset.txt" 2>&1 || true
	ip -N -4 rule show >"${output}/ip-rules.txt" 2>&1 || true
	curl --silent --show-error --max-time 5 "$api/setup" >"${output}/setup.json" 2>"${output}/setup.stderr" || true
	curl --silent --show-error --max-time 5 --header 'Content-Type: application/json' \
		--data "{\"password\":\"${integration_password}\"}" \
		"$api/setup" >"${output}/setup-result.json" 2>>"${output}/setup.stderr" || true
	curl --silent --show-error --max-time 10 --cookie-jar "$cookie_jar" --header 'Content-Type: application/json' \
		--data "{\"password\":\"${integration_password}\"}" \
		"$api/auth/login" >"${output}/login.json" 2>"${output}/login.stderr" || true
	curl --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/status" >"${output}/status.json" 2>"${output}/status.stderr" || true
	curl --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/logs/system" >"${output}/system-logs.json" 2>"${output}/system-logs.stderr" || true
	cp "$root/.boxctl/active-gateway.json" "${output}/active-gateway-diagnostic.json" 2>/dev/null || true
	cp "$process_state" "${output}/process-state-diagnostic.json" 2>/dev/null || true
	manager_pid=$(exact_pid "$root/bin/boxctl" 2>/dev/null || true)
	if [ -n "$manager_pid" ]; then
		kill -QUIT "$manager_pid" 2>/dev/null || true
		sleep 2
	fi
	logread >"${output}/logread.log" 2>&1 || true
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
	jq -e '.data.authenticated == true and (.data.user | has("username") | not)' "${output}/login.json" >/dev/null || return 1
	csrf_token=$(jq -r '.data.csrfToken // empty' "${output}/login.json") || return 1
	[ -n "$csrf_token" ] || return 1
}

wait_management_authentication() {
	authentication_remaining=60
	while [ "$authentication_remaining" -gt 0 ]; do
		if authenticate_management; then
			return 0
		fi
		sleep 1
		authentication_remaining=$((authentication_remaining - 1))
	done
	return 1
}

assert_status_resources() {
	status_label=$1
	curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/status" >"${output}/status-${status_label}-first.json"
	sleep 1
	curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/status" >"${output}/status-${status_label}-resources.json"
	jq -e '
		.data.resources.manager.memoryBytes > 0 and
		.data.resources.core.memoryBytes > 0 and
		(.data.resources.manager.cpuPercent | type) == "number" and
		(.data.resources.core.cpuPercent | type) == "number"
	' "${output}/status-${status_label}-resources.json" >/dev/null
}

create_profile() {
	create_engine=$1
	create_name=$2
	create_fixture=$3
	create_label=$4
	create_request=/tmp/boxctl-create-profile.json
	jq -n --arg name "$create_name" --arg engine "$create_engine" --rawfile content "$create_fixture" \
		'{name:$name, engine:$engine, content:$content}' >"$create_request"
	curl --fail --silent --show-error --max-time 30 --cookie "$cookie_jar" \
		--header 'Content-Type: application/json' --header "X-CSRF-Token: ${csrf_token}" \
		--data-binary "@${create_request}" "$api/profiles" >"${output}/profile-create-${create_label}.json"
	jq -r '.data.id // empty' "${output}/profile-create-${create_label}.json"
}

activate_profile() {
	activation_id=$1
	activation_label=$2
	curl --fail --silent --show-error --max-time 90 --cookie "$cookie_jar" \
		--header 'Content-Type: application/json' --header "X-CSRF-Token: ${csrf_token}" \
		--data '{"confirmRestart":true}' "$api/profiles/${activation_id}/activate" \
		>"${output}/profile-activate-${activation_label}.json"
	jq -e --arg id "$activation_id" '.data.id == $id and .data.active == true' \
		"${output}/profile-activate-${activation_label}.json" >/dev/null
}

assert_profile_catalog() {
	mihomo_profile=$1
	sing_profile=$2
	catalog_label=$3
	curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/profiles" >"${output}/profiles-${catalog_label}.json"
	jq -e --arg mihomo "$mihomo_profile" --arg sing "$sing_profile" '
		([.data[] | select(.id == $mihomo and .engine == "mihomo")] | length) == 1 and
		([.data[] | select(.id == $sing and .engine == "sing-box")] | length) == 1
	' "${output}/profiles-${catalog_label}.json" >/dev/null || die 'engine-tagged profiles are missing from the catalog'
}

assert_active_profile() {
	active_id=$1
	active_engine=$2
	active_name=$3
	active_label=$4
	curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/profiles" >"${output}/profiles-active-${active_label}.json"
	jq -e --arg id "$active_id" --arg engine "$active_engine" '
		([.data[] | select(.active)] | length) == 1 and
		any(.data[]; .id == $id and .engine == $engine and .active == true)
	' "${output}/profiles-active-${active_label}.json" >/dev/null || die "$active_label profile selection is inconsistent"
	jq -e --arg name "$active_name" --arg engine "$active_engine" \
		'.name == $name and .engine == $engine' "$root/.boxctl/active-profile" >/dev/null || die "$active_label active-profile marker is inconsistent"
	case "$active_engine" in
		mihomo) cmp "$root/config.yaml" "$input/fixtures/config.yaml" >/dev/null || die 'Mihomo active mirror differs from its profile' ;;
		sing-box) cmp "$root/config.json" "$input/fixtures/config.json" >/dev/null || die 'sing-box active mirror differs from its profile' ;;
		*) die "unsupported active engine in integration assertion: $active_engine" ;;
	esac
}

assert_engine_catalog() {
	curl --fail --silent --show-error --max-time 10 --cookie "$cookie_jar" \
		"$api/engines" >"${output}/engines.json"
	jq -e '
		any(.data[]; .id == "mihomo" and .installed == true and .compatible == true and .running == true) and
		any(.data[]; .id == "sing-box" and .installed == true and .compatible == true and (.version | startswith("1.14.")))
	' "${output}/engines.json" >/dev/null || die 'engine catalog does not expose both compatible binaries'
}

assert_policy() {
	ip -N -4 rule show | grep -Eq '^1000:.*fwmark 0x1.*lookup 100.*proto 196' || die 'owned policy rule is absent'
	ip -N -4 route show table 100 | grep -Eq '^(local|2) default dev lo.*proto 196' || die 'owned policy route is absent'
}

assert_stopped() {
	[ -z "$(exact_pid "$mihomo_binary" 2>/dev/null || true)" ] || die 'Mihomo survived service stop'
	[ -z "$(exact_pid "$sing_box_binary" 2>/dev/null || true)" ] || die 'sing-box survived service stop'
	! nft list table inet clash >/dev/null 2>&1 || die 'nft table survived service stop'
	! nft list table inet boxctl_guard >/dev/null 2>&1 || die 'restart guard survived service stop'
	! ip -N -4 rule show | grep -Eq '^1000:.*proto 196' || die 'policy rule survived service stop'
	! ip -N -4 route show table 100 | grep -Eq '^(local|2) default dev lo.*proto 196' || die 'policy route survived service stop'
	[ ! -e "$process_state" ] || die 'process state survived service stop'
	[ ! -e "$root/.boxctl/active-gateway.json" ] || die 'active gateway generation survived service stop'
	[ ! -e "$root/.boxctl/dns-backup.json" ] || die 'DNS backup survived service stop'
	[ ! -e "$root/.boxctl/profile-transition.v1.json" ] || die 'profile transition journal survived service stop'
	[ -z "$(find /tmp -maxdepth 1 -type d \( -name 'boxctl-mihomo-*' -o -name 'boxctl-sing-box-*' \) -print)" ] || die 'private engine runtime survived service stop'
}

note 'starting service and checking owned network state'
/etc/init.d/boxctl enable
/etc/init.d/boxctl start
if ! wait_active; then
	capture_service_diagnostics
	die 'service or Mihomo did not become ready'
fi
if ! authenticate_management; then
	die 'password-only management login failed'
fi
manager_identity=$(exact_pid "$root/bin/boxctl")
core_pid=$(exact_pid "$mihomo_binary")
assert_engine_catalog
assert_process_identity mihomo "$mihomo_binary" "$core_pid" mihomo-legacy
assert_engine_dataplane mihomo mihomo-legacy
assert_dns_upstream mihomo-legacy
assert_status_resources mihomo-legacy || die 'legacy Mihomo process resource status is incomplete'

note 'creating native engine-tagged profiles'
mihomo_profile=$(create_profile mihomo IntegrationMihomo "$input/fixtures/config.yaml" mihomo)
sing_profile=$(create_profile sing-box IntegrationSing "$input/fixtures/config.json" sing-box)
[ "$mihomo_profile" = 'mihomo:IntegrationMihomo' ] || die 'Mihomo profile received an unexpected ID'
[ "$sing_profile" = 'sing-box:IntegrationSing' ] || die 'sing-box profile received an unexpected ID'
assert_profile_catalog "$mihomo_profile" "$sing_profile" created

note 'selecting the engine-tagged Mihomo profile'
if ! activate_profile "$mihomo_profile" mihomo; then
	capture_service_diagnostics
	die 'Mihomo profile activation failed'
fi
wait_managed_engine mihomo "$mihomo_binary" "$mihomo_profile" || die 'engine-tagged Mihomo profile did not become ready'
[ "$manager_pid" = "$manager_identity" ] || die 'profile activation replaced the manager process'
core_pid=$(exact_pid "$mihomo_binary")
assert_active_profile "$mihomo_profile" mihomo IntegrationMihomo mihomo
assert_process_identity mihomo "$mihomo_binary" "$core_pid" mihomo-tagged
assert_engine_dataplane mihomo mihomo-tagged
assert_dns_upstream mihomo-tagged
assert_status_resources mihomo-tagged || die 'tagged Mihomo process resource status is incomplete'

note 'verifying panel restart traffic guard and kernel expiry'
sh -x "$input/guest/restart-guard.sh" "$output" "$manager_pid" "$core_pid" "$csrf_token" >"$output/restart-guard-traffic.log" 2>&1 || die 'restart guard traffic test failed'
wait_managed_engine mihomo "$mihomo_binary" "$mihomo_profile" || die 'Mihomo did not recover after guarded restart'
core_pid=$(exact_pid "$mihomo_binary")

note 'running captured and direct traffic flows'
"$input/guest/traffic.sh" "$output" "$manager_pid" "$core_pid" || die 'traffic test failed'

note 'switching live from Mihomo to sing-box'
if ! activate_profile "$sing_profile" sing-box; then
	capture_service_diagnostics
	die 'sing-box profile activation failed'
fi
wait_managed_engine sing-box "$sing_box_binary" "$sing_profile" || die 'sing-box profile did not become ready'
[ "$manager_pid" = "$manager_identity" ] || die 'sing-box switch replaced the manager process'
core_pid=$(exact_pid "$sing_box_binary")
assert_active_profile "$sing_profile" sing-box IntegrationSing sing-box
assert_process_identity sing-box "$sing_box_binary" "$core_pid" sing-box
assert_engine_dataplane sing-box sing-box
assert_dns_upstream sing-box
jq -e '.plan.CaptureCIDRsConfigured == false and (.plan.CaptureCIDRs | length) == 0' \
	"$root/.boxctl/active-gateway.json" >/dev/null || die 'sing-box broad capture policy was not published'
assert_status_resources sing-box || die 'sing-box process resource status is incomplete'
"$input/guest/singbox-traffic.sh" "$output" "$manager_pid" "$core_pid" || die 'sing-box traffic test failed'

note 'switching live back to Mihomo'
if ! activate_profile "$mihomo_profile" mihomo-return; then
	capture_service_diagnostics
	die 'switch back to Mihomo failed'
fi
wait_managed_engine mihomo "$mihomo_binary" "$mihomo_profile" || die 'Mihomo did not recover after the sing-box switch'
[ "$manager_pid" = "$manager_identity" ] || die 'switch back to Mihomo replaced the manager process'
core_pid=$(exact_pid "$mihomo_binary")
assert_active_profile "$mihomo_profile" mihomo IntegrationMihomo mihomo-return
assert_process_identity mihomo "$mihomo_binary" "$core_pid" mihomo-return
assert_engine_dataplane mihomo mihomo-return
assert_dns_upstream mihomo-return

note 'checking automatic recovery after an unrequested manager crash'
crashed_manager_pid=$manager_identity
surviving_core_pid=$core_pid
surviving_core_identity=$(jq -er '.identity | select(type == "string" and length > 0)' "$process_state") || \
	die 'Mihomo process identity is unavailable before the manager crash'
kill -KILL "$crashed_manager_pid" || die 'could not SIGKILL the manager'
kill -0 "$surviving_core_pid" 2>/dev/null || die 'Mihomo exited together with the crashed manager'
if ! wait_replacement_manager "$crashed_manager_pid"; then
	capture_service_diagnostics
	die 'procd did not respawn the manager with a new PID'
fi
replacement_manager_pid=$manager_pid
if ! wait_management_authentication; then
	capture_service_diagnostics
	die 'management login did not recover after the manager respawn'
fi
if ! wait_managed_engine mihomo "$mihomo_binary" "$mihomo_profile"; then
	capture_service_diagnostics
	die 'Mihomo did not recover after the unrequested manager crash'
fi
[ "$manager_pid" = "$replacement_manager_pid" ] || die 'manager restarted again during crash recovery'
recovered_core_pid=$(exact_pid "$mihomo_binary")
[ "$recovered_core_pid" = "$surviving_core_pid" ] || die 'manager crash recovery restarted Mihomo instead of adopting it'
recovered_core_identity=$(jq -er '.identity | select(type == "string" and length > 0)' "$process_state") || \
	die 'Mihomo process identity is unavailable after manager crash recovery'
[ "$recovered_core_identity" = "$surviving_core_identity" ] || die 'manager crash recovery replaced the persisted Mihomo identity'
manager_identity=$replacement_manager_pid
core_pid=$recovered_core_pid
assert_active_profile "$mihomo_profile" mihomo IntegrationMihomo mihomo-crash-recovery
assert_process_identity mihomo "$mihomo_binary" "$core_pid" mihomo-crash-recovery
assert_engine_dataplane mihomo mihomo-crash-recovery
assert_dns_upstream mihomo-crash-recovery
assert_status_resources mihomo-crash-recovery || die 'crash-recovered process resource status is incomplete'
mkdir -p "${output}/manager-crash-traffic"
"$input/guest/traffic.sh" "${output}/manager-crash-traffic" "$manager_pid" "$core_pid" || \
	die 'captured or direct traffic failed after manager crash recovery'

note 'checking stop and second start'
/etc/init.d/boxctl stop
assert_stopped
assert_dns_restored first-stop
/etc/init.d/boxctl start
wait_managed_engine mihomo "$mihomo_binary" "$mihomo_profile" || die 'service did not recover after a second start'
core_pid=$(exact_pid "$mihomo_binary")
assert_process_identity mihomo "$mihomo_binary" "$core_pid" mihomo-second-start
assert_engine_dataplane mihomo mihomo-second-start
assert_dns_upstream mihomo-second-start

note 'checking procd reload'
/etc/init.d/boxctl reload
wait_managed_engine mihomo "$mihomo_binary" "$mihomo_profile" || die 'service did not recover after reload'
core_pid=$(exact_pid "$mihomo_binary")
assert_process_identity mihomo "$mihomo_binary" "$core_pid" mihomo-reload
assert_engine_dataplane mihomo mihomo-reload
assert_dns_upstream mihomo-reload

note 'checking panel firewall recovery while running and already stopped'
nft list table inet clash >"${output}/recovery-capture.nft"
sed -E 's/ expires [0-9][^[:space:];,}]*//g' "${output}/restart-guard.nft" >"${output}/recovery-guard.nft"
nft add table inet boxctl_integration_foreign
nft -f "${output}/recovery-guard.nft"
curl --fail --silent --show-error --max-time 30 --cookie "$cookie_jar" \
	-H "X-CSRF-Token: $csrf_token" -X POST "$api/firewall/cleanup" >"${output}/firewall-cleanup-running.json"
jq -e '.data.cleaned == true' "${output}/firewall-cleanup-running.json" >/dev/null || die 'panel recovery did not report success'
assert_stopped
assert_dns_restored panel-recovery
# Unknown stale rules must also be removed after the lifecycle already says stopped.
nft -f "${output}/recovery-capture.nft"
nft -f "${output}/recovery-guard.nft"
ip -4 rule add priority 1000 fwmark 1 table 100 protocol 196
ip -4 route add local default dev lo table 100 proto 196
curl --fail --silent --show-error --max-time 30 --cookie "$cookie_jar" \
	-H "X-CSRF-Token: $csrf_token" -X POST "$api/firewall/cleanup" >"${output}/firewall-cleanup-stopped.json"
assert_stopped
nft list table inet boxctl_integration_foreign >/dev/null || die 'panel recovery deleted a foreign table'

note 'checking startup cleanup after manager and core die with stale guard, capture and DNS'
/etc/init.d/boxctl stop
mkdir -p "$root/.install"
: >"$root/.install/start-stopped-until-first-success"
/etc/init.d/boxctl start
wait_management_authentication || die 'management-only service did not start'
assert_stopped
curl --fail --silent --show-error --max-time 60 --cookie "$cookie_jar" \
	-H "X-CSRF-Token: $csrf_token" -X POST "$api/service/start" >"${output}/recovery-core-start.json"
wait_managed_engine mihomo "$mihomo_binary" "$mihomo_profile" || die 'core did not start from management-only mode'
assert_dns_upstream recovery-before-crash
crashed_manager_pid=$manager_pid
core_pid=$(exact_pid "$mihomo_binary")
kill -STOP "$crashed_manager_pid"
nft -f "${output}/recovery-guard.nft"
kill -KILL "$core_pid" "$crashed_manager_pid"
# procd retains --start-stopped even after the successful Start consumed the marker.
wait_replacement_manager "$crashed_manager_pid" || die 'manager did not respawn after the interrupted recovery'
wait_management_authentication || die 'management did not recover after the interrupted recovery'
assert_stopped
assert_dns_restored interrupted-startup
nft list table inet boxctl_integration_foreign >/dev/null || die 'startup recovery deleted a foreign table'
nft delete table inet boxctl_integration_foreign

note 'checking final cleanup'
/etc/init.d/boxctl stop
assert_stopped
assert_dns_restored final-stop
printf 'service_start=true\npassword_login=true\nstatus_resources=true\nengine_profiles=true\ndns_upstream=true\nmihomo_traffic=true\nsing_box_switch=true\nsing_box_identity=true\nsing_box_traffic=true\nmihomo_return=true\nmanager_crash_recovery=true\nservice_restart=true\nservice_reload=true\npanel_firewall_recovery=true\nstale_startup_cleanup=true\ncleanup=true\n' >"${output}/result.txt"
note 'all integration checks passed'
