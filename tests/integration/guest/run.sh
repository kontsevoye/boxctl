#!/bin/sh
set -eu
umask 077

input=/mnt/integration-input
output=$1
root=/opt/boxctl
api=http://192.168.111.1:9091/api/v1
integration_password=integration-password
cookie_jar=/tmp/boxctl-integration-cookies

die() { printf 'INTEGRATION-ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf 'INTEGRATION-PHASE: %s\n' "$*"; }

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
	apk add ip-full kmod-tun kmod-nft-tproxy nftables-json curl ca-bundle kmod-veth iperf3 jq
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

note 'installing boxctl test instance'
mkdir -p "$root/bin" "$root/engines/mihomo" "$root/.boxctl"
chmod 700 "$root" "$root/bin" "$root/engines/mihomo" "$root/.boxctl"
cp "$input/boxctl" "$root/bin/boxctl"
cp "$input/mihomo" "$root/engines/mihomo/mihomo"
cp "$input/fixtures/config.yaml" "$root/config.yaml"
cp "$input/fixtures/settings" "$root/.boxctl/settings"
chmod 700 "$root/bin/boxctl" "$root/engines/mihomo/mihomo"
chmod 600 "$root/config.yaml" "$root/.boxctl/settings"
cp "$input/openwrt-files/etc/init.d/boxctl" /etc/init.d/boxctl
cp "$input/openwrt-files/etc/hotplug.d/iface/40-boxctl" /etc/hotplug.d/iface/40-boxctl
cp "$input/openwrt-files/etc/hotplug.d/net/99-boxctl-tun" /etc/hotplug.d/net/99-boxctl-tun
chmod 700 /etc/init.d/boxctl /etc/hotplug.d/iface/40-boxctl /etc/hotplug.d/net/99-boxctl-tun
{
	"$root/bin/boxctl" version
	"$root/engines/mihomo/mihomo" -v
} >"${output}/versions.txt" 2>&1

exact_pid() {
	expected=$1
	for executable in /proc/[0-9]*/exe; do
		[ -L "$executable" ] || continue
		resolved=$(readlink "$executable" 2>/dev/null || true)
		case "$resolved" in "$expected"|"$expected (deleted)") basename "$(dirname "$executable")"; return 0 ;; esac
	done
	return 1
}

wait_active() {
	remaining=60
	while [ "$remaining" -gt 0 ]; do
		manager_pid=$(exact_pid "$root/bin/boxctl" 2>/dev/null || true)
		core_pid=$(exact_pid "$root/engines/mihomo/mihomo" 2>/dev/null || true)
		if [ -n "$manager_pid" ] && [ -n "$core_pid" ] && \
			nft list table inet clash >/dev/null 2>&1 && \
			curl --fail --silent --max-time 2 http://127.0.0.1:9090/version >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	return 1
}

capture_service_diagnostics() {
	ubus call service list '{"name":"boxctl"}' >"${output}/service.json" 2>&1 || true
	ps w >"${output}/processes.txt" 2>&1 || true
	netstat -lntp >"${output}/listeners.txt" 2>&1 || true
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
	manager_pid=$(exact_pid "$root/bin/boxctl" 2>/dev/null || true)
	if [ -n "$manager_pid" ]; then
		kill -QUIT "$manager_pid" 2>/dev/null || true
		sleep 2
	fi
	logread >"${output}/logread.log" 2>&1 || true
}

authenticate_management() {
	curl --fail --silent --show-error --max-time 5 "$api/setup" >"${output}/setup.json"
	if jq -e '.data.required == true' "${output}/setup.json" >/dev/null; then
		curl --fail --silent --show-error --max-time 10 --header 'Content-Type: application/json' \
			--data "{\"password\":\"${integration_password}\"}" \
			"$api/setup" >"${output}/setup-result.json"
	fi
	curl --fail --silent --show-error --max-time 10 --cookie-jar "$cookie_jar" --header 'Content-Type: application/json' \
		--data "{\"password\":\"${integration_password}\"}" \
		"$api/auth/login" >"${output}/login.json"
	jq -e '.data.authenticated == true and (.data.user | has("username") | not)' "${output}/login.json" >/dev/null
}

assert_status_resources() {
	curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/status" >"${output}/status-first.json"
	sleep 1
	curl --fail --silent --show-error --max-time 5 --cookie "$cookie_jar" \
		"$api/status" >"${output}/status.json"
	jq -e '
		.data.resources.manager.memoryBytes > 0 and
		.data.resources.core.memoryBytes > 0 and
		(.data.resources.manager.cpuPercent | type) == "number" and
		(.data.resources.core.cpuPercent | type) == "number"
	' "${output}/status.json" >/dev/null
}

assert_policy() {
	ip -N -4 rule show | grep -Eq '^1000:.*fwmark 0x1.*lookup 100.*proto 196' || die 'owned policy rule is absent'
	ip -N -4 route show table 100 | grep -Eq '^(local|2) default dev lo.*proto 196' || die 'owned policy route is absent'
}

assert_stopped() {
	[ -z "$(exact_pid "$root/engines/mihomo/mihomo" 2>/dev/null || true)" ] || die 'Mihomo survived service stop'
	! nft list table inet clash >/dev/null 2>&1 || die 'nft table survived service stop'
	! ip -N -4 rule show | grep -Eq '^1000:.*proto 196' || die 'policy rule survived service stop'
}

note 'starting service and checking owned network state'
/etc/init.d/boxctl enable
/etc/init.d/boxctl start
if ! wait_active; then
	capture_service_diagnostics
	die 'service or Mihomo did not become ready'
fi
assert_policy
"$root/bin/boxctl" fw diagnose >"${output}/diagnose.json"
authenticate_management || die 'password-only management login failed'
assert_status_resources || die 'process resource status is incomplete'
manager_pid=$(exact_pid "$root/bin/boxctl")
core_pid=$(exact_pid "$root/engines/mihomo/mihomo")

note 'running captured and direct traffic flows'
"$input/guest/traffic.sh" "$output" "$manager_pid" "$core_pid" || die 'traffic test failed'

note 'checking stop and second start'
/etc/init.d/boxctl stop
assert_stopped
/etc/init.d/boxctl start
wait_active || die 'service did not recover after a second start'
assert_policy

note 'checking procd reload'
/etc/init.d/boxctl reload
wait_active || die 'service did not recover after reload'
assert_policy

note 'checking final cleanup'
/etc/init.d/boxctl stop
assert_stopped
printf 'service_start=true\npassword_login=true\nstatus_resources=true\ntraffic_capture=true\nservice_restart=true\nservice_reload=true\ncleanup=true\n' >"${output}/result.txt"
note 'all integration checks passed'
