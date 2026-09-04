#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "${script_dir}/../.." && pwd -P)
readonly OPENWRT_SHA256="f510b0c73c1ee70a64df384d7e2ad4404caf83e6bc7cce9ac13426f77b9ae3be"

die() { printf 'integration: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

manager="${repo_root}/dist/boxctl-linux-arm64"
mihomo="${script_dir}/.private/mihomo-linux-arm64"
sing_box="${script_dir}/.private/sing-box-linux-arm64"
image=
output=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--manager) [ "$#" -ge 2 ] || die '--manager needs a file'; manager=$2; shift 2 ;;
		--core|--mihomo) [ "$#" -ge 2 ] || die "$1 needs a file"; mihomo=$2; shift 2 ;;
		--sing-box) [ "$#" -ge 2 ] || die '--sing-box needs a file'; sing_box=$2; shift 2 ;;
		--image) [ "$#" -ge 2 ] || die '--image needs a file'; image=$2; shift 2 ;;
		--output) [ "$#" -ge 2 ] || die '--output needs a directory'; output=$2; shift 2 ;;
		-h|--help)
			printf 'usage: %s [--manager FILE] [--mihomo FILE] [--sing-box FILE] [--image FILE] [--output DIR]\n' "$0"
			printf '       --core FILE is retained as an alias for --mihomo FILE\n'
			exit 0
			;;
		*) die "unknown argument: $1" ;;
	esac
done

for command_name in qemu-system-aarch64 expect nc python3; do require_command "$command_name"; done
[ -f "$manager" ] && [ -x "$manager" ] && [ ! -L "$manager" ] || die "manager is missing or unsafe: $manager"
[ -f "$mihomo" ] && [ -x "$mihomo" ] && [ ! -L "$mihomo" ] || die "Mihomo is missing or unsafe: $mihomo"
[ -f "$sing_box" ] && [ -x "$sing_box" ] && [ ! -L "$sing_box" ] || die "sing-box is missing or unsafe: $sing_box"
if [ -z "$image" ]; then image=$("${script_dir}/fetch-openwrt.sh"); fi
[ -f "$image" ] && [ "$(sha256_file "$image")" = "$OPENWRT_SHA256" ] || die 'OpenWrt image checksum mismatch'

temporary_root=${TMPDIR:-/tmp}
[ -d "$temporary_root" ] || die "temporary directory does not exist: $temporary_root"
if [ -z "$output" ]; then output="${temporary_root%/}/boxctl-integration.$(date -u +%Y%m%dT%H%M%SZ).$$"; fi
[ ! -e "$output" ] || die "output already exists: $output"
mkdir -p "$output"
chmod 700 "$output"
output=$(CDPATH='' cd -- "$output" && pwd -P)
input=$(mktemp -d "${temporary_root%/}/boxctl-integration-input.XXXXXX")
cleanup_input() { rm -rf "$input"; }
trap cleanup_input EXIT HUP INT TERM

install -m 0700 "$manager" "$input/boxctl"
install -m 0700 "$mihomo" "$input/mihomo"
install -m 0700 "$sing_box" "$input/sing-box"
cp -R "${script_dir}/guest" "$input/guest"
cp -R "${script_dir}/fixtures" "$input/fixtures"
cp -R "${repo_root}/packaging/openwrt/files" "$input/openwrt-files"
find "$input" -type l -print -quit | grep -q . && die 'staged input contains a symbolic link'

{
	printf 'openwrt_sha256=%s\n' "$OPENWRT_SHA256"
	printf 'manager_sha256=%s\n' "$(sha256_file "$manager")"
	printf 'mihomo_sha256=%s\n' "$(sha256_file "$mihomo")"
	printf 'sing_box_sha256=%s\n' "$(sha256_file "$sing_box")"
} >"${output}/manifest.txt"

serial="${output}/serial.sock"
qmp="${output}/qmp.sock"
if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then
	acceleration=(-accel hvf -cpu host)
else
	acceleration=(-accel "tcg,thread=multi" -cpu max)
fi

qemu-system-aarch64 \
	-machine virt "${acceleration[@]}" -m 1024 -smp 2 -display none -no-reboot \
	-kernel "$image" -append 'console=ttyAMA0,115200 root=/dev/ram0 rw loglevel=5' \
	-serial "unix:${serial},server=on,wait=off" \
	-qmp "unix:${qmp},server=on,wait=off" -monitor none -device virtio-rng-pci \
	-netdev 'user,id=lan,net=192.168.111.0/24,dhcpstart=192.168.111.100,restrict=on' \
	-device 'virtio-net-pci,netdev=lan,mac=52:54:00:11:00:01' \
	-netdev 'user,id=wan,net=192.168.112.0/24,dhcpstart=192.168.112.100,restrict=on' \
	-device 'virtio-net-pci,netdev=wan,mac=52:54:00:12:00:01' \
	-netdev 'user,id=prep,net=192.168.113.0/24,dhcpstart=192.168.113.100' \
	-device 'pcie-root-port,id=prep-root-port,chassis=1,slot=1' \
	-device 'virtio-net-pci,bus=prep-root-port,id=prep-nic,netdev=prep,mac=52:54:00:13:00:01' \
	-fsdev "local,id=input,path=${input},security_model=none,readonly=on" \
	-device virtio-9p-pci,fsdev=input,mount_tag=integration_input \
	-fsdev "local,id=output,path=${output},security_model=none" \
	-device virtio-9p-pci,fsdev=output,mount_tag=integration_output \
	-D "${output}/qemu.log" >"${output}/qemu-stderr.log" 2>&1 &
qemu_pid=$!
cleanup_qemu() {
	kill "$qemu_pid" 2>/dev/null || true
	wait "$qemu_pid" 2>/dev/null || true
}
trap 'cleanup_qemu; cleanup_input' EXIT HUP INT TERM

for _ in {1..100}; do [ -S "$serial" ] && [ -S "$qmp" ] && break; sleep 0.1; done
[ -S "$serial" ] && [ -S "$qmp" ] || die 'QEMU did not create its control sockets'
set +e
expect -f "${script_dir}/lib/console.exp" "$serial" "$qmp" "${BOXCTL_INTEGRATION_TIMEOUT:-900}" >"${output}/console.log" 2>&1
result=$?
set -e
cleanup_qemu
trap cleanup_input EXIT HUP INT TERM
[ "$result" -eq 0 ] || die "OpenWrt integration failed; see ${output}/console.log"
printf 'integration: passed; output: %s\n' "$output"
