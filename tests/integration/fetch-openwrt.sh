#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly OPENWRT_VERSION="25.12.5"
readonly OPENWRT_IMAGE="openwrt-${OPENWRT_VERSION}-armsr-armv8-generic-initramfs-kernel.bin"
readonly OPENWRT_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/armsr/armv8/${OPENWRT_IMAGE}"
readonly OPENWRT_SHA256="f510b0c73c1ee70a64df384d7e2ad4404caf83e6bc7cce9ac13426f77b9ae3be"

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
	printf 'usage: %s [DESTINATION]\n' "$0"
	exit 0
fi
[ "$#" -le 1 ] || exit 2

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
destination=${1:-"${script_dir}/.cache/${OPENWRT_IMAGE}"}
mkdir -p "$(dirname -- "$destination")"

if [ -f "$destination" ]; then
	actual=$(sha256_file "$destination")
	[ "$actual" = "$OPENWRT_SHA256" ] || {
		printf 'existing OpenWrt image checksum mismatch\n' >&2
		exit 1
	}
	printf '%s\n' "$destination"
	exit 0
fi

temporary=$(mktemp "${destination}.partial.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
	--output "$temporary" "$OPENWRT_URL"
[ "$(sha256_file "$temporary")" = "$OPENWRT_SHA256" ] || {
	printf 'downloaded OpenWrt image checksum mismatch\n' >&2
	exit 1
}
chmod 600 "$temporary"
mv -- "$temporary" "$destination"
trap - EXIT HUP INT TERM
printf '%s\n' "$destination"
