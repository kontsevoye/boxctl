#!/usr/bin/env bash
set -euo pipefail
umask 022

readonly OPENWRT_VERSION="25.12.5"
readonly OPENWRT_TARGET="mediatek"
readonly OPENWRT_SUBTARGET="filogic"
readonly SDK_BASENAME="openwrt-sdk-${OPENWRT_VERSION}-${OPENWRT_TARGET}-${OPENWRT_SUBTARGET}_gcc-14.3.0_musl.Linux-x86_64"
readonly SDK_ARCHIVE="${SDK_BASENAME}.tar.zst"
readonly SDK_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${OPENWRT_TARGET}/${OPENWRT_SUBTARGET}/${SDK_ARCHIVE}"
readonly SDK_SHA256="ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25"

die() {
	printf 'build-openwrt-apk: %s\n' "$*" >&2
	exit 1
}

sha256_file() {
	sha256sum "$1" | awk '{print $1}'
}

for command in curl file gawk git make perl python3 rsync sha256sum tar unzstd wget; do
	command -v "$command" >/dev/null 2>&1 || die "$command is required"
done

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] ||
	die "the official SDK requires a Linux x86-64 host"

: "${VERSION:?VERSION is required (expected YYYY.MM.N)}"
[[ $VERSION =~ ^[0-9]{4}\.(0[1-9]|1[0-2])\.[1-9][0-9]*$ ]] ||
	die "VERSION must use YYYY.MM.N"

REPOSITORY_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
readonly REPOSITORY_ROOT
readonly BINARY=${BINARY:-"${REPOSITORY_ROOT}/dist/boxctl-linux-arm64"}
readonly DIST_DIR=${DIST_DIR:-"${REPOSITORY_ROOT}/dist"}
readonly SDK_CACHE_DIR=${SDK_CACHE_DIR:-"${REPOSITORY_ROOT}/.cache/openwrt-sdk"}
readonly ARCHIVE_PATH="${SDK_CACHE_DIR}/${SDK_ARCHIVE}"
readonly SDK_ROOT="${SDK_CACHE_DIR}/${SDK_BASENAME}"

[[ -f $BINARY && ! -L $BINARY && -s $BINARY ]] ||
	die "BINARY must be a non-empty regular file: $BINARY"
binary_type=$(file -b "$BINARY")
[[ $binary_type == *"ELF 64-bit"* && $binary_type == *"ARM aarch64"* && $binary_type == *"statically linked"* ]] ||
	die "BINARY must be a static Linux aarch64 ELF (found: $binary_type)"
grep -aFq -- "$VERSION" "$BINARY" ||
	die "BINARY does not contain VERSION in its linked build information"
mkdir -p "$SDK_CACHE_DIR" "$DIST_DIR"

if [[ ! -f $ARCHIVE_PATH ]]; then
	temporary=$(mktemp "${ARCHIVE_PATH}.partial.XXXXXX")
	trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
	curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
		--output "$temporary" "$SDK_URL"
	[[ $(sha256_file "$temporary") == "$SDK_SHA256" ]] ||
		die "downloaded SDK checksum mismatch"
	mv -- "$temporary" "$ARCHIVE_PATH"
	trap - EXIT HUP INT TERM
fi
[[ $(sha256_file "$ARCHIVE_PATH") == "$SDK_SHA256" ]] ||
	die "cached SDK checksum mismatch: $ARCHIVE_PATH"

if [[ ! -d $SDK_ROOT ]]; then
	tar --use-compress-program=unzstd -xf "$ARCHIVE_PATH" -C "$SDK_CACHE_DIR"
fi
[[ -f $SDK_ROOT/rules.mk && -f $SDK_ROOT/include/package.mk ]] ||
	die "invalid SDK extraction: $SDK_ROOT"

feeds_stamp="${SDK_ROOT}/.boxctl-base-feed-${OPENWRT_VERSION}"
if [[ ! -f $feeds_stamp ]]; then
	"${SDK_ROOT}/scripts/feeds" update base
	"${SDK_ROOT}/scripts/feeds" install -p base \
		ca-bundle dnsmasq firewall4 ip-full nftables-json procd ubus uci
	touch "$feeds_stamp"
fi

package_link="${SDK_ROOT}/package/boxctl"
if [[ -L $package_link ]]; then
	ln -sfn "$REPOSITORY_ROOT/packaging/openwrt" "$package_link"
elif [[ -e $package_link ]]; then
	die "refusing to replace non-symlink SDK package path: $package_link"
else
	ln -s "$REPOSITORY_ROOT/packaging/openwrt" "$package_link"
fi

{
	printf '# CONFIG_ALL is not set\n'
	printf '# CONFIG_ALL_NONSHARED is not set\n'
	printf '# CONFIG_ALL_KMODS is not set\n'
	printf 'CONFIG_PACKAGE_boxctl=m\n'
} > "${SDK_ROOT}/.config"
make -C "$SDK_ROOT" defconfig BOXCTL_PREBUILT=1

for setting in \
	'# CONFIG_ALL is not set' \
	'# CONFIG_ALL_NONSHARED is not set' \
	'# CONFIG_ALL_KMODS is not set' \
	'CONFIG_PACKAGE_boxctl=m'; do
	grep -Fxq -- "$setting" "${SDK_ROOT}/.config" ||
		die "SDK defconfig did not retain: $setting"
done

find "${SDK_ROOT}/bin" -type f -name 'boxctl-*.apk' -delete 2>/dev/null || true
make -C "$SDK_ROOT" package/boxctl/clean BOXCTL_PREBUILT=1
make -C "$SDK_ROOT" package/boxctl/compile \
	BOXCTL_PREBUILT=1 \
	BOXCTL_BINARY="$BINARY" \
	BOXCTL_LEGAL_DIR="$REPOSITORY_ROOT" \
	BOXCTL_VERSION="$VERSION"

mapfile -t packages < <(find "${SDK_ROOT}/bin" -type f -name "boxctl-${VERSION}-r1.apk" -print)
[[ ${#packages[@]} -eq 1 ]] ||
	die "expected one SDK-built boxctl APK, found ${#packages[@]}"

host_apk="${SDK_ROOT}/staging_dir/host/bin/apk"
[[ -x $host_apk ]] || die "SDK host apk tool is missing"
metadata_file=$(mktemp "${DIST_DIR}/.boxctl-apk-metadata.XXXXXX")
trap 'rm -f -- "$metadata_file"' EXIT HUP INT TERM
$host_apk adbdump --format json "${packages[0]}" > "$metadata_file"
python3 - "$metadata_file" "$VERSION" <<'PY'
import json
import pathlib
import re
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
version = sys.argv[2]
info = metadata.get("info", {})
assert info.get("name") == "boxctl", info
assert info.get("version") == f"{version}-r1", info
assert info.get("arch") == "aarch64_cortex-a53", info

dependencies = {re.split(r"[<>=~]", item, maxsplit=1)[0] for item in info.get("depends", [])}
required_dependencies = {
    "ca-bundle",
    "dnsmasq",
    "firewall4",
    "ip-full",
    "kmod-inet-diag",
    "kmod-nft-tproxy",
    "kmod-tun",
    "nftables-json",
    "procd",
    "ubus",
    "uci",
}
assert required_dependencies <= dependencies, dependencies

files = {}
directories = {}
for entry in metadata.get("paths", []):
    directory = "/" + entry.get("name", "").strip("/")
    directories[directory] = entry.get("acl", {}).get("mode")
    for file_entry in entry.get("files", []):
        path = (directory.rstrip("/") + "/" + file_entry["name"]).replace("//", "/")
        files[path] = file_entry.get("acl", {}).get("mode")

expected_files = {
    "/opt/boxctl/bin/boxctl": 0o755,
    "/etc/init.d/boxctl": 0o755,
    "/etc/hotplug.d/iface/40-boxctl": 0o755,
    "/etc/hotplug.d/net/99-boxctl-tun": 0o755,
    # OpenWrt INSTALL_CONF deliberately keeps UCI configuration owner-only.
    "/etc/config/boxctl": 0o600,
    "/etc/apk/protected_paths.d/boxctl.list": 0o644,
    "/lib/upgrade/keep.d/boxctl": 0o644,
    "/usr/share/licenses/boxctl/LICENSE": 0o644,
}
for path, mode in expected_files.items():
    assert files.get(path) == mode, (path, files.get(path))
assert "/opt/boxctl/.install/start-stopped-until-first-success" not in files, files
for path in ("/opt/boxctl", "/opt/boxctl/.boxctl", "/opt/boxctl/.install"):
    assert directories.get(path) == 0o700, (path, directories.get(path))
assert directories.get("/opt/boxctl/configs") == 0o755, directories
assert "/opt/boxctl/profiles" not in directories, directories

scripts = metadata.get("scripts", {})
for phase in ("pre-install", "pre-upgrade"):
    script = scripts.get(phase, "")
    assert 'bin/boxctl" ] || fresh=1' in script, phase
    assert "start-stopped-until-first-success" in script, phase
for phase in ("post-install", "post-upgrade"):
    assert "default_postinst" in scripts.get(phase, ""), phase
PY

output="${DIST_DIR}/boxctl-openwrt-25.12-mediatek-filogic-${VERSION}.apk"
install -m 0644 "${packages[0]}" "$output"
(
	cd "$DIST_DIR"
	sha256sum "$(basename -- "$output")" > "$(basename -- "${output}.sha256")"
)
rm -f -- "$metadata_file"
trap - EXIT HUP INT TERM
printf '%s\n' "$output"
