#!/bin/sh
set -eu

usage() {
	printf 'usage: %s BINARY [--no-start] [--prefer-seamless]\n' "$0" >&2
	exit 2
}

[ "$(id -u)" = "0" ] || {
	printf 'boxctl install must run as root\n' >&2
	exit 1
}
[ "$#" -ge 1 ] || usage

SOURCE_BINARY=$1
shift
ROOT=/opt/boxctl
SERVICE=/etc/init.d/boxctl
CONFIG=/etc/config/boxctl
HOTPLUG_IFACE=/etc/hotplug.d/iface/40-boxctl
HOTPLUG_TUN=/etc/hotplug.d/net/99-boxctl-tun
APK_PATHS=/etc/apk/protected_paths.d/boxctl.list
SYSUPGRADE_KEEP=/lib/upgrade/keep.d/boxctl
START_STOPPED_MARKER="${ROOT}/.install/start-stopped-until-first-success"
SERVICE_TRANSITION_TIMEOUT=60
START_AFTER=1
PREFER_SEAMLESS=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--no-start) START_AFTER=0; shift ;;
		--prefer-seamless) PREFER_SEAMLESS=1; shift ;;
		*) usage ;;
	esac
done

[ -s "$SOURCE_BINARY" ] && [ ! -L "$SOURCE_BINARY" ] || {
	printf 'binary must be a non-empty regular file: %s\n' "$SOURCE_BINARY" >&2
	exit 1
}
SOURCE_DIRECTORY=$(dirname "$SOURCE_BINARY")
SOURCE_BASENAME=$(basename "$SOURCE_BINARY")
SOURCE_DIRECTORY=$(CDPATH='' cd -P "$SOURCE_DIRECTORY" && pwd)
SOURCE_BINARY=$SOURCE_DIRECTORY/$SOURCE_BASENAME

SCRIPT_DIR=$(dirname "$0")
SCRIPT_DIR=$(CDPATH='' cd -P "$SCRIPT_DIR" && pwd)
for required in \
	"${SCRIPT_DIR}/files/etc/init.d/boxctl" \
	"${SCRIPT_DIR}/files/etc/config/boxctl" \
	"${SCRIPT_DIR}/files/etc/hotplug.d/iface/40-boxctl" \
	"${SCRIPT_DIR}/files/etc/hotplug.d/net/99-boxctl-tun" \
	"${SCRIPT_DIR}/files/etc/apk/protected_paths.d/boxctl.list" \
	"${SCRIPT_DIR}/files/lib/upgrade/keep.d/boxctl"
do
	[ -f "$required" ] && [ ! -L "$required" ] || {
		printf 'bundle artifact is missing or unsafe: %s\n' "$required" >&2
		exit 1
	}
done

# Read-only checks happen before the existing service is stopped.
"$SOURCE_BINARY" version >/dev/null
ip -N -4 rule show >/dev/null 2>&1 || {
	printf 'ip-full is required (run: apk update && apk add ip-full)\n' >&2
	exit 1
}
if [ -e "$ROOT" ] || [ -L "$ROOT" ]; then
	[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || {
		printf 'boxctl root is not a regular directory: %s\n' "$ROOT" >&2
		exit 1
	}
	ROOT_WAS_PRESENT=1
else
	ROOT_WAS_PRESENT=0
fi
if [ -e "$CONFIG" ] || [ -L "$CONFIG" ]; then
	[ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] || {
		printf 'boxctl configuration is not a regular file: %s\n' "$CONFIG" >&2
		exit 1
	}
fi

service_running() {
	[ -x "$SERVICE" ] && "$SERVICE" running >/dev/null 2>&1
}

service_enabled() {
	[ -x "$SERVICE" ] && "$SERVICE" enabled >/dev/null 2>&1
}

wait_service_stopped() {
	remaining=$SERVICE_TRANSITION_TIMEOUT
	while service_running; do
		[ "$remaining" -gt 0 ] || {
			printf 'service did not stop within %ss\n' "$SERVICE_TRANSITION_TIMEOUT" >&2
			return 1
		}
		sleep 1
		remaining=$((remaining - 1))
	done
}

wait_service_running() {
	remaining=$SERVICE_TRANSITION_TIMEOUT
	while ! service_running; do
		[ "$remaining" -gt 0 ] || {
			printf 'service did not start within %ss\n' "$SERVICE_TRANSITION_TIMEOUT" >&2
			return 1
		}
		sleep 1
		remaining=$((remaining - 1))
	done
}

WAS_RUNNING=0
WAS_ENABLED=0
service_running && WAS_RUNNING=1
service_enabled && WAS_ENABLED=1

same_integration_file() {
	source=$1
	target=$2
	[ -f "$target" ] && [ ! -L "$target" ] && cmp -s "$source" "$target"
}

integration_files_match() {
	same_integration_file "${SCRIPT_DIR}/files/etc/init.d/boxctl" "$SERVICE" &&
		same_integration_file "${SCRIPT_DIR}/files/etc/hotplug.d/iface/40-boxctl" "$HOTPLUG_IFACE" &&
		same_integration_file "${SCRIPT_DIR}/files/etc/hotplug.d/net/99-boxctl-tun" "$HOTPLUG_TUN" &&
		same_integration_file "${SCRIPT_DIR}/files/etc/apk/protected_paths.d/boxctl.list" "$APK_PATHS" &&
		same_integration_file "${SCRIPT_DIR}/files/lib/upgrade/keep.d/boxctl" "$SYSUPGRADE_KEEP"
}

try_seamless_update() {
	installed="${ROOT}/bin/boxctl"
	if [ "$START_AFTER" != "1" ]; then
		printf '%s\n' 'seamless update unavailable: --no-start requests a stopped service'
		return 1
	fi
	if [ "$ROOT_WAS_PRESENT" != "1" ] || [ ! -x "$installed" ] || [ -L "$installed" ]; then
		printf '%s\n' 'seamless update unavailable: no existing regular boxctl binary'
		return 1
	fi
	if [ "$WAS_RUNNING" != "1" ]; then
		printf '%s\n' 'seamless update unavailable: boxctl service is not running'
		return 1
	fi
	if ! grep -Fq 'manager_handoff()' "$SERVICE" || ! integration_files_match; then
		printf '%s\n' 'seamless update unavailable: OpenWrt integration files need an update'
		return 1
	fi
	command -v jsonfilter >/dev/null 2>&1 || {
		printf '%s\n' 'seamless update unavailable: jsonfilter is missing'
		return 1
	}
	current_build=$("$installed" version --json 2>/dev/null) || {
		printf '%s\n' 'seamless update unavailable: installed boxctl has no compatibility metadata'
		return 1
	}
	candidate_build=$("$SOURCE_BINARY" version --json 2>/dev/null) || {
		printf '%s\n' 'seamless update unavailable: candidate boxctl has no compatibility metadata'
		return 1
	}
	current_settings=$(jsonfilter -s "$current_build" -e '@.settingsSchemaVersion' 2>/dev/null) || return 1
	current_capture=$(jsonfilter -s "$current_build" -e '@.captureInjectorVersion' 2>/dev/null) || return 1
	candidate_settings=$(jsonfilter -s "$candidate_build" -e '@.settingsSchemaVersion' 2>/dev/null) || return 1
	candidate_capture=$(jsonfilter -s "$candidate_build" -e '@.captureInjectorVersion' 2>/dev/null) || return 1
	for compatibility_version in \
		"$current_settings" "$current_capture" "$candidate_settings" "$candidate_capture"
	do
		case "$compatibility_version" in
			''|0|*[!0-9]*)
				printf '%s\n' 'seamless update unavailable: invalid compatibility metadata'
				return 1
				;;
		esac
	done
	if [ "$current_settings" != "$candidate_settings" ] || [ "$current_capture" != "$candidate_capture" ]; then
		printf 'seamless update unavailable: compatibility changed (settings %s -> %s, capture %s -> %s)\n' \
			"$current_settings" "$candidate_settings" "$current_capture" "$candidate_capture"
		return 1
	fi
	digest=$(sha256sum "$SOURCE_BINARY" | awk '{print $1}')
	printf '%s\n' 'existing compatible installation detected; updating only the boxctl manager'
	if ! "$installed" self-update install --file "$SOURCE_BINARY" --sha256 "$digest"; then
		printf '%s\n' 'seamless boxctl update failed; refusing to continue with a full reinstall' >&2
		return 2
	fi
	printf 'updated boxctl seamlessly in %s; Mihomo and the active dataplane were preserved\n' "$ROOT"
	return 0
}

if [ "$PREFER_SEAMLESS" = "1" ]; then
	if try_seamless_update; then
		exit 0
	else
		seamless_status=$?
		[ "$seamless_status" = "1" ] || exit "$seamless_status"
	fi
	printf '%s\n' 'falling back to the transactional installer; the managed service will restart'
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="/tmp/boxctl-install-${STAMP}-$$"
mkdir "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

backup_file() {
	key=$1
	path=$2
	if [ -e "$path" ] || [ -L "$path" ]; then
		cp -a "$path" "${BACKUP_DIR}/${key}"
		printf 'present\n' > "${BACKUP_DIR}/${key}.state"
	else
		printf 'absent\n' > "${BACKUP_DIR}/${key}.state"
	fi
}

restore_file() {
	key=$1
	target=$2
	state=$(sed -n '1p' "${BACKUP_DIR}/${key}.state")
	case "$state" in
		present)
			mkdir -p "$(dirname "$target")"
			cp -a "${BACKUP_DIR}/${key}" "${target}.rollback-$$"
			mv -f "${target}.rollback-$$" "$target"
			;;
		absent) rm -f "$target" ;;
		*) printf 'invalid installer backup state for %s\n' "$key" >&2; return 1 ;;
	esac
}

backup_file binary "${ROOT}/bin/boxctl"
backup_file service "$SERVICE"
backup_file config "$CONFIG"
backup_file hotplug_iface "$HOTPLUG_IFACE"
backup_file hotplug_tun "$HOTPLUG_TUN"
backup_file apk_paths "$APK_PATHS"
backup_file sysupgrade_keep "$SYSUPGRADE_KEEP"

cleanup_backup() {
	case "$BACKUP_DIR" in
		/tmp/boxctl-install-*) rm -rf "$BACKUP_DIR" ;;
		*) printf 'refusing to remove unexpected backup path: %s\n' "$BACKUP_DIR" >&2 ;;
	esac
}

rollback_on_error() {
	status=$?
	trap - EXIT HUP INT TERM
	printf 'install failed; restoring the previous boxctl installation\n' >&2
	[ ! -x "$SERVICE" ] || "$SERVICE" stop >/dev/null 2>&1 || true
	if [ "$ROOT_WAS_PRESENT" = "0" ]; then
		case "$ROOT" in /opt/boxctl) rm -rf "$ROOT" ;; esac
	else
		restore_file binary "${ROOT}/bin/boxctl" || true
	fi
	restore_file service "$SERVICE" || true
	restore_file config "$CONFIG" || true
	restore_file hotplug_iface "$HOTPLUG_IFACE" || true
	restore_file hotplug_tun "$HOTPLUG_TUN" || true
	restore_file apk_paths "$APK_PATHS" || true
	restore_file sysupgrade_keep "$SYSUPGRADE_KEEP" || true
	if [ "$WAS_ENABLED" = "1" ] && [ -x "$SERVICE" ]; then "$SERVICE" enable || true; fi
	if [ "$WAS_RUNNING" = "1" ] && [ -x "$SERVICE" ]; then "$SERVICE" start || true; fi
	cleanup_backup
	exit "$status"
}
trap rollback_on_error EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if service_running; then
	"$SERVICE" stop
	wait_service_stopped
fi

install_atomic() {
	source=$1
	target=$2
	mode=$3
	directory=$(dirname "$target")
	mkdir -p "$directory"
	temporary="${directory}/.boxctl-install-$$"
	cp "$source" "$temporary"
	chmod "$mode" "$temporary"
	mv -f "$temporary" "$target"
}

mkdir -p \
	"${ROOT}/bin" \
	"${ROOT}/engines/mihomo" \
	"${ROOT}/.boxctl" \
	"${ROOT}/profiles" \
	"${ROOT}/local-rules" \
	"${ROOT}/rule-providers" \
	"${ROOT}/proxy-providers" \
	"${ROOT}/subscriptions" \
	"${ROOT}/.install"
chmod 700 "$ROOT" "${ROOT}/.boxctl" "${ROOT}/.install"

install_atomic "$SOURCE_BINARY" "${ROOT}/bin/boxctl" 0755
install_atomic "${SCRIPT_DIR}/files/etc/init.d/boxctl" "$SERVICE" 0755
if [ ! -e "$CONFIG" ]; then
	install_atomic "${SCRIPT_DIR}/files/etc/config/boxctl" "$CONFIG" 0644
fi
install_atomic "${SCRIPT_DIR}/files/etc/hotplug.d/iface/40-boxctl" "$HOTPLUG_IFACE" 0755
install_atomic "${SCRIPT_DIR}/files/etc/hotplug.d/net/99-boxctl-tun" "$HOTPLUG_TUN" 0755
install_atomic "${SCRIPT_DIR}/files/etc/apk/protected_paths.d/boxctl.list" "$APK_PATHS" 0644
install_atomic "${SCRIPT_DIR}/files/lib/upgrade/keep.d/boxctl" "$SYSUPGRADE_KEEP" 0644

if [ "$ROOT_WAS_PRESENT" = "0" ]; then
	: > "$START_STOPPED_MARKER"
	chmod 600 "$START_STOPPED_MARKER"
fi

if [ "$START_AFTER" = "1" ] || [ "$WAS_ENABLED" = "1" ]; then
	"$SERVICE" enable
else
	"$SERVICE" disable
fi
if [ "$START_AFTER" = "1" ]; then
	"$SERVICE" start
	wait_service_running
fi

trap - EXIT HUP INT TERM
cleanup_backup
printf 'installed boxctl in %s\n' "$ROOT"
if [ "$START_AFTER" = "1" ]; then
	printf 'management service is running; fresh installs keep the core stopped until Start is pressed in the UI\n'
else
	printf 'management service is installed but not running\n'
fi
