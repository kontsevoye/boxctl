#!/bin/sh
set -eu

PROGRAM=${0##*/}
DEFAULT_TARGET=root@router.lan
DEFAULT_PORT=22
DEFAULT_UI_PORT=9091
UI_ATTEMPTS=20
UI_REQUEST_TIMEOUT=2

usage() {
	cat <<EOF
Usage: $PROGRAM [OPTIONS]

Build and deploy the Linux/AArch64 OpenWrt bundle. On a fresh installation the
manager starts with Mihomo stopped, so routing changes only after you review
the UI and press Start. Existing boxctl state is retained during updates. The
deploy preflight installs ip-full and ca-bundle when necessary.

Options:
  --target USER@HOST  SSH target (default: $DEFAULT_TARGET)
  --port PORT         SSH port (default: $DEFAULT_PORT)
  --identity FILE     SSH private key
  --ui-host HOST      Host printed in the UI URL (default: target host)
  --version VERSION   Build version metadata (default: current Git revision)
  --dry-run           Validate options and print commands; do not build or connect
  -h, --help          Show this help

The same defaults can be overridden with BOXCTL_OPENWRT_TARGET,
BOXCTL_SSH_PORT, BOXCTL_SSH_IDENTITY, BOXCTL_UI_HOST and BOXCTL_VERSION.
EOF
}

die() {
	printf '%s: %s\n' "$PROGRAM" "$*" >&2
	exit 2
}

require_value() {
	[ "$#" -ge 2 ] || die "$1 requires a value"
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

quote_arg() {
	escaped=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
	printf "'%s'" "$escaped"
}

print_command_words() {
	_boxctl_print_separator=
	for argument do
		printf '%s' "$_boxctl_print_separator"
		quote_arg "$argument"
		_boxctl_print_separator=' '
	done
	printf '\n'
	unset _boxctl_print_separator
}

print_command() {
	printf '+ '
	print_command_words "$@"
}

target=${BOXCTL_OPENWRT_TARGET:-$DEFAULT_TARGET}
ssh_port=${BOXCTL_SSH_PORT:-$DEFAULT_PORT}
identity=${BOXCTL_SSH_IDENTITY:-}
ui_host=${BOXCTL_UI_HOST:-}
version=${BOXCTL_VERSION:-}
dry_run=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--target)
			require_value "$@"
			target=$2
			shift 2
			;;
		--port)
			require_value "$@"
			ssh_port=$2
			shift 2
			;;
		--identity)
			require_value "$@"
			identity=$2
			shift 2
			;;
		--ui-host)
			require_value "$@"
			ui_host=$2
			shift 2
			;;
		--version)
			require_value "$@"
			version=$2
			shift 2
			;;
		--dry-run)
			dry_run=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		--)
			shift
			[ "$#" -eq 0 ] || die "positional arguments are not supported"
			;;
		*) die "unknown option: $1" ;;
	esac
done

# Keep the connection destination data-only. In particular, do not accept SSH
# options, remote paths, shell metacharacters, or multiple user separators.
case "$target" in
	''|-*|@*|*/*|*:*|*@*@*|*[!A-Za-z0-9._@%+-]*) die "unsafe SSH target: $target" ;;
esac
target_host=${target#*@}
[ -n "$target_host" ] || die "SSH target has an empty host"

case "$ssh_port" in
	''|*[!0-9]*) die "SSH port must be an integer" ;;
esac
[ "${#ssh_port}" -le 5 ] || die "SSH port is outside 1..65535"
[ "$ssh_port" -ge 1 ] && [ "$ssh_port" -le 65535 ] || die "SSH port is outside 1..65535"

if [ -n "$identity" ]; then
	[ -f "$identity" ] && [ -r "$identity" ] || die "SSH identity is not a readable regular file: $identity"
fi

if [ -z "$ui_host" ]; then
	ui_host=$target_host
fi
case "$ui_host" in
	''|-*|*/*|*:*|*[!A-Za-z0-9._-]*) die "unsafe UI host: $ui_host" ;;
esac
SCRIPT_DIR=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(CDPATH='' cd -P "$SCRIPT_DIR/.." && pwd)
BUNDLE=$PROJECT_ROOT/dist/boxctl-openwrt-linux-arm64.tar.gz
BUNDLE_NAME=${BUNDLE##*/}
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if COMMIT=$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null); then
	:
else
	COMMIT=unknown
fi
STAGE_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
if [ -z "$version" ]; then
	if [ "$COMMIT" = "unknown" ]; then
		version=dev-$STAGE_STAMP
	elif [ -n "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
		version=$COMMIT-dirty-$STAGE_STAMP
	else
		version=$COMMIT
	fi
fi
case "$version" in
	''|*[!A-Za-z0-9._+:-]*) die "version contains unsupported characters" ;;
esac
REMOTE_STAGE=/tmp/boxctl-deploy-$STAGE_STAMP-$$
REMOTE_PREPARE="set -eu; umask 077; mkdir '$REMOTE_STAGE'"
REMOTE_VERIFY="set -eu; cd '$REMOTE_STAGE'; sha256sum -c bundle.sha256; mkdir payload; tar -xzf '$BUNDLE_NAME' -C payload"
# Variables in this template are expanded by the remote shell.
# shellcheck disable=SC2016
REMOTE_DEPENDENCIES='set -eu
need_ip_full=0
need_ca_bundle=0
ca_bundle_installed() {
	apk info 2>/dev/null | grep -qx ca-bundle
}
if ip -N -4 rule show >/dev/null 2>&1; then
	printf "%s\n" "dependency preflight: ip-full capability is available"
else
	need_ip_full=1
	printf "%s\n" "dependency preflight: ip-full capability is missing"
fi
if ca_bundle_installed; then
	printf "%s\n" "dependency preflight: ca-bundle is installed"
else
	need_ca_bundle=1
	printf "%s\n" "dependency preflight: ca-bundle is missing"
fi
if [ "$need_ip_full" -eq 1 ] || [ "$need_ca_bundle" -eq 1 ]; then
	command -v apk >/dev/null 2>&1 || {
		printf "%s\n" "dependency preflight: apk is required to install missing packages" >&2
		exit 1
	}
	printf "%s\n" "dependency preflight: refreshing signed OpenWrt package indexes"
	apk update
	case "$need_ip_full:$need_ca_bundle" in
		1:1) printf "%s\n" "dependency preflight: installing ip-full and ca-bundle"; apk add ip-full ca-bundle ;;
		1:0) printf "%s\n" "dependency preflight: installing ip-full"; apk add ip-full ;;
		0:1) printf "%s\n" "dependency preflight: installing ca-bundle"; apk add ca-bundle ;;
	esac
	hash -r 2>/dev/null || :
fi
ip -N -4 rule show >/dev/null 2>&1 || {
	printf "%s\n" "dependency preflight: ip-full capability is still unavailable after package installation" >&2
	exit 1
}
ca_bundle_installed || {
	printf "%s\n" "dependency preflight: ca-bundle is still not installed after package installation" >&2
	exit 1
}
printf "%s\n" "dependency preflight: ip-full and ca-bundle are ready"'
REMOTE_INSTALL="set -eu; cd '$REMOTE_STAGE/payload'; ./install.sh ./boxctl-linux-arm64 --prefer-seamless"
REMOTE_CLEANUP="rm -rf '$REMOTE_STAGE'"
UI_URL=http://$ui_host:$DEFAULT_UI_PORT/

run_ssh() {
	if [ -n "$identity" ]; then
		ssh -p "$ssh_port" -i "$identity" "$target" "$1"
	else
		ssh -p "$ssh_port" "$target" "$1"
	fi
}

put_bundle() {
	checksum_file=$1
	if [ -n "$identity" ]; then
		scp -O -P "$ssh_port" -i "$identity" "$BUNDLE" "$checksum_file" "$target:$REMOTE_STAGE/"
	else
		scp -O -P "$ssh_port" "$BUNDLE" "$checksum_file" "$target:$REMOTE_STAGE/"
	fi
}

print_ssh() {
	if [ -n "$identity" ]; then
		print_command ssh -p "$ssh_port" -i "$identity" "$target" "$1"
	else
		print_command ssh -p "$ssh_port" "$target" "$1"
	fi
}

print_ssh_plain() {
	if [ -n "$identity" ]; then
		print_command_words ssh -p "$ssh_port" -i "$identity" "$target" "$1"
	else
		print_command_words ssh -p "$ssh_port" "$target" "$1"
	fi
}

print_scp() {
	if [ -n "$identity" ]; then
		print_command scp -O -P "$ssh_port" -i "$identity" "$BUNDLE" '<generated-checksum-file>' "$target:$REMOTE_STAGE/"
	else
		print_command scp -O -P "$ssh_port" "$BUNDLE" '<generated-checksum-file>' "$target:$REMOTE_STAGE/"
	fi
}

verify_ui() {
	attempt=1
	while [ "$attempt" -le "$UI_ATTEMPTS" ]; do
		if curl --fail --silent --show-error --max-time "$UI_REQUEST_TIMEOUT" \
			--output /dev/null "$UI_URL" 2>/dev/null
		then
			return 0
		fi
		if [ "$attempt" -lt "$UI_ATTEMPTS" ]; then
			sleep 1
		fi
		attempt=$((attempt + 1))
	done
	return 1
}

if [ "$dry_run" = 1 ]; then
	print_command make -C "$PROJECT_ROOT" bundle-openwrt-arm64 "VERSION=$version" "COMMIT=$COMMIT" "DATE=$BUILD_DATE"
	printf "+ calculate SHA-256 for "
	quote_arg "$BUNDLE"
	printf '\n'
	print_ssh "$REMOTE_PREPARE"
	print_scp
	printf '# Verify and extract the uploaded bundle.\n'
	print_ssh "$REMOTE_VERIFY"
	printf '# Check and install required OpenWrt packages.\n'
	print_ssh "$REMOTE_DEPENDENCIES"
	printf '# Prefer a core-preserving self-update; use the transactional installer when unavailable.\n'
	print_ssh "$REMOTE_INSTALL"
	print_ssh "$REMOTE_CLEANUP"
	print_command curl --fail --silent --show-error --max-time "$UI_REQUEST_TIMEOUT" --output /dev/null "$UI_URL"
	printf '  # retried up to %s times\n' "$UI_ATTEMPTS"
	printf '\nDry run only; the router was not contacted.\n'
	printf 'UI after deployment: %s\n' "$UI_URL"
	exit 0
fi

for command_name in make git date mktemp sed awk ssh scp curl sleep; do
	require_command "$command_name"
done

printf 'Building Linux/AArch64 OpenWrt bundle...\n'
make -C "$PROJECT_ROOT" bundle-openwrt-arm64 \
	"VERSION=$version" "COMMIT=$COMMIT" "DATE=$BUILD_DATE"
[ -f "$BUNDLE" ] && [ -s "$BUNDLE" ] || die "bundle was not created: $BUNDLE"

if command -v sha256sum >/dev/null 2>&1; then
	BUNDLE_SHA256=$(sha256sum "$BUNDLE" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
	BUNDLE_SHA256=$(shasum -a 256 "$BUNDLE" | awk '{print $1}')
else
	die "sha256sum or shasum is required"
fi
case "$BUNDLE_SHA256" in
	????????????????????????????????????????????????????????????????) ;;
	*) die "failed to calculate bundle SHA-256" ;;
esac

LOCAL_STAGE=$(mktemp -d "${TMPDIR:-/tmp}/boxctl-deploy.XXXXXX")
REMOTE_STAGE_PREPARED=0
cleanup_deploy() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$REMOTE_STAGE_PREPARED" = 1 ]; then
		if ! run_ssh "$REMOTE_CLEANUP" >/dev/null 2>&1; then
			printf 'warning: could not remove remote transport stage %s\n' "$REMOTE_STAGE" >&2
		fi
	fi
	rm -rf "$LOCAL_STAGE"
	exit "$status"
}
trap cleanup_deploy EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s  %s\n' "$BUNDLE_SHA256" "$BUNDLE_NAME" > "$LOCAL_STAGE/bundle.sha256"

printf 'Preparing private remote stage %s...\n' "$REMOTE_STAGE"
run_ssh "$REMOTE_PREPARE"
REMOTE_STAGE_PREPARED=1
printf 'Uploading bundle (%s)...\n' "$BUNDLE_SHA256"
put_bundle "$LOCAL_STAGE/bundle.sha256"
printf 'Verifying remote checksum and extracting the bundle...\n'
run_ssh "$REMOTE_VERIFY"
printf 'Checking OpenWrt dependencies...\n'
run_ssh "$REMOTE_DEPENDENCIES"
printf 'Installing boxctl (preferring a core-preserving manager handoff)...\n'
run_ssh "$REMOTE_INSTALL"
if run_ssh "$REMOTE_CLEANUP"; then
	REMOTE_STAGE_PREPARED=0
else
	printf 'warning: could not remove remote transport stage %s\n' "$REMOTE_STAGE" >&2
fi

printf 'Waiting for management UI at %s...\n' "$UI_URL"
if ! verify_ui; then
	printf 'boxctl was installed, but its management UI did not become reachable after %s attempts.\n' "$UI_ATTEMPTS" >&2
	printf 'Inspect from this host: ' >&2
	print_ssh_plain 'logread -e boxctl' >&2
	exit 1
fi

printf '\nboxctl is installed and its management UI is available.\n'
printf 'Open: %s\n' "$UI_URL"
printf 'On a fresh installation, configure Mihomo and press Start in the boxctl UI.\n'
