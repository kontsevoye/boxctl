#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
DEPLOY=$SCRIPT_DIR/deploy-openwrt.sh
PROJECT_ROOT=$(CDPATH='' cd -P "$SCRIPT_DIR/.." && pwd)

grep -F "install -m 0644 LICENSE" "$PROJECT_ROOT/Makefile" >/dev/null || {
	printf 'OpenWrt bundle does not install LICENSE\n' >&2
	exit 1
}
if [ ! -f "$PROJECT_ROOT/LICENSE" ]; then
	printf 'OpenWrt bundle references a missing LICENSE\n' >&2
	exit 1
fi

for expected in \
	'cleanup_deploy()' \
	'trap cleanup_deploy EXIT' \
	'REMOTE_STAGE_PREPARED=1' \
	"run_ssh \"\$REMOTE_CLEANUP\""
do
	grep -F "$expected" "$DEPLOY" >/dev/null || {
		printf 'deploy cleanup contract is missing: %s\n' "$expected" >&2
		exit 1
	}
done

help=$("$DEPLOY" --help)
case "$help" in
	*'--target USER@HOST'*'--dry-run'*) ;;
	*) printf 'deploy help is incomplete\n' >&2; exit 1 ;;
esac

rendered=$("$DEPLOY" --dry-run)
current_commit=$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD)
for expected in \
	'bundle-openwrt-arm64' \
	"VERSION=$current_commit" \
	'root@router.lan' \
	'sha256sum -c bundle.sha256' \
	'ip -N -4 rule show' \
	'apk info' \
	'grep -qx ca-bundle' \
	'apk update' \
	'apk add ip-full ca-bundle' \
	'./install.sh ./boxctl-linux-arm64 --prefer-seamless' \
	'Prefer a core-preserving self-update' \
	'curl' \
	'http://router.lan:9091/'
do
	case "$rendered" in
		*"$expected"*) ;;
		*) printf 'dry-run output is missing: %s\n' "$expected" >&2; exit 1 ;;
	esac
done

case "$rendered" in
	*'sha256sum -c bundle.sha256'*'ip -N -4 rule show'*'apk update'*'./install.sh ./boxctl-linux-arm64 --prefer-seamless'*) ;;
	*) printf 'dependency preflight is not rendered before install.sh\n' >&2; exit 1 ;;
esac
case "$rendered" in
	*'allow-untrusted'*) printf 'dry-run contains an insecure apk option\n' >&2; exit 1 ;;
esac

custom=$("$DEPLOY" --dry-run --target admin@router.lan --port 2222 --ui-host 192.0.2.10 --version test-build)
case "$custom" in
	*"'VERSION=test-build'"*"'2222'"*"'admin@router.lan'"*'http://192.0.2.10:9091/'*) ;;
	*) printf 'safe target overrides were not rendered\n' >&2; exit 1 ;;
esac

if "$DEPLOY" --dry-run --target '-oProxyCommand=bad' >/dev/null 2>&1; then
	printf 'unsafe SSH target was accepted\n' >&2
	exit 1
fi
if "$DEPLOY" --dry-run --port 70000 >/dev/null 2>&1; then
	printf 'invalid SSH port was accepted\n' >&2
	exit 1
fi

printf 'deploy-openwrt script checks passed\n'
