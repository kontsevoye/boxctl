#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
CALVER="${SCRIPT_DIR}/calver.sh"
VALIDATE_CALVER="${SCRIPT_DIR}/validate-calver.sh"

actual=$(CALVER_YEAR=2025 CALVER_MONTH=01 "$CALVER" v2025.01.2 v2025.01.15 v2024.12.99 v2025.01.invalid)
[ "$actual" = "2025.01.16" ] || {
	printf 'unexpected next CalVer: %s\n' "$actual" >&2
	exit 1
}
"$VALIDATE_CALVER" "$actual"

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
git -C "$temporary" init --quiet
object=$(printf 'boxctl test\n' | git -C "$temporary" hash-object -w --stdin)
git -C "$temporary" update-ref refs/tags/v2025.01.2 "$object"
git -C "$temporary" update-ref refs/tags/v2025.01.15 "$object"
git -C "$temporary" update-ref refs/tags/v2025.01.15.1 "$object"
from_tags=$(cd "$temporary" && CALVER_YEAR=2025 CALVER_MONTH=01 "$CALVER")
[ "$from_tags" = "2025.01.16" ] || {
	printf 'unexpected tag-derived CalVer: %s\n' "$from_tags" >&2
	exit 1
}

first=$(CALVER_YEAR=2025 CALVER_MONTH=02 "$CALVER" v2025.01.15)
[ "$first" = "2025.02.1" ] || {
	printf 'unexpected first monthly CalVer: %s\n' "$first" >&2
	exit 1
}

for invalid in 2025.1.15 2025.01.0 2025.01.015 2025.13.1 25.01.1 v2025.01.15 2025.01.15.1; do
	if "$VALIDATE_CALVER" "$invalid" >/dev/null 2>&1; then
		printf 'invalid canonical CalVer was accepted: %s\n' "$invalid" >&2
		exit 1
	fi
done

if CALVER_YEAR=2025 CALVER_MONTH=1 "$CALVER" >/dev/null 2>&1; then
	printf 'non-padded month was accepted\n' >&2
	exit 1
fi

printf 'CalVer tests passed\n'
