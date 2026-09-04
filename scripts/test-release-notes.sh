#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
RELEASE_NOTES=${SCRIPT_DIR}/release-notes.sh
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

git -C "$temporary" init --quiet
git -C "$temporary" config user.name 'boxctl test'
git -C "$temporary" config user.email 'boxctl@example.invalid'
git -C "$temporary" config commit.gpgsign false
git -C "$temporary" config tag.gpgsign false

printf 'initial\n' > "$temporary/file"
git -C "$temporary" add file
git -C "$temporary" commit --quiet -m 'initial release'
git -C "$temporary" tag v2025.01.15

printf 'first\n' >> "$temporary/file"
git -C "$temporary" commit --quiet -am 'fix first issue'
first=$(git -C "$temporary" rev-parse --short=7 HEAD)
printf 'second\n' >> "$temporary/file"
git -C "$temporary" commit --quiet -am 'add second feature'
second=$(git -C "$temporary" rev-parse --short=7 HEAD)

notes=$(cd "$temporary" && RELEASE_REPOSITORY_URL=https://github.com/example/boxctl \
	"$RELEASE_NOTES" v2025.01.16 HEAD)
for required in \
	'## Changes' \
	'- fix first issue' \
	"[\`$first\`](https://github.com/example/boxctl/commit/" \
	'- add second feature' \
	"[\`$second\`](https://github.com/example/boxctl/commit/" \
	'**Full Changelog**: https://github.com/example/boxctl/compare/v2025.01.15...v2025.01.16'
do
	printf '%s\n' "$notes" | grep -F -- "$required" >/dev/null || {
		printf 'release notes are missing %s\n%s\n' "$required" "$notes" >&2
		exit 1
	}
done
if printf '%s\n' "$notes" | grep -F 'initial release' >/dev/null; then
	printf 'release notes include a commit from the previous release\n' >&2
	exit 1
fi

printf 'Release-notes tests passed\n'
