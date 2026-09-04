#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
TAG=${1:-}
TARGET=${2:-HEAD}

case "$TAG" in
	v*) version=${TAG#v} ;;
	*) printf 'usage: %s vYYYY.MM.N [commit]\n' "$0" >&2; exit 2 ;;
esac
"${SCRIPT_DIR}/validate-calver.sh" "$version"
git rev-parse --verify "${TARGET}^{commit}" >/dev/null

repository_url=${RELEASE_REPOSITORY_URL:-}
if [ -z "$repository_url" ] && [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
	repository_url=${GITHUB_SERVER_URL%/}/${GITHUB_REPOSITORY}
fi
if [ -z "$repository_url" ]; then
	printf 'RELEASE_REPOSITORY_URL or GITHUB_SERVER_URL/GITHUB_REPOSITORY must be set\n' >&2
	exit 2
fi
repository_url=${repository_url%/}

previous=
nearest_distance=
for candidate in $(git tag --merged "$TARGET" --list 'v*'); do
	[ "$candidate" = "$TAG" ] && continue
	if ! "${SCRIPT_DIR}/validate-calver.sh" "${candidate#v}" >/dev/null 2>&1; then
		continue
	fi
	distance=$(git rev-list --count "${candidate}..${TARGET}")
	[ "$distance" -gt 0 ] || continue
	if [ -z "$nearest_distance" ] || [ "$distance" -lt "$nearest_distance" ]; then
		previous=$candidate
		nearest_distance=$distance
	fi
done

if [ -n "$previous" ]; then
	range=${previous}..${TARGET}
	changelog_url=${repository_url}/compare/${previous}...${TAG}
else
	range=$TARGET
	changelog_url=${repository_url}/commits/${TAG}
fi

printf '## Changes\n\n'
git log --reverse --format='%H%x09%s' "$range" |
	while IFS="$(printf '\t')" read -r commit subject; do
		short=$(git rev-parse --short=7 "$commit")
		printf -- "- %s ([\`%s\`](%s/commit/%s))\n" "$subject" "$short" "$repository_url" "$commit"
	done
printf '\n**Full Changelog**: %s\n' "$changelog_url"
