#!/bin/sh

set -eu

static_dir=${1:-internal/web/static}
assets_dir="$static_dir/assets"

if [ ! -d "$assets_dir" ]; then
	printf 'frontend asset directory does not exist: %s\n' "$assets_dir" >&2
	exit 1
fi

find "$assets_dir" -type f ! -name '*.gz' -size +1024c -print | while IFS= read -r asset; do
	temporary="$asset.gz.tmp"
	rm -f "$temporary"
	if ! gzip -n -9 -c "$asset" >"$temporary"; then
		rm -f "$temporary"
		exit 1
	fi
	mv -f "$temporary" "$asset.gz"
done
