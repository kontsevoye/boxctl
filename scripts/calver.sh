#!/bin/sh
set -eu

if [ -n "${CALVER_YEAR:-}" ]; then
	year=$CALVER_YEAR
else
	year=$(date -u +%Y)
fi
if [ -n "${CALVER_MONTH:-}" ]; then
	month=$CALVER_MONTH
else
	month=$(date -u +%m)
fi

case "$year" in
	[1-9][0-9][0-9][0-9]) ;;
	*) printf 'CALVER_YEAR must use YYYY\n' >&2; exit 2 ;;
esac
case "$month" in
	0[1-9]|1[0-2]) ;;
	*) printf 'CALVER_MONTH must use zero-padded MM\n' >&2; exit 2 ;;
esac

maximum=0
if [ "$#" -gt 0 ]; then
	for tag in "$@"; do
		case "$tag" in
			"v${year}.${month}."[1-9]*) ;;
			*) continue ;;
		esac
		version=${tag#v}
		[ "$version" = "${year}.${month}.${version##*.}" ] || continue
		sequence=${version##*.}
		case "$sequence" in
			*[!0-9]*) continue ;;
		esac
		[ "$sequence" -gt "$maximum" ] && maximum=$sequence
	done
else
	maximum=$(git for-each-ref --format='%(refname:short)' "refs/tags/v${year}.${month}.*" |
		awk -F. -v year="v${year}" -v month="$month" '
			NF == 3 && $1 == year && $2 == month && $3 ~ /^[1-9][0-9]*$/ && $3 > maximum { maximum = $3 }
			END { print maximum + 0 }
		')
fi

next=$((maximum + 1))
printf '%s.%s.%s\n' "$year" "$month" "$next"
