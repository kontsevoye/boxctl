#!/bin/sh
set -eu

[ "$#" -eq 1 ] || {
	printf 'usage: %s YYYY.MM.N\n' "$0" >&2
	exit 2
}

value=$1
year=${value%%.*}
remainder=${value#*.}
month=${remainder%%.*}
sequence=${remainder#*.}

[ "$year" != "$value" ] && [ "$month" != "$remainder" ] && [ "$sequence" != "$remainder" ] || {
	printf 'CalVer must use YYYY.MM.N\n' >&2
	exit 2
}
case "$year" in
	[1-9][0-9][0-9][0-9]) ;;
	*) printf 'CalVer year must use YYYY\n' >&2; exit 2 ;;
esac
case "$month" in
	0[1-9]|1[0-2]) ;;
	*) printf 'CalVer month must use zero-padded MM\n' >&2; exit 2 ;;
esac
case "$sequence" in
	''|0|0[0-9]*|*[!0-9]*) printf 'CalVer release number must be a canonical positive integer\n' >&2; exit 2 ;;
esac

[ "$value" = "${year}.${month}.${sequence}" ] || {
	printf 'CalVer must use its canonical YYYY.MM.N form\n' >&2
	exit 2
}
