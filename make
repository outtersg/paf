#!/bin/sh

_()
{
	echo "[90m$@[0m"
	"$@"
}

copier()
{
	local d f
	find etc -name paf.conf -o -name paf.lua -o -name paf.regles | cut -d / -f 2- | while read f
	do
		d="`dirname "$f"`"
		[ -d "$DEST/$d" ] || mkdir "$DEST/$d"
		_ cp "etc/$f" "$DEST/$f"
	done
}

faire()
{
	set -e
	DEST="$1"
	if [ -z "$DEST" -o ! -d "$DEST" ]
	then
		printf "\033[31m# %s\033[0m\n" "./make <destination>" >&2
		exit 1
	fi
	
	copier
}

faire "$@"
