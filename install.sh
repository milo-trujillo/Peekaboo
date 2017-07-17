#!/bin/sh

if [[ $EUID -ne 0 ]]; then
	echo "Cannot install without root priviledges, please use sudo" 1>&2
	exit 1
fi

# Not all systems store manpages in the same place, so we may eventually
# want to use more complex logic for determining that path.
DIR=`dirname $0`
cp -v $DIR/peekaboo.py /usr/local/sbin/peekaboo
cp -v $DIR/peekaboo.8 /usr/local/man/man8/peekaboo.8
