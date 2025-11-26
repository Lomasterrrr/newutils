#!/bin/sh

CFLAGS="-Wall -g -O2"
[ -f /proc/sys/kernel/osrelease ] && uname -s | grep -q '^Linux$' && CFLAGS="$CFLAGS -D__LINUX"

case "$1" in
    clean) rm -f *.o arping ;;
    *) 
        cc $CFLAGS -c src/base/*.c
        cc $CFLAGS -c src/*.c
        cc $CFLAGS err.o if.o utils.o arping.o -o arping
        ;;
esac

