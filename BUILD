#!/bin/sh

CFLAGS="-Wall -g -O2"
[ -f /proc/sys/kernel/osrelease ] && uname -s | grep -q '^Linux$' && CFLAGS="$CFLAGS -D__LINUX"

case "$1" in
	format)
	if command -v clang-format19 >/dev/null 2>&1; then
		find src -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format19 -i {} \;
    	fi
	;;

	clean) rm -f *.o arping traceroute ;;

	*) 
	cc $CFLAGS -c src/base/*.c
	cc $CFLAGS -c src/*.c
	cc $CFLAGS err.o if.o utils.o arping.o -o arping
	cc $CFLAGS cksum.o random.o err.o if.o utils.o traceroute.o -o traceroute
        ;;
esac

