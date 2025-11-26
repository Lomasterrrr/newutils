#ifndef __NU_INCLUDE_H
#define __NU_INCLUDE_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include <poll.h>
#include <getopt.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#ifdef __LINUX
#include <netpacket/packet.h>
#include <netinet/ether.h>
#else
#include <net/bpf.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <err.h>
#endif

#endif
