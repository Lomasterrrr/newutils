/*
 * Copyright (c) 2025, lomaster. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "../include/base.h"

/*	Ping methods.	*/
#define ECHO_METHOD	 (1U << 0)
#define SYN_METHOD	 (1U << 1)
#define ACK_METHOD	 (1U << 2)
#define INFO_METHOD	 (1U << 3)
#define TIMESTAMP_METHOD (1U << 4)
#define UDP_METHOD	 (1U << 5)
#define COOKIE_METHOD	 (1U << 6)
#define INIT_METHOD	 (1U << 7)

static bool Iflag = 0;
static char *Iopt = NULL;
static dlt_t *dlt = NULL;		     /* socket */
static long long interval = 1000 * 1000000L; /* delay/interval */
static bool sflag = 0;
static bool vflag = 0;
static u_char outpack[2048] = { 0 };
static struct in_addr sopt = { 0 };
static bool Sflag = 0;
static bool Tflag = 0;
static struct ether_addr Sopt = { 0 };
static bool prstats = 0; /* print last stats? */
static size_t ntransmitted = 0;
static size_t nreceived = 0;
static size_t npackets = 5;
static long long tmin = 0;
static long long wait = 1000 * 1000000LL; /* timeout */
static long long tmax = 0;
static if_data_t ifd = { 0 }; /* interface data */
static long long tsum = 0;
static u_int method = 0;
static bool Rflag = 0;
static bool _3flag = 0;
static bool Pflag = 0;
static bool pflag = 0;
static bool Dflag = 0;
static size_t Dopt = 0;
static bool zflag = 0;
static bool fflag = 0;
static int zopt = 0;
static bool Nflag = 0;
static int dstport = 80; /* default 80 */
static int srcport = 0;
static bool _6flag = 0;
static struct in6_addr _6opt = { 0 };
static int ttl = 0;
static int off = 0;
static ipaddr_t curtp = { 0 }; /* current target */
static u_char *payload = NULL;
static size_t payloadlen = 0;
static u_char *xipopts = NULL;
static size_t xipoptslen = 0;
static u_char *xtcpopts = NULL;
static size_t xtcpoptslen = 0;

/* These counters store the number of responses and
 * requests; here, one request consists of sending
 * the corresponding packets for all enabled methods,
 * and one response consists of at least one successful
 8 reception of our transmissions (see. loop()).  */
size_t rcv = 0, snd = 0;

/* This structure represents callback data; it is needed
 * for filtering and for passing the IP address of the
 * sender of the packet (<from>) and a flag indicating
 * an error during reception (<err>).  */
typedef struct __cbdata_t {
	ipaddr_t target;
	u_int method;
	u_short dstport;
	u_short srcport;

	/* Fills in the callback itself.  */
	ipaddr_t from;
	u_short err; /* TYPE|CODE */
} cbdata_t;

/*
 *		U S A G E
 *
 * Takes a vector of arguments (argv) and prints help
 * about the PING options; also, terminates the program.
 */
inline static void
usage(char **av)
{
	fputs("Usage\n", stderr);
	fprintf(stderr, "  %s [options] <targets>\n\n", av[0]);
	/* Interface */
	fputs("  -I <dev>\tset your interface and his info\n", stderr);
	fputs("  -s <ipv4>\tset source ipv4 address\n", stderr);
	fputs("  -6 <ipv6>\tset source custom ipv6 address\n", stderr);
	fputs("  -S <mac>\tset source mac address\n", stderr);

	fputs("  -i <time>\tset interval between packets; ex: 300ms\n", stderr);
	fputs("  -w <time>\tset wait time or timeout; ex: 2s, 10ms\n", stderr);
	fputs("  -n <count>\tset your num of try\n", stderr);
	fputs("  -D <num>\tset your ping preload\n", stderr);
	fputs("  -N <count>\tset how many packets to recv (replies)\n", stderr);

	/* IP options */
	fputs("  -4\t\tset More Fragment flag (ipv4)\n", stderr);
	fputs("  -r\t\tset Reserved Fragment flag (ipv4)\n", stderr);
	fputs("  -d\t\tset Dont't Fragment flag (ipv4)\n", stderr);
	fputs("  -O <hex>\tset your ip options in hex (ipv4)\n", stderr);
	fputs("  -z <tos>\tset num in type of service/traffic class\n", stderr);
	fputs("  -T <ttl>\tset ttl/hop limit\n", stderr);

	/* ICMP options */
	fputs("  -E\t\tenable icmp echo ping method\n", stderr); /* echo */
	fputs("  -F\t\tenable icmp info ping method\n", stderr); /* info */
	fputs("  -M\t\tenable icmp timestamp ping method\n",
	    stderr); /* timestamp */

	/* TCP, UDP, SCTP, UDP-LITE */
	fputs("  -K\t\tenable tcp ack ping method\n", stderr);
	fputs("  -Y\t\tenable tcp syn ping method\n", stderr);
	fputs("  -U\t\tenable udp ping method\n", stderr);
	fputs("  -C\t\tenable sctp cookie ping method\n", stderr);
	fputs("  -V\t\tenable sctp init ping method\n", stderr);
	fputs("  -p <port>\tset destination port\n", stderr);
	fputs("  -G <hex>\tset your tcp options in hex (tcp)\n", stderr);
	fputs("  -P <port>\tset source (your) port\n", stderr);
	fputs("  -H <hex>\tset payload data in hex numbers\n", stderr);
	fputs("  -a <ascii>\tset payload data in ascii\n", stderr);
	fputs("  -l <len>\tset random payload data\n", stderr);
	fputs("  -3\t\tuse adler32 sctp checksum\n", stderr);

	fputs("  -A\t\tenable all ping methods\n", stderr);
	fputs("  -f\t\tflood ping\n", stderr);
	fputs("  -o\t\texit after first reply packet\n", stderr);
	fputs("  -R\t\tno resolve dns\n", stderr);
	fputs("  -v\t\tshow some debugging information\n", stderr);
	fputs("  -h\t\tshow this help message and exit\n", stderr);

	fputs("\nExamples\n", stderr);
	exit(0);
}

/*
 *		C A L L B A C K
 *
 * Essentially, this is a packet filter that is passed
 * to the receiving function so it can receive the
 * desired packet.  If the packet is ours, it returns 1,
 * or 0.
 */
inline static bool
callback(void *in, size_t n, void *arg)
{
	cbdata_t *cbdata = (cbdata_t *)arg;
	u_char *buf = (u_char *)in;
	ssize_t s = 0;

	switch (cbdata->target.af) {
	case AF_INET:
		if (n <= 34)
			return 0;
		if (ntohs(*(u_short *)(buf + 12)) != 0x0800)
			return 0;

		/* IPv4 header + MAC header length.  */
		s = ((buf[14] & 0x0f) * 4) + 14;

		/* ICMP error received.  */
		if (buf[23] == IPPROTO_ICMP &&
		    (buf[s] != 0 && buf[s] != 16 && buf[s] != 14)) {
			if (memcmp((buf + s + 20), ifd.srcip4, 4) != 0)
				return 0;
			cbdata->err = ((u_short)buf[s] << 8) | buf[s + 1];
			goto out;
		}

		if (memcmp((buf + 30), ifd.srcip4, 4) != 0)
			return 0;
		if (memcmp((buf + 26), &cbdata->target.ip.v4, 4) != 0)
			return 0;

		break;
	case AF_INET6:
		if (n <= 54)
			return 0;
		if (ntohs(*(u_short *)(buf + 12)) != 0x86dd)
			return 0;

		/* IPv6 header + Extended headers + MAC header length.  */
		if ((s = ipv6_offset(buf + 14, n - 14)) == -1)
			return 0;
		s += 14;

		/* ICMPV6 error received.  */
		if (buf[20] == IPPROTO_ICMPV6 && buf[s] != 129) {
			if (memcmp((buf + s + 16), ifd.srcip6, 16) != 0)
				return 0;
			cbdata->err = ((u_short)buf[s] << 8) | buf[s + 1];
			goto out;
		}

		if (memcmp((buf + 38), ifd.srcip6, 16) != 0)
			return 0;
		if (memcmp((buf + 22), &cbdata->target.ip.v6, 16) != 0)
			return 0;
		break;
	}

	switch (cbdata->method) {
	case SYN_METHOD:
	case ACK_METHOD:
		if (buf[(s == 34) ? 23 : 20] != IPPROTO_TCP)
			return 0;

		/* SYN/ACK or RST.  */
		if (buf[s + 13] != 18 && buf[s + 13] != 4)
			return 0;
	ports:
		if (ntohs(*(u_short *)(buf + s)) != cbdata->dstport)
			return 0;
		if (ntohs(*(u_short *)(buf + s + 2)) != cbdata->srcport)
			return 0;
		break;
	case INFO_METHOD:
	case ECHO_METHOD:
	case TIMESTAMP_METHOD:
		if (s == 34 && buf[23] != IPPROTO_ICMP)
			return 0;
		if (s == 54 && buf[20] != IPPROTO_ICMPV6)
			return 0;
		if (ntohs((*(u_short *)(buf + s + 6))) != snd)
			return 0;
		if (cbdata->method == ECHO_METHOD &&
		    buf[s] != ((s == 34) ? 0 : 129))
			return 0;

		/* Solum IPv4.  */
		if (cbdata->method == INFO_METHOD && buf[s] != 16)
			return 0;
		if (cbdata->method == TIMESTAMP_METHOD && buf[s] != 14)
			return 0;

		break;
	case UDP_METHOD:
		if (buf[(s == 34) ? 23 : 20] != IPPROTO_UDP)
			return 0;
		goto ports;
	case INIT_METHOD:
	case COOKIE_METHOD:
		if (buf[(s == 34) ? 23 : 20] != IPPROTO_SCTP)
			return 0;
		goto ports;
	}

out:
	cbdata->from.af = cbdata->target.af;
	switch (cbdata->target.af) {
	case AF_INET:
		memcpy(&cbdata->from.ip.v4, buf + 26, 4);
		break;
	case AF_INET6:
		memcpy(&cbdata->from.ip.v6, buf + 22, 16);
		break;
	}

	return 1;
}

/*
 *		S T A T S
 *
 * Takes the IP address of the target in <target>,
 * and prints the current TRACEROUTE statistics
 * according to the options.
 */
inline static void
stats(ipaddr_t *target)
{
	printf("\n----%s PING Statistics----\n", ipaddr_ntoa(target));
	printf("%ld packets transmitted, %ld packets received", ntransmitted,
	    nreceived);
	if (ntransmitted) {
		if (nreceived > ntransmitted)
			printf(" -- somebody's printing up packets!\n");
		else
			printf(", %ld%% packet loss\n",
			    (size_t)(((ntransmitted - nreceived) * 100) /
				ntransmitted));
	}
	if (nreceived) {
		char tmp[1000];
		printf("round-trip (rtt) min/avg/max = %s",
		    timefmt(tmin, tmp, sizeof(tmp)));
		printf("/%s",
		    timefmt((long long)tsum / (long long)nreceived, tmp,
			sizeof(tmp)));
		printf("/%s", timefmt(tmax, tmp, sizeof(tmp)));
		putchar('\n');
	}

	putchar('\n');
	prstats = 1;
}

/*
 *		R E S O L V E _ D N S
 *
 * Gets DNS based on its IP address, works with both
 * IPv4 and IPv6; returns a static buffer. It returns
 * the DNS by enclosing it in parentheses (). If it is
 * not found, it returns (???)
 */
static inline const char *
resolve_dns(ipaddr_t *target)
{
	struct sockaddr_in6 sin6 = { 0 };
	struct sockaddr_in sin = { 0 };
	static char res[4096 + 3];
	char host[4096] = { 0 };

	memset(res, 0, sizeof(res));
	switch (target->af) {
	case AF_INET:
		sin.sin_family = (u_short)target->af;
		sin.sin_addr = target->ip.v4;
		if (getnameinfo((struct sockaddr *)&sin, sizeof(sin), host,
			sizeof(host), NULL, 0, 0) == 0) {
			snprintf(res, sizeof(res), " (%s)", host);
			return res;
		}
		break;
	case AF_INET6:
		sin6.sin6_family = (u_short)target->af;
		sin6.sin6_addr = target->ip.v6;
		if (getnameinfo((struct sockaddr *)&sin6, sizeof(sin6), host,
			sizeof(host), NULL, 0, 0) == 0) {
			snprintf(res, sizeof(res), " (%s)", host);
			return res;
		}
		break;
	}

	return "(\?\?\?)";
}

/*
 *		F I N I S H
 *
 * Should be called when the program terminates;
 * prints the last target's statistics if none
 * were printed, and closes the socket.
 */
inline static NORETURN void
finish(int sig)
{
	(void)sig;
	if (!prstats)
		stats(&curtp);
	if (payload)
		free(payload);
	if (xipopts)
		free(xipopts);
	if (xtcpopts)
		free(xtcpopts);
	if (dlt)
		dlt_close(dlt);
	exit(0);
}

/*
 *		T V R T T
 *
 * Calculates the corrected response time using
 * tvsub(), updates statistics, and returns the
 * response time.
 */
inline static long long
tvrtt(struct timeval *ts_s, struct timeval *ts_e)
{
	struct timeval tv = *ts_e;
	long long rtt;

	tvsub(&tv, ts_s);
	rtt = (long long)tv.tv_sec * 1000000000LL +
	    (long long)tv.tv_usec * 1000LL;

	tsum += rtt;
	tmax = (rtt > tmax) ? rtt : tmax;
	tmin = (rtt < tmin) ? rtt : tmin;

	return rtt;
}

/*
 *		P I N G E R
 *
 * Creates a package in <outpack> according to
 * the options, sends it, and updates statistics.
 */
inline static void
pinger(ipaddr_t *target, int method, u_char *data, u_int datalen,
    u_char *ipopts, u_int ipoptslen, u_char *tcpopts, u_int tcpoptslen)
{
	memset(outpack, 0, sizeof(outpack));

	size_t len = 0, s, n;
	int proto;
	u_short id;

	len += 34;
	if (target->af == AF_INET6)
		len += 20;
	else
		len += ipoptslen;
	s = len; /* skip ad payload */

	switch (method) {
	case SYN_METHOD:
	case ACK_METHOD:
		proto = IPPROTO_TCP;
		len += 20;
		len += tcpoptslen;
		break;
	case ECHO_METHOD:
	case INFO_METHOD:
	case TIMESTAMP_METHOD:
		switch (target->af) {
		case AF_INET:
			proto = IPPROTO_ICMP;
			if (method == TIMESTAMP_METHOD)
				len += 12;
			break;
		case AF_INET6:
			proto = IPPROTO_ICMPV6;
			break;
		}
		len += 8;
		break;
	case UDP_METHOD:
		proto = IPPROTO_UDP;
		len += 8;
		break;
	case INIT_METHOD:
		proto = IPPROTO_SCTP;
		len += 32; /* init chunk 12 */
		break;
	case COOKIE_METHOD:
		proto = IPPROTO_SCTP;
		len += 16;
		break;
	}

	len += datalen;

	id = random_range(106, USHRT_MAX);
	if (!Pflag)
		srcport = random_range(48, USHRT_MAX);
	if (!Tflag)
		ttl = random_range(52, UCHAR_MAX);

	memcpy(outpack, ifd.dst, 6);
	memcpy(outpack + 6, ifd.src, 6);
	*(u_short *)(outpack + 12) = htons(
	    (target->af == AF_INET) ? 0x0800 : 0x86dd);

	switch (target->af) {
	case AF_INET:
		outpack[14] = (4 << 4) |
		    (5 + (ipoptslen / 4));	  /* version|ihl */
		outpack[15] = (zflag) ? zopt : 0; /* tos */
		*(u_short *)(outpack + 16) = htons(
		    (u_short)(len - 14));		/* tot_len +optslen */
		*(u_short *)(outpack + 18) = htons(id); /* id */
		*(u_short *)(outpack + 20) = htons((u_short)off); /* off */
		outpack[22] = (u_char)ttl;			  /* ttl */
		outpack[23] = (u_char)proto;			  /* proto */
		*(u_short *)(void *)(outpack + 24) = 0;		  /* chksum */

		/* via in caelum */
		for (n = 0; n < 4; n++)
			outpack[26 + n] = ifd.srcip4[n],
				     outpack[30 + n] =
					 (ntohl(target->ip.v4.s_addr) >>
					     (24 - 8 * n)) &
			    0xff;

		if (ipopts && ipoptslen)
			memcpy(outpack + 34, ipopts, ipoptslen);

		*(u_short *)(outpack + 24) = in_cksum((u_short *)(outpack + 14),
		    20 + ipoptslen);
		break;
	case AF_INET6:
		outpack[14] = ((0x06 << 4) |
		    ((((zflag) ? zopt : 0) & 0xF0) >> 4)); /* version|tc */
		outpack[15] = (u_char)(((((zflag) ? zopt : 0) & 0x0F)
					   << 4) | /* flowlabel */
		    ((id & 0xF0000) >> 16));
		outpack[16] = ((id & 0x0FF00) >> 8),
		outpack[17] = ((id & 0x000FF));
		*(u_short *)(outpack + 18) = htons(
		    (u_short)len - (54));    /* payload length */
		outpack[20] = (u_char)proto; /* nexthdr (protocol) */
		outpack[21] = (u_char)ttl;   /* hoplimit (ttl) */

		for (n = 0; n < 16; n++) /* src+dst */
			outpack[22 + n] = ifd.srcip6[n],
				     outpack[22 + 16 + n] =
					 target->ip.v6.s6_addr[n];
		break;
	}

	switch (proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		switch (method) { /* icmp type */
		case ECHO_METHOD:
			outpack[s] = (target->af == AF_INET6) ? 128 : 8;
			break;
		case TIMESTAMP_METHOD:
			outpack[s] = 13;
			break;
		case INFO_METHOD:
			outpack[s] = 15;
			break;
		}
		outpack[s + 1] = 0;			    /* code */
		*(u_short *)(outpack + s + 2) = htons(0);   /* chksum */
		*(u_short *)(outpack + s + 4) = htons(id);  /* id */
		*(u_short *)(outpack + s + 6) = htons(snd); /* seq */

		if (method == TIMESTAMP_METHOD) {
			*(u_int *)(outpack + s + 8) = htonl(random_u32());
			*(u_int *)(outpack + s + 12) = htonl(random_u32());
			*(u_int *)(outpack + s + 16) = htonl(random_u32());
		}

		/* Only data ECHO_METHOD */
		if (data && datalen && method == ECHO_METHOD)
			memcpy(outpack + s + 8, data, datalen);

		switch (target->af) {
		case AF_INET:
			*(u_short *)(outpack + s +
			    2) = in_cksum((u_short *)(outpack + s),
			    (int)((method == TIMESTAMP_METHOD) ? 20 :
								 8 + datalen));
			break;
		case AF_INET6:
			*(u_short *)(outpack + s +
			    2) = in6_pseudocksum(ifd.srcip6,
			    (u_char *)&target->ip.v6, IPPROTO_ICMPV6,
			    (u_int)(8 + datalen), (outpack + s));
			break;
		}

		break;
	case IPPROTO_TCP:
		*(u_short *)(outpack + s) = htons(srcport);	/* src port */
		*(u_short *)(outpack + s + 2) = htons(dstport); /* dst port */
		memcpy(outpack + s + 4,
		    &(u_int) { htonl(random_range(5, UINT_MAX)) },
		    sizeof(u_int)); /* seq */
		memcpy(outpack + s + 8, &(u_int) { htonl(0) },
		    sizeof(u_int)); /* ack */
		outpack[s + 12] = ((5 + (tcpoptslen / 4)) << 4) |
		    (0 & 0x0f); /* off | res */
		outpack[s + 13] = (method == SYN_METHOD) ? 2 : 16; /* flags */
		*(u_short *)(outpack + s + 14) = htons(1024);	   /* window */
		*(u_short *)(outpack + s + 16) = 0;		   /* chksum */
		*(u_short *)(outpack + s + 18) = 0;		   /* urp */

		if (tcpopts && tcpoptslen)
			memcpy(outpack + s + 20, tcpopts, tcpoptslen);

		if (data && datalen)
			memcpy(outpack + s + 20 + tcpoptslen, data, datalen);

		switch (target->af) {
		case AF_INET:
			*(u_short *)(outpack + s +
			    16) = in_pseudocksum(ifd.srcip4,
			    (u_char *)&target->ip.v4, (u_char)proto,
			    (20 + (u_short)datalen + tcpoptslen),
			    (outpack + s));
			break;
		case AF_INET6:
			*(u_short *)(outpack + s +
			    16) = in6_pseudocksum(ifd.srcip6,
			    (u_char *)&target->ip.v6, (u_char)proto,
			    (u_int)(20 + datalen + tcpoptslen), (outpack + s));
			break;
		}

		break;
	case IPPROTO_SCTP:
		*(u_short *)(outpack + s) = htons(srcport);	/* src port */
		*(u_short *)(outpack + s + 2) = htons(dstport); /* dst port */
		*(u_int *)(outpack + s + 4) = htonl((method == INIT_METHOD) ?
			0 :
			random_range(5, UINT_MAX));		    /* vtag */
		*(u_int *)(outpack + s + 8) = htonl(0);		    /* chksum */
		outpack[s + 12] = (method == INIT_METHOD) ? 1 : 10; /* type */
		outpack[s + 13] = 0;				    /* flags */
		*(u_short *)(outpack + s + 14) = htons(
		    ((method == INIT_METHOD) ?
			    20 :
			    (4 + (u_short)datalen))); /* len */

		if (method == INIT_METHOD) {
			*(u_int *)(outpack + s + 16) = htonl(
			    random_range(5, UINT_MAX)); /* itag */
			*(u_int *)(outpack + s + 20) = htonl(
			    random_range(5, UINT_MAX)); /* arwnd */
			*(u_short *)(outpack + s + 24) = htonl(
			    random_range(5, USHRT_MAX)); /* nos */
			*(u_short *)(outpack + s + 26) = htonl(
			    random_range(5, USHRT_MAX)); /* nis */
			*(u_int *)(outpack + s + 28) = htonl(
			    random_range(5, UINT_MAX)); /* itsn */
		} else if (data && datalen)
			memcpy(outpack + s + 16, data, datalen);

		/* final checksum */
		*(u_int *)(outpack + s + 8) = htonl(((_3flag) ?
			adler32(1, (outpack + s),
			    (method == INIT_METHOD) ? 32 : (16 + datalen)) :
			crc32c((outpack + s),
			    (method == INIT_METHOD) ? 32 : (16 + datalen))));
		break;
	case IPPROTO_UDP:
		*(u_short *)(outpack + s) = htons(srcport);	/* src port */
		*(u_short *)(outpack + s + 2) = htons(dstport); /* dst port */
		*(u_short *)(outpack + s + 4) = htons(
		    8 + (u_short)datalen);		  /* len */
		*(u_short *)(outpack + s + 6) = htons(0); /* chksum */

		if (data && datalen)
			memcpy(outpack + s + 8, data, datalen);

		switch (target->af) {
		case AF_INET:
			*(u_short *)(outpack + s +
			    6) = in_pseudocksum(ifd.srcip4,
			    (u_char *)&target->ip.v4, (u_char)proto,
			    (8 + (u_short)datalen), (outpack + s));
			break;
		case AF_INET6:
			*(u_short *)(outpack + s +
			    6) = in6_pseudocksum(ifd.srcip6,
			    (u_char *)&target->ip.v6, (u_char)proto,
			    (u_int)(8 + datalen), (outpack + s));
			break;
		}

		break;
	}

	n = dlt_send(dlt, outpack, len);
	if (n < 0 || n != len) {
		if (n < 0)
			warn("sendto");

		warnx("wrote %s %lu chars, ret=%zd", ipaddr_ntoa(target), len,
		    n);
	}

	++ntransmitted;
}

/*
 *		P R _ P A C K
 *
 * Prints information about the packet according
 * to the options (i. e. the selected style).
 */
inline static void
pr_pack(u_char *buf, size_t n, long long rtt, size_t id, ipaddr_t *from,
    u_short err, char *hostname)
{
	int proto = (from->af == AF_INET) ? buf[23] : buf[20];
	char t[65535] = { 0 };
	ssize_t s = 0;

	printf("%zu bytes from %s%s%s:", n,

	    (method & (method - 1)) ?
		((proto == IPPROTO_ICMP)	  ? "ICMP " :
			(proto == IPPROTO_ICMPV6) ? "ICMPV6 " :
			(proto == IPPROTO_TCP)	  ? "TCP " :
			(proto == IPPROTO_UDP)	  ? "UDP " :
			(proto == IPPROTO_SCTP)	  ? "SCTP " :
						    "UNKNOWN ") :
		"",

	    ipaddr_ntoa(from), hostname);

	s = (from->af == AF_INET) ? ((buf[14] & 0x0f) * 4) + 14 :
				    (ipv6_offset(buf + 14, n - 14) + 14);

	if (!err) {
		switch (proto) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			printf(" icmp_seq=%hu",
			    ntohs((*(u_short *)(buf + s + 6))));
			break;
		case IPPROTO_TCP:
			printf(" id=%zu flags=", id);

			/* In tcpdump style: https://github.com/
			 * the-tcpdump-group/tcpdump/blob/master/
			 * print-tcp.c.  */
			if (buf[s + 13] & 0x01) /* FIN */
				putchar('F');
			if (buf[s + 13] & 0x02) /* SYN */
				putchar('S');
			if (buf[s + 13] & 0x04) /* RST */
				putchar('R');
			if (buf[s + 13] & 0x08) /* PUSH */
				putchar('P');
			if (buf[s + 13] & 0x10) /* ACK */
				putchar('.');
			if (buf[s + 13] & 0x20) /* URG */
				putchar('U');
			if (buf[s + 13] & 0x40) /* ECE */
				putchar('E');
			if (buf[s + 13] & 0x80) /* CWR */
				putchar('W');
			if (buf[s + 13] & 0x100) /* AE */
				putchar('e');
			break;
		case IPPROTO_SCTP:
			printf(" id=%zu type=", id);
			switch (buf[s + 12]) { /* CHUNK TYPE */
			case 0:		       /* Payload Data */
				printf("data");
				break;
			case 1: /* Initiation */
				printf("init");
				break;
			case 2: /* Initiation Acknowledgement */
				printf("init-ack");
				break;
			case 3: /* Selective Acknowledgement */
				printf("sack");
				break;
			case 4: /* Heartbeat Request */
				printf("heartbeat");
				break;
			case 5: /* Heartbeat Acknowledgement */
				printf("heartbeat-ack");
				break;
			case 6: /* Abort */
				printf("abort");
				break;
			case 7: /* Shutdown */
				printf("shutdown");
				break;
			case 8: /* Shutdown Acknowledgement */
				printf("shutdown-ack");
				break;
			case 9: /* Operation Error */
				printf("error");
				break;
			case 10: /* State Cookie */
				printf("cookie-echo");
				break;
			case 11: /* Cookie Acknowledgement */
				printf("cookie-ack");
				break;
			case 12: /* Reserved for Explicit Congestion
				  * Notification Echo */
				printf("ecne");
				break;
			case 13: /* Reserved for Congestion Window Reduced */
				printf("cwr");
				break;
			case 14: /* Shutdown Complete */
				printf("shutdown-complete");
				break;
			default:
				printf("Bad SCTP type: %hhu", buf[s + 12]);
				break;
			}
			break;
		case IPPROTO_UDP:
			printf(" id=%zu", id);
			break;
		}
		printf(" ttl=%hhu", (from->af == AF_INET) ? buf[22] : buf[11]);
	} else if (proto == IPPROTO_ICMP) {
		putchar(' ');
		switch (((err >> 8) & 0xff)) {
		case 3: /* UNREACH */
			switch ((err & 0xff)) {
			case 0: /* NET */
				printf("Destination Net Unreachable");
				break;
			case 1: /* HOST */
				printf("Destination Host Unreachable");
				break;
			case 2: /* PROTOCOL */
				printf("Destination Protocol Unreachable");
				break;
			case 3: /* PORT */
				printf("Destination Port Unreachable");
				break;
			case 4: /* NEEDFRAG */
				printf("frag needed and DF set (MTU %d)\n",
				    ntohs((*(u_short *)(buf + 42))));
				break;
			case 5: /* SRCFAIL */
				printf("Source Route Failed");
				break;
			case 13: /* FILTER_PROHIB */
				printf("Communication prohibited by filter");
				break;
			default:
				printf("Dest Unreachable, Bad Code: 0x%x\n",
				    (err & 0xff));
				break;
			}
			break;
		case 4: /* SOURCEQUENCH*/
			printf("Source Quench");
			break;
		case 5: /* REDIRECT */
			switch ((err & 0xff)) {
			case 0: /* NET */
				printf("Network Redirect");
				break;
			case 1: /* HOST */
				printf("Host Redirect");
				break;
			case 2: /* TOSNET */
				printf("Type of Service and Network Redirect");
				break;
			case 3: /* TOHOST */
				printf("Type of Service and Host Redirect");
				break;
			default:
				printf("Redirect, Bad Code: 0x%x",
				    (err & 0xff));
				break;
			}
			printf(" (New addr: %hhu.%hhu.%hhu.%hhu)\n", buf[38],
			    buf[39], buf[40], buf[41]);
			break;
		case 11: /* TIMXCEED */
			switch ((err & 0xff)) {
			case 0: /* INTRANS */
				printf("Time to live exceeded in transit");
				break;
			case 1: /* REASS */
				printf("Fragment reassembly time exceeded");
				break;
			default:
				printf("Time exceeded, Bad Code: 0x%x\n",
				    (err & 0xff));
				break;
			}
			break;
		case 12: /* PARAMPROB */
			switch ((err & 0xff)) {
			case 0:
				printf(
				    "Parameter problem: error detected at byte 0x%02x\n",
				    buf[38]);
				break;
			default:
				printf("Unspecified parameter problem");
				break;
			}
			break;
		case 9: /* ROUTERADVERT*/
			printf("Router Advertisement");
			break;
		case 10: /* ROUTERSOLICIT*/
			printf("Router Solicitation");
			break;
		default:
			printf("Bad ICMP error type: 0x%x (code %hhu)\n",
			    ((err >> 8) & 0xff), (err & 0xff));
			break;
		}
	} else if (proto == IPPROTO_ICMPV6) {
		putchar(' ');
		switch (((err >> 8) & 0xff)) {
		case 1: /* UNREACH */
			switch ((err & 0xff)) {
			case 0: /* NOROUTE */
				printf("No Route to Destination");
				break;
			case 1: /* ADMIN */
				printf(
				    "Destination Administratively Unreachable");
				break;
			case 2: /* BEYONDSCOPE */
				printf("Destination Unreachable Beyond Scope");
				break;
			case 3: /* ADDR */
				printf("Destination Addr (Host) Unreachable");
				break;
			case 4: /* PORT */
				printf("Destination Port Unreachable");
				break;
			default:
				printf("Destination Unreachable, Bad Code: %d",
				    buf[55]);
				break;
			}
			break;
		case 2: /* PACKET_TOO_BIG */
			printf("Packet too big mtu = %d",
			    ntohl((*(u_int *)(buf + 58))));
			break;
		case 3: /* TIME_EXCEEDED */
			switch ((err & 0xff)) {
			case 0: /* TRANSIT */
				printf("Time to live exceeded");
				break;
			case 1: /* REASSEMBLY */
				printf("Frag reassembly time exceeded");
				break;
			default:
				printf("Time exceeded, Bad Code: %d", buf[55]);
				break;
			}
			break;
		case 4: /* PARAM_PROB */
			printf("Parameter problem: ");
			switch ((err & 0xff)) {
			case 0: /* HEADER */
				printf("Erroneous Header");
				break;
			case 1: /* NEXTHEADER */
				printf("Unknown Nextheader");
				break;
			case 2: /* OPTION */
				printf("Unrecognized Option");
				break;
			default:
				printf("Bad code(%d)", buf[55]);
				break;
			}
			printf("pointer = 0x%02x\n",
			    ntohl((*(u_int *)(buf + 58))));
			break;
		default:
			printf("Bad ICMP error type: 0x%x (code %hhu)\n",
			    ((err >> 8) & 0xff), (err & 0xff));
			break;
		}
	}

	if (rtt)
		printf(" time=%s", timefmt(rtt, t, sizeof(t)));

	putchar('\n');
}

/*
 *		L O O P
 *
 * The main function of the code; receives the
 * target's IP address and tracerouting it; before
 * doing this, of course, it resets the
 * statistics.
 */
inline static void
loop(ipaddr_t *ip)
{
	ntransmitted = 0;
	tsum = 0;
	tmax = LLONG_MIN;
	snd = 0;
	nreceived = 0;
	prstats = 0;
	tmin = LLONG_MAX;
	curtp = *ip;
	rcv = 0;

	char hostname[65535] = { 0 };
	snprintf(hostname, sizeof(hostname), "%s",
	    (!Rflag) ? resolve_dns(ip) : "");

	printf("PING %s%s: %zu data bytes\n", ipaddr_ntoa(ip), hostname,
	    payloadlen);

	/* If preload is specified, perform the corresponding
	 * actions for each enabled method.  */
	if (Dflag) {
		for (u_int j = 0; j < 32; ++j) {
			if (!(method & (1U << j)))
				continue;
			snd = Dopt + 1;
			while (--snd)
				pinger(ip, (1U << j), payload,
				    (u_int)payloadlen, xipopts,
				    (u_int)xipoptslen, xtcpopts,
				    (u_int)xtcpoptslen);
		}
	}

	for (;;) {
		struct timeval ts_s, ts_e;
		u_char buf[65535] = { 0 };
		ssize_t n;

		/* Was there at least one successful attempt during the
		 * cycle below? */
		bool rflg = 0;

		/* We interrupt all enabled methods, send the corresponding
		 * packet (pinger) for each of them, and accept it
		 * (dlt_recv_cb); finally, we output the accepted packet
		 * (pr_pack) if the reception was successful, otherwise we issue
		 * a warning.  In essence, this is a classic ping loop.  */
		for (u_int j = 0; j < 32; ++j) {
			u_int flag = (1U << j);
			if (!(method & flag))
				continue;

			/* We skip methods that are not suitable for us.  */
			if (((flag & TIMESTAMP_METHOD) ||
				(flag & INFO_METHOD)) &&
			    ip->af == AF_INET6) {
				warnx("ipv6 not support %s method (skip)",
				    (flag & INFO_METHOD) ? "info" :
							   "timestamp");
				continue;
			}

			/* We send the appropriate package */
			pinger(ip, flag, payload, (u_int)payloadlen, xipopts,
			    (u_int)xipoptslen, xtcpopts, (u_int)xtcpoptslen);

			/* This structure represents data for callback; all this
			 * data, except for the last variable, is needed to
			 * filter the packet, namely: destination IP, current
			 * method, recipient port, and sender port.  The last
			 * variable will be filled in by the callback itself,
			 * and it will fill it with the IP from which it
			 * successfully received the packet (we will need it for
			 * output).  */
			cbdata_t cbdata = { *ip, flag, dstport, srcport, { 0 },
				0 };

			/* We accept it and output the corresponding package. */
			if ((n = dlt_recv_cb(dlt, buf, sizeof(buf), callback,
				 (void *)&cbdata, wait, &ts_s, &ts_e)) == -1) {
				if (!fflag) {
					if (errno == 0)
						warnx(
						    "%s no response received (timeout)",
						    (flag & ECHO_METHOD) ?
							"echo" :
							(flag & SYN_METHOD) ?
							"syn" :
							(flag & ACK_METHOD) ?
							"ack" :
							(flag & INFO_METHOD) ?
							"info" :
							(flag &
							    TIMESTAMP_METHOD) ?
							"timestamp" :
							(flag & UDP_METHOD) ?
							"udp" :
							(flag & COOKIE_METHOD) ?
							"cookie" :
							(flag & INIT_METHOD) ?
							"init" :
							"");
					else
						warn("recv");
				}
			} else {
				++nreceived;
				if (!rflg) {
					rflg = 1;
					++rcv; /* One response was received. */
				}

				if (!fflag)
					/* We display data about the package we
					 * have successfully received.  */
					pr_pack(buf, n, tvrtt(&ts_s, &ts_e),
					    rcv - 1, &cbdata.from, cbdata.err,
					    hostname);
				else
					putchar('.'), fflush(stdout);
			}
		}
		++snd; /* One request has been completed.  */

		/* Has the ping for this target been completed? */
		if (((Nflag) ? rcv : snd) == npackets)
			break;

		/* There is a delay between requests and responses, but
		 * there is no delay in the first one.  */
		sleepns(interval);
	}

	if (!prstats)
		stats(ip);
}

/*
 *		I F _ S E T U P
 *
 * Gets the network interface and its associated
 * data, also modifies them according to the
 * options, and opens the socket.
 */
inline static void
if_setup(void)
{
	if (!Iflag) {
		if (!if_get(NULL, &ifd))
			errx(1, "no suitable devices found");
	} else {
		if (!if_get(Iopt, &ifd))
			errx(1, "device \"%s\" not found", Iopt);
		if (!__is_network_sendable(&ifd))
			errx(1, "device \"%s\" doesn't fit", Iopt);
	}
	if (sflag)
		memcpy(ifd.srcip4, &sopt, 4);
	if (Sflag)
		memcpy(ifd.src, &Sopt, 6);
	if (_6flag)
		memcpy(ifd.srcip6, _6opt.s6_addr, 16);
	if (vflag)
		if_output(stderr, &ifd);
	if (payloadlen > (size_t)ifd.mtu)
		errx(1,
		    "your mtu is (%d), your length"
		    " data is \"%zu\"",
		    ifd.mtu, payloadlen);

	if (!(dlt = dlt_open(ifd.name)))
		errx(1, "failed open socket");
}

/*
 *		P I N G
 */
int
main(int c, char **av)
{
	ipaddr_t ip;
	int ch;

	if (c <= 1)
		usage(av);

	signal(SIGINT, finish);

	/* Good method.  */
	random_init(dev_urandom, NULL);

	while (
	    (ch = getopt(c, av,
		 "D:I:s:6:S:i:w:n:4rdO:z:T:EFMKYUCp:P:H:a:l:3AfoN:vhRVG:")) !=
	    -1) {
		switch (ch) {
		case 'D':
			if (!u_numarg(optarg, 0, UCHAR_MAX, &Dopt,
				sizeof(Dopt)))
				errx(1, "invalid preload \"%s\"", optarg);
			Dflag = 1;
			break;
		case 'I':
			Iflag = 1;
			Iopt = optarg;
			break;
		case 'f':
			fflag = 1;
			interval = 0;
			npackets = 1000000;
			wait = 100 * 1000000L; /* 100 ms */
			break;
		case 'o':
			npackets = 1, Nflag = 1;
			break;
		case 'z':
			if (!u_numarg(optarg, 0, UCHAR_MAX, &zopt,
				sizeof(zopt)))
				errx(1, "invalid tos \"%s\"", optarg);
			zflag = 1;
			break;
		case '3':
			_3flag = 1;
			break;
		case 'A':
			method = ECHO_METHOD | ECHO_METHOD | ACK_METHOD |
			    INFO_METHOD | TIMESTAMP_METHOD | UDP_METHOD |
			    COOKIE_METHOD | INIT_METHOD;
			break;
		case 'E':
			method |= ECHO_METHOD;
			break;
		case 'V':
			method |= INIT_METHOD;
			break;
		case 'F':
			method |= INFO_METHOD;
			break;
		case 'G': {
			u_char *hextmp = NULL;
			if (!(hextmp = hex_ahtoh(optarg, &xtcpoptslen)))
				errx(1, "invalid hex string specification");
			if (!(xtcpopts = memcpy(calloc(1, xtcpoptslen), hextmp,
				  xtcpoptslen)))
				errx(1, "memory allocation failed");
			break;
		}
		case 'O': {
			u_char *hextmp = NULL;
			if (!(hextmp = hex_ahtoh(optarg, &xipoptslen)))
				errx(1, "invalid hex string specification");
			if (!(xipopts = memcpy(calloc(1, xipoptslen), hextmp,
				  xipoptslen)))
				errx(1, "memory allocation failed");
			break;
		}
		case 'Y':
			method |= SYN_METHOD;
			break;
		case 'M':
			method |= TIMESTAMP_METHOD;
			break;
		case 'K':
			method |= ACK_METHOD;
			break;
		case 'C':
			method |= COOKIE_METHOD;
			break;
		case 'U':
			method |= UDP_METHOD;
			break;
		case '4':
			off |= 0x8000;
			break;
		case '6':
			if (inet_pton(AF_INET6, optarg, &_6opt) != 1)
				errx(1, "failed convert \"%s\" in ipv6",
				    optarg);
			_6flag = 1;
			break;
		case 'r':
			off |= 0x8000;
			break;
		case 'd':
			off |= 0x4000;
			break;
		case 'v':
			vflag = 1;
			break;
		case 'p':
			if (!u_numarg(optarg, 0, USHRT_MAX, &dstport,
				sizeof(dstport)))
				errx(1, "invalid port \"%s\"", optarg);
			pflag = 1;
			break;
		case 'P':
			if (!u_numarg(optarg, 0, USHRT_MAX, &srcport,
				sizeof(srcport)))
				errx(1, "invalid port \"%s\"", optarg);
			Pflag = 1;
			break;
		case 'R':
			Rflag = 1;
			break;
		case 'N':
		case 'n':
			if (ch == 'N')
				Nflag = 1;
			if (!u_numarg(optarg, 0, SIZE_MAX, &npackets,
				sizeof(npackets)))
				errx(1, "invalid number \"%s\"", optarg);
			break;
		case 'H': {
			u_char *hextmp = NULL;
			if (!(hextmp = hex_ahtoh(optarg, &payloadlen)))
				errx(1, "invalid hex string specification");
			if (!(payload = memcpy(calloc(1, payloadlen), hextmp,
				  payloadlen)))
				errx(1, "memory allocation failed");
			break;
		}
		case 'T':
			if (!u_numarg(optarg, 0, UCHAR_MAX, &ttl, sizeof(ttl)))
				errx(1, "invalid ttl \"%s\"", optarg);
			Tflag = 1;
			break;
		case 'a':
			if (!(payload = (u_char *)strdup(optarg)))
				errx(1, "failed allocated");
			payloadlen = strlen((char *)payload);
			break;
		case 'l':
			if (!u_numarg(optarg, 0, UINT_MAX, &payloadlen,
				sizeof(payloadlen)))
				errx(1, "invalid data len \"%s\"", optarg);
			if (!(payload = (u_char *)randomstr(payloadlen,
				  DEFAULT_DICTIONARY)))
				errx(1, "failed generate random data");
			break;
		case 'w':
			if ((wait = strtons(optarg)) == -1)
				errx(1, "failed convert \"%s\" in time",
				    optarg);
			break;
		case 'i':
			if ((interval = strtons(optarg)) == -1)
				errx(1, "failed convert \"%s\" in time",
				    optarg);
			break;
		case 's':
			if (inet_pton(AF_INET, optarg, &sopt) != 1)
				errx(1, "failed convert \"%s\" in ipv4",
				    optarg);
			sflag = 1;
			break;
		case 'S':
			if (!(ether_aton_r(optarg, &Sopt)))
				errx(1, "failed convert \"%s\" in mac", optarg);
			Sflag = 1;
			break;
		case 'h':
		case '?':
		default:
			usage(av);
		}
	}

	c -= optind;
	av += optind;
	if_setup();

	if (fflag) {
		random_init(splitmix64, splitmix64_seed);
		random_srand(time(NULL));
	}

	if (!method)
		method = ECHO_METHOD;

	if (c <= 0)
		errx(1, "no targets specified");

	while (*av) {
		char *p = *av++, *sb;

		if ((sb = strchr(p, '/')))
			*sb++ = '\0';
		if (!ipaddr_pton(p, &ip)) {
			if (!resolveipv4(p, &ip.ip.v4))
				errx(1, "failed resolve \"%s\"", p);
			else
				ip.af = AF_INET;
		}

		if (ip.af == AF_INET && !ifd.support4)
			errx(1, "device does not support ipv4");
		if (ip.af == AF_INET6 && !ifd.support6)
			errx(1, "device does not support ipv6");

		if (!sb)
			loop(&ip);
		else {
			u_char mask[16] = { 0 };
			u_char net[16] = { 0 };
			__uint128_t ip6 = 0;
			__uint128_t n;
			u_short bits;
			int i;

			if (!u_numarg(sb, 0, (ip.af == AF_INET) ? 32 : 128,
				&bits, sizeof(bits)))
				errx(1, "invalid bits \"%s\"", sb);

			ip_btom(ip.af, bits, mask);
			ip_net(((ip.af == AF_INET) ? (u_char *)&ip.ip.v4 :
						     (u_char *)&ip.ip.v6),
			    mask, net);
			switch (ip.af) {
			case AF_INET:
				n = (__uint128_t)1 << (32 - bits);
				ip.ip.v4.s_addr = htonl((net[0] << 24) |
				    (net[1] << 16) | (net[2] << 8) | net[3]);
				break;
			case AF_INET6:
				if (bits == 0)
					n = ~(__uint128_t)0;
				else
					n = (__uint128_t)1 << (128 - bits);
				for (i = 0; i < 16; i++) {
					ip6 <<= 8;
					ip6 |= net[i];
				}
				break;
			}

			if (vflag) {
				fprintf(stderr, "Target cidr: %s/%s (", p, sb);
				p128(n);
				fflush(stdout);
				fprintf(stderr, " ips)\n");
			}

			while (n--) {
				for (i = 15; ip.af == AF_INET6 && i >= 0; i--)
					ip.ip.v6.s6_addr[i] =
					    (u_char)((ip6 >> (8 * (15 - i))) &
						0xFF);

				loop(&ip);

				/* Next address.  */
				switch (ip.af) {
				case AF_INET6:
					++ip6;
					break;
				case AF_INET:
					ip.ip.v4.s_addr = ntohl(
					    ip.ip.v4.s_addr);
					ip.ip.v4.s_addr = htonl(
					    ++ip.ip.v4.s_addr);
					break;
				}
			}
		}
	}

	finish(0);
}
