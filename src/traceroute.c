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

static dlt_t *dlt;      /* socket */
static long long interval; /* delay/interval */
static bool sflag;
static bool vflag;
static struct in_addr sopt;
static bool Sflag;
static struct ether_addr Sopt;
static bool Iflag;
static char *Iopt;
static bool prstats; /* print last stats? */
static size_t ntransmitted;
static size_t nreceived;
static size_t ntry = 3;
static long long tmin;
static long long wait = 150 * 1000000LL; /* timeout */
static long long tmax;
static if_data_t ifd; /* interface data */
static long long tsum;
static int method = IPPROTO_UDP;
static long long *rtts;
static bool reached;
static int curhop;
static u_short lid; /* last ip id */
static bool Aflag;
static bool Pflag;
static bool pflag;
static size_t unreachable;
static int Popt;
static int popt;
static int dstport;
static bool _6flag;
static struct in6_addr _6opt;
static int first = 1;
static int total = 30;
static int ttl;
static int mttl;
static ipaddr_t source;
static int off;
static ipaddr_t curtp; /* current target */
static bool oflag;
static int oopt;
static size_t hopid;
static u_char *payload;
static size_t payloadlen;

/*
 *		U S A G E
 *
 * Takes a vector of arguments (argv) and prints help
 * about the TRACEROUTE options; also, terminates the
 * program.
 */
inline static void
usage(char **av)
{
	fputs("Usage\n", stderr);
	fprintf(stderr, "  %s [options] <targets>\n\n", av[0]);
	fputs("  -I <dev>\tset your interface and his info\n", stderr);
	fputs("  -s <ipv4>\tset source ipv4 address\n", stderr);
	fputs("  -6 <ipv6>\tset source custom ipv6 address\n", stderr);
	fputs("  -o <tos>\tset num in Type Of Service/Traffic class\n", stderr);
	fputs("  -S <mac>\tset source mac address\n", stderr);
	fputs("  -i <time>\tset interval between packets; ex: 300ms\n", stderr);
	fputs("  -P <port>\tset source (your) port\n", stderr);
	fputs("  -p <port>\tset destination port\n", stderr);
	fputs("  -w <time>\tset wait time or timeout; ex: 2s, 10ms\n", stderr);
	fputs("  -m <ttl>\tset max ttl/hop limit (num hops)\n", stderr);
	fputs("  -f <ttl>\tset first ttl/hop limit (start hop)\n", stderr);
	fputs("  -n <count>\tset your num of try\n", stderr);
	fputs("  -H <hex>\tset payload data in hex numbers\n", stderr);
	fputs("  -a <ascii>\tset payload data in ascii\n", stderr);
	fputs("  -l <len>\tset random payload data\n", stderr);
	fputs("  -v\t\tshow some debugging information\n", stderr);
	fputs("  -4\t\tset More Fragment flag (ipv4)\n", stderr);
	fputs("  -r\t\tset Reserved Fragment flag (ipv4)\n", stderr);
	fputs("  -d\t\tset Dont't Fragment flag (ipv4)\n", stderr);
	fputs("  -A\t\tuse all methods and protos\n", stderr);
	fputs("  -E\t\tuse only icmp4 echo packets\n", stderr);
	fputs("  -Y\t\tuse only tcp syn packets\n", stderr);
	fputs("  -U\t\tuse only udp packets\n", stderr);
	fputs("  -L\t\tuse only udp-lite packets\n", stderr);
	fputs("  -C\t\tuse only sctp-cookie packets\n", stderr);
	fputs("  -h\t\tshow this help message and exit\n", stderr);
	fputs("\nExamples\n", stderr);
	fprintf(stderr, "  %s -A google.com\n", av[0]);
	fprintf(stderr, "  %s -n10 -w 50ms 5.255.255.77\n", av[0]);
	fprintf(stderr, "  %s -n10 -A github.com 5.255.255.77\n", av[0]);
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
	ipaddr_t *target = (ipaddr_t *)arg;
	u_char *buf = (u_char *)in;
	ssize_t s = 0;

	source.af = target->af;
	switch (target->af) {
	case AF_INET:
		if (n < 42)
			return 0;
		if (ntohs(*(u_short *)(buf + 12)) != 0x0800)
			return 0;
		if (buf[23] != IPPROTO_ICMP) /* only icmp packets */
			return 0;

		s = ((buf[14] & 0x0f) * 4) + 14;

		/* We can conclude whether the host has been reached
		 * on the current TTL from the fact that we received
		 * a DEST UNREACHED message indicating that the
		 * protocol or port is unavailable.  */
		if (buf[s] == 3) {
			if (memcmp((buf + s + 20), ifd.srcip4, 4) != 0)
				return 0;
			if (memcmp((buf + s + 24), &target->ip.v4, 4) != 0)
				return 0;
			if (buf[s + 1] != 3 && buf[s + 1] != 2) {
				if (vflag)
					warnx("destination unreachable");

				++unreachable;
				return 0;
			}

			if (ntohs((*(u_short *)(buf + s + 12))) != lid)
				return 0;

			memcpy(&source.ip.v4, (buf + s + 24), 4);
			reached = 1; /* AEEEE */
			break;
		}
		/* Or coming from ICMP_ECHO_REPLY, but only when the
		 * ID and seq match.  */
		else if (buf[s] == 0) {
			if (ntohs((*(u_short *)(buf + s + 4))) != lid)
				return 0;
			if (ntohs((*(u_short *)(buf + s + 6))) != hopid)
				return 0;

			memcpy(&source.ip.v4, (buf + 26), 4);
			reached = 1; /* AEEEE */
			break;
		}
		if (buf[s] != /* Time Exceed */ 11 &&
		    buf[s + 1] == /* Intrans */ 0)
			return 0;
		if (memcmp((buf + 30), ifd.srcip4, 4) != 0) /* ip dst */
			return 0;
		if (ntohs((*(u_short *)(buf + s + 12))) != lid)
			return 0;

		memcpy(&source.ip.v4, (buf + 26), 4);
		break;
	case AF_INET6:
		if (n < 54)
			return 0;
		if (ntohs(*(u_short *)(buf + 12)) != 0x86dd)
			return 0;
		if (buf[20] != IPPROTO_ICMPV6) /* only icmp6 packets */
			return 0;

		if ((s = ipv6_offset(buf + 14, n - 14)) == -1)
			return 0;
		s += 14;

		/* The same as with IPv4, but there is no protocol
		 * error.  */
		if (buf[s] == 1) {
			const u_int *inner_ipv6_hdr = (const u_int *)(buf + s +
			    8);
			if ((ntohl(inner_ipv6_hdr[0]) & 0x000FFFFF) != lid)
				return 0;
			if (buf[s + 1] == 4) {
				memcpy(source.ip.v6.s6_addr, (buf + s + 32),
				    16);
				reached = 1; /* AEEEE */
				break;
			}
			/* However, the PARAM PROBLEM type with code 1 also
			 * reports host availability with ICMPv6.  */
		} else if (buf[s] == 4 && buf[s + 1] == 1) {
			memcpy(source.ip.v6.s6_addr, (buf + s + 32), 16);
			reached = 1; /* AEEEE */
			break;
		} else if (buf[s] == 129) {
			if (ntohs((*(u_short *)(buf + s + 4))) != lid)
				return 0;
			if (ntohs((*(u_short *)(buf + s + 6))) != hopid)
				return 0;

			memcpy(source.ip.v6.s6_addr, (buf + 22), 16);
			reached = 1; /* AEEEE */
			break;
		}

		if (buf[s] != /* Time Exceed */ 3 &&
		    buf[s + 1] == /* Intrans */ 0)
			return 0;
		if (memcmp((buf + 38), ifd.srcip6, 16) != 0) /* ip dst */
			return 0;

		const u_int *inner_ipv6_hdr = (const u_int *)(buf + s + 8);
		if ((ntohl(inner_ipv6_hdr[0]) & 0x000FFFFF) != lid)
			return 0;

		memcpy(source.ip.v6.s6_addr, (buf + 22), 16);
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
	printf("\n----%s TRACEROUTE Statistics----\n", ipaddr_ntoa(target));
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

	printf("target %s %s %d hops\n", ipaddr_ntoa(target),
	    (reached) ? "was reached in" : "has been missed for", curhop);

	putchar('\n');
	prstats = 1;
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
	if (rtts)
		free(rtts);
	if (dlt)
		dlt_close(dlt);
	exit(0);
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
	static char res[4096 + 2];
	char host[4096] = { 0 };

	memset(res, 0, sizeof(res));
	switch (target->af) {
	case AF_INET:
		sin.sin_family = (u_short)target->af;
		sin.sin_addr = target->ip.v4;
		if (getnameinfo((struct sockaddr *)&sin, sizeof(sin), host,
			sizeof(host), NULL, 0, 0) == 0) {
			snprintf(res, sizeof(res), "(%s)", host);
			return res;
		}
		break;
	case AF_INET6:
		sin6.sin6_family = (u_short)target->af;
		sin6.sin6_addr = target->ip.v6;
		if (getnameinfo((struct sockaddr *)&sin6, sizeof(sin6), host,
			sizeof(host), NULL, 0, 0) == 0) {
			snprintf(res, sizeof(res), "(%s)", host);
			return res;
		}
		break;
	}

	return "(\?\?\?)";
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
 *		S E N D P R O B E
 *
 * Creates a package in <outpack> according to
 * the options, sends it, and updates statistics.
 */
inline static void
sendprobe(ipaddr_t *target, int proto, u_char *data, u_int datalen)
{
	u_char outpack[2048] = { 0 };
	size_t len = 0, s;
	u_short srcport;
	ssize_t n;

	len += 34;
	if (target->af == AF_INET6) {
		len += 20;

		/* fix proto */
		proto = (proto == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : proto;
	}
	s = len; /* skip ad payload */
	switch (proto) {
	case IPPROTO_TCP:
		len += 20;
		break;
	case IPPROTO_SCTP:
		len += 16; /* sctp + cookie chunk */
		break;
	case IPPROTO_ICMP: /* icmp + echo msg (valid for ipv6) */
	case IPPROTO_ICMPV6:
	case IPPROTO_UDPLITE:
	case IPPROTO_UDP:
		len += 8;
		break;
	}
	len += datalen;

	lid = random_range(106, USHRT_MAX);
	srcport = random_range(48, USHRT_MAX);

	memcpy(outpack, ifd.dst, 6);
	memcpy(outpack + 6, ifd.src, 6);
	*(u_short *)(outpack + 12) = htons(
	    (target->af == AF_INET) ? 0x0800 : 0x86dd);

	switch (target->af) {
	case AF_INET:
		outpack[14] = (4 << 4) | 5 /*5+(optslen/4)*/; /* version|ihl */
		outpack[15] = (oflag) ? oopt : 0;	      /* tos */
		*(u_short *)(outpack + 16) = htons(
		    (u_short)(len - 14));		 /* tot_len +optslen */
		*(u_short *)(outpack + 18) = htons(lid); /* id */
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

		*(u_short *)(outpack + 24) = in_cksum((u_short *)(outpack + 14),
		    20);
		break;
	case AF_INET6:
		outpack[14] = ((0x06 << 4) |
		    ((((oflag) ? oopt : 0) & 0xF0) >> 4)); /* version|tc */
		outpack[15] = (u_char)(((((oflag) ? oopt : 0) & 0x0F)
					   << 4) | /* flowlabel */
		    ((lid & 0xF0000) >> 16));
		outpack[16] = ((lid & 0x0FF00) >> 8),
		outpack[17] = ((lid & 0x000FF));
		*(u_short *)(outpack + 18) = htons(
		    (u_short)len - (54));    /* payload length */
		outpack[20] = (u_char)proto; /* nexthdr (protocol) */
		outpack[21] = (u_char)ttl;   /* hoplimit (ttl) */
		for (n = 0; n < 16; n++)     /* src+dst */
			outpack[22 + n] = ifd.srcip6[n],
				     outpack[22 + 16 + n] =
					 target->ip.v6.s6_addr[n];
		break;
	}

	switch (proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		outpack[s] = (target->af == AF_INET6) ? 128 : 8; /* type */
		outpack[s + 1] = 0;				 /* code */
		*(u_short *)(outpack + s + 2) = htons(0);	 /* chksum */
		*(u_short *)(outpack + s + 4) = htons(lid);	 /* id */
		*(u_short *)(outpack + s + 6) = htons(hopid);	 /* seq */

		if (data && datalen)
			memcpy(outpack + s + 8, data, datalen);

		switch (target->af) {
		case AF_INET:
			*(u_short *)(outpack + s +
			    2) = in_cksum((u_short *)(outpack + s),
			    (int)(8 + datalen));
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
		*(u_short *)(outpack + s) = (Pflag) ?
		    htons(Popt) :
		    htons(srcport); /* src port */
		*(u_short *)(outpack + s + 2) = (pflag) ?
		    htons(popt) :
		    htons(dstport + hopid); /* dst port */
		memcpy(outpack + s + 4,
		    &(u_int) { htonl(random_range(5, UINT_MAX)) },
		    sizeof(u_int)); /* seq */
		memcpy(outpack + s + 8, &(u_int) { htonl(0) },
		    sizeof(u_int));			      /* ack */
		outpack[s + 12] = (5 << 4) | (0 & 0x0f);      /* off | res */
		outpack[s + 13] = 2;			      /* flags */
		*(u_short *)(outpack + s + 14) = htons(1024); /* window */
		*(u_short *)(outpack + s + 16) = 0;	      /* chksum */
		*(u_short *)(outpack + s + 18) = 0;	      /* urp */

		if (data && datalen)
			memcpy(outpack + s + 20, data, datalen);

		switch (target->af) {
		case AF_INET:
			*(u_short *)(outpack + s +
			    16) = in_pseudocksum(ifd.srcip4,
			    (u_char *)&target->ip.v4, (u_char)proto,
			    (20 + (u_short)datalen), (outpack + s));
			break;
		case AF_INET6:
			*(u_short *)(outpack + s +
			    16) = in6_pseudocksum(ifd.srcip6,
			    (u_char *)&target->ip.v6, (u_char)proto,
			    (u_int)(20 + datalen), (outpack + s));
			break;
		}

		break;
	case IPPROTO_SCTP:
		*(u_short *)(outpack + s) = (Pflag) ?
		    htons(Popt) :
		    htons(srcport); /* src port */
		*(u_short *)(outpack + s + 2) = (pflag) ?
		    htons(popt) :
		    htons(dstport + hopid); /* dst port */
		*(u_int *)(outpack + s + 4) = htonl(
		    random_range(5, UINT_MAX));		/* vtag */
		*(u_int *)(outpack + s + 8) = htonl(0); /* chksum */
		outpack[s + 12] = 0x0a;			/* type */
		outpack[s + 13] = 0;			/* flags */
		*(u_short *)(outpack + s + 14) = htons(
		    4 + (u_short)datalen); /* len */

		if (data && datalen)
			memcpy(outpack + s + 16, data, datalen);

		*(u_int *)(outpack + s + 8) = htonl(
		    adler32(1, (outpack + s) /* final chksum */
			,
			16 + datalen));
		break;
	case IPPROTO_UDP:
		*(u_short *)(outpack + s) = (Pflag) ?
		    htons(Popt) :
		    htons(srcport); /* src port */
		*(u_short *)(outpack + s + 2) = (pflag) ?
		    htons(popt) :
		    htons(dstport + hopid); /* dst port */
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
	case IPPROTO_UDPLITE:
		*(u_short *)(outpack + s) = (Pflag) ?
		    htons(Popt) :
		    htons(srcport); /* src port */
		*(u_short *)(outpack + s + 2) = (pflag) ?
		    htons(popt) :
		    htons(dstport + hopid);		  /* dst port */
		*(u_short *)(outpack + s + 4) = htons(0); /* checkcrg */
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
	nreceived = 0;
	dstport = 33434; /* 32768 + 666 */
	lid = 0;
	prstats = 0;
	tmin = LLONG_MAX;
	reached = 0;
	curtp = *ip;
	curhop = 0;

	printf("TRACEROUTE %s %s, %d hops max, %zu data bytes\n",
	    ipaddr_ntoa(ip), resolve_dns(ip), total, payloadlen);

	ttl = first;
	mttl = total - (ttl - 1);

	/* We loop through all the TTLs and send ntry probes on each
	 * one: we send the probe (sendprobe), receive the response
	 * (dlt_recv_cb), and output the results. If the host is
	 * reached or unavailable, we terminate.*/
	for (; mttl; mttl--) {
		struct timeval ts_s, ts_e;
		u_char buf[65535] = { 0 };
		ipaddr_t tmpip = { 0 };
		bool okttl = 0;
		ssize_t n;

		memset(rtts, 0, (ntry * sizeof(long long)));
		printf("%2d  ", ttl);
		unreachable = 0;
		curhop = ttl;

		for (hopid = 1; hopid <= ntry; hopid++) {
			sleepns(interval);
			sendprobe(ip, method, payload, (u_int)payloadlen);
			if ((n = dlt_recv_cb(dlt, buf, sizeof(buf), callback,
				 (void *)ip, wait, &ts_s, &ts_e)) == -1) {
				/* If the -A flag is set, then we try all
				 * methods until we get an answer, or until
				 * they run out.  */
				if (Aflag) {
					switch (method) {
					case IPPROTO_ICMP:
						method = IPPROTO_TCP;
						break;
					case IPPROTO_TCP:
						method = IPPROTO_UDP;
						break;
					case IPPROTO_UDP:
						method = IPPROTO_SCTP;
						break;
					case IPPROTO_SCTP:
						method = IPPROTO_UDPLITE;
						break;
					case IPPROTO_UDPLITE:
						method = IPPROTO_ICMP;
						goto next;
					}
					--hopid;
					continue;
				}
			next:
				putchar('.');
				fflush(stdout);
			} else {
				++nreceived;

				/* We save our response time in a buffer.  */
				rtts[hopid - 1] = tvrtt(&ts_s, &ts_e);

				/* We check whether the response came from the
				 * new host, or whether there was one already.
				 */
				if (memcmp(&source, &tmpip,
					(source.af == AF_INET) ? 4 : 6)) {
					printf("%s %s", ipaddr_ntoa(&source),
					    resolve_dns(&source));
					tmpip = source;
				}

				okttl = 1;
			}
		}

		/* We display the response time if at least one attempt
		 * was successful. */
		if (okttl) {
			printf("    ");
			for (n = 1; n <= ntry; n++)
				printf("%s ",
				    timefmt(rtts[n - 1], (char *)buf,
					sizeof(buf)));
		}

		putchar('\n');

		/* If 10% all hosts send us an error, and one that
		 * doesn't indicate availability, then there's no
		 * point in continuing.  */
		n = (ntry * 10 + 99) / 100;
		n = (n < 1) ? 1 : n;

		if (unreachable && unreachable >= n) {
			fprintf(stderr, "Host is down (%zu unreachable)\n",
			    unreachable);
			break;
		}

		/* We have achieved our target.  */
		if (reached)
			break;

		++ttl;
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
 *		T R A C E R O U T E
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

	while ((ch = getopt(c, av,
		    "I:s:6:o:S:i:P:p:w:m:f:n:H:a:l:v4rdAEYULCh")) != -1) {
		switch (ch) {
		case 'I':
			Iflag = 1;
			Iopt = optarg;
			break;
		case '4':
			off |= 0x8000;
			break;
		case 'A':
			Aflag = 1;
			method = IPPROTO_ICMP;
			break;
		case 'E':
			method = IPPROTO_ICMP;
			break;
		case 'Y':
			method = IPPROTO_TCP;
			break;
		case 'U':
			method = IPPROTO_UDP;
			break;
		case 'L':
			method = IPPROTO_UDPLITE;
			break;
		case 'C':
			method = IPPROTO_SCTP;
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
		case 'm':
			if (!u_numarg(optarg, 0, UCHAR_MAX, &total,
				sizeof(total)))
				errx(1, "invalid ttl \"%s\"", optarg);
			break;
		case 'f':
			if (!u_numarg(optarg, 0, UCHAR_MAX, &first,
				sizeof(first)))
				errx(1, "invalid ttl \"%s\"", optarg);
			break;
		case 'd':
			off |= 0x4000;
			break;
		case 'o':
			if (!u_numarg(optarg, 0, UCHAR_MAX, &oopt,
				sizeof(oopt)))
				errx(1, "invalid tos \"%s\"", optarg);
			oflag = 1;
			break;
		case 'v':
			vflag = 1;
			break;
		case 'p':
			if (!u_numarg(optarg, 0, USHRT_MAX, &popt,
				sizeof(popt)))
				errx(1, "invalid port \"%s\"", optarg);
			pflag = 1;
			break;
		case 'P':
			if (!u_numarg(optarg, 0, USHRT_MAX, &Popt,
				sizeof(Popt)))
				errx(1, "invalid port \"%s\"", optarg);
			Pflag = 1;
			break;
		case 'n':
			if (!u_numarg(optarg, 0, SIZE_MAX, &ntry, sizeof(ntry)))
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

	if (c <= 0)
		errx(1, "no targets specified");

	if (!(rtts = calloc(ntry, sizeof(long long))))
		errx(1, "failed allocated time");

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
