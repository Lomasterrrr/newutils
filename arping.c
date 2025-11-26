#include "../include/base.h"

static bool Iflag = 0;
static bool _0flag = 0;
static bool sflag = 0;
static struct in_addr sopt = {0};
static bool Sflag = 0;
static struct ether_addr Sopt = {0};
static bool bflag = 0;
static bool Bflag = 0;
static bool Gflag = 0;
static bool Nflag = 0;
static bool tflag = 0;
static struct ether_addr topt = {0};
static bool vflag = 0;
static bool eflag = 0;
static bool Vflag = 0;
static bool Dflag = 0;
static bool lflag = 0;
static if_data_t ifd = {0};
static struct ether_addr lmac = {0};
static bool prstats = 0;
static struct in_addr *curtp = NULL;
static u_char outpack[42];
static u_short op = 1;
static size_t npackets = 5;
static dlt_t *dlt = NULL;
static size_t ntransmitted = 0;
static size_t nreceived = 0;
static size_t nbroadcast = 0;
static long long tmin = 0;
static long long tmax = 0;
static long long tsum = 0;
static long long wait = 1000 * 1000000LL;
static long long interval = 1000 * 1000000LL;

inline static void usage(char **av)
{
	fputs("Usage\n", stderr);
	fprintf(stderr, "  %s [options] <targets>\n\n", av[0]);
	fputs("  -I <dev>   set your interface and his info\n", stderr);
	fputs("  -S <mac>   set source mac address\n", stderr);
	fputs("  -s <ipv4>  set source ipv4 address\n", stderr);
	fputs("  -t <mac>   set obviously target mac\n", stderr);
	fputs("  -o <num>   set your arp operation; advice 1-4\n", stderr);
	fputs("  -i <time>  set interval between packets; ex: 300ms\n", stderr);
	fputs("  -w <time>  set wait time or timeout; ex: 2s, 10ms\n", stderr);
	fputs("  -n <count> set how many packets to send\n", stderr);
	fputs("  -N <count> set how many packets to recv (replies)\n", stderr);
	fputc('\n', stderr);
	fputs("  -0  use ipv4 address 0.0.0.0 in spa\n", stderr);
	fputs("  -b  keep on broadcasting, do not unicast\n", stderr);
	fputs("  -e  display info in easy (wireshark) style\n", stderr);
	fputs("  -V  display all info very verbose\n", stderr);
	fputs("  -l  display only success results\n", stderr);
	fputs("  -D  display in line (cisco) style (! reply) (. noreply)\n", stderr);
	fputs("  -B  use ipv4 address 255.255.255.255 how target\n", stderr);
	fputs("  -G  use device gateway ipv4 how target\n", stderr);
	fputs("  -v  show some debugging information\n", stderr);
	fputs("  -f  quit on first reply\n", stderr);
	fputs("  -h  show this help message and exit\n", stderr);
	fputs("\nExamples\n", stderr);
	fprintf(stderr, "  %s -f -e 192.168.1.1 localhost\n", av[0]);
	fprintf(stderr, "  %s -G -i 300ms\n", av[0]);
	fprintf(stderr, "  %s -G -V -n 1000 -i 10ms -0\n", av[0]);
	exit(0);
}

inline static bool callback(void *in, size_t n, void *arg)
{
	struct in_addr *target = (struct in_addr *)arg;
	u_char *buf = (u_char *)in;

	if (n < 42)
		return 0;

	if (ntohs(*(u_short *)(buf + 12)) != 0x0806)
		return 0;
	if (tflag && (memcmp(buf + 6, &topt, 6) != 0))
		return 0;
	switch (ntohs(*(u_short *)(buf + 20))) {
		case 1: case 2: case 3: case 4:
			break;
		default: return 0;
	}

	switch (op) {
	case 1:
	case 2:
		if (op == 1 && ntohs(*(u_short *)(buf + 20)) != 2)
			return 0;
		if (op == 2 && ntohs(*(u_short *)(buf + 20)) != 1)
			return 0;

		if (memcmp(buf + 38, ifd.srcip4, 4) != 0)
			return 0;

		if (*(u_int *)(buf + 28) != target->s_addr)
			return 0;

		break;
	case 3:
		if (ntohs(*(u_short *)(buf + 20)) != 4)
			return 0;

		if (memcmp((buf + 32), ifd.src, 6) != 0)
			return 0;

		if (*(u_int *)(buf + 38) != target->s_addr)
			return 0;
		
		break;
	case 4:
		if (ntohs(*(u_short *)(buf + 20)) != 3)
			return 0;
		
		if (memcmp((buf + 22), ifd.src, 6) != 0)
			return 0;

		break;
	}

	if (ntohs(*(u_short *)(buf + 14)) != 0x0001 &&
			(/*0x0001 != 0x0306 || */
			ntohs(*(u_short *)buf + 14) !=
			htons(0x0001)))
		return 0;
	if ((ntohs(*(u_short *)(buf + 14)) == 0x03) ||
			(ntohs(*(u_short *)buf + 14) == 0x00)) {
		if (ntohs(*(u_short*)(buf + 16)) != 0xcc)
			return 0;
	} else if (ntohs(*(u_short *)(buf + 16))!=0x0800)
		return 0;

	if (buf[18] != 6 || buf[19] != 4)
		return 0;

	if (op == 1 && lmac.__ether_octet[0] == '\n') {

		if (vflag)
			fprintf(stderr, "Found mac address: "
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
				buf[22], buf[22+1], buf[22+2],
				buf[22+3], buf[22+4], buf[22+5]);

		memcpy(&lmac, buf + 22, 6);
	}

	return 1;
}

inline static void stats(struct in_addr *target)
{
	if (!nreceived && lflag)
		goto end;

	if (Dflag) {
		if (ntransmitted)
			printf(" %ld%% packet loss", (size_t)
				(((ntransmitted - nreceived) * 100) /
				ntransmitted));
		goto end;
	}

	printf("\n----%s ARPING Statistics----\n", inet_ntoa(*target));
	printf("%ld packets transmitted (%ld broadcast), %ld packets received",
		ntransmitted, nbroadcast, nreceived);
	if (ntransmitted) {
		if (nreceived > ntransmitted)
			printf(" -- somebody's printing up packets!\n");
		else
			printf(", %ld%% packet loss\n", (size_t)
				(((ntransmitted - nreceived) * 100) /
				ntransmitted));
	}
	if (nreceived) {
		char tmp[1000];
		printf("round-trip (rtt) min/avg/max = %s",
			timefmt(tmin, tmp, sizeof(tmp)));
		printf("/%s", timefmt((long long)tsum /
			(long long)nreceived, tmp,
			sizeof(tmp)));
		printf("/%s", timefmt(tmax, tmp, sizeof(tmp)));
		putchar('\n');
	}
end:
	putchar('\n');
	prstats = 1;
}

inline static NORETURN void finish(int sig)
{
	(void)sig;
	if (!prstats)
		stats(curtp);
	if (dlt)
		dlt_close(dlt);
	exit(0);
}

inline static void tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		out->tv_sec--;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

inline static long long tvrtt(struct timeval *ts_s,
		struct timeval *ts_e)
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

inline static void pr_pack(u_char *buf, size_t n, long long rtt, size_t id)
{
	char t[65535] = {0};

	if (eflag) {
		switch ((ntohs(*(u_short *)(buf + 20)))) {
		case 1:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x ARP Who has"
				" %hhu.%hhu.%hhu.%hhu? Tell %hhu.%hhu.%hhu.%hhu",
				n, buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], 
				buf[38], buf[39], buf[40], buf[41], buf[28],
				buf[29], buf[30], buf[31]);
			break;
		case 2:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x ARP"
				" %hhu.%hhu.%hhu.%hhu at %02x:%02x:%02x:"
					"%02x:%02x:%02x",
				n,  buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], 
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], 
				buf[28], buf[29], buf[30], buf[31], buf[22], buf[23],
				buf[24], buf[25], buf[26], buf[27]);
			break;
		case 3:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x RARP Who is"
				" %02x:%02x:%02x:%02x:%02x:%02x? Tell"
				" %02x:%02x:%02x:%02x:%02x:%02x",
				n,  buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], 
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], 
				buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], 
				buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
			break;
		case 4:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x RARP"
				" %02x:%02x:%02x:%02x:%02x:%02x is at "
				"%hhu.%hhu.%hhu.%hhu",
				n,  buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], 
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], 
				buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], 
				buf[38], buf[39], buf[40], buf[41]);
			break;
		}
		if (rtt)
			printf(" %s", timefmt(rtt, t, sizeof(t)));

		putchar('\n');
	} else if (Vflag) {
		printf("%ld bytes", n);

		printf(" MAC {%02x:%02x:%02x:%02x:%02x:%02x > "
			"%02x:%02x:%02x:%02x:%02x:%02x 0x%02x%02x}",
			buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], 
			buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], 
			buf[12], buf[13]);

		printf(" %s {%hu 0x%02x%02x %hhu %hhu %hu",
			(((ntohs(*(u_short*)(buf + 20)) == 1 ||
				ntohs(*(u_short*)(buf + 20)) == 2) ?
				"ARP" : "RARP")),
			ntohs(*(u_short*)(buf + 14)),
			buf[16], buf[17], buf[18], buf[19],
			ntohs(*(u_short*)(buf + 20)));

		printf("%02x:%02x:%02x:%02x:%02x:%02x|%hhu.%hhu.%hhu.%hhu", 
			buf[22], buf[23], buf[24], buf[25], buf[26], buf[27], 
			buf[28], buf[29], buf[30], buf[31]);

		printf(" > %02x:%02x:%02x:%02x:%02x:%02x|%hhu.%hhu.%hhu.%hhu}", 
			buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], 
			buf[38], buf[39], buf[40], buf[41]);

		printf(" ( %s )", (rtt) ? timefmt(rtt, t, sizeof(t)) : "notime");
		putchar('\n');
	} else if (Dflag) {
		putchar('!');
		fflush(stdout);
	} else {
		printf("%ld bytes from %s %hhu.%hhu.%hhu.%hhu"
			" (%02x:%02x:%02x:%02x:%02x:%02x) id=%ld"
			" time=%s\n",
			n, ((ntohs(*(u_short *)(buf + 20)) == 1) ? "arp-req" :
			(ntohs(*(u_short *)(buf + 20)) == 2) ? "arp-reply" :
			(ntohs(*(u_short *)(buf + 20)) == 3) ? "rarp-req" :
			(ntohs(*(u_short *)(buf + 20)) == 4) ? "rarp-reply" : "???"),
			buf[28], buf[29], buf[30], buf[31], buf[22], buf[23],
			buf[24], buf[25], buf[26], buf[27],
			nreceived, timefmt(rtt, t, sizeof(t))
		);
	}

}

inline static void pinger(struct in_addr *target)
{
	memset(outpack, 0, sizeof(outpack));
	memset(outpack, 0xff, 6);
	memcpy(outpack + 6, ifd.src, 6);
	*(u_short *)(outpack + 12) = htons(0x0806);
	*(u_short *)(outpack + 14) = htons(0x0001);
	*(u_short *)(outpack + 16) = htons(0x0800);
	outpack[18] = 6, outpack[19] = 4;
	*(u_short *)(outpack + 20) = htons(op);
	memcpy(outpack + 22, ifd.src, 6);
	memcpy(outpack + 28, ifd.srcip4, 4);
	memset(outpack + 32, 0xff, 6);
	memcpy(outpack + 38, target, 4);

	if (tflag) {
		memcpy(outpack, &topt, 6);
		memcpy(outpack + 32, &topt, 6);
	} else if (!bflag && lmac.__ether_octet[0] != '\n') {
		memcpy(outpack, &lmac, 6);
		memcpy(outpack + 32, &lmac, 6);
	}

	if (outpack[0] == 0xff && outpack[1] == 0xff &&
			outpack[2] == 0xff && outpack[3] == 0xff &&
			outpack[4] == 0xff && outpack[5] == 0xff)
		++nbroadcast;
		
	ssize_t n = dlt_send(dlt, outpack, sizeof(outpack));
	if (n < 0 || n != sizeof(outpack)) {
		if (n < 0)
			warn("sendto");
		warnx("wrote %s %lu chars, ret=%zd",
			inet_ntoa(*target),
			sizeof(outpack), n);
	}

	++ntransmitted;
}

inline static void loop(struct in_addr *ip)
{
	lmac.__ether_octet[0] = '\n';
	ntransmitted = 0;
	tsum = 0;
	nbroadcast = 0;
	tmax = LLONG_MIN;
	nreceived = 0;
	prstats = 0;
	tmin = LLONG_MAX;
	curtp = ip;

	if (!Dflag)
		printf("ARPING %s\n", inet_ntoa(*ip));

	for (;;) {

		/* Classic ping loop; packet creation & sending
		   (pinger), receiving (dlt_recv_cb), displaying
		   the received data (pr_pack), delay (sleepns). */

		struct timeval ts_s, ts_e;
		u_char buf[2048] = {0};
		ssize_t n;

		pinger(ip);
		if ((n = dlt_recv_cb(dlt, buf, sizeof(buf), callback, 
				(void *)ip, wait, &ts_s, &ts_e)) == -1) {

			/* There is no reason to believe that he
			   is the same; although it is hard to
			   believe in change.  */
			lmac.__ether_octet[0] = '\n';

			if ((eflag || Vflag) && !lflag)
				pr_pack(outpack, sizeof(outpack), 0, 0);
			if (!lflag) {
				if (Dflag) {
					putchar('.');
					fflush(stdout);
				} else
					warnx("no response received");
			}
			if (errno != 0)
				warn("recv");
				
		} else {
			nreceived++; /* Packet received.  */
			if (eflag || Vflag)
				pr_pack(outpack, sizeof(outpack), 0, 0);
			pr_pack(buf, n, tvrtt(&ts_s, &ts_e), ntransmitted);
		}

		if (((Nflag) ? nreceived : ntransmitted) == npackets)
			break;

		sleepns(interval);
	}

	stats(ip);
}

inline static void if_setup(void)
{
	if (!Iflag) {
		if (!if_get(NULL, &ifd))
			errx(1, "no suitable devices found");
	} else {
		if (!if_get(optarg, &ifd))
			errx(1, "device \"%s\" not found", optarg);
		if (!__is_network_sendable(&ifd))
			errx(1, "device \"%s\" doesn't fit", optarg);
	}
	if (!ifd.support4)
		errx(1, "device does not support ipv4");
	if (_0flag)
		memset(ifd.srcip4, 0x00, 4);
	if (sflag)
		memcpy(ifd.srcip4, &sopt, 4);
	if (Sflag)
		memcpy(ifd.src, &Sopt, 6);
	if (vflag)
		if_output(stderr, &ifd);

	if (!(dlt = dlt_open(ifd.name)))
		errx(1, "failed open socket");
}

int main(int c, char **av)
{
	struct in_addr ip;
	int ch;

	if (c <= 1)
		usage(av);

	signal(SIGINT, finish);
	while ((ch = getopt(c, av, "GBfhS:s:I:0vo:t:bi:w:n:N:eVDl")) != -1) {
		switch (ch) {
		case 'V': Vflag = 1; break;
		case 'D': Dflag = 1; break;
		case 'e': eflag = 1; break;
		case 'G': Gflag = 1; break;
		case 'B': Bflag = 1; break;
		case 'f': npackets = 1, Nflag = 1; break;
		case 'b': bflag = 1; break;
		case 'I': Iflag = 1; break;
		case 'l': lflag = 1; break;
		case 'N': case 'n': 
			if (ch == 'N')
				Nflag = 1;
			if (!u_numarg(optarg, 0, SIZE_MAX,
					&npackets, sizeof(npackets)))
				errx(1, "invalid number \"%s\"", optarg);
			break;
		case 'w': 
			if ((wait = strtons(optarg)) == -1)
				errx(1, "failed convert \"%s\" in time", optarg);
			break;
		case 'i': 
			if ((interval = strtons(optarg)) == -1)
				errx(1, "failed convert \"%s\" in time", optarg);
			break;
		case 't': 
			if (!(ether_aton_r(optarg, &topt)))
				errx(1, "failed convert \"%s\" in mac", optarg);
			tflag = 1;
			break;
		case 's': 
			if (inet_pton(AF_INET, optarg, &sopt) != 1)
				errx(1, "failed convert \"%s\" in ipv4", optarg);
			sflag = 1;
			break;
		case 'S': 
			if (!(ether_aton_r(optarg, &Sopt)))
				errx(1, "failed convert \"%s\" in mac", optarg);
			Sflag = 1;
			break;
		case 'o': 
			if (!u_numarg(optarg, 1, 4, &op, sizeof(op)))
				errx(1, "invalid operation \"%s\"", optarg);
			break;
		case '0': _0flag = 1; break;
		case 'v': vflag = 1; break;
		case '?': default: usage(av);
		}
	}

	if ((Vflag + eflag + Dflag) > 1)
		errx(1, "only one output style must be specified");

	c -= optind;
	av += optind;
	if_setup();

	/* Broadcast ipv4 address.  */
	if (Bflag) {
		memset(&ip, 0xff, 4);
		loop(&ip);
	}

	/* Gateway ipv4 address.  */
	else if (Gflag) {
		memcpy(&ip, ifd.gate4, 4);
		loop(&ip);
	}

	/* Custom user targets: cidr4, ipv4, dns.  */
	else while (*av) {
		char *p = *av++, *sb;

		if ((sb = strchr(p, '/')))
			*sb++ = '\0';

		if ((inet_pton(AF_INET, p, &ip)) != 1)
			if (!resolveipv4(p, &ip))
				errx(1, "failed resolve \"%s\"", p);

		if (!sb)
			loop(&ip);
		else {
			u_char mask[4];
			u_char net[4];
			u_short bits;
			size_t n;

			if (!u_numarg(sb, 0, 32, &bits, sizeof(bits)))
				errx(1, "invalid bits \"%s\"", sb);

			ip_btom(AF_INET, bits, mask);
			ip_net((u_char *)&ip, mask, net);

			ip.s_addr = htonl((net[0] << 24) | (net[1] << 16) |
					(net[2] << 8) | net[3]);

			n = (bits == 32) ? 1 : 1 << (32 - bits);

			if (vflag)
				fprintf(stderr, "Target cidr: %s/%s"
					" (%ld ips)\n", p, sb, n);

			while (n--) {
				loop(&ip);

				/* Next address.  */
				ip.s_addr = ntohl(ip.s_addr);
				ip.s_addr = htonl(++ip.s_addr);
			}
		}

	}

	finish(0);
}
