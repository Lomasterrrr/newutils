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

#include "../../include/base.h"

struct dlt_handle {
	int fd;			/* File descriptor.  */
	u_char buf[DLT_BUFLEN]; /* Read buffer.  */
};

dlt_t *
dlt_open(const char *if_name)
{
	dlt_t *dlt = NULL;
#ifndef __LINUX
	int n = 0;
#endif

	if (!if_name)
		return NULL;
	if (!(dlt = calloc(1, sizeof(*dlt))))
		return NULL;

	/* This is important.  */
	memset(dlt, 0, sizeof(*dlt));

#ifdef __LINUX
	dlt->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#else
	char name[512] = { 0 };

	if ((dlt->fd = open("/dev/bpf", O_RDWR)) == -1) {
		if (errno == EACCES)
			dlt->fd = open("/dev/bpf", O_RDONLY);
		if (dlt->fd == -1 && errno != ENOENT) {
			do {
				/* Brute force /dev/bpf[0-256].  */
				snprintf(name, sizeof(name), "/dev/bpf%d", n++);
				if (((dlt->fd = open(name, O_RDWR))) == -1 &&
				    errno == EACCES)
					dlt->fd = open(name, O_RDONLY);
			} while (dlt->fd < 0 && errno == EBUSY && n < 256);
		}
	}

	n = DLT_BUFLEN;
	if (ioctl(dlt->fd, BIOCSBLEN, (u_int *)&n) < 0)
		goto err;

	n = 1; /* Leads to a similarity to Linux.  */
	if (ioctl(dlt->fd, BIOCIMMEDIATE, (u_int *)&n) < 0)
		goto err;
#endif

	if (dlt->fd < 0)
		goto err;

#ifdef __LINUX
	struct sockaddr_ll sll = { .sll_ifindex = if_nametoindex(if_name),
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL) };
	struct packet_mreq mreq = { .mr_ifindex = sll.sll_ifindex,
		.mr_type = PACKET_MR_PROMISC };

	if (bind(dlt->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		return 0;

	setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
#else
	struct ifreq ifr = { 0 };
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", if_name);

	if (ioctl(dlt->fd, BIOCSETIF, &ifr) < 0)
		goto err;

	n = 1;
	if (ioctl(dlt->fd, BIOCPROMISC, (u_int *)&n) < 0)
		goto err;
#endif

	return dlt;

err:
	if (dlt)
		free(dlt);

	return NULL;
}

ssize_t
dlt_send(dlt_t *dlt, void *ptr, size_t n)
{
	if (!dlt)
		return -1;

	return write(dlt->fd, ptr, n);
}

ssize_t
dlt_recv(dlt_t *dlt, void *ptr, size_t n)
{
	if (!dlt)
		return -1;

	u_char *p = dlt->buf;
	ssize_t ret;

	memset(p, 0, DLT_BUFLEN);
	if ((ret = read(dlt->fd, p, DLT_BUFLEN)) <= 0)
		return ret;

#ifndef __LINUX
	if (ret <= (ssize_t)sizeof(struct bpf_hdr))
		return 0;

	struct bpf_hdr *bh = (struct bpf_hdr *)p;

	/* Skip bpf header.  */
	p += bh->bh_hdrlen;
	ret -= bh->bh_hdrlen;
#endif

	if (ptr && n) {
		n = (n > (size_t)ret) ? (size_t)ret : n;
		memcpy(ptr, p, n);
	}

	return n;
}

void
dlt_close(dlt_t *dlt)
{
	if (dlt) {
		if (dlt->fd != -1)
			close(dlt->fd);
		free(dlt);
	}
}

ssize_t
dlt_recv_cb(dlt_t *dlt, void *buf, size_t n, dlt_rcall_t cb, void *arg,
    long long ns, struct timeval *ts_s, struct timeval *ts_e)
{
	if (!dlt || !buf || !n || !cb)
		return -1;

	struct timespec s = { 0 }, c = { 0 };
	ssize_t ret;

	clock_gettime(CLOCK_MONOTONIC, &s);
	if (ts_s)
		gettimeofday(ts_s, NULL);

	for (;;) {
		errno = 0;
		ret = dlt_recv(dlt, buf, n);
		if (ts_e)
			gettimeofday(ts_e, NULL);

		if (ret == 0)
			continue;
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		/* Filtering.  */
		if (!cb(buf, (size_t)ret, arg)) {
			clock_gettime(CLOCK_MONOTONIC, &c);

			/* Time left; return? */
			if (((c.tv_sec - s.tv_sec) * 1000000000LL +
				(c.tv_nsec - s.tv_nsec)) >= ns)
				return -1;

			continue;
		}

		return ret;
	}

	/* NOTREACHED */
	return -1;
}

inline static bool
__get_dstmac(const char *if_name, int if_index, u_char *gw, u_char *buf)
{
#ifdef __LINUX
	(void)if_index;
	char name[512];
	char line[2048];
	char mac[32];
	char ip[32];
	FILE *fp;

	if (!(fp = fopen("/proc/net/arp", "r")))
		return 0;

	if (!(fgets(line, sizeof(line), fp))) {
		fclose(fp);
		return 0;
	}
	while ((fgets(line, sizeof(line), fp))) {
		struct ether_addr *tmp1 = NULL;
		struct in_addr tmp = { 0 };

		if (sscanf(line, "%31s %*31s %*31s %31s %*31s %16s", ip, mac,
			name) != 3)
			continue;

		if (strcmp(name, if_name))
			continue;
		memcpy(&tmp.s_addr, gw, 4);
		if (strcmp(ip, inet_ntoa(tmp)))
			continue;
		if (!(tmp1 = ether_aton(mac)))
			continue;

		/* On BSD this field est "octet".  */
		memcpy(buf, tmp1->ether_addr_octet, 6);

		fclose(fp);
		return 1;
	}

	fclose(fp);
	return 0;
#else
	(void)if_name;
	char *tmp, *lim, *nxt;
	size_t n;

	int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS,
		RTF_LLINFO };

	if (sysctl(mib, 6, NULL, &n, NULL, 0) < 0)
		return 0;
	if (!(tmp = calloc(1, n)))
		return 0;
	if (sysctl(mib, 6, tmp, &n, NULL, 0) < 0) {
		free(tmp);
		return 0;
	}

	lim = tmp + n;
	nxt = tmp;

	while (nxt < lim) {
		struct rt_msghdr *rtm = (struct rt_msghdr *)nxt;
		nxt += rtm->rtm_msglen;

		char *ptr = (char *)(rtm + 1);
		struct sockaddr_in *dst = NULL;
		struct sockaddr_dl *sdl = NULL;

		for (n = 0; n < RTAX_MAX; n++) {
			if (rtm->rtm_addrs & (1 << n)) {
				struct sockaddr *sa = (struct sockaddr *)ptr;

				if (sa->sa_family == AF_INET && n == RTAX_DST)
					dst = (struct sockaddr_in *)sa;

				if (sa->sa_family == AF_LINK &&
				    n == RTAX_GATEWAY)
					sdl = (struct sockaddr_dl *)sa;

				ptr += sa->sa_len;
			}
		}

		/* if != gateway */
		if (memcmp(&dst->sin_addr, gw, 4))
			continue;

		if (dst && sdl && sdl->sdl_index == if_index) {
			u_char *mac = (u_char *)LLADDR(sdl);
			memcpy(buf, mac, 6);

			free(tmp);
			return 1;
		}
	}

	free(tmp);
	return 0;
#endif
}

inline static bool
__get_ipv6(const char *if_name, u_char *buf)
{
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) == -1)
		return 0;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6 &&
		    !strcmp(ifa->ifa_name, if_name)) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
							ifa->ifa_addr;

			/* Localhost? Hoc okay.  */
			memcpy(buf, &sin6->sin6_addr, 16);
			return 1;
		}
	}

	return 0;
}

inline static bool
__get_gate4_to_internet(const char *if_name, int if_index, u_char *buf)
{
#ifdef __LINUX
	(void)if_index;
	char line[2048];
	char name[512];
	u_long dst, gw;
	FILE *fp;

	if (!(fp = fopen("/proc/net/route", "r")))
		return 0;

	if (!(fgets(line, sizeof(line), fp))) {
		fclose(fp);
		return 0;
	}
	while ((fgets(line, sizeof(line), fp))) {
		if (sscanf(line, "%15s %lx %lx", name, &dst, &gw) != 3)
			continue;

		/* Via in internet.  */
		if (dst == 0 && !(strcmp(name, if_name))) {
			gw = ntohl((u_int)gw);

			buf[0] = ((u_int)gw >> 24) & 0xff;
			buf[1] = ((u_int)gw >> 16) & 0xff;
			buf[2] = ((u_int)gw >> 8) & 0xff;
			buf[3] = ((u_int)gw & 0xff);

			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return 0;
#else
	(void)if_name;
	char *tmp, *lim, *nxt;
	size_t n;

	int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS,
		RTF_GATEWAY };

	if (sysctl(mib, 6, NULL, &n, NULL, 0) < 0)
		return 0;
	if (!(tmp = calloc(1, n)))
		return 0;
	if (sysctl(mib, 6, tmp, &n, NULL, 0) < 0) {
		free(tmp);
		return 0;
	}

	lim = tmp + n;
	nxt = tmp;

	while (nxt < lim) {
		struct rt_msghdr *rtm = (struct rt_msghdr *)nxt;
		nxt += rtm->rtm_msglen;

		struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
		struct sockaddr_in *dst = NULL;
		struct sockaddr_in *gw = NULL;

		for (n = 0; n < RTAX_MAX; n++) {
			if (rtm->rtm_addrs & (1 << n)) {
				if (n == RTAX_GATEWAY)
					gw = (struct sockaddr_in *)sa;
				if (n == RTAX_DST)
					dst = (struct sockaddr_in *)sa;
				sa = (struct sockaddr *)((char *)sa +
				    sa->sa_len);
			}
		}

		/* Via in internet.  */
		if (dst && dst->sin_addr.s_addr == 0 && gw &&
		    rtm->rtm_index == if_index) {
			memcpy(buf, &gw->sin_addr, 4);
			free(tmp);
			return 1;
		}
	}

	free(tmp);
	return 0;
#endif
}

/* If the interface is found, it returns 1; otherwise, 0.
 * It does not react to the presence of data; let other
 * functions do that.  */
inline static bool
__generic_if_get(const char *if_name, if_data_t *buf)
{
	if (!buf)
		return 0;

	struct ifreq ifr = { 0 };
	int fd = 0;

	/* Not found? */
	if (!if_nametoindex(if_name))
		return 0;

	buf->index = if_nametoindex(if_name);
	snprintf(buf->name, sizeof(buf->name), "%s", if_name);

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", if_name);
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1) {
		if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0)
			buf->flags = ifr.ifr_flags;

		if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
			buf->mtu = ifr.ifr_mtu;
#ifdef __LINUX
		/* We get the sender's MAC address; on Linux
		   via ioctl, on BSD by another system call.  */
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
			memcpy(buf->src, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
#endif
		/* Getting an IPv4 address and everything
		   related to it.  */
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			memcpy(buf->srcip4, (ifr.ifr_addr.sa_data + 2), 4);
			buf->support4 = 1;
		}

		__get_gate4_to_internet(if_name, buf->index, buf->gate4);
		__get_dstmac(if_name, buf->index, buf->gate4, buf->dst);

		close(fd);
	}

	/* For IPv6 address.  */
	if (__get_ipv6(if_name, buf->srcip6))
		buf->support6 = 1;

	/* BSD source MAC address.  */
#ifndef __LINUX
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifap) != -1) {
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr &&
			    ifa->ifa_addr->sa_family == AF_LINK &&
			    strcmp(ifa->ifa_name, if_name) == 0) {
				sdl = (struct sockaddr_dl *)ifa->ifa_addr;
				u_char *mac = (u_char *)LLADDR(sdl);
				memcpy(buf->src, mac, 6);
			}
		}
		freeifaddrs(ifap);
	}
#endif

	return 1;
}

bool
__is_network_sendable(if_data_t *buf)
{
	if (!buf)
		return 0;

#ifdef IFF_UP
	if (!(buf->flags & IFF_UP))
		return 0;
#endif
#ifdef IFF_LOOPBACK
	if (buf->flags & IFF_LOOPBACK)
		return 0;
#endif
#ifdef IFF_POINTOPOINT
	if (buf->flags & IFF_POINTOPOINT)
		return 0;
#endif
#ifdef IFF_SLAVE
	if (buf->flags & IFF_SLAVE)
		return 0;
#endif
#ifdef IFF_NOARP
	if (buf->flags & IFF_NOARP)
		return 0;
#endif

	if (!buf->support6 && !buf->support4)
		return 0;
	if (buf->mtu < 576)
		return 0;

	return 1;
}

bool
if_get(const char *if_name, if_data_t *buf)
{
	if (if_name)
		return __generic_if_get(if_name, buf);

	/* Otherwise, we take the first
	   suitable one.  */
	struct if_nameindex *ifni, *start;
	if (!(ifni = if_nameindex()))
		return 0;
	for (start = ifni; ifni->if_name; ifni++) {
		memset(buf, 0, sizeof(if_data_t));
		if (__generic_if_get(ifni->if_name, buf) &&
		    __is_network_sendable(buf)) {
			if_freenameindex(start);
			return 1;
		}
	}

	if_freenameindex(start);
	return 0;
}

void
if_output(FILE *stream, if_data_t *ifd)
{
	if (ifd && stream) {
		fprintf(stream, "Name:\t%s\n", ifd->name);
		fprintf(stream, "Index:\t%d\n", ifd->index);
		fprintf(stream,
		    "Flags:\t<%s"
#if defined(IFF_LOWER_UP)
		    "%s"
#endif
#if defined(IFF_DORMANT)
		    "%s"
#endif
#if defined(IFF_ECHO)
		    "%s"
#endif
#if defined(IFF_SLAVE)
		    "%s"
#endif
#if defined(IFF_NOTRAILERS)
		    "%s"
#endif
#if defined(IFF_MASTER)
		    "%s"
#endif
#if defined(IFF_PORTSEL)
		    "%s"
#endif
#if defined(IFF_AUTOMEDIA)
		    "%s"
#endif
#if defined(IFF_DYNAMIC)
		    "%s"
#endif
#if defined(IFF_BROADCAST)
		    "%s"
#endif
#if defined(IFF_DEBUG)
		    "%s"
#endif
#if defined(IFF_LOOPBACK)
		    "%s"
#endif
#if defined(IFF_POINTOPOINT)
		    "%s"
#endif
#if defined(IFF_RUNNING)
		    "%s"
#endif
#if defined(IFF_NOARP)
		    "%s"
#endif
#if defined(IFF_PROMISC)
		    "%s"
#endif
#if defined(IFF_ALLMULTI)
		    "%s"
#endif
#if defined(IFF_MULTICAST)
		    "%s"
#endif
		    ">\n",
		    (ifd->flags & IFF_UP) ? "UP;" : ""

#if defined(IFF_BROADCAST)
		    ,
		    (ifd->flags & IFF_BROADCAST) ? "BROADCAST;" : ""
#endif
#if defined(IFF_DEBUG)
		    ,
		    (ifd->flags & IFF_DEBUG) ? "DEBUG;" : ""
#endif
#if defined(IFF_LOOPBACK)
		    ,
		    (ifd->flags & IFF_LOOPBACK) ? "LOOPBACK;" : ""
#endif
#if defined(IFF_POINTOPOINT)
		    ,
		    (ifd->flags & IFF_POINTOPOINT) ? "POINTTOPOINT;" : ""
#endif
#if defined(IFF_RUNNING)
		    ,
		    (ifd->flags & IFF_RUNNING) ? "RUNNING;" : ""
#endif
#if defined(IFF_NOARP)
		    ,
		    (ifd->flags & IFF_NOARP) ? "NOARP;" : ""
#endif
#if defined(IFF_PROMISC)
		    ,
		    (ifd->flags & IFF_PROMISC) ? "PROMISC;" : ""
#endif
#if defined(IFF_ALLMULTI)
		    ,
		    (ifd->flags & IFF_ALLMULTI) ? "ALLMULTI;" : ""
#endif
#if defined(IFF_MULTICAST)
		    ,
		    (ifd->flags & IFF_MULTICAST) ? "MULTICAST;" : ""
#endif
#if defined(IFF_LOWER_UP)
		    ,
		    (ifd->flags & IFF_LOWER_UP) ? "LOWER_UP;" : ""
#endif
#if defined(IFF_DORMANT)
		    ,
		    (ifd->flags & IFF_DORMANT) ? "DORMANT;" : ""
#endif
#if defined(IFF_ECHO)
		    ,
		    (ifd->flags & IFF_ECHO) ? "ECHO;" : ""
#endif
#if defined(IFF_SLAVE)
		    ,
		    (ifd->flags & IFF_SLAVE) ? "SLAVE;" : ""
#endif
#if defined(IFF_NOTRAILERS)
		    ,
		    (ifd->flags & IFF_NOTRAILERS) ? "NOTRAILERS;" : ""
#endif
#if defined(IFF_MASTER)
		    ,
		    (ifd->flags & IFF_MASTER) ? "MASTER;" : ""
#endif
#if defined(IFF_PORTSEL)
		    ,
		    (ifd->flags & IFF_PORTSEL) ? "PORTSEL;" : ""
#endif
#if defined(IFF_AUTOMEDIA)
		    ,
		    (ifd->flags & IFF_AUTOMEDIA) ? "AUTOMEDIA;" : ""
#endif
#if defined(IFF_DYNAMIC)
		    ,
		    (ifd->flags & IFF_DYNAMIC) ? "DYNAMIC;" : ""
#endif
		);
		fprintf(stream, "MTU:\t%d\n", ifd->mtu);

		fprintf(stream, "MAC source:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
		    ifd->src[0], ifd->src[1], ifd->src[2], ifd->src[3],
		    ifd->src[4], ifd->src[5]);

		fprintf(stream, "MAC dest:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
		    ifd->dst[0], ifd->dst[1], ifd->dst[2], ifd->dst[3],
		    ifd->dst[4], ifd->dst[5]);

		fprintf(stream, "IPv4 source:\t%hhu.%hhu.%hhu.%hhu\n",
		    ifd->srcip4[0], ifd->srcip4[1], ifd->srcip4[2],
		    ifd->srcip4[3]);

		char ip6[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, ifd->srcip6, ip6, sizeof(ip6));
		fprintf(stream, "IPv6 source:\t%s\n", ip6);

		fprintf(stream, "IPv4 gateway:\t%hhu.%hhu.%hhu.%hhu\n",
		    ifd->gate4[0], ifd->gate4[1], ifd->gate4[2], ifd->gate4[3]);

		fprintf(stream, "Support IPv4:\t%s\n",
		    (ifd->support4) ? "yes" : "no");
		fprintf(stream, "Support IPv6:\t%s\n",
		    (ifd->support6) ? "yes" : "no");
	}
}
