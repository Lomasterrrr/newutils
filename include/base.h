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

#ifndef __NU_BASE_H
#define __NU_BASE_H

#include "include.h"

/* Noreturn processing.  */
#if defined(__cplusplus)
	#define NORETURN [[noreturn]]
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
	#define NORETURN _Noreturn
#elif defined(__GNUC__)
	#define NORETURN __attribute__((noreturn))
#else
	#define NORETURN /* vacuum */
#endif

/* For struct ether_addr.  */
#ifdef __LINUX	/* et OpenBSD */
	#define __ether_octet ether_addr_octet
#else
	#define __ether_octet octet
#endif

/* Ecce, data link interface (libdnet style).  */
typedef struct dlt_handle dlt_t;	/* See, if.c */
#define DLT_BUFLEN 65535

/* Callback for recv_cb: <frame> <frame len> <arg>.  */
typedef bool (*dlt_rcall_t)(void *, size_t, void *);

/* Open file descriptor; return object *dlt.  */
dlt_t	*dlt_open(const char *if_name);

/* Send frame <ptr> of size <n> based on <dlt>.  */
ssize_t	dlt_send(dlt_t *dlt, void *ptr, size_t n);

/* Recv frame <ptr> of size <n> based on <dlt>.  */
ssize_t	dlt_recv(dlt_t *dlt, void *ptr, size_t n);

/* Recv frame with callback <cb> (with <arg>) and
   timeout <ns> to <buf> with len <n>; <ts_s, ts_e>
   is timestamps.  */
ssize_t dlt_recv_cb(dlt_t *dlt, void *buf, size_t n,
		dlt_rcall_t cb, void *arg, long long ns,
		struct timeval *ts_s, struct timeval *ts_e);

/* Close file descriptor; based on <dlt> */
void	dlt_close(dlt_t *dlt);

/* For interface (device) data.  */
typedef struct __if_data {
	char name[IF_NAMESIZE];
	int index;
	int flags;
	int mtu;

	u_char src[6];
	u_char dst[6];
	u_char srcip4[4];
	u_char srcip6[16];
	u_char gate4[4];

	bool support4;
	bool support6;
} if_data_t;

/* Fill <buf> interface data; if <if_name> = NULL:
  get first good interface */
bool if_get(const char *if_name, if_data_t *buf);
bool __is_network_sendable(if_data_t *buf);

/* Write this structure */
void if_output(FILE *stream, if_data_t *ifd);

/* IPv4 checksum.  */
u_short	in_cksum(u_short *ptr, size_t n);

/* IPv4/IPv6 checksum on pseudo header.  */
u_short	in_pseudocksum(u_char *src, u_char *dst,
		u_char proto, u_short len, void *ptr);

u_short	in6_pseudocksum(u_char *src, u_char *dst,
	 	u_char proto, u_int len, void *ptr);

/* For SCTP.  */
u_int	adler32(u_int adler, u_char *ptr, size_t n);
u_long	crc32c(u_char *ptr, size_t n);

/* Init method, for "random_" interface.  */
void	random_init(u_long (*rand)(void),
		void (*srand)(u_long));
void	random_srand(u_long seed);	/* As srand() func.  */
u_long	random_rand(void);	/* As rand() func.   */

/* Random range <min> and <max>.  */
u_long	random_range(u_long min, u_long max);

u_int	random_u32(void);	/* Random 32 bit.  */
u_short	random_u16(void);	/* Random 16 bit.  */
u_char	random_u8(void);	/* Random 8 bit.  */
u_int	random_ipv4(void);	/* Random IPv4 address.  */

/* Accuracy methods.  */
u_long dev_urandom(void);	/* Use /dev/(u?)random.  */

/* Most speed methods.  */
u_long splitmix64(void);
void splitmix64_seed(u_long seed);
u_long romuduojr(void);	/* Very simple method. */
void romuduojr_seed(u_long seed);

/* Hic err.h not found.  */
#ifdef __LINUX
NORETURN void err(int eval, const char *fmt, ...);
NORETURN void errx(int eval, const char *fmt, ...);
void warn(const char *fmt, ...);
void warnx(const char *fmt, ...);
#endif

/* Convert ASCII string in u_long with range <min>
   and <max>; writting output in <dst>.  */
bool u_numarg(const char *nptr, u_long min,
		u_long max, void *buf, size_t n);

/* Convert ASCII string in long long with range <min>
   and <max>; writting output in <dst>.  */
bool numarg(const char *nptr, long long min,
		long long max, void *buf, size_t n);

/* Output beautiful format.  */
const char *timefmt(long long ns, char *buf, size_t n);

/* Sleep delay in nanoseconds.  */
void sleepns(long long ns);

/* String time to nanoseconds; ex.: 10ms, 5s.  */
long long strtons(const char *ptr);

/* Get mask.  */
void ip_btom(int af, int bits, u_char *buf);

/* Get network addr.  */
void ip_net(u_char *p, u_char *mask, u_char *buf);

/* Get ipv4 from dns.  */
bool resolveipv4(const char *hostname, struct in_addr *buf);

#endif
