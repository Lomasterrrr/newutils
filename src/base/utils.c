#include "../../include/base.h"

bool u_numarg(const char *nptr, u_long min,
		u_long max, void *buf, size_t n)
{
	char *endptr;
	u_long val;

	if (!nptr || !buf || !n)
		return 0;
	while (isspace((u_char)*nptr))
		nptr++;
	if (*nptr == '-')
		return 0;

	errno = 0;
	val = strtoull(nptr, &endptr, 10);
	if (errno != 0) 
		return 0;
	if (endptr == nptr)
		return 0;
	while (isspace((u_char)*endptr))
		endptr++;
	if (*endptr)
		return 0;
	if (val < min || val > max)
		return 0;

	switch (n) {
		case sizeof(u_long):
			*(u_long *)buf = (u_long)val;
			break;
		case sizeof(u_int):
			*(u_int *)buf = (u_int)val;
			break;
		case sizeof(u_short):
			*(u_short *)buf = (u_short)val;
			break;
		case sizeof(u_char):
			*(u_char *)buf = (u_char)val;
			break;
		default:
			return 0;
	}

	return 1;
}

bool numarg(const char *nptr, long long min,
		long long max, void *buf, size_t n)
{
	long long val;
	char *endptr;

	if (!nptr || !buf || !n)
		return 0;
	while (isspace((u_char)*nptr))
		nptr++;

	errno = 0;
	val = strtoll(nptr, &endptr, 10);
	if (errno != 0)
		return 0;
	if (endptr == nptr)
		return 0;
	while (isspace((u_char)*endptr))
		endptr++;
	if (*endptr)
		return 0;
	if (val < min || val > max)
		return 0;

	switch (n) {
		case sizeof(long long):
			*(long long *)buf =
				(long long)val;
			break;
		case sizeof(int):
			*(int *)buf = (int)val;
			break;
		case sizeof(short):
			*(short *)buf = (short)val;
			break;
		case sizeof(char):
			*(char *)buf = (char)val;
			break;
		default:
			return 0;
	}

	return 1;
}

const char *timefmt(long long ns, char *buf, size_t n)
{
	const char *prefixes[] = {"ns", "μs", "ms", "sec",
				 "min", "h", "d"};
	double val = (double)ns;
	int prfx = 0;

	if (val >= 86400000000000.0) {
		prfx = 6;
		val /= 86400000000000.0;
	} else if (val >= 3600000000000.0) {
		prfx = 5;
		val /= 3600000000000.0;
	} else if (val >= 60000000000.0) {
		prfx = 4;
		val /= 60000000000.0;
	} else if (val >= 1000000000.0) {
		prfx = 3;
		val /= 1000000000.0;
	} else if (val >= 1000000.0) {
		prfx = 2;
		val /= 1000000.0;
	} else if (val >= 1000.0) {
		prfx = 1;
		val /= 1000.0;
	}

	snprintf(buf, n, "%.2f %s", val, prefixes[prfx]);
	return buf;
}

void sleepns(long long ns)
{
	struct timespec	rem, req =
		{.tv_sec = (ns / 1000000000),
		.tv_nsec = (ns % 1000000000)};
	nanosleep(&req, &rem);
}

long long strtons(const char *ptr)
{
	char unit[3] = {0};
	long long val;
	char *endptr;
	size_t n;

	if (!ptr)
		return -1;

	errno = 0;
	val = strtoll(ptr, &endptr, 10);
	if (!*endptr)
		return val;
	if (endptr == ptr)
		return -1;

	n = strlen(endptr);
	if (n > 2)
		return -1;

	strncpy(unit, endptr, 2);
	if (!strcmp(unit, "ms"))
		val *= 1000000LL;
	else if (!strcmp(unit, "s"))
		val *= 1000000000LL;
	else if (!strcmp(unit, "m"))
		val *= 60000000000LL;
	else if (!strcmp(unit, "h"))
		val *= 3600000000000LL;
	else
		val = -1;

	return val;
}

void ip_btom(int af, int bits, u_char *buf)
{
	u_int tmp;
	int n, h;

	switch (af) {
		case AF_INET:
			tmp = (bits) ?
				htonl(0xffffffff <<
				(32 - bits)) : 0;
			memcpy(buf, &tmp, 4);
			break;
		case AF_INET6:
			n = bits / 8;
			h = bits % 8;

			if (n > 0)
				memset(buf, 0xff, (u_long)n);
			if (n < 16) {
				buf[n] = (u_char)(h) ?
					(u_char)(0xff <<
					(8 - h)) : 0x00;
				if (n + 1 < 16)
					memset(buf + n + 1,
						0x00, (u_long)
						(16 - n - 1));
			}
			break;
	}
}

void ip_net(u_char *p, u_char *mask, u_char *buf)
{
	int i, j;
	for (i = 0; i <= 15; i++)
		for (j = 7; j >= 0; j--)
			if ((mask[i] & (1 << j)))
				buf[i] |= (p[i] & (1 << j));
}

bool resolveipv4(const char *hostname, struct in_addr *buf)
{
	struct addrinfo hints = {0}, *res;

	hints.ai_family = AF_INET;
	if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
		memcpy(buf, &((struct sockaddr_in *)
			res->ai_addr)->sin_addr, 4);
		return 1;
	}
	return 0;
	
}
