#include "../../include/base.h"

/* Core "random_" interface.  */
static u_long (*RAND)(void) = NULL;
static void (*SRAND)(u_long) = NULL;

/* Seeds for methods.  */
static u_long romuduojr_s1, romuduojr_s2;
static u_long splitmix64_s;

void random_init(u_long (*rand)(void),
		void (*srand)(u_long))
{
	RAND = rand;
	SRAND = srand;
}

void random_srand(u_long seed)
{
	if (SRAND)
		SRAND(seed);
}

u_long random_rand(void)
{
	return (RAND) ? RAND() : 0;
}

u_long random_range(u_long min, u_long max)
{
	if (min > max)
		return 0;
	if (min == max)
		return min;
	return min + (random_rand() %
		(max - min + 1UL));
}

u_int random_u32(void)
{
	return (u_int)random_range(0, UINT_MAX);
}

u_short random_u16(void)
{
	return (u_short)random_range(0, USHRT_MAX);
}

u_char random_u8(void)
{
	return (u_char)random_range(0, UCHAR_MAX);
}

u_int random_ipv4(void)
{
	/* Ready to use IPv4 address.  */
	return (u_int)(htonl((
		(u_int)(random_u8()) << 24) |
		((u_int)(random_u8()) << 16) |
		((u_int)(random_u8()) << 8) |
		(u_int)random_u8()));
}

u_long splitmix64(void)
{
	u_long z = (splitmix64_s +=
		 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) *
		 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) *
		 0x94d049bb133111ebULL;
	z = z ^ (z >> 31);
	return (u_long)z;
}

void splitmix64_seed(u_long seed)
{
	splitmix64_s = (u_long)seed;
}

#define ROTL64(d, lrot)	(((d) << (lrot)) |	\
	 ((d) >> (64 - (lrot))))

u_long romuduojr(void)
{
	u_long xp = romuduojr_s1;
	romuduojr_s1 = 15241094284759029579u *
		 romuduojr_s2;
	romuduojr_s2 = romuduojr_s2 - xp;
	romuduojr_s2 = ROTL64(romuduojr_s2, 27);
	return xp;
}

void romuduojr_seed(u_long seed)
{
	romuduojr_s1 = seed ^
		0xA5A5A5A5A5A5A5A5UL;
	romuduojr_s2 = seed *
		0x5851F42D4C957F2DUL+1;
}

u_long dev_urandom(void)
{
	ssize_t n;
	u_long r;

	n = getrandom(&r, sizeof(r),
		GRND_NONBLOCK | GRND_RANDOM);

	return (n == -1 || n != sizeof(r)) ? 0 : r;
}
