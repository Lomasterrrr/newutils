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

/* CRC-32C (Castagnoli). Public domain.
 * From libdnet (ip-util.c and crc32ct.h) */

u_long crc_c[256] = {
	0x00000000L,
	0xF26B8303L,
	0xE13B70F7L,
	0x1350F3F4L,
	0xC79A971FL,
	0x35F1141CL,
	0x26A1E7E8L,
	0xD4CA64EBL,
	0x8AD958CFL,
	0x78B2DBCCL,
	0x6BE22838L,
	0x9989AB3BL,
	0x4D43CFD0L,
	0xBF284CD3L,
	0xAC78BF27L,
	0x5E133C24L,
	0x105EC76FL,
	0xE235446CL,
	0xF165B798L,
	0x030E349BL,
	0xD7C45070L,
	0x25AFD373L,
	0x36FF2087L,
	0xC494A384L,
	0x9A879FA0L,
	0x68EC1CA3L,
	0x7BBCEF57L,
	0x89D76C54L,
	0x5D1D08BFL,
	0xAF768BBCL,
	0xBC267848L,
	0x4E4DFB4BL,
	0x20BD8EDEL,
	0xD2D60DDDL,
	0xC186FE29L,
	0x33ED7D2AL,
	0xE72719C1L,
	0x154C9AC2L,
	0x061C6936L,
	0xF477EA35L,
	0xAA64D611L,
	0x580F5512L,
	0x4B5FA6E6L,
	0xB93425E5L,
	0x6DFE410EL,
	0x9F95C20DL,
	0x8CC531F9L,
	0x7EAEB2FAL,
	0x30E349B1L,
	0xC288CAB2L,
	0xD1D83946L,
	0x23B3BA45L,
	0xF779DEAEL,
	0x05125DADL,
	0x1642AE59L,
	0xE4292D5AL,
	0xBA3A117EL,
	0x4851927DL,
	0x5B016189L,
	0xA96AE28AL,
	0x7DA08661L,
	0x8FCB0562L,
	0x9C9BF696L,
	0x6EF07595L,
	0x417B1DBCL,
	0xB3109EBFL,
	0xA0406D4BL,
	0x522BEE48L,
	0x86E18AA3L,
	0x748A09A0L,
	0x67DAFA54L,
	0x95B17957L,
	0xCBA24573L,
	0x39C9C670L,
	0x2A993584L,
	0xD8F2B687L,
	0x0C38D26CL,
	0xFE53516FL,
	0xED03A29BL,
	0x1F682198L,
	0x5125DAD3L,
	0xA34E59D0L,
	0xB01EAA24L,
	0x42752927L,
	0x96BF4DCCL,
	0x64D4CECFL,
	0x77843D3BL,
	0x85EFBE38L,
	0xDBFC821CL,
	0x2997011FL,
	0x3AC7F2EBL,
	0xC8AC71E8L,
	0x1C661503L,
	0xEE0D9600L,
	0xFD5D65F4L,
	0x0F36E6F7L,
	0x61C69362L,
	0x93AD1061L,
	0x80FDE395L,
	0x72966096L,
	0xA65C047DL,
	0x5437877EL,
	0x4767748AL,
	0xB50CF789L,
	0xEB1FCBADL,
	0x197448AEL,
	0x0A24BB5AL,
	0xF84F3859L,
	0x2C855CB2L,
	0xDEEEDFB1L,
	0xCDBE2C45L,
	0x3FD5AF46L,
	0x7198540DL,
	0x83F3D70EL,
	0x90A324FAL,
	0x62C8A7F9L,
	0xB602C312L,
	0x44694011L,
	0x5739B3E5L,
	0xA55230E6L,
	0xFB410CC2L,
	0x092A8FC1L,
	0x1A7A7C35L,
	0xE811FF36L,
	0x3CDB9BDDL,
	0xCEB018DEL,
	0xDDE0EB2AL,
	0x2F8B6829L,
	0x82F63B78L,
	0x709DB87BL,
	0x63CD4B8FL,
	0x91A6C88CL,
	0x456CAC67L,
	0xB7072F64L,
	0xA457DC90L,
	0x563C5F93L,
	0x082F63B7L,
	0xFA44E0B4L,
	0xE9141340L,
	0x1B7F9043L,
	0xCFB5F4A8L,
	0x3DDE77ABL,
	0x2E8E845FL,
	0xDCE5075CL,
	0x92A8FC17L,
	0x60C37F14L,
	0x73938CE0L,
	0x81F80FE3L,
	0x55326B08L,
	0xA759E80BL,
	0xB4091BFFL,
	0x466298FCL,
	0x1871A4D8L,
	0xEA1A27DBL,
	0xF94AD42FL,
	0x0B21572CL,
	0xDFEB33C7L,
	0x2D80B0C4L,
	0x3ED04330L,
	0xCCBBC033L,
	0xA24BB5A6L,
	0x502036A5L,
	0x4370C551L,
	0xB11B4652L,
	0x65D122B9L,
	0x97BAA1BAL,
	0x84EA524EL,
	0x7681D14DL,
	0x2892ED69L,
	0xDAF96E6AL,
	0xC9A99D9EL,
	0x3BC21E9DL,
	0xEF087A76L,
	0x1D63F975L,
	0x0E330A81L,
	0xFC588982L,
	0xB21572C9L,
	0x407EF1CAL,
	0x532E023EL,
	0xA145813DL,
	0x758FE5D6L,
	0x87E466D5L,
	0x94B49521L,
	0x66DF1622L,
	0x38CC2A06L,
	0xCAA7A905L,
	0xD9F75AF1L,
	0x2B9CD9F2L,
	0xFF56BD19L,
	0x0D3D3E1AL,
	0x1E6DCDEEL,
	0xEC064EEDL,
	0xC38D26C4L,
	0x31E6A5C7L,
	0x22B65633L,
	0xD0DDD530L,
	0x0417B1DBL,
	0xF67C32D8L,
	0xE52CC12CL,
	0x1747422FL,
	0x49547E0BL,
	0xBB3FFD08L,
	0xA86F0EFCL,
	0x5A048DFFL,
	0x8ECEE914L,
	0x7CA56A17L,
	0x6FF599E3L,
	0x9D9E1AE0L,
	0xD3D3E1ABL,
	0x21B862A8L,
	0x32E8915CL,
	0xC083125FL,
	0x144976B4L,
	0xE622F5B7L,
	0xF5720643L,
	0x07198540L,
	0x590AB964L,
	0xAB613A67L,
	0xB831C993L,
	0x4A5A4A90L,
	0x9E902E7BL,
	0x6CFBAD78L,
	0x7FAB5E8CL,
	0x8DC0DD8FL,
	0xE330A81AL,
	0x115B2B19L,
	0x020BD8EDL,
	0xF0605BEEL,
	0x24AA3F05L,
	0xD6C1BC06L,
	0xC5914FF2L,
	0x37FACCF1L,
	0x69E9F0D5L,
	0x9B8273D6L,
	0x88D28022L,
	0x7AB90321L,
	0xAE7367CAL,
	0x5C18E4C9L,
	0x4F48173DL,
	0xBD23943EL,
	0xF36E6F75L,
	0x0105EC76L,
	0x12551F82L,
	0xE03E9C81L,
	0x34F4F86AL,
	0xC69F7B69L,
	0xD5CF889DL,
	0x27A40B9EL,
	0x79B737BAL,
	0x8BDCB4B9L,
	0x988C474DL,
	0x6AE7C44EL,
	0xBE2DA0A5L,
	0x4C4623A6L,
	0x5F16D052L,
	0xAD7D5351L,
};

#define CRC32C(c, d) (c = (c >> 8) ^ crc_c[(c ^ (d)) & 0xFF])

u_long
crc32c(u_char *ptr, size_t n)
{
	u_long t, b0, b1, b2, b3;
	u_long crc32 = ~0L;

	for (size_t i = 0; i < n; i++)
		CRC32C(crc32, ptr[i]);

	t = ~crc32;

	b0 = t & 0xff;
	b1 = (t >> 8) & 0xff;
	b2 = (t >> 16) & 0xff;
	b3 = (t >> 24) & 0xff;

	crc32 = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3);

	return crc32;
}

/* adler32.c -- compute the Adler-32 checksum of a data stream
 * Copyright (C) 1995-2011, 2016 Mark Adler */

#define BASE 65521U
#define NMAX 5552

#define DO1(ptr, i)                \
	{                          \
		adler += (ptr)[i]; \
		sum2 += adler;     \
	}
#define DO2(ptr, i)  \
	DO1(ptr, i); \
	DO1(ptr, i + 1);
#define DO4(ptr, i)  \
	DO2(ptr, i); \
	DO2(ptr, i + 2);
#define DO8(ptr, i)  \
	DO4(ptr, i); \
	DO4(ptr, i + 4);
#define DO16(ptr)    \
	DO8(ptr, 0); \
	DO8(ptr, 8);

#if defined(__DIVIDE)
#define MOD(a)	 a %= BASE
#define MOD28(a) a %= BASE
#define MOD63(a) a %= BASE
#else
#define CHOP(a)                              \
	do {                                 \
		unsigned long tmp = a >> 16; \
		a &= 0xffffUL;               \
		a += (tmp << 4) - tmp;       \
	} while (0)

#define MOD28(a)                   \
	do {                       \
		CHOP(a);           \
		if (a >= BASE)     \
			a -= BASE; \
	} while (0)
#define MOD(a)            \
	do {              \
		CHOP(a);  \
		MOD28(a); \
	} while (0)
#define MOD63(a)                                    \
	do {                                        \
		off64_t tmp = a >> 32;              \
		a &= 0xffffffffL;                   \
		a += (tmp << 8) - (tmp << 5) + tmp; \
		tmp = a >> 16;                      \
		a &= 0xffffL;                       \
		a += (tmp << 4) - tmp;              \
		tmp = a >> 16;                      \
		a &= 0xffffL;                       \
		a += (tmp << 4) - tmp;              \
		if (a >= BASE)                      \
			a -= BASE;                  \
	} while (0)
#endif

u_int
adler32(u_int adler, u_char *ptr, size_t n)
{
	u_long sum2;
	u_int i;

	sum2 = (adler >> 16) & 0xffff;
	adler &= 0xffff;

	if (n == 1) {
		adler += ptr[0];
		if (adler >= BASE)
			adler -= BASE;
		sum2 += adler;
		if (sum2 >= BASE)
			sum2 -= BASE;
		goto out;
	}

	if (ptr == 0)
		return 1L;

	if (n < 16) {
		while (n--) {
			adler += *ptr++;
			sum2 += adler;
		}
		if (adler >= BASE)
			adler -= BASE;
		MOD28(sum2);
		goto out;
	}

	while (n >= NMAX) {
		n -= NMAX;
		i = NMAX / 16;

		do {
			DO16(ptr);
			ptr += 16;
		} while (--i);

		MOD(adler);
		MOD(sum2);
	}

	if (n) {
		while (n >= 16) {
			n -= 16;
			DO16(ptr);
			ptr += 16;
		}

		while (n--) {
			adler += *ptr++;
			sum2 += adler;
		}

		MOD(adler);
		MOD(sum2);
	}

out:
	return (adler | ((u_int)sum2 << 16));
}

/* Changed libdnet + nmap.  */

#define in_cksum_carry(x) \
	(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

inline static int
in_cksum_add(void *ptr, size_t n, int cksum)
{
	u_short *p = (u_short *)ptr;
	size_t i = n / 2;

	while (i--)
		cksum += *p++;

	return (n & 1) ? (cksum += htons((u_short)(*(u_char *)p << 8))) : cksum;
}

u_short
in_cksum(u_short *ptr, size_t n)
{
	int sum = in_cksum_add(ptr, n, 0);
	return (in_cksum_carry(sum));
}

u_short
in_pseudocksum(u_char *src, u_char *dst, u_char proto, u_short len, void *ptr)
{
	u_char hdr[12];
	int sum;

	memcpy(hdr, src, 4);
	memcpy(hdr + 4, dst, 4);
	hdr[8] = 0, hdr[9] = proto;
	*(u_short *)(hdr + 10) = htons(len);

	sum = in_cksum_add(hdr, 12, 0);
	sum = in_cksum_add(ptr, len, sum);
	sum = in_cksum_carry(sum);

	if (proto == 17 && sum == 0)
		sum = 0xffff;

	return (u_short)sum;
}

u_short
in6_pseudocksum(u_char *src, u_char *dst, u_char proto, u_int len, void *ptr)
{
	u_char hdr[40];
	int sum;

	memcpy(hdr, src, 16);
	memcpy(hdr + 16, dst, 16);
	*(u_int *)(hdr + 32) = htonl(len);
	memset(hdr + 36, 0, 3);
	hdr[39] = proto;

	sum = in_cksum_add(hdr, 40, 0);
	sum = in_cksum_add(ptr, len, sum);
	sum = in_cksum_carry(sum);

	if (proto == 17 && sum == 0)
		sum = 0xffff;

	return (u_short)sum;
}
