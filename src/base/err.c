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

#ifdef __LINUX
NORETURN void
err(int eval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (fmt) {
		fprintf(stderr, "err: ");
		vfprintf(stderr, fmt, ap);
	}
	va_end(ap);
	fprintf(stderr, " (%s)\n", strerror(errno));
	exit(eval);
}

NORETURN void
errx(int eval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (fmt) {
		fprintf(stderr, "err: ");
		vfprintf(stderr, fmt, ap);
	}
	fputc(0x0a, stderr);
	va_end(ap);
	exit(eval);
}

void
warn(const char *fmt, ...)
{
	int save = errno;
	va_list ap;

	va_start(ap, fmt);
	if (fmt) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, ": ");
	}
	va_end(ap);
	fprintf(stderr, "%s\n", strerror(errno));

	errno = save;
}

void
warnx(const char *fmt, ...)
{
	int save = errno;
	va_list ap;

	va_start(ap, fmt);
	if (fmt)
		vfprintf(stderr, fmt, ap);
	fputc(0x0a, stderr);
	va_end(ap);

	errno = save;
}
#endif
