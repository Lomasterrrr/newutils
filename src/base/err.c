#include "../../include/base.h"

#ifdef __LINUX
NORETURN void err(int eval, const char *fmt, ...)
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

NORETURN void errx(int eval, const char *fmt, ...)
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


void warn(const char *fmt, ...)
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


void warnx(const char *fmt, ...)
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
