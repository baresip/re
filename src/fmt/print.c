/**
 * @file fmt/print.c Formatted printing
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <math.h>
#include <re_types.h>
#include <re_sa.h>
#include <re_fmt.h>
#include <re_mem.h>
#ifdef _MSC_VER
#include <float.h>
#ifndef isinf
#define isinf(d) (!_finite(d))
#endif
#ifndef isnan
#define isnan(d) _isnan(d)
#endif
#endif
#ifdef SOLARIS
#include <ieeefp.h>
#undef isinf
#define isinf(a) (fpclass((a)) == FP_NINF || fpclass((a)) == FP_PINF)
#undef isnan
#define isnan(a) isnand((a))
#endif

#define DEBUG_MODULE "print"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

enum length_modifier {
	LENMOD_NONE      = 0,
	LENMOD_LONG      = 1,
	LENMOD_LONG_LONG = 2,
	LENMOD_INT64     = 3,
	LENMOD_SIZE      = 42,
};

enum {
	DEC_SIZE = 42,
	NUM_SIZE = 64
};

static const char prfx_neg[]  = "-";
static const char prfx_hex[]  = "0x";
static const char str_nil[]  = "(nil)";


static int write_padded(const char *p, size_t sz, size_t pad, char pch,
			bool plr, const char *prfx, re_vprintf_h *vph,
			void *arg)
{
	const size_t prfx_len = str_len(prfx);
	int err = 0;

	pad -= MIN(pad, prfx_len);

	if (prfx && pch == '0')
		err |= vph(prfx, prfx_len, arg);

	while (!plr && (pad-- > sz))
		err |= vph(&pch, 1, arg);

	if (prfx && pch != '0')
		err |= vph(prfx, prfx_len, arg);

	if (p && sz)
		err |= vph(p, sz, arg);

	while (plr && pad-- > sz)
		err |= vph(&pch, 1, arg);

	return err;
}


static uint32_t local_itoa(char *buf, uint64_t n, uint8_t base, bool uc)
{
	char c, *p = buf + (NUM_SIZE - 1);
	uint32_t len = 1;
	const char a = uc ? 'A' : 'a';

	*p = '\0';
	do {
		const uint64_t dv  = n / base;
		const uint64_t mul = dv * base;

		c = (char)(n - mul);

		if (c < 10)
			*--p = '0' + c;
		else
			*--p = a + (c - 10);

		n = dv;
		++len;

	} while (n != 0);

	memmove(buf, p, len);

	return len - 1;
}


static size_t local_ftoa(char *buf, double n, size_t dp)
{
	char *p = buf;
	long long a = (long long)n;
	double b = n - (double)a;

	b = (b < 0) ? -b : b;

	/* integral part */
	p += local_itoa(p, (a < 0) ? -a : a, 10, false);

	*p++ = '.';

	/* decimal digits */
	while (dp--) {
		char v;

		b *= 10;
		v  = (char)b;
		b -= v;

		*p++ = '0' + (char)v;
	}

	*p = '\0';

	return p - buf;
}


static int vhprintf(const char *fmt, va_list ap, re_vprintf_h *vph, void *arg,
		    bool safe)
{
	uint8_t base, *bptr;
	char pch = 0, ch, num[NUM_SIZE], addr[64], msg[256];
	enum length_modifier lenmod = LENMOD_NONE;
	struct re_printf pf;
	bool fm = false, plr = false;
	const struct pl *pl;
	size_t pad = 0, fpad = -1, len, i;
	const char *str, *p = fmt, *p0 = fmt;
	const struct sa *sa;
	re_printf_h *ph;
	void *ph_arg;
	va_list *apl;
	int err = 0;
	void *ptr;
	uint64_t n;
	int64_t sn;
	bool uc = false;
	double dbl;
	int errnum;

	if (!fmt || !vph)
		return EINVAL;

	pf.vph = vph;
	pf.arg = arg;

	for (;*p && !err; p++) {
		if (!fm) {
			if (*p != '%')
				continue;

			pch = ' ';
			plr = false;
			pad = 0;
			fpad = -1;
			lenmod = LENMOD_NONE;
			uc = false;

			if (p > p0)
				err |= vph(p0, p - p0, arg);

			fm = true;
			continue;
		}

		fm = false;
		base = 10;

		switch (*p) {

		case '-':
			plr = true;
			fm  = true;
			break;

		case '.':
			fpad = pad;
			pad = 0;
			fm = true;
			break;

		case '%':
			ch = '%';

			err |= vph(&ch, 1, arg);
			break;

		case 'b':
			RE_VA_ARG(ap, str, const char *, safe);
			RE_VA_ARG(ap, len, size_t, safe);

			err |= write_padded(str, str ? len : 0, pad, ' ',
					    plr, NULL, vph, arg);
			break;

		case 'c':
			RE_VA_ARG(ap, ch, int, safe);

			err |= write_padded(&ch, 1, pad, ' ', plr, NULL,
					    vph, arg);
			break;

		case 'd':
		case 'i':
			switch (lenmod) {

			case LENMOD_INT64:
				RE_VA_ARG(ap, sn, int64_t, safe);
				break;

			case LENMOD_SIZE:
				RE_VA_ARG(ap, sn, ssize_t, safe);
				break;

			default:
			case LENMOD_LONG_LONG:
				RE_VA_ARG(ap, sn, signed long long, safe);
				break;

			case LENMOD_LONG:
				RE_VA_ARG(ap, sn, signed long, safe);
				break;

			case LENMOD_NONE:
				RE_VA_ARG(ap, sn, signed, safe);
				break;
			}

			len = local_itoa(num, (sn < 0) ? -sn : sn, base,
					 false);

			err |= write_padded(num, len, pad,
					    plr ? ' ' : pch, plr,
					    (sn < 0) ? prfx_neg : NULL,
					    vph, arg);
			break;

		case 'f':
		case 'F':
			RE_VA_ARG(ap, dbl, double, safe);

			if (fpad == (size_t)-1) {
				fpad = pad;
				pad  = 0;
			}

			if (isinf(dbl)) {
				err |= write_padded("inf", 3, fpad,
						    ' ', plr, NULL, vph, arg);
			}
			else if (isnan(dbl)) {
				err |= write_padded("nan", 3, fpad,
						    ' ', plr, NULL, vph, arg);
			}
			else {
				len = local_ftoa(num, dbl,
						 pad ? min(pad, DEC_SIZE) : 6);

				err |= write_padded(num, len, fpad,
						    plr ? ' ' : pch, plr,
						    (dbl<0) ? prfx_neg : NULL,
						    vph, arg);
			}
			break;

		case 'H':
			RE_VA_ARG(ap, ph, re_printf_h *, safe);
			RE_VA_ARG(ap, ph_arg, void *, safe);

			if (ph)
				err |= ph(&pf, ph_arg);
			break;

		case 'l':
			++lenmod;
			fm = true;
			break;

		case 'm':
			RE_VA_ARG(ap, errnum, int, safe);
			str = str_error(errnum, msg, sizeof(msg));
			err |= write_padded(str, str_len(str), pad,
					    ' ', plr, NULL, vph, arg);
			break;

		case 'p':
			RE_VA_ARG(ap, ptr, void *, safe);

			if (ptr) {
				len = local_itoa(num, (size_t)ptr,
						 16, false);
				err |= write_padded(num, len, pad,
						    plr ? ' ' : pch, plr,
						    prfx_hex, vph, arg);
			}
			else {
				err |= write_padded(str_nil,
						    sizeof(str_nil) - 1,
						    pad, ' ', plr, NULL,
						    vph, arg);
			}
			break;

		case 'r':
			RE_VA_ARG(ap, pl, const struct pl *, safe);

			err |= write_padded(pl ? pl->p : NULL,
					    (pl && pl->p) ? pl->l : 0,
					    pad, ' ', plr, NULL, vph, arg);
			break;

		case 's':
			RE_VA_ARG(ap, str, char *, safe);
			err |= write_padded(str, str_len(str), pad,
					    ' ', plr, NULL, vph, arg);
			break;

		case 'X':
			uc = true;
			/*@fallthrough@*/
		case 'x':
			base = 16;
			/*@fallthrough@*/
		case 'u':
			switch (lenmod) {

			case LENMOD_INT64:
				RE_VA_ARG(ap, n, uint64_t, safe);
				break;

			case LENMOD_SIZE:
				RE_VA_ARG(ap, n, size_t, safe);
				break;

			default:
			case LENMOD_LONG_LONG:
				RE_VA_ARG(ap, n, unsigned long long, safe);
				break;

			case LENMOD_LONG:
				RE_VA_ARG(ap, n, unsigned long, safe);
				break;

			case LENMOD_NONE:
				RE_VA_ARG(ap, n, unsigned, safe);
				break;
			}

			len = local_itoa(num, n, base, uc);

			err |= write_padded(num, len, pad,
					    plr ? ' ' : pch, plr, NULL,
					    vph, arg);
			break;

		case 'v':
			RE_VA_ARG(ap, str, char *, safe);
			RE_VA_ARG(ap, apl, void *, safe);

			if (!str || !apl)
				break;

			err |= re_vhprintf(str, *apl, vph, arg);
			break;

		case 'W':
			uc = true;
			/*@fallthrough@*/
		case 'w':
			RE_VA_ARG(ap, bptr, void *, safe);
			RE_VA_ARG(ap, len, size_t, safe);

			len = bptr ? len : 0;
			pch = plr ? ' ' : pch;

			while (!plr && pad-- > (len * 2))
				err |= vph(&pch, 1, arg);

			for (i=0; i<len; i++) {
				const uint8_t v = *bptr++;
				uint32_t l = local_itoa(num, v, 16, uc);
				err |= write_padded(num, l, 2, '0',
						    false, NULL, vph, arg);
			}

			while (plr && pad-- > (len * 2))
				err |= vph(&pch, 1, arg);

			break;

		case 'z':
			lenmod = LENMOD_SIZE;
			fm = true;
			break;

		case 'L':
			lenmod = LENMOD_INT64;
			fm = true;
			break;

		case 'j':
			RE_VA_ARG(ap, sa, struct sa *, safe);
			if (!sa)
				break;
			if (sa_ntop(sa, addr, sizeof(addr))) {
				err |= write_padded("?", 1, pad, ' ',
						    plr, NULL, vph, arg);
				break;
			}
			err |= write_padded(addr, strlen(addr), pad, ' ',
					    plr, NULL, vph, arg);
			break;


		case 'J':
			RE_VA_ARG(ap, sa, struct sa *, safe);
			if (!sa)
				break;
			if (sa_ntop(sa, addr, sizeof(addr))) {
				err |= write_padded("?", 1, pad, ' ',
						    plr, NULL, vph, arg);
				break;
			}

			if (AF_INET6 == sa_af(sa)) {
				ch = '[';
				err |= vph(&ch, 1, arg);
			}
			err |= write_padded(addr, strlen(addr), pad, ' ',
					    plr, NULL, vph, arg);
			if (AF_INET6 == sa_af(sa)) {
				ch = ']';
				err |= vph(&ch, 1, arg);
			}

			ch = ':';
			err |= vph(&ch, 1, arg);
			len = local_itoa(num, sa_port(sa), 10, false);
			err |= write_padded(num, len, pad,
					    plr ? ' ' : pch, plr, NULL,
					    vph, arg);

			break;

		default:
			if (('0' <= *p) && (*p <= '9')) {
				if (!pad && ('0' == *p)) {
					pch = '0';
				}
				else {
					pad *= 10;
					pad += *p - '0';
				}
				fm = true;
				break;
			}

			ch = '?';

			err |= vph(&ch, 1, arg);
			break;
		}

		if (!fm)
			p0 = p + 1;
	}

	if (!fm && p > p0)
		err |= vph(p0, p - p0, arg);

out:
#ifndef RELEASE
	if (err == ENODATA) {
		re_fprintf(stderr, "Format: \"%b<-- NO ARG\n",
			   fmt, p - fmt + 1);
		re_assert(0 && "RE_VA_ARG: no more arguments");
	}
	if (err == EOVERFLOW) {
		re_fprintf(stderr, "Format: \"%b<-- SIZE ERROR\n", fmt,
			      p - fmt + 1);
		re_assert(0 && "RE_VA_ARG: arg is not compatible");
	}
#endif
	return err;
}


/**
 * Print a formatted string
 *
 * @param fmt Formatted string
 * @param ap  Variable argument
 * @param vph Print handler
 * @param arg Handler argument
 *
 * @return 0 if success, otherwise errorcode
 *
 * Extensions:
 *
 * <pre>
 *   %b  (char *, size_t)        Buffer string with pointer and length
 *   %r  (struct pl *)           Pointer-length object
 *   %w  (uint8_t *, size_t)     Binary buffer to hexadecimal format
 *   %j  (struct sa *)           Socket address - address part only
 *   %J  (struct sa *)           Socket address and port - like 1.2.3.4:1234
 *   %H  (re_printf_h *, void *) Print handler with argument
 *   %v  (char *fmt, va_list *)  Variable argument list
 *   %m  (int)                   Describe an error code
 *   %L  (uint64_t/int64_t)      64-bit length modifier for %i, %d, %x and %u
 * </pre>
 *
 * Reserved for the future:
 *
 *   %k
 *   %y
 *
 */
int re_vhprintf(const char *fmt, va_list ap, re_vprintf_h *vph, void *arg)
{
	return vhprintf(fmt, ap, vph, arg, false);
}


/**
 * Print a safe formatted string
 *
 * @param fmt Formatted string
 * @param ap  Variable argument
 * @param vph Print handler
 * @param arg Handler argument
 *
 * @return 0 if success, otherwise errorcode
 *
 * Extensions:
 *
 * <pre>
 *   %b  (char *, size_t)        Buffer string with pointer and length
 *   %r  (struct pl *)           Pointer-length object
 *   %w  (uint8_t *, size_t)     Binary buffer to hexadecimal format
 *   %j  (struct sa *)           Socket address - address part only
 *   %J  (struct sa *)           Socket address and port - like 1.2.3.4:1234
 *   %H  (re_printf_h *, void *) Print handler with argument
 *   %v  (char *fmt, va_list *)  Variable argument list
 *   %m  (int)                   Describe an error code
 * </pre>
 *
 * Reserved for the future:
 *
 *   %k
 *   %y
 *
 */
int re_vhprintf_s(const char *fmt, va_list ap, re_vprintf_h *vph, void *arg)
{
	return vhprintf(fmt, ap, vph, arg, true);
}


static int print_handler(const char *p, size_t size, void *arg)
{
	struct pl *pl = arg;

	if (size > pl->l)
		return ENOMEM;

	memcpy((void *)pl->p, p, size);

	pl_advance(pl, size);

	return 0;
}


struct dyn_print {
	char *str;
	char *p;
	size_t l;
	size_t size;
};


static int print_handler_dyn(const char *p, size_t size, void *arg)
{
	struct dyn_print *dp = arg;

	if (size > dp->l - 1) {
		const size_t new_size = MAX(dp->size + size, dp->size * 2);
		char *str = mem_realloc(dp->str, new_size);
		if (!str)
			return ENOMEM;

		dp->str = str;
		dp->l += new_size - dp->size;
		dp->p = dp->str + new_size - dp->l;
		dp->size = new_size;
	}

	memcpy(dp->p, p, size);

	dp->p += size;
	dp->l -= size;

	return 0;
}


struct strm_print {
	FILE *f;
	size_t n;
};

static int print_handler_stream(const char *p, size_t size, void *arg)
{
	struct strm_print *sp = arg;

	if (1 != fwrite(p, size, 1, sp->f))
		return ENOMEM;

	sp->n += size;

	return 0;
}


/**
 * Print a formatted string to a file stream, using va_list
 *
 * @param stream File stream for the output
 * @param fmt    Formatted string
 * @param ap     Variable-arguments list
 *
 * @return The number of characters printed, or -1 if error
 */
int re_vfprintf(FILE *stream, const char *fmt, va_list ap)
{
	struct strm_print sp;

	if (!stream)
		return -1;

	sp.f = stream;
	sp.n = 0;

	if (0 != vhprintf(fmt, ap, print_handler_stream, &sp, false))
		return -1;

	return (int)sp.n;
}


/**
 * Print a safe formatted string to a file stream, using va_list
 *
 * @param stream File stream for the output
 * @param fmt    Formatted string
 * @param ap     Variable-arguments list
 *
 * @return The number of characters printed, or -1 if error
 */
int re_vfprintf_s(FILE *stream, const char *fmt, va_list ap)
{
	struct strm_print sp;

	if (!stream)
		return -1;

	sp.f = stream;
	sp.n = 0;

	if (0 != vhprintf(fmt, ap, print_handler_stream, &sp, true))
		return -1;

	return (int)sp.n;
}


/**
 * Print a formatted string to stdout, using va_list
 *
 * @param fmt Formatted string
 * @param ap  Variable-arguments list
 *
 * @return The number of characters printed, or -1 if error
 */
int re_vprintf(const char *fmt, va_list ap)
{
	return re_vfprintf(stdout, fmt, ap);
}


/**
 * Print a safe formatted string to stdout, using va_list
 *
 * @param fmt Formatted string
 * @param ap  Variable-arguments list
 *
 * @return The number of characters printed, or -1 if error
 */
int re_vprintf_s(const char *fmt, va_list ap)
{
	return re_vfprintf_s(stdout, fmt, ap);
}


/**
 * Print a formatted string to a buffer, using va_list
 *
 * @param str  Buffer for output string
 * @param size Size of buffer
 * @param fmt  Formatted string
 * @param ap   Variable-arguments list
 *
 * @return The number of characters printed, or -1 if error
 */
int re_vsnprintf(char *re_restrict str, size_t size,
		 const char *re_restrict fmt, va_list ap)
{
	struct pl pl;
	int err;

	if (!str || !size)
		return -1;

	pl.p = str;
	pl.l = size - 1;

	err = vhprintf(fmt, ap, print_handler, &pl, false);

	str[size - pl.l - 1] = '\0';

	return err ? -1 : (int)(size - pl.l - 1);
}


/**
 * Print a safe formatted string to a buffer, using va_list
 *
 * @param str  Buffer for output string
 * @param size Size of buffer
 * @param fmt  Formatted string
 * @param ap   Variable-arguments list
 *
 * @return The number of characters printed, or -1 if error
 */
int re_vsnprintf_s(char *re_restrict str, size_t size,
		 const char *re_restrict fmt, va_list ap)
{
	struct pl pl;
	int err;

	if (!str || !size)
		return -1;

	pl.p = str;
	pl.l = size - 1;

	err = vhprintf(fmt, ap, print_handler, &pl, true);

	str[size - pl.l - 1] = '\0';

	return err ? -1 : (int)(size - pl.l - 1);
}


static int vsdprintf(char **strp, const char *fmt, va_list ap, bool safe)
{
	struct dyn_print dp;
	int err;

	if (!strp)
		return EINVAL;

	dp.size = 16;
	dp.str  = mem_alloc(dp.size, NULL);
	if (!dp.str)
		return ENOMEM;

	dp.p = dp.str;
	dp.l = dp.size;

	err = vhprintf(fmt, ap, print_handler_dyn, &dp, safe);
	if (err)
		goto out;

	*dp.p = '\0';

 out:
	if (err)
		mem_deref(dp.str);
	else
		*strp = dp.str;

	return err;
}


/**
 * Print a formatted string to a dynamically allocated buffer, using va_list
 *
 * @param strp Pointer for output string
 * @param fmt  Formatted string
 * @param ap   Variable-arguments list
 *
 * @return 0 if success, otherwise errorcode
 */
int re_vsdprintf(char **strp, const char *fmt, va_list ap)
{
	return vsdprintf(strp, fmt, ap, false);
}


/**
 * Print a safe formatted string to a dynamically allocated buffer, using
 * va_list
 *
 * @param strp Pointer for output string
 * @param fmt  Formatted string
 * @param ap   Variable-arguments list
 *
 * @return 0 if success, otherwise errorcode
 */
int re_vsdprintf_s(char **strp, const char *fmt, va_list ap)
{
	return vsdprintf(strp, fmt, ap, true);
}


/**
 * Print a formatted string
 *
 * @param pf  Print backend
 * @param fmt Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int _re_hprintf(struct re_printf *pf, const char *fmt, ...)
{
	va_list ap;
	int err;

	if (!pf)
		return EINVAL;

	va_start(ap, fmt);
	err = re_vhprintf(fmt, ap, pf->vph, pf->arg);
	va_end(ap);

	return err;
}


/**
 * Print a safe formatted string
 *
 * @param pf  Print backend
 * @param fmt Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int _re_hprintf_s(struct re_printf *pf, const char *fmt, ...)
{
	va_list ap;
	int err;

	if (!pf)
		return EINVAL;

	va_start(ap, fmt);
	err = re_vhprintf_s(fmt, ap, pf->vph, pf->arg);
	va_end(ap);

	return err;
}


/**
 * Print a formatted string to a file stream
 *
 * @param stream File stream for output
 * @param fmt    Formatted string
 *
 * @return The number of characters printed, or -1 if error
 */
int _re_fprintf(FILE *stream, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = re_vfprintf(stream, fmt, ap);
	va_end(ap);

	return n;
}


/**
 * Print a safe formatted string to a file stream
 *
 * @param stream File stream for output
 * @param fmt    Formatted string
 *
 * @return The number of characters printed, or -1 if error
 */
int _re_fprintf_s(FILE *stream, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = re_vfprintf_s(stream, fmt, ap);
	va_end(ap);

	return n;
}


/**
 * Print a formatted string to stdout
 *
 * @param fmt    Formatted string
 *
 * @return The number of characters printed, or -1 if error
 */
int _re_printf(const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = re_vprintf(fmt, ap);
	va_end(ap);

	return n;
}


/**
 * Print a safe formatted string to stdout
 *
 * @param fmt    Formatted string
 *
 * @return The number of characters printed, or -1 if error
 */
int _re_printf_s(const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = re_vprintf_s(fmt, ap);
	va_end(ap);

	return n;
}


/**
 * Print a formatted string to a buffer
 *
 * @param str  Buffer for output string
 * @param size Size of buffer
 * @param fmt  Formatted string
 *
 * @return The number of characters printed, or -1 if error
 */
int _re_snprintf(char *re_restrict str, size_t size,
		const char *re_restrict fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = re_vsnprintf(str, size, fmt, ap);
	va_end(ap);

	return n;
}


/**
 * Print a safe formatted string to a buffer
 *
 * @param str  Buffer for output string
 * @param size Size of buffer
 * @param fmt  Formatted string
 *
 * @return The number of characters printed, or -1 if error
 */
int _re_snprintf_s(char *re_restrict str, size_t size,
		const char *re_restrict fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = re_vsnprintf_s(str, size, fmt, ap);
	va_end(ap);

	return n;
}


/**
 * Print a formatted string to a buffer
 *
 * @param strp Buffer pointer for output string
 * @param fmt  Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int _re_sdprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = re_vsdprintf(strp, fmt, ap);
	va_end(ap);

	return err;
}


/**
 * Print a safe formatted string to a buffer
 *
 * @param strp Buffer pointer for output string
 * @param fmt  Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int _re_sdprintf_s(char **strp, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = re_vsdprintf_s(strp, fmt, ap);
	va_end(ap);

	return err;
}
