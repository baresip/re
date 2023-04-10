/**
 * @file fmt/arg.c VA_ARG helpers
 *
 * Copyright (C) 2023 Sebastian Reimers
 */

#include <assert.h>
#include <re_types.h>
#include <re_fmt.h>


int re_va_arg_int(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(int) && "re_va_arg: arg is not compatible");

	return va_arg(ap, int);
}


char *re_va_arg_char_p(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(char *) && "re_va_arg: arg is not compatible");

	return va_arg(ap, char *);
}


const char *re_va_arg_const_char_p(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(const char *) &&
	       "re_va_arg: arg is not compatible");

	return va_arg(ap, const char *);
}


size_t re_va_arg_size_t(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(size_t) && "re_va_arg: arg is not compatible");

	return va_arg(ap, size_t);
}


ssize_t re_va_arg_ssize_t(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(ssize_t) && "re_va_arg: arg is not compatible");

	return va_arg(ap, ssize_t);
}


signed long long re_va_arg_signed_long_long(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(signed long long) &&
	       "re_va_arg: arg is not compatible");

	return va_arg(ap, signed long long);
}


signed long re_va_arg_signed_long(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(signed long) &&
	       "re_va_arg: arg is not compatible");

	return va_arg(ap, signed long);
}


signed re_va_arg_signed(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(signed) && "re_va_arg: arg is not compatible");

	return va_arg(ap, signed);
}


unsigned long long re_va_arg_unsigned_long_long(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(unsigned long long) &&
	       "re_va_arg: arg is not compatible");

	return va_arg(ap, unsigned long long);
}


unsigned long re_va_arg_unsigned_long(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(unsigned long) &&
	       "re_va_arg: arg is not compatible");

	return va_arg(ap, unsigned long);
}


unsigned re_va_arg_unsigned(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(unsigned) && "re_va_arg: arg is not compatible");

	return va_arg(ap, unsigned);
}


double re_va_arg_double(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(double) && "re_va_arg: arg is not compatible");

	return va_arg(ap, double);
}


void *re_va_arg_void_p(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(void *) && "re_va_arg: arg is not compatible");

	return va_arg(ap, void *);
}


re_printf_h *re_va_arg_re_printf_h(va_list ap)
{
	size_t sz = va_arg(ap, size_t);

	assert(sz && "re_va_arg: no more arguments");
	assert(sz == sizeof(re_printf_h *) && "re_va_arg: arg is not compatible");

	return va_arg(ap, re_printf_h *);
}
