/**
 * @file h264/getbit.c Generic bit parser
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_h264.h>
#include "h264.h"


#define DEBUG_MODULE "getbit"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


void getbit_init(struct getbit *gb, const uint8_t *buf, size_t size)
{
	if (!gb)
		return;

	gb->buf = buf;
	gb->pos = 0;
	gb->end = size;
}


size_t getbit_get_left(const struct getbit *gb)
{
	if (!gb)
		return 0;

	if (gb->end > gb->pos)
		return gb->end - gb->pos;
	else
		return 0;
}


unsigned get_bit(struct getbit *gb)
{
	const uint8_t *p;
	register unsigned tmp;

	if (!gb)
		return 0;

	if (gb->pos >= gb->end) {
		re_fprintf(stderr, "get_bit: read past end"
			   " (%zu >= %zu)\n", gb->pos, gb->end);
		return 0;
	}

	p = gb->buf;
	tmp = ((*(p + (gb->pos >> 0x3))) >> (0x7 - (gb->pos & 0x7))) & 0x1;

	++gb->pos;

	return tmp;
}


int get_ue_golomb(struct getbit *gb, unsigned *valp)
{
	unsigned zeros = 0;
	unsigned info;
	int i;

	if (!gb)
		return EINVAL;

	while (1) {

		if (getbit_get_left(gb) < 1)
			return EBADMSG;

		if (0 == get_bit(gb))
			++zeros;
		else
			break;
	}

	info = 1 << zeros;

	for (i = zeros - 1; i >= 0; i--) {

		if (getbit_get_left(gb) < 1)
			return EBADMSG;

		info |= get_bit(gb) << i;
	}

	if (valp)
		*valp = info - 1;

	return 0;
}


/*
  x = 0
  for ( i = 0; i < n; i++ ) {
   x = 2 * x + read_bit()
  }
  TotalConsumedBits += n
  return x
 */
unsigned get_bits(struct getbit *gb, unsigned n)
{
	unsigned x = 0;

	if (getbit_get_left(gb) < n) {
		DEBUG_WARNING("get_bits: read past end"
			" (n=%zu, left=%zu)\n", n, getbit_get_left(gb));
		return 0;
	}

	for (unsigned i=0; i<n; i++) {

		x = 2*x + get_bit(gb);
	}

	return x;
}


#define dd_f(n) get_bits(gb, (n))


/*
 * ns(n) - non-symmetric unsigned encoded integer with maximum
 *         number of values n (i.e., output in range 0..n-1).
 *
 */
unsigned getbit_read_ns(struct getbit *gb, unsigned n)
{
	unsigned w = 0;
	unsigned x = n;

	while (x != 0) {

		x = x >> 1;
		++w;
	}

	unsigned m = (1u << w) - n;
	unsigned v = dd_f(w - 1);

	if (v < m)
		return v;

	unsigned extra_bit = dd_f(1);

	return (v << 1) - m + extra_bit;
}
