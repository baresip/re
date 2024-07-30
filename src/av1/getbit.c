/**
 * @file getbit.c Get bits helper
 *
 * Copyright (C) 2023 Alfred E. Heggestad
 */

#include <re.h>
#include <re_av1.h>


#define DEBUG_MODULE "av1"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


void getbit_init(struct getbit *gb, const uint8_t *buf, size_t size_bits)
{
	if (!gb)
		return;

	gb->buf = buf;
	gb->pos = 0;
	gb->end = size_bits;
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
	register unsigned tmp;

	if (!gb)
		return 0;

	if (gb->pos >= gb->end) {
		DEBUG_WARNING("get_bit: read past end"
			" (%zu >= %zu)\n", gb->pos, gb->end);
		assert(0);
		return 0;
	}

	const uint8_t *p = gb->buf;
	tmp = ((*(p + (gb->pos >> 0x3))) >> (0x7 - (gb->pos & 0x7))) & 0x1;

	++gb->pos;

	return tmp;
}


