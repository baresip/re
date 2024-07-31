/**
 * @file putbit.c Put bits helper
 *
 * Copyright (C) 2023 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <re_dd.h>


void putbit_init(struct putbit *pb, struct mbuf *mb)
{
	if (!pb || !mb)
		return;

	pb->mb      = mb;
	pb->bit_pos = 0;

	memset(pb->mb->buf, 0, pb->mb->size);
}


int putbit_one(struct putbit *pb, unsigned bit)
{
	if (!pb)
		return EINVAL;

	size_t byte_pos = pb->bit_pos >> 0x3;

	/* resize mbuf */
	if (byte_pos >= pb->mb->size) {

		int err = mbuf_resize(pb->mb, pb->mb->size * 2);
		if (err)
			return err;
	}

	uint8_t *p = pb->mb->buf;
	size_t bit_pos = (size_t)(1u << (0x7 - (pb->bit_pos & 0x7)));

	if (bit) {
		p[byte_pos] |= bit_pos;
	}
	else {
		p[byte_pos] &= ~bit_pos;
	}

	++pb->bit_pos;

	/* NOTE: mb->pos not used */
	mbuf_set_end(pb->mb, (pb->bit_pos + 7) >> 0x3);

	return 0;
}


int putbit_write(struct putbit *pb, unsigned count, unsigned val)
{
	if (!pb)
		return EINVAL;

	if (count > 32)
		return EINVAL;

	for (unsigned i=0; i<count; i++) {

		unsigned shift = count-i-1;
		unsigned bit = (val >> shift) & 0x1;

		int err = putbit_one(pb, bit);
		if (err)
			return err;
	}

	return 0;
}


int putbit_write_ns(struct putbit *pb, unsigned n, unsigned v)
{
	if (!pb)
		return EINVAL;

	int err;

#if 0
	/* TODO: check this */
	if (n == 1)
		return EINVAL;
#endif

	unsigned w = 0;
	unsigned x = n;

	while (x != 0) {
		x = x >> 1;
		++w;
	}

	unsigned m = (1 << w) - n;
	if (v < m)
		err = putbit_write(pb, w - 1, v);
	else
		err = putbit_write(pb, w, v + m);

	return err;
}
