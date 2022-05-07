/**
 * @file av1/obu.c AV1 Open Bitstream Unit (OBU)
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_av1.h>


#define DEBUG_MODULE "av1"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int av1_leb128_encode(struct mbuf *mb, size_t value)
{
	int err = 0;

	if (!mb)
		return EINVAL;

	while (value >= 0x80) {

		uint8_t u8 = 0x80 | (value & 0x7f);

		err |= mbuf_write_u8(mb, u8);

		value >>= 7;
	}

	err |= mbuf_write_u8(mb, value);

	return err;
}


int av1_leb128_decode(struct mbuf *mb, size_t *value)
{
	size_t ret = 0;
	unsigned i;

	if (!mb || !value)
		return EINVAL;

	for (i = 0; i < 8; i++) {

		size_t byte;

		if (mbuf_get_left(mb) < 1)
			return EBADMSG;

		byte = mbuf_read_u8(mb);

		ret |= (size_t)(byte & 0x7f) << (i * 7);

		if (!(byte & 0x80))
			break;
	}

	*value = ret;

	return 0;
}


int av1_obu_encode(struct mbuf *mb, uint8_t type, bool has_size,
		   size_t len, const uint8_t *payload)
{
	uint8_t val;
	int err;

	if (!mb || type==0)
		return EINVAL;

	val  = (type&0xf) << 3;
	val |= (unsigned)has_size << 1;

	err  = mbuf_write_u8(mb, val);

	if (has_size)
		err |= av1_leb128_encode(mb, len);

	if (payload && len)
		err |= mbuf_write_mem(mb, payload, len);

	return err;
}


int av1_obu_decode(struct av1_obu_hdr *hdr, struct mbuf *mb)
{
	uint8_t val;
	bool f;
	int err;

	if (!hdr || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < 1)
		return EBADMSG;

	memset(hdr, 0, sizeof(*hdr));

	val = mbuf_read_u8(mb);

	f         = (val >> 7) & 0x1;
	hdr->type = (val >> 3) & 0xf;
	hdr->x    = (val >> 2) & 0x1;
	hdr->s    = (val >> 1) & 0x1;

	if (f) {
		DEBUG_WARNING("av1: header: obu forbidden bit!"
			" [type=%u, x=%d, s=%d, left=%zu bytes]\n",
			hdr->type, hdr->x, hdr->s, mbuf_get_left(mb));
		return EBADMSG;
	}

	if (hdr->type == 0) {
		DEBUG_WARNING("av1: header: obu type 0 is reserved [%H]\n",
			      av1_obu_print, hdr);
		return EBADMSG;
	}

	if (hdr->x) {
		DEBUG_WARNING("av1: header: extension not supported (%u)\n",
			      hdr->type);
		return ENOTSUP;
	}

	if (hdr->s) {
		err = av1_leb128_decode(mb, &hdr->size);
		if (err)
			return err;

		if (hdr->size > mbuf_get_left(mb)) {
			DEBUG_WARNING("av1: obu decode: short packet:"
				      " %zu > %zu\n",
				      hdr->size, mbuf_get_left(mb));
			return EBADMSG;
		}
	}
	else {
		hdr->size = mbuf_get_left(mb);
	}

	return 0;
}


int av1_obu_print(struct re_printf *pf, const struct av1_obu_hdr *hdr)
{
	if (!hdr)
		return 0;

	return re_hprintf(pf, "type=%u x=%d s=%d size=%zu",
			  hdr->type, hdr->x, hdr->s, hdr->size);
}
