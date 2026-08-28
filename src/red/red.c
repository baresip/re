/**
 * @file red.c  RTP Redundant Payload (RFC 2198)
 *
 * Copyright (C) 2026 Emmanuel BUU
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_red.h>


/*
 * Implements the redundancy mechanism of RFC 2198,
 * "RTP Payload for Redundant Audio Data".
 *
 * A RED payload is a chain of header blocks followed by the payload of
 * each block, in the same order. All blocks but the last carry a 4-byte
 * header; the last block is the primary data and carries a 1-byte header
 * with no length, its length being implied by the rest of the packet.
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |1|   block PT  |  timestamp offset         |   block length    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |0|   block PT  |
 *   +-+-+-+-+-+-+-+-+
 *
 * The timestamp offset is unsigned and is subtracted from the timestamp in
 * the RTP header, so redundant data is always older than the primary data.
 *
 * The encoder keeps the last N generations of primary data and prepends
 * them to every new packet. Sending an empty primary block (len 0) is
 * legal and is how the tail of a burst is protected once the source has
 * gone idle.
 *
 * NOTE: the payload type in the RTP header is the payload type of "red"
 *       itself and is kept in the application, exactly like the RTP
 *       timestamp and sequence number.
 */


/** One generation of redundant data */
struct redgen {
	struct mbuf *mb;
	uint32_t ts;
};


/** Defines a RED encoder state */
struct red {
	struct redgen genv[RED_MAX_GEN];  /**< Oldest first             */
	unsigned n;                       /**< Valid entries in genv    */
	unsigned ngen;                    /**< Generations to encode    */
	uint8_t pt;                       /**< Payload type of a block  */
	bool pad;                         /**< Pad the header blocks    */
};


/** One decoded header block */
struct redhdr {
	uint16_t tsoff;
	uint16_t len;
	uint8_t pt;
};


static void destructor(void *arg)
{
	struct red *red = arg;
	unsigned i;

	for (i=0; i<RE_ARRAY_SIZE(red->genv); i++)
		mem_deref(red->genv[i].mb);
}


/**
 * Drop the oldest generation, shifting the remaining ones down and
 * keeping its buffer for re-use at the tail
 */
static void gen_drop_oldest(struct red *red)
{
	struct redgen oldest;

	if (!red->n || !red->ngen)
		return;

	oldest = red->genv[0];

	memmove(&red->genv[0], &red->genv[1],
		(red->ngen - 1) * sizeof(red->genv[0]));

	red->genv[red->ngen - 1] = oldest;
	--red->n;
}


/**
 * Drop the generations that can no longer be expressed as a 14-bit
 * timestamp offset relative to ts
 */
static void gen_expire(struct red *red, uint32_t ts)
{
	while (red->n && (uint32_t)(ts - red->genv[0].ts) > RED_MAX_TSOFF)
		gen_drop_oldest(red);
}


static int gen_push(struct red *red, uint32_t ts, const uint8_t *buf,
		    size_t len)
{
	struct redgen *g;
	int err;

	if (!red->ngen)
		return 0;

	if (red->n >= red->ngen)
		gen_drop_oldest(red);

	g = &red->genv[red->n];

	if (!g->mb) {
		g->mb = mbuf_alloc(len ? len : 16);
		if (!g->mb)
			return ENOMEM;
	}

	mbuf_rewind(g->mb);
	g->ts = ts;

	err = len ? mbuf_write_mem(g->mb, buf, len) : 0;
	if (err)
		return err;

	++red->n;

	return 0;
}


static int hdr_encode(struct mbuf *mb, uint8_t pt, uint16_t tsoff,
		      uint16_t len)
{
	int err;

	err  = mbuf_write_u8(mb, (uint8_t)(0x80 | (pt & 0x7f)));
	err |= mbuf_write_u8(mb, (uint8_t)(tsoff >> 6));
	err |= mbuf_write_u8(mb, (uint8_t)(((tsoff & 0x3f) << 2) | (len >> 8)));
	err |= mbuf_write_u8(mb, (uint8_t)(len & 0xff));

	return err;
}


/**
 * Allocate a new RED encoder
 *
 * The payload type is the one of the redundant and primary blocks, not the
 * one of "red" itself; the latter goes into the RTP header and is kept in
 * the application.
 *
 * @param redp Pointer to allocated object
 * @param pt   Payload type carried in every block
 * @param ngen Number of redundant generations, 0 to RED_MAX_GEN
 *
 * @return 0 if success, otherwise errorcode
 */
int red_alloc(struct red **redp, uint8_t pt, unsigned ngen)
{
	struct red *red;

	if (!redp || pt > 0x7f || ngen > RED_MAX_GEN)
		return EINVAL;

	red = mem_zalloc(sizeof(*red), destructor);
	if (!red)
		return ENOMEM;

	red->pt   = pt;
	red->ngen = ngen;

	*redp = red;

	return 0;
}


/**
 * Enable padding of the header blocks
 *
 * When enabled, empty header blocks are emitted so that every packet
 * carries the same number of headers even before the generation history is
 * full. Some legacy peers expect a fixed header layout. Disabled by
 * default.
 *
 * @param red RED encoder
 * @param pad True to enable padding
 */
void red_set_pad(struct red *red, bool pad)
{
	if (!red)
		return;

	red->pad = pad;
}


/**
 * Encode a RED payload
 *
 * The redundant generations recorded so far are written first, followed by
 * the primary data, which is then recorded as the newest generation. An
 * empty primary block is legal and protects the tail of a burst.
 *
 * A primary block longer than RED_MAX_LEN is encoded but is not recorded
 * as a generation, since its length cannot be expressed in the 10-bit
 * length field of a redundant header block.
 *
 * @param red RED encoder
 * @param mb  Buffer to encode into
 * @param ts  RTP timestamp of the primary data
 * @param buf Primary data (may be NULL if len is zero)
 * @param len Length of the primary data
 *
 * @return 0 if success, otherwise errorcode
 */
int red_encode(struct red *red, struct mbuf *mb, uint32_t ts,
	       const uint8_t *buf, size_t len)
{
	size_t pos, end;
	unsigned i;
	int err;

	if (!red || !mb || (len && !buf))
		return EINVAL;

	gen_expire(red, ts);

	pos = mb->pos;
	end = mb->end;

	err = 0;

	if (red->pad) {
		for (i=red->n; i<red->ngen; i++)
			err |= hdr_encode(mb, red->pt, 0, 0);
	}

	for (i=0; i<red->n; i++) {

		const struct redgen *g = &red->genv[i];

		err |= hdr_encode(mb, red->pt, (uint16_t)(ts - g->ts),
				  (uint16_t)g->mb->end);
	}

	/* final header block: no F bit, no length */
	err |= mbuf_write_u8(mb, red->pt & 0x7f);

	for (i=0; i<red->n; i++) {

		const struct redgen *g = &red->genv[i];

		if (!g->mb->end)
			continue;

		err |= mbuf_write_mem(mb, g->mb->buf, g->mb->end);
	}

	if (len)
		err |= mbuf_write_mem(mb, buf, len);

	if (err)
		goto out;

	if (len <= RED_MAX_LEN)
		err = gen_push(red, ts, buf, len);
	else
		red_flush(red);

 out:
	if (err) {
		mb->pos = pos;
		mb->end = end;
	}

	return err;
}


/**
 * Flush the generation history of a RED encoder
 *
 * @param red RED encoder
 */
void red_flush(struct red *red)
{
	if (!red)
		return;

	red->n = 0;
}


/**
 * Get the number of redundant generations currently held
 *
 * @param red RED encoder
 *
 * @return Number of generations
 */
unsigned red_gen_count(const struct red *red)
{
	return red ? red->n : 0;
}


/**
 * Decode a RED payload
 *
 * The handler is called once per block, oldest redundant block first and
 * the primary block last. On success the read position of the buffer is
 * left at the end of the payload; on error it is left untouched.
 *
 * @param mb     Buffer to decode
 * @param ts     RTP timestamp from the RTP header
 * @param blockh Block handler
 * @param arg    Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int red_decode(struct mbuf *mb, uint32_t ts, red_block_h *blockh, void *arg)
{
	struct redhdr hdrv[RED_MAX_BLOCKS];
	size_t pos, sum = 0;
	unsigned i, n = 0;
	uint8_t pt_pri;
	int err = 0;

	if (!mb || !blockh)
		return EINVAL;

	pos = mb->pos;

	for (;;) {
		uint8_t v[RED_HDR_SIZE];

		if (mbuf_get_left(mb) < 1) {
			err = EBADMSG;
			goto out;
		}

		if (!(mbuf_buf(mb)[0] & 0x80)) {
			pt_pri = mbuf_read_u8(mb) & 0x7f;
			break;
		}

		if (n >= RE_ARRAY_SIZE(hdrv) ||
		    mbuf_get_left(mb) < RED_HDR_SIZE) {
			err = EBADMSG;
			goto out;
		}

		(void)mbuf_read_mem(mb, v, sizeof(v));

		hdrv[n].pt    = v[0] & 0x7f;
		hdrv[n].tsoff = (uint16_t)(v[1] << 6 | v[2] >> 2);
		hdrv[n].len   = (uint16_t)((v[2] & 0x03) << 8 | v[3]);

		sum += hdrv[n].len;
		++n;
	}

	if (mbuf_get_left(mb) < sum) {
		err = EBADMSG;
		goto out;
	}

	for (i=0; i<n; i++) {

		blockh(hdrv[i].pt, ts - hdrv[i].tsoff, mbuf_buf(mb),
		       hdrv[i].len, arg);

		mbuf_advance(mb, hdrv[i].len);
	}

	blockh(pt_pri, ts, mbuf_buf(mb), mbuf_get_left(mb), arg);

	mbuf_skip_to_end(mb);

 out:
	if (err)
		mb->pos = pos;

	return err;
}


/**
 * Print debug information about a RED encoder
 *
 * @param pf  Print function
 * @param red RED encoder
 *
 * @return 0 if success, otherwise errorcode
 */
int red_debug(struct re_printf *pf, const struct red *red)
{
	unsigned i;
	int err;

	if (!red)
		return 0;

	err = re_hprintf(pf, "red: pt=%u ngen=%u pad=%d generations=%u\n",
			 red->pt, red->ngen, red->pad, red->n);

	for (i=0; i<red->n; i++) {

		err |= re_hprintf(pf, "  [%u] ts=%u len=%zu\n", i,
				  red->genv[i].ts, red->genv[i].mb->end);
	}

	return err;
}
