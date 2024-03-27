/**
 * @file av1/pkt.c AV1 Packetizer
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_av1.h>


#define DEBUG_MODULE "av1"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	MAX_OBUS = 3  /* Maximum number of OBUs for W field */
};


/*
 * Calculate length of LEB128 field
 *
 * Add high 1 bits on all but last (most significant) group to form bytes
 */
static size_t leb128_calc_size(uint64_t value)
{
	size_t bytes = 1;

	/* Bit7: 1=more bytes coming, 0=complete */
	while (value >= 0x80) {

		++bytes;

		value >>= 7;
	}

	return bytes;
}


/*
 * Z: MUST be set to 1 if the first OBU element is an OBU fragment that is a
 *    continuation of an OBU fragment from the previous packet, and MUST be
 *    set to 0 otherwise.
 *
 * Y: MUST be set to 1 if the last OBU element is an OBU fragment that will
 *    continue in the next packet, and MUST be set to 0 otherwise.
 */
static void hdr_encode(uint8_t hdr[AV1_AGGR_HDR_SIZE],
		       bool z, bool y, uint8_t w, bool n)
{
	hdr[0] = z<<7 | y<<6 | w<<4 | n<<3;
}


static struct mbuf *encode_obu(uint8_t type, const uint8_t *p, size_t len)
{
	struct mbuf *mb = mbuf_alloc(len);
	const bool has_size = false;  /* NOTE */
	int err;

	if (!mb)
		return NULL;

	err = av1_obu_encode(mb, type, has_size, len, p);
	if (err) {
		mem_deref(mb);
		return NULL;
	}

	mb->pos = 0;

	return mb;
}


static int copy_obus(struct mbuf *mb_pkt, const uint8_t *buf, size_t size,
		     bool w0, size_t maxlen, unsigned *small_obus)
{
	struct mbuf wrap = {
		.buf  = (uint8_t *)buf,
		.size = size,
		.pos  = 0,
		.end  = size
	};
	struct mbuf *mb_obu = NULL;
	size_t accum = AV1_AGGR_HDR_SIZE;
	unsigned count = 0;
	enum { OBU_HEADER_SIZE=1 };
	int err = 0;

	while (mbuf_get_left(&wrap) >= 2) {

		struct av1_obu_hdr hdr;
		bool last;
		size_t tmp;

		err = av1_obu_decode(&hdr, &wrap);
		if (err) {
			DEBUG_WARNING("av1: encode: hdr dec error (%m)\n",
				      err);
			return err;
		}

		last = (hdr.size == mbuf_get_left(&wrap));

		switch (hdr.type) {

		case AV1_OBU_SEQUENCE_HEADER:
		case AV1_OBU_FRAME_HEADER:
		case AV1_OBU_METADATA:
		case AV1_OBU_FRAME:
		case AV1_OBU_REDUNDANT_FRAME_HEADER:
		case AV1_OBU_TILE_GROUP:
			mb_obu = encode_obu(hdr.type, mbuf_buf(&wrap),
					    hdr.size);
			if (!mb_obu) {
				err = ENOMEM;
				goto out;
			}

			if (last) {
				if (w0)
					err = av1_leb128_encode(mb_pkt,
								mb_obu->end);
			}
			else {
				err = av1_leb128_encode(mb_pkt, mb_obu->end);
			}

			if (err)
				goto out;

			err = mbuf_write_mem(mb_pkt, mb_obu->buf, mb_obu->end);
			if (err)
				goto out;

			/* Count number of small OBUs that fits */

			tmp = OBU_HEADER_SIZE
				+ leb128_calc_size(hdr.size)
				+ hdr.size;

			accum += tmp;

			if (accum < maxlen) {
				++count;
			}
			break;

		case AV1_OBU_TEMPORAL_DELIMITER:
		case AV1_OBU_TILE_LIST:
		case AV1_OBU_PADDING:
			/* skip */
			break;

		default:
			DEBUG_WARNING("av1: unknown obu type %u\n", hdr.type);
			break;
		}

		mbuf_advance(&wrap, hdr.size);

		mb_obu = mem_deref(mb_obu);
	}

	if (small_obus)
		*small_obus = count;

 out:
	mem_deref(mb_obu);
	return err;
}


static int av1_packetize_internal(bool *newp, bool marker, uint64_t rtp_ts,
				  const uint8_t *buf, size_t len,
				  size_t maxlen, uint8_t w,
				  bool use_w_field, unsigned small_obus,
				  av1_packet_h *pkth, void *arg)
{
	uint8_t hdr[AV1_AGGR_HDR_SIZE];
	bool z_cont = false;
	int err = 0;

	if (w > 3) {
		DEBUG_WARNING("w too large\n");
		return EPROTO;
	}

	maxlen -= sizeof(hdr);

	while (len > maxlen) {

		hdr_encode(hdr, z_cont, true, w, *newp);
		*newp = false;

		err |= pkth(false, rtp_ts, hdr, sizeof(hdr), buf, maxlen, arg);

		buf  += maxlen;
		len  -= maxlen;
		z_cont = true;

		/* If OBUs are fragmented */
		if (use_w_field && small_obus > 0) {

			if (w==2 || w==3) {
				w -= small_obus;
			}
		}
	}

	hdr_encode(hdr, z_cont, false, w, *newp);
	*newp = false;

	err |= pkth(marker, rtp_ts, hdr, sizeof(hdr), buf, len, arg);

	return err;
}


/**
 * Packetize an AV1 bitstream with one or more OBUs
 *
 * @param newp    Pointer to new stream flag
 * @param marker  Set marker bit
 * @param rtp_ts  RTP timestamp
 * @param buf     Input buffer
 * @param len     Buffer length
 * @param maxlen  Maximum RTP packet size
 * @param pkth    Packet handler
 * @param arg     Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int av1_packetize_high(bool *newp, bool marker, uint64_t rtp_ts,
		       const uint8_t *buf, size_t len, size_t maxlen,
		       av1_packet_h *pkth, void *arg)
{
	struct mbuf *mb_pkt;
	unsigned count = 0;
	uint8_t w;
	int err;

	if (!newp || !buf || !len || maxlen < (AV1_AGGR_HDR_SIZE + 1) || !pkth)
		return EINVAL;

	mb_pkt = mbuf_alloc(len);
	if (!mb_pkt)
		return ENOMEM;

	count = av1_obu_count_rtp(buf, len);

	if (count > MAX_OBUS) {
		w = 0;
	}
	else {
		w = count;
	}

	bool use_w_field = count <= MAX_OBUS;
	unsigned small_obus = 0;

	err = copy_obus(mb_pkt, buf, len, count > MAX_OBUS,
			maxlen, &small_obus);
	if (err)
		goto out;

	err = av1_packetize_internal(newp, marker, rtp_ts,
				     mb_pkt->buf, mb_pkt->end, maxlen,
				     w, use_w_field, small_obus,
				     pkth, arg);

 out:
	mem_deref(mb_pkt);
	return err;
}


/**
 * Packetize an AV1 bitstream with one or more OBUs, using W=1 mode
 *
 * @param newp    Pointer to new stream flag
 * @param marker  Set marker bit
 * @param rtp_ts  RTP timestamp
 * @param buf     Input buffer
 * @param len     Buffer length
 * @param maxlen  Maximum RTP packet size
 * @param pkth    Packet handler
 * @param arg     Handler argument
 *
 * @return 0 if success, otherwise errorcode
 *
 * W: two bit field that describes the number of OBU elements in the packet.
 *    This field MUST be set equal to 0 or equal to the number of OBU elements
 *    contained in the packet. If set to 0, each OBU element MUST be preceded
 *    by a length field.
 *    If not set to 0 (i.e., W = 1, 2 or 3) the last OBU element MUST NOT be
 *    preceded by a length field.
 *
 */
int av1_packetize_one_w(bool *newp, bool marker, uint64_t rtp_ts,
			const uint8_t *buf, size_t len, size_t maxlen,
			av1_packet_h *pkth, void *arg)
{
	struct mbuf wrap = {
		.buf  = (uint8_t *)buf,
		.size = len,
		.pos  = 0,
		.end  = len
	};
	int err = 0;

	while (mbuf_get_left(&wrap) >= 2) {

		struct av1_obu_hdr hdr;
		size_t start = wrap.pos;

		err = av1_obu_decode(&hdr, &wrap);
		if (err) {
			DEBUG_WARNING("av1: encode: hdr dec error (%m)\n",
				      err);
			return err;
		}

		if (obu_allowed_rtp(hdr.type)) {

			size_t header_size = wrap.pos - start;
			size_t total_size = header_size + hdr.size;
			bool last = (hdr.size == mbuf_get_left(&wrap));
			bool use_w_field = true;

			err = av1_packetize_internal(newp,
						     marker && last,
						     rtp_ts,
						     &wrap.buf[start],
						     total_size,
						     maxlen,
						     1,
						     use_w_field,
						     0,
						     pkth,
						     arg);
			if (err)
				return err;
		}

		mbuf_advance(&wrap, hdr.size);
	}

	return err;
}
