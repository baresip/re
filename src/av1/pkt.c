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
	MAX_OBUS = 3,   /* Maximum number of OBUs for W field */
	AV1_OBU_HEADER_SIZE = 1,
};

struct av1_context {
	/* The current RTP packet being created */
	struct mbuf *mb_pkt;
	/* The current OBU being packetized. This only contains the OBU
	 * payload, not the header or size */
	struct mbuf *curr_obu;
	/* The input buffer provided by the application.
	 * The position always points to immediately after curr_obu */
	struct mbuf *mb_buf;
	/* The OBU header for the current OBU being packetized */
	struct av1_obu_hdr curr_hdr;
	/* The number of bytes which still need to be written from the
	 * current OBU. This can be greater than the OBU size if the OBU
	 * header hasn't been written yet.
	 * If this is zero at the end of a packet, packetization is done */
	size_t curr_remaining;
	/* The max length of each RTP packet */
	size_t maxlen;
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
 * Serialize the AV1 RTP aggregation header
 *
 * Z: MUST be set to 1 if the first OBU element is an OBU fragment that is a
 *    continuation of an OBU fragment from the previous packet, and MUST be
 *    set to 0 otherwise.
 *
 * Y: MUST be set to 1 if the last OBU element is an OBU fragment that will
 *    continue in the next packet, and MUST be set to 0 otherwise.
 */
static void aggr_hdr_encode(uint8_t hdr[AV1_AGGR_HDR_SIZE],
		       bool z, bool y, uint8_t w, bool n)
{
	hdr[0] = z<<7 | y<<6 | w<<4 | n<<3;
}


/**
 * @returns the size the given OBU will be once we packetize it.
 * We force has_size to false in the OBU header, so this is the size of the OBU
 * and the one-byte OBU header.
 */
static size_t packetized_obu_size(const struct av1_obu_hdr* hdr) {
	return AV1_OBU_HEADER_SIZE + hdr->size;
}


/**
 * Searches through mb_buf until it finds an OBU which should be packetized,
 * and updates the current OBU when one is found.
 * If there are no more OBUs, curr_remaining will be set to 0
 *
 * @return 0 if success, otherwise errorcode
 */
static int update_curr_obu(struct av1_context* context) {
	int err = 0;
	do {
		size_t remaining = mbuf_get_left(context->mb_buf);
		/* OBUs must be at least 2 bytes */
		if (remaining < 2) {
			if (remaining > 0) {
				DEBUG_WARNING(
					"av1: encode: leftover data "
					"(%zu bytes)\n",
					remaining);
				mbuf_advance(context->mb_buf, remaining);
			}
			context->curr_obu->pos = context->curr_obu->end;
			context->curr_remaining = 0;
			break;
		}
		err = av1_obu_decode(&context->curr_hdr, context->mb_buf);
		if (err) {
			break;
		}
		context->curr_obu->buf = mbuf_buf(context->mb_buf);
		context->curr_obu->size = context->curr_hdr.size;
		context->curr_obu->pos = 0;
		context->curr_obu->end = context->curr_hdr.size;
		context->curr_remaining =
			packetized_obu_size(&context->curr_hdr);
		mbuf_advance(context->mb_buf, context->curr_hdr.size);
	} while (!obu_allowed_rtp(context->curr_hdr.type));

	return err;
}


/**
 * Copies len_to_copy of the current OBU to the RTP packet, taking the OBU
 * header into account. The caller is responsible for ensuring there is
 * enough space left in the packet for this many bytes:
 *     len_to_copy +
 *         include_prefix ? leb128_calc_size(len_to_copy) : 0
 *
 * @param context        Packetization context
 * @param include_prefix Whether to include the size prefix before the fragment
 * @param len_to_copy    The length of the OBU fragment to write. This is the
 *                       number of bytes to copy from the OBU
 *
 * @return 0 if success, otherwise errorcode
 */
static int copy_fragment(struct av1_context* context, bool include_prefix,
		size_t len_to_copy) {
	int err = 0;
	if (include_prefix) {
		err = av1_leb128_encode(context->mb_pkt, len_to_copy);
		if (err) {
			goto out;
		}
	}
	/*
	 * If this is the first time we're writing this OBU, we need to take
	 * the OBU header into account. The header can't be copied normally
	 * because we might need to modify it to remove the size information.
	 */
	if (context->curr_remaining == packetized_obu_size(&context->curr_hdr))
	{
		uint8_t obu_hdr = (context->curr_hdr.type & 0xf) << 3;
		err |= mbuf_write_u8(context->mb_pkt, obu_hdr);
		if (err) {
			goto out;
		}
		--len_to_copy;
		--context->curr_remaining;
	}

	err = mbuf_write_mem(context->mb_pkt,
		mbuf_buf(context->curr_obu), len_to_copy);
	if (err) {
		goto out;
	}
	mbuf_advance(context->curr_obu, len_to_copy);
	context->curr_remaining -= len_to_copy;
out:
	return err;
}


/**
 * Calculates the length of a fragment and the length of the leb128-encoded
 * size prefix for it.
 *
 * @param context         Packetization context
 * @param remaining_pkt   The number of bytes remaining in the current packet.
 *                        Must be greater than zero
 * @param len_to_copy_out Pointer to receive the length of the fragment to be
 *                        written
 * @param prefix_len_out  Pointer to receive the length of the size prefix to
 *                        be written
 */
static void calc_fragment_len_with_prefix(
		struct av1_context* context,
		size_t remaining_pkt,
		size_t* len_to_copy_out,
		size_t* prefix_len_out) {
	/* The size always uses at least 1 byte, so subtract one from the
	 * remaining packet space */
	size_t len_to_copy = min(context->curr_remaining, remaining_pkt - 1);
	size_t prefix_len = leb128_calc_size(len_to_copy);

	if (len_to_copy + prefix_len > remaining_pkt) {
		/* If there's not enough room in the packet for the initial
		 * estimate, reserve space in the packet for the length of the
		 * prefix and try again. Note that prefix_len can change here
		 * if len_to_copy changes from, say, 128 to 127, but the new
		 * prefix_len will always be <= the old one. */
		len_to_copy = remaining_pkt - prefix_len;
		prefix_len = leb128_calc_size(len_to_copy);
	}

	*len_to_copy_out = len_to_copy;
	*prefix_len_out = prefix_len;
}


/**
 * Calculates the length of the next fragment to write to the RTP packet and
 * whether it needs a size prefix.
 *
 * @param context            Packetization context
 * @param count              The number of fragments already written to the RTP
 *                           packet
 * @param include_prefix_out Pointer to receive whether the size prefix should
 *                           be written before this fragment
 * @param len_to_copy_out    Pointer to receive the length of the fragment to
 *                           be written. If set to zero, there was not enough
 *                           room in the packet for another fragment
 *
 * @returns 0 on success and non-zero otherwise. On success, check
 *          len_to_copy_out to determine if there was room in the packet for
 *          another fragment
 */
static int calc_fragment_len(
		struct av1_context* context,
		size_t count,
		bool* include_prefix_out,
		size_t* len_to_copy_out) {
	/* Note: This checks for space left in the entire buffer,
	 * not the current OBU */
	bool is_last_obu = mbuf_get_left(context->mb_buf) == 0;
	size_t pkt_len = mbuf_pos(context->mb_pkt);
	size_t remaining_pkt = 0;
	size_t len_to_copy = 0;
	size_t fragment_size_len = 0;
	bool include_prefix = false;

	*include_prefix_out = 0;
	*len_to_copy_out = 0;

	if (pkt_len > context->maxlen) {
		DEBUG_WARNING("av1: encode: packet too large (%zu > %zu)\n",
				pkt_len, context->maxlen);
		return ERANGE;
	}
	remaining_pkt = context->maxlen - pkt_len;
	if (remaining_pkt < 1) {
		return 0;
	}

	/* The size prefix can be elided for the last fragment only when there
	 * are 3 or fewer fragments in the packet. */
	if (count > MAX_OBUS) {
		include_prefix = true;
	}
	else if (!is_last_obu && remaining_pkt > context->curr_remaining) {
		/* If the next fragment would need a prefix, we need a minimum
		 * of 2 bytes for it. */
		size_t next_fragment = count > 2 ? 2 : 1;
		calc_fragment_len_with_prefix(context,
			remaining_pkt,
			&len_to_copy,
			&fragment_size_len);

		/* Only include a prefix if there
		 * is room for another fragment. */
		include_prefix = len_to_copy + fragment_size_len <=
				remaining_pkt - next_fragment;
	}

	if (include_prefix) {
		/* A prefixed fragment needs a minimum of 2 bytes:
		 * 1 for the prefix itself and at least 1 for the data. */
		if (remaining_pkt < 2) {
			return 0;
		}
		/* Only calculate this if it wasn't calculated above when
		 * count <= 3 */
		if (len_to_copy == 0) {
			calc_fragment_len_with_prefix(context,
				remaining_pkt,
				&len_to_copy,
				&fragment_size_len);
		}
	}
	else {
		/* No prefix is needed, fill as much
		 * of the packet as possible. */
		len_to_copy = min(context->curr_remaining, remaining_pkt);
	}

	*include_prefix_out = include_prefix;
	*len_to_copy_out = len_to_copy;
	return 0;
}


/**
 * Copy as many OBU fragments as possible to the current RTP packet.
 *
 * @param context Packetization context
 * @param w       The value of w for this packet (whether each fragment is
 *                prefixed or the last one is elided)
 * @param y       The value of y for this packet (whether the last fragment
 *                will continue to the next packet)
 */
static int copy_obus_to_packet(struct av1_context* context, uint8_t* w,
		bool *y) {
	unsigned count = 0;
	int err = 0;
	bool include_prefix = true;

	/* Stop copying OBUs when:
	 * 1. There are no more OBUs left (curr_remaining == 0), or
	 * 2. The last fragment didn't include a prefix. We aren't allowed to
	 *    copy another fragment even if there's space in the packet, or
	 * 3. calc_fragment_len determines there isn't enough room for another
	 *    fragment */
	while (context->curr_remaining > 0 && include_prefix) {
		size_t len_to_copy = 0;
		err = calc_fragment_len(context, count + 1, &include_prefix,
			&len_to_copy);
		if (err) {
			goto out;
		}
		/* Not enough room for another fragment */
		if (len_to_copy == 0) {
			break;
		}
		err = copy_fragment(context, include_prefix, len_to_copy);
		if (err) {
			goto out;
		}
		++count;

		if (context->curr_remaining == 0) {
			/* We finished packetizing the current OBU,
			 * move onto the next one. */
			*y = false;
			err = update_curr_obu(context);
			if (err) {
				goto out;
			}
		}
		else {
			/* The current OBU still has data left to packetize. */
			*y = true;
		}
	}
	/* It's possible for copy_obu_to_packet to accidentally include the
	 * size prefix before the last OBU in the packet if the last OBU in
	 * the buffer is skipped. We need to set w = 0 in that case even if
	 * there are <= 3 OBU fragments */
	*w = count > MAX_OBUS || include_prefix ? 0 : count;

out:
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
int av1_packetize(bool *newp, bool marker, uint64_t rtp_ts,
		  const uint8_t *buf, size_t len, size_t maxlen,
		  av1_packet_h *pkth, void *arg)
{
	struct mbuf *mb_pkt;
	uint8_t w;
	int err;
	bool continuing_to_next_packet = false;
	bool continued_from_previous_packet = false;
	struct mbuf mb_buf = {
		.buf  = (uint8_t *)buf,
		.size = len,
		.pos  = 0,
		.end  = len
	};
	struct mbuf curr_obu;
	uint8_t aggr_hdr[AV1_AGGR_HDR_SIZE];

	if (!newp || !buf || !len || maxlen < (AV1_AGGR_HDR_SIZE + 1) || !pkth)
		return EINVAL;

	maxlen -= sizeof(aggr_hdr);
	mb_pkt = mbuf_alloc(maxlen);
	if (!mb_pkt)
		return ENOMEM;
	mbuf_init(&curr_obu);

	struct av1_context context = {
		.mb_pkt = mb_pkt,
		.mb_buf = &mb_buf,
		.curr_obu = &curr_obu,
		.curr_remaining = 0,
		.maxlen = maxlen
	};
	err = update_curr_obu(&context);
	if (err) {
		goto out;
	}

	while (context.curr_remaining > 0) {
		continued_from_previous_packet = continuing_to_next_packet;
		err = copy_obus_to_packet(&context, &w,
			&continuing_to_next_packet);
		if (err) {
			goto out;
		}
		aggr_hdr_encode(aggr_hdr, continued_from_previous_packet,
			continuing_to_next_packet, w, *newp);
		*newp = false;

		mbuf_set_pos(context.mb_pkt, 0);
		err = pkth(marker && context.curr_remaining == 0,
			rtp_ts,
			aggr_hdr,
			sizeof(aggr_hdr),
			mbuf_buf(context.mb_pkt),
			mbuf_get_left(context.mb_pkt),
			arg);
		if (err) {
			goto out;
		}
		mbuf_rewind(context.mb_pkt);
	}

 out:
	mem_deref(mb_pkt);
	return err;
}
