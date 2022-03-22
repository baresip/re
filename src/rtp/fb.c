/**
 * @file fb.c Real-time Transport Control Protocol (RTCP)-Based Feedback
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sys.h>
#include <re_sa.h>
#include <re_rtp.h>
#include "rtcp.h"


#define DEBUG_MODULE "rtcp_pb"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	GNACK_SIZE = 4,
	SLI_SIZE   = 4
};


/* Encode functions */


/**
 * Encode an RTCP Generic NACK (GNACK) message
 *
 * @param mb  Buffer to encode into
 * @param pid Packet ID
 * @param blp Bitmask of following lost packets (BLP)
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_rtpfb_gnack_encode(struct mbuf *mb, uint16_t pid, uint16_t blp)
{
	int err;
	err  = mbuf_write_u16(mb, htons(pid));
	err |= mbuf_write_u16(mb, htons(blp));
	return err;
}


/**
 * Encode an RTCP Slice Loss Indication (SLI) message
 *
 * @param mb     Buffer to encode into
 * @param first  Macroblock (MB) address of the first lost macroblock
 * @param number Number of lost macroblocks
 * @param picid  Picture ID
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_psfb_sli_encode(struct mbuf *mb, uint16_t first, uint16_t number,
			 uint8_t picid)
{
	const uint32_t v = first<<19 | number<<6 | picid;
	return mbuf_write_u32(mb, htonl(v));
}


/* Decode functions */


/**
 * Decode an RTCP Transport-wide congestion control Feedback Message
 *
 * @param mb  Buffer to decode
 * @param msg transport-cc struct to decode into
 * @param n   length of the RTCP packet in 32bit words minus one
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_rtpfb_twcc_decode(struct mbuf *mb, struct twcc *msg, int n)
{
	size_t j, sz;

	if (!msg)
		return EINVAL;

	if (mbuf_get_left(mb) < 8)
		return EBADMSG;

	msg->seq = ntohs(mbuf_read_u16(mb));
	msg->count = ntohs(mbuf_read_u16(mb));
	if (msg->count == 0)
		return EBADMSG;

	msg->reftime = ntohl(mbuf_read_u32(mb));
	msg->fbcount = msg->reftime & 0xff;
	msg->reftime >>= 8;

	msg->chunks = mbuf_alloc_ref(mb);
	if (!msg->chunks)
		return ENOMEM;

	msg->chunks->end = msg->chunks->pos;
	sz = 0;
	for (size_t i = msg->count; i > 0;) {
		uint16_t chunk;

		if (mbuf_get_left(mb) < 2)
			return EBADMSG;
		chunk  = ntohs(mbuf_read_u16(mb));
		msg->chunks->end += 2;
		if (chunk & 0x8000) {
			/* status vector chunk */
			if (chunk & 0x4000) {
				for (j = 0; j < i && j < 7; j++)
					sz += chunk >> (2 * (7 - 1 - j))
						& 0x03;
			}
			else {
				for (j = 0; j < i && j < 14; j++)
					sz += (chunk >> (14 - 1 - j)) & 0x01;
			}
		}
		else {
			/* run length chunk */
			for (j = 0; j < i && j < (chunk & 0x1fffu); j++)
				sz += (chunk >> 13) & 0x03;
		}
		i -= j;
	}
	if (mbuf_get_left(mb) < sz)
		return EBADMSG;

	msg->deltas = mbuf_alloc_ref(mb);
	if (!msg->deltas)
		return ENOMEM;

	msg->deltas->end = msg->deltas->pos + sz;

	sz = n * sizeof(uint32_t) - 8 - mbuf_get_left(msg->chunks);
	if (mbuf_get_left(mb) < sz)
		return EBADMSG;

	mbuf_advance(mb, sz);

	return 0;
}

/**
 * Decode an RTCP Transport Layer Feedback Message
 *
 * @param mb  Buffer to decode
 * @param msg RTCP Message to decode into
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_rtpfb_decode(struct mbuf *mb, struct rtcp_msg *msg)
{
	size_t i, sz;
	int err;

	if (!msg)
		return EINVAL;

	switch (msg->hdr.count) {

	case RTCP_RTPFB_GNACK:
		sz = msg->r.fb.n * sizeof(*msg->r.fb.fci.gnackv);
		msg->r.fb.fci.gnackv = mem_alloc(sz, NULL);
		if (!msg->r.fb.fci.gnackv)
			return ENOMEM;

		if (mbuf_get_left(mb) < msg->r.fb.n * GNACK_SIZE)
			return EBADMSG;
		for (i=0; i<msg->r.fb.n; i++) {
			msg->r.fb.fci.gnackv[i].pid = ntohs(mbuf_read_u16(mb));
			msg->r.fb.fci.gnackv[i].blp = ntohs(mbuf_read_u16(mb));
		}
		break;

	case RTCP_RTPFB_TWCC:
		if (mbuf_get_left(mb) < 8)
			return EBADMSG;
		msg->r.fb.fci.twccv = mem_zalloc(sizeof(*msg->r.fb.fci.twccv),
			NULL);
		if (!msg->r.fb.fci.twccv)
			return ENOMEM;
		err = rtcp_rtpfb_twcc_decode(mb, msg->r.fb.fci.twccv,
			msg->r.fb.n);
		if (err)
			return err;

		break;

	default:
		DEBUG_NOTICE("unknown RTPFB fmt %d\n", msg->hdr.count);
		break;
	}

	return 0;
}


/**
 * Decode an RTCP Payload-Specific Feedback Message
 *
 * @param mb  Buffer to decode
 * @param msg RTCP Message to decode into
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_psfb_decode(struct mbuf *mb, struct rtcp_msg *msg)
{
	size_t i, sz;

	if (!msg)
		return EINVAL;

	switch (msg->hdr.count) {

	case RTCP_PSFB_PLI:
		/* no params */
		break;

	case RTCP_PSFB_SLI:
		sz = msg->r.fb.n * sizeof(*msg->r.fb.fci.sliv);
		msg->r.fb.fci.sliv = mem_alloc(sz, NULL);
		if (!msg->r.fb.fci.sliv)
			return ENOMEM;

		if (mbuf_get_left(mb) < msg->r.fb.n * SLI_SIZE)
			return EBADMSG;
		for (i=0; i<msg->r.fb.n; i++) {
			const uint32_t v = ntohl(mbuf_read_u32(mb));

			msg->r.fb.fci.sliv[i].first  = v>>19 & 0x1fff;
			msg->r.fb.fci.sliv[i].number = v>> 6 & 0x1fff;
			msg->r.fb.fci.sliv[i].picid  = v>> 0 & 0x003f;
		}
		break;

	case RTCP_PSFB_AFB:
		sz = msg->r.fb.n * 4;

		if (mbuf_get_left(mb) < sz)
			return EBADMSG;

		msg->r.fb.fci.afb = mbuf_alloc_ref(mb);
		if (!msg->r.fb.fci.afb)
			return ENOMEM;

		msg->r.fb.fci.afb->end = msg->r.fb.fci.afb->pos + sz;
		mbuf_advance(mb, sz);
		break;

	default:
		DEBUG_NOTICE("unknown PSFB fmt %d\n", msg->hdr.count);
		break;
	}

	return 0;
}
