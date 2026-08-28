/**
 * @file rx.c  Receive path of ITU-T T.140 Real-Time Text
 *
 * Copyright (C) 2026 Emmanuel BUU
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_sdp.h>
#include <re_rtp.h>
#include <re_red.h>
#include <re_t140.h>
#include "t140.h"


/*
 * Over a reliable data channel a received block is simply text, and the
 * whole of what follows collapses to the UTF-8 reassembly at the end.
 *
 * Over RTP it is not. A RED payload carries the primary data of the last N
 * packets alongside the current one, so a packet that never arrives can
 * still be recovered from the next one. Three things have to be got right:
 *
 *   - a block that has already been delivered must not be delivered twice.
 *     Blocks are identified by their absolute timestamp, which is what the
 *     14-bit offset in the RED header is for;
 *
 *   - a gap that redundancy cannot fill must be reported. A packet with N
 *     redundant blocks covers the N packets before it, so a sequence-number
 *     gap wider than that has lost text in it, and T.140 marks lost text
 *     with U+FFFD;
 *
 *   - a zero-length block carries no text. It is either padding or an idle
 *     generation, and it must never be recorded as delivered, otherwise the
 *     primary block sharing its timestamp would look like a duplicate.
 */


struct rxctx {
	struct t140 *t;
	uint32_t ts;     /**< Timestamp of the packet          */
	unsigned nred;   /**< Redundant blocks in this payload */
	bool count;      /**< Counting pass, do not deliver    */
	int err;
};


static bool ts_seen(const struct t140 *t, uint32_t ts)
{
	unsigned i;

	for (i=0; i<t->tsc; i++) {

		if (t->tsv[i] == ts)
			return true;
	}

	return false;
}


static void ts_add(struct t140 *t, uint32_t ts)
{
	t->tsv[t->tsn] = ts;
	t->tsn = (t->tsn + 1) % T140_TSWIN;

	if (t->tsc < T140_TSWIN)
		++t->tsc;
}


static void block_handler(uint8_t pt, uint32_t ts, const uint8_t *buf,
			  size_t len, void *arg)
{
	struct rxctx *c = arg;
	struct t140 *t = c->t;

	(void)pt;

	if (c->count) {

		/* a block older than the packet covers a previous packet,
		   whether or not it carries any text */
		if (ts != c->ts)
			++c->nred;

		return;
	}

	if (!len)
		return;

	if (ts_seen(t, ts)) {
		++t->stats.rx_dup;
		return;
	}

	ts_add(t, ts);

	if (ts != c->ts)
		t->stats.rx_recovered += t140_utf8_chars(buf, len);

	c->err |= t140_utf8_decode(&t->dec, t->rxmb, buf, len);
}


/**
 * Reset the receive state
 *
 * Called when the marker bit says a new burst starts, so that a partial
 * sequence or a stale timestamp window cannot leak into it.
 *
 * @param t T.140 session
 */
void t140_rx_reset(struct t140 *t)
{
	if (!t)
		return;

	t140_utf8_reset(&t->dec);

	t->tsn = 0;
	t->tsc = 0;
	t->rx_seq_valid = false;
	t->rx_bom = true;
}


/**
 * Receive a T.140 packet
 *
 * The same entry point serves every transport: on T140_TRANSPORT_RTP the
 * packet carries the fields of the RTP header, which t140_pkt_rtp() fills
 * in, and the payload is decoded as RED when the payload type matches the
 * negotiated "red" format. On a reliable transport the payload is a bare
 * T140 block and the RTP fields are ignored.
 *
 * Recovered and newly arrived text is handed to the receive handler in one
 * call, in the order it was typed.
 *
 * @param t   T.140 session
 * @param pkt Received packet
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_recv(struct t140 *t, const struct t140_pkt *pkt)
{
	struct rxctx c;
	struct mbuf *mb;
	size_t pos;
	unsigned gap = 0;
	bool rtp, red;
	int err = 0;

	if (!t || !pkt || !pkt->mb)
		return EINVAL;

	if (!(t->dir & SDP_RECVONLY))
		return 0;

	mb  = pkt->mb;
	rtp = T140_TRANSPORT_RTP == t->conf.transport;
	red = rtp && t->conf.u.rtp.pt_red && pkt->pt == t->conf.u.rtp.pt_red;

	/*
	 * A duplicated packet carries the same marker bit as the original,
	 * so only reset on a marker that actually opens a new burst,
	 * otherwise a duplicate would wipe the state that detects it.
	 */
	if (rtp && pkt->marker &&
	    (!t->rx_seq_valid || (int16_t)(pkt->seq - t->rx_seq) > 0))
		t140_rx_reset(t);

	pos = mb->pos;

	memset(&c, 0, sizeof(c));
	c.t  = t;
	c.ts = pkt->ts;

	/* first pass: how many previous packets does this one cover */
	if (red) {
		c.count = true;

		err = red_decode(mb, pkt->ts, block_handler, &c);
		if (err)
			return err;

		mb->pos = pos;
	}

	if (rtp && t->rx_seq_valid) {

		int16_t d = (int16_t)(pkt->seq - t->rx_seq);

		if (d > 0)
			gap = (unsigned)d - 1;
	}

	mbuf_rewind(t->rxmb);

	if (gap > c.nred) {

		/* whatever was held back is part of the loss */
		t140_utf8_reset(&t->dec);

		err = t140_utf8_encode(t->rxmb, T140_LOSS);
		if (err)
			return err;

		++t->stats.rx_lost;
	}

	/* second pass: deliver */
	c.count = false;

	if (red)
		err = red_decode(mb, pkt->ts, block_handler, &c);
	else
		block_handler(pkt->pt, pkt->ts, mbuf_buf(mb),
			      mbuf_get_left(mb), &c);

	if (err)
		return err;

	err = c.err;
	if (err)
		return err;

	if (!red)
		mbuf_skip_to_end(mb);

	if (rtp && (!t->rx_seq_valid ||
		    (int16_t)(pkt->seq - t->rx_seq) > 0)) {
		t->rx_seq = pkt->seq;
		t->rx_seq_valid = true;
	}

	++t->stats.rx_packets;

	if (!t->rxmb->end)
		return 0;

	mbuf_set_pos(t->rxmb, 0);

	/* T.140 allows a BOM to open the stream; it is not text */
	if (t->rx_bom && t->rxmb->end >= 3 &&
	    !memcmp(t->rxmb->buf, "\xef\xbb\xbf", 3))
		mbuf_advance(t->rxmb, 3);

	t->rx_bom = false;

	if (!mbuf_get_left(t->rxmb))
		return 0;

	t->stats.rx_chars += t140_utf8_chars(mbuf_buf(t->rxmb),
					     mbuf_get_left(t->rxmb));

	if (t->recvh) {
		t->recvh((const char *)mbuf_buf(t->rxmb),
			 mbuf_get_left(t->rxmb), t->arg);
	}

	return 0;
}
