/**
 * @file tx.c  Transmit path of ITU-T T.140 Real-Time Text
 *
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
#include <re_sys.h>
#include <re_red.h>
#include <re_t140.h>
#include "t140.h"


#define DEBUG_MODULE "t140"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * Text handed to t140_send() is buffered and drained on a fixed interval,
 * 300 ms by default, so that a fast typist produces a steady packet rate
 * instead of one packet per keystroke. This part is the same for every
 * transport.
 *
 * What the transport decides is what happens to the drained text. Over RTP
 * it is wrapped in RFC 2198 redundancy and carries a timestamp and a
 * marker bit; once the buffer runs dry the transmitter keeps sending
 * redundancy-only packets for as many intervals as there are generations,
 * so that the tail of a burst is protected as well as its head, and then
 * falls silent except for the optional keep-alive. Over a reliable data
 * channel none of that applies and the block goes out as it is.
 */


/**
 * Queue text for transmission
 *
 * The text is appended at the end of the buffer without disturbing the
 * read cursor, which the transmitter advances as it drains.
 */
int t140_tx_queue(struct t140 *t, const uint8_t *buf, size_t len)
{
	size_t pos;
	int err;

	if (!t || (len && !buf))
		return EINVAL;

	if (!len)
		return 0;

	if (t->txmb->end + len > T140_TXBUF_MAX)
		return EOVERFLOW;

	pos = t->txmb->pos;
	t->txmb->pos = t->txmb->end;

	err = mbuf_write_mem(t->txmb, buf, len);

	t->txmb->pos = pos;

	return err;
}


/**
 * Number of characters we are allowed to drain on one interval
 */
static unsigned tx_budget(const struct t140 *t)
{
	unsigned cps   = t->conf.cps   ? t->conf.cps   : T140_CPS;
	unsigned ptime = t->conf.ptime ? t->conf.ptime : T140_PTIME;
	unsigned n     = cps * ptime / 1000;

	return n ? n : 1;
}


/**
 * Build the next packet to transmit
 *
 * @param t   T.140 session
 * @param pkt Packet, set on return
 * @param mb  Buffer to encode into
 *
 * @return 0 if a packet was built, ENOENT if there is nothing to send,
 *         otherwise errorcode
 */
int t140_tx_build(struct t140 *t, struct t140_pkt *pkt, struct mbuf *mb)
{
	const uint8_t *buf = NULL;
	unsigned chars = 0;
	size_t len = 0;
	uint32_t tstamp = 0;
	uint64_t now;
	int err;

	if (!t || !pkt || !mb)
		return EINVAL;

	if (!(t->dir & SDP_SENDONLY)) {
		t->tx_idle = true;
		return ENOENT;
	}

	now = tmr_jiffies();

	if (mbuf_get_left(t->txmb)) {

		buf = mbuf_buf(t->txmb);
		len = t140_utf8_take(buf, mbuf_get_left(t->txmb),
				     T140_MAX_PKTSZ, tx_budget(t), &chars);
	}

	if (!len) {

		buf = NULL;

		if (t->tx_tail) {
			--t->tx_tail;
		}
		else if (T140_TRANSPORT_RTP != t->conf.transport ||
			 !t->conf.u.rtp.idle ||
			 (now - t->tx_last) < t->conf.u.rtp.idle) {

			t->tx_idle = true;
			return ENOENT;
		}
	}

	if (T140_TRANSPORT_RTP == t->conf.transport) {

		tstamp = t->ts_base + (uint32_t)(now - t->jfs);

		/*
		 * Redundant blocks are identified by their timestamp, so two
		 * packets built within the same millisecond would be
		 * indistinguishable and the receiver would discard the
		 * second one as a duplicate. Keep the clock strictly
		 * increasing.
		 */
		if (t->ts_valid && (int32_t)(tstamp - t->ts_last) <= 0)
			tstamp = t->ts_last + 1;
	}

	if (t->red)
		err = red_encode(t->red, mb, tstamp, buf, len);
	else if (len)
		err = mbuf_write_mem(mb, buf, len);
	else
		err = 0;

	if (err)
		return err;

	if (len) {
		mbuf_advance(t->txmb, len);

		if (!mbuf_get_left(t->txmb))
			mbuf_rewind(t->txmb);

		if (T140_TRANSPORT_RTP == t->conf.transport)
			t->tx_tail = t->conf.u.rtp.ngen;

		t->stats.tx_chars += chars;
	}

	memset(pkt, 0, sizeof(*pkt));

	pkt->mb = mb;

	if (T140_TRANSPORT_RTP == t->conf.transport) {

		pkt->marker = t->tx_idle;
		pkt->ts     = tstamp;
		pkt->pt     = t->red ? t->conf.u.rtp.pt_red : t->conf.u.rtp.pt;

		t->ts_last  = tstamp;
		t->ts_valid = true;
	}

	t->tx_idle = false;
	t->tx_last = now;
	++t->stats.tx_packets;

	return 0;
}


static void tmr_handler(void *arg)
{
	struct t140 *t = arg;
	struct t140_pkt pkt;
	struct mbuf *mb;
	int err;

	t140_tx_tmr_start(t);

	mb = mbuf_alloc(RTP_HEADER_SIZE + 256);
	if (!mb)
		return;

	mbuf_set_posend(mb, RTP_HEADER_SIZE, RTP_HEADER_SIZE);

	err = t140_tx_build(t, &pkt, mb);
	if (err) {
		if (ENOENT != err) {
			DEBUG_WARNING("tx_build failed (%m)\n", err);
		}
		goto out;
	}

	mbuf_set_pos(mb, RTP_HEADER_SIZE);

	err = t->sendh(&pkt, t->arg);
	if (err) {
		DEBUG_WARNING("send handler failed, packet dropped (%m)\n",
			      err);
	}

 out:
	mem_deref(mb);
}


void t140_tx_tmr_start(struct t140 *t)
{
	tmr_start(&t->tmr, t->conf.ptime ? t->conf.ptime : T140_PTIME,
		  tmr_handler, t);
}


/**
 * Allocate the RED encoder if the transport and the configuration call
 * for one. A reliable data channel never does.
 */
int t140_tx_red_alloc(struct t140 *t)
{
	int err;

	if (T140_TRANSPORT_RTP != t->conf.transport)
		return 0;

	if (!t->conf.u.rtp.pt_red || !t->conf.u.rtp.ngen)
		return 0;

	err = red_alloc(&t->red, t->conf.u.rtp.pt, t->conf.u.rtp.ngen);
	if (err)
		return err;

	red_set_pad(t->red, t->conf.u.rtp.red_pad);

	return 0;
}


/**
 * Allocate the transmit side
 */
int t140_tx_alloc(struct t140 *t)
{
	t->txmb = mbuf_alloc(256);
	if (!t->txmb)
		return ENOMEM;

	t->jfs     = tmr_jiffies();
	t->tx_last = t->jfs;
	t->ts_base = rand_u32();
	t->tx_idle = true;

	return t140_tx_red_alloc(t);
}
