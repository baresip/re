/**
 * @file t140.c  ITU-T T.140 Real-Time Text
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


/*
 * Implements the ITU-T T.140 presentation protocol, carried over RTP as
 * RFC 4103 defines it.
 *
 * T.140 text is a UTF-8 stream sent character by character, so that the
 * far end sees the text as it is typed. It is the text medium of Total
 * Conversation and the one required by NG112 and NG911: RFC 4103 with
 * RFC 2198 redundancy is what conformant emergency call-taking equipment
 * accepts.
 *
 * The application owns the transport. This module owns the text: it
 * buffers what is typed, drains it on a fixed interval, wraps it in
 * redundancy where the transport needs it, and on the way back recovers
 * what redundancy can recover and marks what it cannot.
 *
 * The transport is a parameter of the session, not a different API. What
 * differs between RFC 4103 and RFC 8865 is only whether the payload is
 * wrapped in RED and whether the RTP fields of struct t140_pkt carry
 * anything; the text engine above it is the same, which is what makes an
 * RTP to data-channel gateway a matter of cross-wiring two sessions.
 *
 * An application that would rather drive the clock itself, in lock step
 * with an audio thread say, skips t140_start() and calls t140_poll() on
 * its own interval.
 *
 * NOTE: RTP sequence number and SSRC are kept in the application. The RTP
 *       timestamp is generated here, because the redundancy depends on it.
 */


const char t140_rtpfmt[]     = "t140";
const char t140_red_rtpfmt[] = "red";


static void destructor(void *arg)
{
	struct t140 *t = arg;

	tmr_cancel(&t->tmr);

	mem_deref(t->red);
	mem_deref(t->txmb);
	mem_deref(t->rxmb);
}


/**
 * Validate a configuration against the transport it names
 */
static int conf_check(const struct t140_conf *conf)
{
	switch (conf->transport) {

	case T140_TRANSPORT_RTP:
		if (!conf->u.rtp.pt || conf->u.rtp.pt > 0x7f)
			return EINVAL;

		if (conf->u.rtp.pt_red > 0x7f)
			return EINVAL;

		if (conf->u.rtp.ngen > RED_MAX_GEN)
			return EINVAL;

		if (conf->u.rtp.pt_red && !conf->u.rtp.ngen)
			return EINVAL;

		return 0;

	case T140_TRANSPORT_DC:
		return 0;

	default:
		return EINVAL;
	}
}


/**
 * Allocate a new T.140 session
 *
 * The transport is fixed here and cannot change afterwards. Only
 * T140_TRANSPORT_RTP is implemented; T140_TRANSPORT_DC, the data channel
 * of RFC 8865, returns ENOSYS.
 *
 * @param t140p Pointer to allocated object
 * @param conf  Session configuration, including the transport
 * @param sendh Send handler, required to use the internal timer
 * @param recvh Receive handler
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_alloc(struct t140 **t140p, const struct t140_conf *conf,
	       t140_send_h *sendh, t140_recv_h *recvh, void *arg)
{
	struct t140 *t;
	int err;

	if (!t140p || !conf)
		return EINVAL;

	err = conf_check(conf);
	if (err)
		return err;

	if (T140_TRANSPORT_DC == conf->transport)
		return ENOSYS;

	t = mem_zalloc(sizeof(*t), destructor);
	if (!t)
		return ENOMEM;

	t->conf  = *conf;
	t->dir   = SDP_SENDRECV;
	t->sendh = sendh;
	t->recvh = recvh;
	t->arg   = arg;

	tmr_init(&t->tmr);

	err = t140_tx_alloc(t);
	if (err)
		goto out;

	t->rxmb = mbuf_alloc(256);
	if (!t->rxmb) {
		err = ENOMEM;
		goto out;
	}

	t140_rx_reset(t);

	/* T.140 allows the stream to open with a BOM */
	if (conf->bom)
		err = t140_send_bom(t);

 out:
	if (err)
		mem_deref(t);
	else
		*t140p = t;

	return err;
}


/**
 * Get the transport a session runs over
 *
 * @param t T.140 session
 *
 * @return Transport, T140_TRANSPORT_RTP if t is NULL
 */
enum t140_transport t140_transport(const struct t140 *t)
{
	return t ? t->conf.transport : T140_TRANSPORT_RTP;
}


/**
 * Update the configuration of a T.140 session
 *
 * The payload types, the number of generations and the transmission
 * interval may all change when the session is renegotiated. Any text
 * already queued is kept. The transport may not change: a configuration
 * naming a different one is refused with EINVAL.
 *
 * @param t    T.140 session
 * @param conf New configuration
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_update(struct t140 *t, const struct t140_conf *conf)
{
	bool running;
	int err;

	if (!t || !conf)
		return EINVAL;

	if (conf->transport != t->conf.transport)
		return EINVAL;

	err = conf_check(conf);
	if (err)
		return err;

	running = tmr_isrunning(&t->tmr);

	tmr_cancel(&t->tmr);

	t->red  = mem_deref(t->red);
	t->conf = *conf;

	err = t140_tx_red_alloc(t);
	if (err)
		return err;

	t->tx_tail = 0;
	t->tx_idle = true;

	if (running)
		t140_tx_tmr_start(t);

	return 0;
}


/**
 * Start the transmission timer
 *
 * @param t T.140 session
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_start(struct t140 *t)
{
	if (!t || !t->sendh)
		return EINVAL;

	if (tmr_isrunning(&t->tmr))
		return EALREADY;

	t140_tx_tmr_start(t);

	return 0;
}


/**
 * Stop the transmission timer
 *
 * @param t T.140 session
 */
void t140_stop(struct t140 *t)
{
	if (!t)
		return;

	tmr_cancel(&t->tmr);
}


/**
 * Set the direction of the text stream
 *
 * A stream that is not sending refuses t140_send(), and one that is not
 * receiving delivers nothing. This is what lets a relay operator mute one
 * leg of a call.
 *
 * @param t   T.140 session
 * @param dir Direction
 */
void t140_set_dir(struct t140 *t, enum sdp_dir dir)
{
	if (!t)
		return;

	t->dir = dir;

	if (SDP_INACTIVE == dir)
		tmr_cancel(&t->tmr);
}


/**
 * Send text
 *
 * The text is queued and transmitted on the next interval. It must be
 * well-formed UTF-8 and must not end in the middle of a code point.
 *
 * @param t    T.140 session
 * @param utf8 Text to send, UTF-8 encoded
 * @param len  Length of the text in bytes
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_send(struct t140 *t, const char *utf8, size_t len)
{
	int err;

	if (!t || (len && !utf8))
		return EINVAL;

	if (!(t->dir & SDP_SENDONLY))
		return EPERM;

	if (!len)
		return 0;

	err = t140_utf8_check((const uint8_t *)utf8, len);
	if (err)
		return err;

	return t140_tx_queue(t, (const uint8_t *)utf8, len);
}


/**
 * Send formatted text
 *
 * @param t   T.140 session
 * @param fmt Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_sendf(struct t140 *t, const char *fmt, ...)
{
	struct mbuf *mb;
	va_list ap;
	int err;

	if (!t || !fmt)
		return EINVAL;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	va_start(ap, fmt);
	err = mbuf_vprintf(mb, fmt, ap);
	va_end(ap);

	if (!err)
		err = t140_send(t, (const char *)mb->buf, mb->end);

	mem_deref(mb);

	return err;
}


/**
 * Queue a code point a number of times
 */
static int send_cp(struct t140 *t, uint32_t cp, unsigned count)
{
	struct mbuf *mb;
	unsigned i;
	int err = 0;

	if (!t)
		return EINVAL;

	if (!(t->dir & SDP_SENDONLY))
		return EPERM;

	if (!count)
		return 0;

	mb = mbuf_alloc(4 * count);
	if (!mb)
		return ENOMEM;

	for (i=0; i<count && !err; i++)
		err = t140_utf8_encode(mb, cp);

	if (!err)
		err = t140_tx_queue(t, mb->buf, mb->end);

	mem_deref(mb);

	return err;
}


/**
 * Send a backspace, erasing one character on the far end
 *
 * @param t     T.140 session
 * @param count Number of characters to erase
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_send_bs(struct t140 *t, unsigned count)
{
	return send_cp(t, T140_BS, count);
}


/**
 * Send a new line
 *
 * T.140 prefers U+2028 over CR, LF or CRLF as the line separator.
 *
 * @param t T.140 session
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_send_nl(struct t140 *t)
{
	return send_cp(t, T140_LS, 1);
}


/**
 * Send a byte order mark, opening the text stream
 *
 * @param t T.140 session
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_send_bom(struct t140 *t)
{
	return send_cp(t, T140_BOM, 1);
}


/**
 * Check if there is text waiting to be transmitted
 *
 * @param t T.140 session
 *
 * @return True if nothing is pending
 */
bool t140_is_empty(const struct t140 *t)
{
	if (!t)
		return true;

	return !mbuf_get_left(t->txmb) && !t->tx_tail;
}


/**
 * Poll a T.140 session for a packet to transmit
 *
 * For applications that drive the transmission interval themselves rather
 * than through t140_start(). On T140_TRANSPORT_RTP the buffer must have
 * room for an RTP header in front of the read position if it is to be
 * passed to rtp_send().
 *
 * @param t   T.140 session
 * @param pkt Packet, set on return
 * @param mb  Buffer to encode into
 *
 * @return 0 if a packet was built, ENOENT if there is nothing to send,
 *         otherwise errorcode
 */
int t140_poll(struct t140 *t, struct t140_pkt *pkt, struct mbuf *mb)
{
	return t140_tx_build(t, pkt, mb);
}


/**
 * Fill in a packet from an RTP header
 *
 * A convenience for the receive path of T140_TRANSPORT_RTP, so that no
 * caller forgets the marker bit, which is what tells the receiver a new
 * burst has started.
 *
 * @param pkt Packet, set on return
 * @param hdr RTP header
 * @param mb  Buffer holding the payload
 */
void t140_pkt_rtp(struct t140_pkt *pkt, const struct rtp_header *hdr,
		  struct mbuf *mb)
{
	if (!pkt || !hdr)
		return;

	pkt->mb     = mb;
	pkt->ts     = hdr->ts;
	pkt->seq    = hdr->seq;
	pkt->pt     = hdr->pt;
	pkt->marker = hdr->m;
}


/**
 * Get the counters of a T.140 session
 *
 * @param t     T.140 session
 * @param stats Counters, set on return
 */
void t140_stats_get(const struct t140 *t, struct t140_stats *stats)
{
	if (!t || !stats)
		return;

	*stats = t->stats;
}


static const char *transport_name(enum t140_transport transport)
{
	switch (transport) {

	case T140_TRANSPORT_RTP: return "rtp";
	case T140_TRANSPORT_DC:  return "datachannel";
	default:                 return "?";
	}
}


/**
 * Print debug information about a T.140 session
 *
 * @param pf Print function
 * @param t  T.140 session
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_debug(struct re_printf *pf, const struct t140 *t)
{
	int err;

	if (!t)
		return 0;

	err = re_hprintf(pf, "t140: transport=%s ptime=%u cps=%u dir=%s\n",
			 transport_name(t->conf.transport),
			 t->conf.ptime ? t->conf.ptime : T140_PTIME,
			 t->conf.cps ? t->conf.cps : T140_CPS,
			 sdp_dir_name(t->dir));

	if (T140_TRANSPORT_RTP == t->conf.transport) {

		err |= re_hprintf(pf, "  pt=%u pt_red=%u ngen=%u\n",
				  t->conf.u.rtp.pt, t->conf.u.rtp.pt_red,
				  t->conf.u.rtp.ngen);
	}

	err |= re_hprintf(pf, "  tx: queued=%zu chars=%llu packets=%llu\n",
			  mbuf_get_left(t->txmb),
			  t->stats.tx_chars, t->stats.tx_packets);

	err |= re_hprintf(pf, "  rx: chars=%llu packets=%llu recovered=%llu"
			  " lost=%llu dup=%llu\n",
			  t->stats.rx_chars, t->stats.rx_packets,
			  t->stats.rx_recovered, t->stats.rx_lost,
			  t->stats.rx_dup);

	if (t->red)
		err |= re_hprintf(pf, "  %H", red_debug, t->red);

	return err;
}
