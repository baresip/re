/**
 * @file rtp/sess.c  Real-time Transport Control Protocol Session
 *
 * Copyright (C) 2010 Creytiv.com
 */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>
#ifdef WIN32
#include <winsock2.h>
#endif
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_thread.h>
#include <re_rtp.h>
#include "rtcp.h"


#define DEBUG_MODULE "rtcp_sess"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/** RTP protocol values */
enum {
	RTCP_INTERVAL = 5000,  /**< Interval in [ms] between sending reports */
	MAX_MEMBERS   = 8,
};

/** RTP Transmit stats */
struct txstat {
	uint32_t psent;      /**< Total number of RTP packets sent */
	uint32_t osent;      /**< Total number of RTP octets  sent */
	uint64_t jfs_rt_ref; /**< Realtime clock timer ticks at RTP timestamp
	                      *   reference */
	uint32_t ts_ref;     /**< RTP timestamp reference (transmit)     */
	bool ts_synced;      /**< RTP timestamp synchronization flag     */
};

/** RTCP Session */
struct rtcp_sess {
	struct rtp_sock *rs;        /**< RTP Socket                          */
	struct hash *members;       /**< Member table                        */
	struct tmr tmr;             /**< Event sender timer                  */
	char *cname;                /**< Canonical Name                      */
	uint32_t memberc;           /**< Number of members                   */
	uint32_t senderc;           /**< Number of senders                   */
	uint32_t srate_tx;          /**< Transmit sampling rate              */
	uint32_t srate_rx;          /**< Receive sampling rate               */
	uint32_t interval;          /**< RTCP interval in [ms]               */
	mtx_t *lock;                /**< Lock for rtcp_sess                  */

	/* stats */
	struct txstat txstat;       /**< Local transmit statistics           */
};


/* Prototypes */
static void schedule(struct rtcp_sess *sess);


static void sess_destructor(void *data)
{
	struct rtcp_sess *sess = data;

	tmr_cancel(&sess->tmr);

	mem_deref(sess->cname);
	hash_flush(sess->members);
	mem_deref(sess->members);
	mem_deref(sess->lock);
}


static struct rtp_member *get_member(struct rtcp_sess *sess, uint32_t src)
{
	struct rtp_member *mbr;

	mbr = rtp_member_find(sess->members, src);
	if (mbr)
		return mbr;

	if (sess->memberc >= MAX_MEMBERS)
		return NULL;

	mbr = rtp_member_add(sess->members, src);
	if (!mbr)
		return NULL;

	++sess->memberc;

	return mbr;
}


/**
 * Calculate Round-Trip Time in [microseconds]
 *
 * @param rtt  Calculated Rount-Trip time [us]
 * @param lsr  Last SR packet from this source [compact NTP timestamp]
 * @param dlsr Delay since last SR packet [units of 1/65536 seconds]
 */
void rtcp_calc_rtt(uint32_t *rtt, uint32_t lsr, uint32_t dlsr)
{
	struct rtp_ntp_time ntp_time;
	uint64_t a_us, lsr_us, dlsr_us;

	ntp_time_get(&ntp_time, NULL);

	a_us    = ntp_compact2us(ntp_compact(&ntp_time));
	lsr_us  = ntp_compact2us(lsr);
	dlsr_us = 1000000ULL * dlsr / 65536;

	/* RTT delay is (A - LSR - DLSR) */
	if (rtt)
		*rtt = MAX((int)(a_us - lsr_us - dlsr_us), 0);
}


/** Decode Reception Report block */
static void handle_rr_block(struct rtcp_sess *sess, struct rtp_member *mbr,
			    const struct rtcp_rr *rr)
{
	/* Lost */
	mbr->cum_lost = rr->lost;

	/* Interarrival jitter */
	if (sess->srate_tx)
		mbr->jit = 1000000 * rr->jitter / sess->srate_tx;

	/* round-trip propagation delay as (A - LSR - DLSR) */
	if (rr->lsr && rr->dlsr)
		rtcp_calc_rtt(&mbr->rtt, rr->lsr, rr->dlsr);
}


/** Handle incoming RR (Receiver Report) packet */
static void handle_incoming_rr(struct rtcp_sess *sess,
			       const struct rtcp_msg *msg)
{
	struct rtp_member *mbr;
	uint32_t i;

	mbr = get_member(sess, msg->r.rr.ssrc);
	if (!mbr)
		return;

	for (i=0; i<msg->hdr.count; i++)
		handle_rr_block(sess, mbr, &msg->r.rr.rrv[i]);
}


/** Handle incoming SR (Sender Report) packet */
static void handle_incoming_sr(struct rtcp_sess *sess,
			       const struct rtcp_msg *msg)
{
	struct rtp_member *mbr;
	uint32_t i;

	mbr = get_member(sess, msg->r.sr.ssrc);
	if (!mbr) {
		DEBUG_WARNING("0x%08x: could not add member\n",
			      msg->r.sr.ssrc);
		return;
	}

	if (mbr->s) {
		/* Save time when SR was received */
		mbr->s->sr_recv = tmr_jiffies();

		/* Save NTP timestamp from SR */
		mbr->s->last_sr.hi = msg->r.sr.ntp_sec;
		mbr->s->last_sr.lo = msg->r.sr.ntp_frac;
		mbr->s->rtp_ts     = msg->r.sr.rtp_ts;
		mbr->s->psent      = msg->r.sr.psent;
		mbr->s->osent      = msg->r.sr.osent;
	}

	for (i=0; i<msg->hdr.count; i++)
		handle_rr_block(sess, mbr, &msg->r.sr.rrv[i]);
}


static void handle_incoming_bye(struct rtcp_sess *sess,
				const struct rtcp_msg *msg)
{
	uint32_t i;

	for (i=0; i<msg->hdr.count; i++) {

		struct rtp_member *mbr;

		mbr = rtp_member_find(sess->members, msg->r.bye.srcv[i]);
		if (mbr) {
			if (mbr->s)
				--sess->senderc;

			--sess->memberc;
			mem_deref(mbr);
		}
	}
}


void rtcp_handler(struct rtcp_sess *sess, struct rtcp_msg *msg)
{
	if (!sess || !msg)
		return;

	mtx_lock(sess->lock);
	switch (msg->hdr.pt) {

	case RTCP_SR:
		handle_incoming_sr(sess, msg);
		break;

	case RTCP_RR:
		handle_incoming_rr(sess, msg);
		break;

	case RTCP_BYE:
		handle_incoming_bye(sess, msg);
		break;

	default:
		break;
	}

	mtx_unlock(sess->lock);
}


int rtcp_sess_alloc(struct rtcp_sess **sessp, struct rtp_sock *rs)
{
	struct rtcp_sess *sess;
	int err;

	if (!sessp)
		return EINVAL;

	sess = mem_zalloc(sizeof(*sess), sess_destructor);
	if (!sess)
		return ENOMEM;

	sess->rs = rs;
	tmr_init(&sess->tmr);

	sess->interval = RTCP_INTERVAL;

	err = mutex_alloc(&sess->lock);
	if (err)
		goto out;

	err  = hash_alloc(&sess->members, MAX_MEMBERS);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(sess);
	else
		*sessp = sess;

	return err;
}


/**
 * Set interval between sending reports on an RTCP Session
 *
 * @param rs  RTP Socket
 * @param n   RTCP interval in [ms]
 */
void rtcp_set_interval(struct rtp_sock *rs, uint32_t n)
{
	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	if (!sess)
		return;

	sess->interval = n;
}


/**
 * Set the Sampling-rate on an RTCP Session
 *
 * @param rs       RTP Socket
 * @param srate_tx Transmit samplerate
 * @param srate_rx Receive samplerate
 */
void rtcp_set_srate(struct rtp_sock *rs, uint32_t srate_tx, uint32_t srate_rx)
{
	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	if (!sess)
		return;

	mtx_lock(sess->lock);
	sess->srate_tx = srate_tx;
	sess->srate_rx = srate_rx;
	mtx_unlock(sess->lock);
}


/**
 * Set the transmit Sampling-rate on an RTCP Session
 *
 * @param rs       RTP Socket
 * @param srate_tx Transmit samplerate
 */
void rtcp_set_srate_tx(struct rtp_sock *rs, uint32_t srate_tx)
{
	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	if (!sess)
		return;

	mtx_lock(sess->lock);
	sess->srate_tx = srate_tx;
	mtx_unlock(sess->lock);
}


/**
 * Set the receive Sampling-rate on an RTCP Session
 *
 * @param rs       RTP Socket
 * @param srate_rx Receive samplerate
 */
void rtcp_set_srate_rx(struct rtp_sock *rs, uint32_t srate_rx)
{
	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	if (!sess)
		return;

	mtx_lock(sess->lock);
	sess->srate_rx = srate_rx;
	mtx_unlock(sess->lock);
}


int rtcp_enable(struct rtcp_sess *sess, bool enabled, const char *cname)
{
	int err;

	if (!sess)
		return EINVAL;

	mtx_lock(sess->lock);
	sess->cname = mem_deref(sess->cname);
	err = str_dup(&sess->cname, cname);
	mtx_unlock(sess->lock);
	if (err)
		return err;

	if (enabled)
		schedule(sess);
	else
		tmr_cancel(&sess->tmr);

	return 0;
}


/** Calculate LSR (middle 32 bits out of 64 in the NTP timestamp) */
static uint32_t calc_lsr(const struct rtp_ntp_time *last_sr)
{
	return last_sr->hi ? ntp_compact(last_sr) : 0;
}


static uint32_t calc_dlsr(uint64_t sr_recv)
{
	if (sr_recv) {
		const uint64_t diff = tmr_jiffies() - sr_recv;
		return (uint32_t)((65536 * diff) / 1000);
	}
	else {
		return 0;
	}
}


static bool sender_apply_handler(struct le *le, void *arg)
{
	struct rtp_member *mbr = le->data;
	struct rtp_source *s = mbr->s;
	struct mbuf *mb = arg;
	struct rtcp_rr rr;

	if (!s)
		return false;

	/* Initialise the members */
	rr.ssrc     = mbr->src;
	rr.fraction = rtp_source_calc_fraction_lost(s);
	rr.lost     = rtp_source_calc_lost(s);
	rr.last_seq = s->cycles | s->max_seq;
	rr.jitter   = s->jitter >> 4;
	rr.lsr      = calc_lsr(&s->last_sr);
	rr.dlsr     = calc_dlsr(s->sr_recv);

	return 0 != rtcp_rr_encode(mb, &rr);
}


static int encode_handler(struct mbuf *mb, void *arg)
{
	struct hash *members = arg;

	/* copy all report blocks */
	if (hash_apply(members, sender_apply_handler, mb))
		return ENOMEM;

	return 0;
}


/** Create a Sender Report */
static int mk_sr(struct rtcp_sess *sess, struct mbuf *mb)
{
	struct txstat txstat;
	uint32_t srate_tx;
	int err;

	mtx_lock(sess->lock);
	txstat = sess->txstat;
	srate_tx = sess->srate_tx;
	sess->txstat.ts_synced = false;
	mtx_unlock(sess->lock);

	if (txstat.jfs_rt_ref) {
		struct rtp_ntp_time ntp;
		uint64_t jfs_rt, dur;
		uint32_t rtp_ts;

		ntp_time_get(&ntp, &jfs_rt);

		dur = jfs_rt - txstat.jfs_rt_ref;
		rtp_ts = (uint32_t)((uint64_t)txstat.ts_ref + dur *
				    srate_tx / 1000000u);

		err = rtcp_encode(mb, RTCP_SR, sess->senderc,
				  rtp_sess_ssrc(sess->rs), ntp.hi, ntp.lo,
				  rtp_ts, txstat.psent, txstat.osent,
				  encode_handler, sess->members);
	}
	else {
		/* No packets were sent yet, no NTP/RTP timestamps available,
		 * generate receiver report */
		err = rtcp_encode(mb, RTCP_RR, sess->senderc,
				  rtp_sess_ssrc(sess->rs),
				  encode_handler, sess->members);
	}

	return err;
}


int rtcp_make_sr(const struct rtp_sock *rs, struct mbuf *mb)
{
	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	if (!sess)
		return EINVAL;

	return mk_sr(sess, mb);
}


static int sdes_encode_handler(struct mbuf *mb, void *arg)
{
	struct rtcp_sess *sess = arg;
	int err;

	mtx_lock(sess->lock);
	err = rtcp_sdes_encode(mb, rtp_sess_ssrc(sess->rs), 1,
				RTCP_SDES_CNAME, sess->cname);
	mtx_unlock(sess->lock);

	return err;
}


static int mk_sdes(struct rtcp_sess *sess, struct mbuf *mb)
{
	return rtcp_encode(mb, RTCP_SDES, 1, sdes_encode_handler, sess);
}


int rtcp_make_sdes_cname(const struct rtp_sock *rs, struct mbuf *mb)
{
	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	if (!sess)
		return EINVAL;

	return mk_sdes(sess, mb);
}


static int send_rtcp_report(struct rtcp_sess *sess)
{
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	mb->pos = RTCP_HEADROOM;

	err  = mk_sr(sess, mb);
	err |= mk_sdes(sess, mb);
	if (err)
		goto out;

	mb->pos = RTCP_HEADROOM;

	err = rtcp_send(sess->rs, mb);

 out:
	mem_deref(mb);
	return err;
}


int rtcp_send_bye_packet(struct rtp_sock *rs)
{
	if (!rs)
		return EINVAL;

	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	const uint32_t ssrc = rtp_sess_ssrc(rs);
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	mb->pos = RTCP_HEADROOM;

	err  = rtcp_encode(mb, RTCP_BYE, 1, &ssrc, "Adjo");
	err |= mk_sdes(sess, mb);
	if (err)
		goto out;

	mb->pos = RTCP_HEADROOM;

	err = rtcp_send(sess->rs, mb);

 out:
	mem_deref(mb);
	return err;
}


static void timeout(void *arg)
{
	struct rtcp_sess *sess = arg;
	int err;

	err = send_rtcp_report(sess);
	if (err) {
		DEBUG_WARNING("Send RTCP report failed: %m\n", err);
	}

	schedule(sess);
}


static void schedule(struct rtcp_sess *sess)
{
	tmr_start(&sess->tmr, sess->interval, timeout, sess);
}


void rtcp_schedule_report(const struct rtp_sock *rs)
{
	struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	if (!sess)
		return;

	tmr_start(&sess->tmr, sess->interval, timeout, sess);
}


void rtcp_sess_tx_rtp(struct rtcp_sess *sess, uint32_t ts, uint64_t jfs_rt,
			   size_t payload_size)
{
	if (!sess)
		return;

	mtx_lock(sess->lock);

	sess->txstat.osent += (uint32_t)payload_size;
	sess->txstat.psent += 1;

	if (!sess->txstat.ts_synced) {
		sess->txstat.jfs_rt_ref = jfs_rt;
		sess->txstat.ts_ref     = ts;
		sess->txstat.ts_synced  = true;
	}

	mtx_unlock(sess->lock);
}


void rtcp_sess_rx_rtp(struct rtcp_sess *sess, struct rtp_header *hdr,
		      size_t payload_size, const struct sa *peer)
{
	struct rtp_member *mbr;

	if (!sess)
		return;

	mtx_lock(sess->lock);
	mbr = get_member(sess, hdr->ssrc);
	if (!mbr) {
		DEBUG_NOTICE("could not add member: 0x%08x\n", hdr->ssrc);
		goto out;
	}

	if (!mbr->s) {
		mbr->s = mem_zalloc(sizeof(*mbr->s), NULL);
		if (!mbr->s) {
			DEBUG_NOTICE("could not add sender: 0x%08x\n",
				     hdr->ssrc);
			goto out;
		}

		/* first packet - init sequence number */
		rtp_source_init_seq(mbr->s, hdr->seq);
		/* probation not used */
		sa_cpy(&mbr->s->rtp_peer, peer);
		++sess->senderc;
	}

	if (!rtp_source_update_seq(mbr->s, hdr->seq)) {
		DEBUG_WARNING("rtp_source_update_seq() returned 0\n");
	}

	if (sess->srate_rx) {
		/* Convert from wall-clock time to timestamp units */
		hdr->ts_arrive = tmr_jiffies() * sess->srate_rx / 1000;

		/*
		 * Calculate jitter only when the timestamp is different than
		 * last packet (see RTP FAQ
		 * https://www.cs.columbia.edu/~hgs/rtp/faq.html#jitter).
		 */
		if (hdr->ts != mbr->s->last_rtp_ts)
			rtp_source_calc_jitter(mbr->s, hdr->ts,
					   (uint32_t)hdr->ts_arrive);
	}

	mbr->s->last_rtp_ts = hdr->ts;
	mbr->s->rtp_rx_bytes += payload_size;
out:
	mtx_unlock(sess->lock);
}


/**
 * Get the RTCP Statistics for a source
 *
 * @param rs    RTP Socket
 * @param ssrc  Synchronization source
 * @param stats RTCP Statistics, set on return
 *
 * @return 0 if success, otherwise errorcode
 */
int rtcp_stats(struct rtp_sock *rs, uint32_t ssrc, struct rtcp_stats *stats)
{
	const struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	struct rtp_member *mbr;
	int err = 0;

	if (!sess || !stats)
		return EINVAL;

	mtx_lock(sess->lock);
	mbr = rtp_member_find(sess->members, ssrc);
	if (!mbr) {
		err = ENOENT;
		goto out;
	}

	stats->tx.sent = sess->txstat.psent;

	stats->tx.lost = mbr->cum_lost;
	stats->tx.jit  = mbr->jit;

	stats->rtt = mbr->rtt;

	if (!mbr->s) {
		memset(&stats->rx, 0, sizeof(stats->rx));
		goto out;
	}

	stats->rx.sent = mbr->s->received;
	stats->rx.lost = rtp_source_calc_lost(mbr->s);
	stats->rx.jit  = sess->srate_rx ?
		1000000 * (mbr->s->jitter>>4) / sess->srate_rx : 0;

out:
	mtx_unlock(sess->lock);
	return err;
}


static bool debug_handler(struct le *le, void *arg)
{
	const struct rtp_member *mbr = le->data;
	struct mbuf *mb = arg;
	int err;

	err = mbuf_printf(mb, "  member 0x%08x: lost=%d Jitter=%.1fms"
			  " RTT=%.1fms\n", mbr->src, mbr->cum_lost,
			  (double)mbr->jit/1000, (double)mbr->rtt/1000);
	if (mbr->s) {
		err |= mbuf_printf(mb,
				   "                 IP=%J psent=%u rcvd=%u\n",
				   &mbr->s->rtp_peer, mbr->s->psent,
				   mbr->s->received);
	}

	return err != 0;
}


/**
 * RTCP Debug handler, use with fmt %H
 *
 * @param pf Print function
 * @param rs RTP Socket
 *
 * @return 0 if success, otherwise errorcode
 */
int rtcp_debug(struct re_printf *pf, const struct rtp_sock *rs)
{
	const struct rtcp_sess *sess = rtp_rtcp_sess(rs);
	struct mbuf *mb;
	int err = 0;

	if (!sess)
		return 0;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err |= mbuf_printf(mb, "----- RTCP Session: -----\n");
	mtx_lock(sess->lock);
	err |= mbuf_printf(mb, "  cname=%s SSRC=0x%08x/%u rx=%uHz\n",
			  sess->cname,
			  rtp_sess_ssrc(sess->rs), rtp_sess_ssrc(sess->rs),
			  sess->srate_rx);

	hash_apply(sess->members, debug_handler, mb);

	err |= mbuf_printf(mb, "  TX: packets=%u, octets=%u\n",
			  sess->txstat.psent, sess->txstat.osent);
	mtx_unlock(sess->lock);

	if (err)
		goto out;

	err = re_hprintf(pf, "%b", mb->buf, mb->pos);

out:
	mem_deref(mb);
	return err;
}
