/**
 * @file rtcp.c Tests for RTCP
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "rtcp_test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 *  .------.       RTP
 *  | RTP  | <--------------- [ Packet Generator ]
 *  | RTCP |
 *  '------'
 */


static const uint32_t GENERATOR_SSRC = 0x00000001;


struct fixture {
	struct rtp_sock *rtp;
	struct sa rtp_addr;
	size_t n_recv;
	size_t num_packets;
};


static int send_rtp_packet(struct udp_sock *us, const struct sa *dst,
			   uint16_t seq, uint32_t ssrc)
{
	struct rtp_header hdr;
	struct mbuf *mb = mbuf_alloc(256);
	int err;

	if (!mb)
		return ENOMEM;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ver  = RTP_VERSION;
	hdr.seq  = seq;
	hdr.ts   = 0;
	hdr.ssrc = ssrc;

	err = rtp_hdr_encode(mb, &hdr);
	if (err)
		goto out;
	mbuf_fill(mb, 160, 0x00);
	mb->pos = 0;

	err = udp_send(us, dst, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);
	return err;
}


static void rtp_recv(const struct sa *src, const struct rtp_header *hdr,
		     struct mbuf *mb, void *arg)
{
	struct fixture *f = arg;
	(void)src;
	(void)hdr;
	(void)mb;

	++f->n_recv;

	if (f->n_recv >= f->num_packets) {
		re_cancel();
	}
}


static int fixture_init(struct fixture *f)
{
	int err;

	memset(f, 0, sizeof(*f));

	err = sa_set_str(&f->rtp_addr, "127.0.0.1", 0);
	TEST_ERR(err);

	err = rtp_listen(&f->rtp, IPPROTO_UDP, &f->rtp_addr, 10000, 49152,
			 true, rtp_recv, NULL, f);
	if (err)
		goto out;

	err = udp_local_get(rtp_sock(f->rtp), &f->rtp_addr);
	TEST_ERR(err);

 out:
	return err;
}


static void fixture_close(struct fixture *f)
{
	mem_deref(f->rtp);
}


static int test_loss(const uint16_t *seqv, size_t seqc,
		     int exp_lost)
{
	struct fixture fix, *f = &fix;
	struct rtcp_stats stats;
	uint32_t ssrc = GENERATOR_SSRC;
	unsigned i;
	int err, e;

	err = fixture_init(f);
	if (err)
		goto out;

	f->num_packets = seqc;

	/* no sources exist yet */
	e = rtcp_stats(f->rtp, ssrc, &stats);
	TEST_EQUALS(ENOENT, e);

	/* start the RTP packet generator, send X number of RTP packets
	 * to the RTP-stack (fixture)
	 */
	for (i=0; i<seqc; i++) {
		uint16_t seq = seqv[i];

		err = send_rtp_packet(rtp_sock(f->rtp), &f->rtp_addr,
				      seq, ssrc);
		if (err)
			goto out;
	}

	err = re_main_timeout(200);
	TEST_ERR(err);

	err = rtcp_stats(f->rtp, ssrc, &stats);
	if (err) {
		if (err == ENOENT)
			err = ENOMEM;
		TEST_ERR(err);
	}

	/* in OOM-test, detect if member/sender was not allocated */
	if (stats.rx.sent == 0 &&
	    stats.rx.lost == 0 &&
	    stats.rx.jit == 0) {

		err = ENOMEM;
		TEST_ERR(err);
	}

	if (test_mode == TEST_MEMORY)
		goto out;

	/* verify expected packets sent and packet loss */
	TEST_EQUALS(seqc, stats.rx.sent);
	TEST_EQUALS(exp_lost, stats.rx.lost);

	TEST_EQUALS(seqc, f->n_recv);

 out:
	fixture_close(f);
	return err;
}


int test_rtcp_packetloss(void)
{
	static const uint16_t seqv1[] = {0, 1, 2};
	static const uint16_t seqv2[] = {0,1,3,2,5,4};
	static const uint16_t seqv3[] = {65534, 65535, 0, 1};
	static const uint16_t seqv4[] = {65534, 0, 1};
	static const uint16_t seqv5[] = {65534, 1, 2};
	static const uint16_t seqv6[] = {65534, 1, 2, 65535};
	static const uint16_t seqv7[] = {1,2,8,9,10};
	int err = 0;

	err = test_loss(seqv1, RE_ARRAY_SIZE(seqv1), 0);
	TEST_ERR(err);
	err = test_loss(seqv2, RE_ARRAY_SIZE(seqv2), 0);
	TEST_ERR(err);
	err = test_loss(seqv3, RE_ARRAY_SIZE(seqv3), 0);
	TEST_ERR(err);
	err = test_loss(seqv4, RE_ARRAY_SIZE(seqv4), 1);
	TEST_ERR(err);
	err = test_loss(seqv5, RE_ARRAY_SIZE(seqv5), 2);
	TEST_ERR(err);
	err = test_loss(seqv6, RE_ARRAY_SIZE(seqv6), 1);
	TEST_ERR(err);
	err = test_loss(seqv7, RE_ARRAY_SIZE(seqv7), 5);
	TEST_ERR(err);

out:
	return err;
}


struct agent {
	struct agent *peer;
	struct rtp_sock *rtp_sock;
	struct sa laddr_rtp;
	struct sa laddr_rtcp;
	unsigned step;
	unsigned rtp_count;
	unsigned psfb_count;
	unsigned rtpfb_count;
	unsigned gnack_count;
	unsigned app_count;
	int err;
};


static bool agents_are_complete(const struct agent *ag)
{
	return ag->app_count && ag->peer->app_count;
}


static int agent_send_rtcp_packet(struct agent *ag)
{
	struct mbuf *mb_chunks = NULL;
	struct mbuf *mb_deltas = NULL;
	const uint8_t fir_seqn = 22;
	int err = 0;

	switch (ag->step) {

	case 0:
		err = rtcp_send_fir_rfc5104(ag->rtp_sock,
					    rtp_sess_ssrc(ag->peer->rtp_sock),
					    fir_seqn);
		break;

	case 1:
		err = rtcp_send_gnack(ag->rtp_sock,
				      rtp_sess_ssrc(ag->peer->rtp_sock),
				      42, 0);
		break;

	case 2:
		err = rtcp_send_pli(ag->rtp_sock,
				    rtp_sess_ssrc(ag->peer->rtp_sock));
		break;

	case 3: {
		mb_chunks = mbuf_alloc(32);
		mb_deltas = mbuf_alloc(32);
		if (!mb_chunks || !mb_deltas) {
			err = ENOMEM;
			goto out;
		}

		static const uint8_t chunks[] = {
			0xad, 0xe0
		};
		static const uint8_t deltas[] = {
			0x14, 0x18, 0x18, 0x38, 0x00, 0x00, 0x00
		};
		mbuf_write_mem(mb_chunks, chunks, sizeof(chunks));
		mbuf_write_mem(mb_deltas, deltas, sizeof(deltas));

		mbuf_set_pos(mb_chunks, 0);
		mbuf_set_pos(mb_deltas, 0);

		struct twcc twcc = {
			.seq     = 11,
			.count   = 22,
			.reftime = 33,
			.fbcount = 44,
			.chunks  = mb_chunks,
			.deltas  = mb_deltas,
		};

		err = rtcp_send_twcc(ag->rtp_sock,
				     rtp_sess_ssrc(ag->peer->rtp_sock), &twcc);
	}
		break;

	case 4:
		/* NOTE: must be last */
		err = rtcp_send_app(ag->rtp_sock, "PING", (void *)"PONG", 4);
		break;

	default:
		DEBUG_NOTICE("agent_send_rtcp_packet: invalid step (%u)\n",
			     ag->step);
		break;
	}

	++ag->step;

 out:
	mem_deref(mb_chunks);
	mem_deref(mb_deltas);

	return err;
}


static void rtp_recv_handler(const struct sa *src,
			     const struct rtp_header *hdr,
			     struct mbuf *mb, void *arg)
{
	struct agent *ag = arg;
	(void)src;
	(void)hdr;
	(void)mb;

	++ag->rtp_count;

	if (ag->step == 0) {

		int err = agent_send_rtcp_packet(ag);
		if (err) {
			ag->err = err;
			re_cancel();
		}
	}
}


static void rtcp_recv_handler(const struct sa *src, struct rtcp_msg *msg,
			      void *arg)
{
	struct agent *ag = arg;
	int err = 0;
	(void)src;

	switch (msg->hdr.pt) {

	case RTCP_RTPFB:
		if (msg->r.fb.fci.gnackv->pid == 42)
			++ag->gnack_count;
		++ag->rtpfb_count;
		err = agent_send_rtcp_packet(ag);
		break;

	case RTCP_PSFB:
		++ag->psfb_count;

		err = agent_send_rtcp_packet(ag);
		break;

	case RTCP_APP:
		++ag->app_count;
		break;

	case RTCP_SR:
	case RTCP_SDES:
		/* ignore */
		break;

	default:
		DEBUG_WARNING("unexpected RTCP message: %H\n",
			      rtcp_msg_print, msg);
		err = EPROTO;
		break;
	}

	if (agents_are_complete(ag)) {
		re_cancel();
		return;
	}

	if (err) {
		ag->err = err;
		re_cancel();
	}
}


static int agent_init(struct agent *ag, bool mux)
{
	struct sa laddr;

	sa_set_str(&laddr, "127.0.0.1", 0);

	int err = rtp_listen(&ag->rtp_sock, IPPROTO_UDP,
			     &laddr, 1024, 65535, true,
			     rtp_recv_handler, rtcp_recv_handler, ag);
	if (err)
		return err;

	rtcp_enable_mux(ag->rtp_sock, mux);

	udp_local_get(rtp_sock(ag->rtp_sock), &ag->laddr_rtp);
	udp_local_get(rtcp_sock(ag->rtp_sock), &ag->laddr_rtcp);

	return 0;
}


static int test_rtcp_loop_param(bool mux)
{
	struct agent a = {0}, b = {0};
	struct mbuf *mb = NULL;
	int err;

	err = agent_init(&a, mux);
	TEST_ERR(err);
	err = agent_init(&b, mux);
	TEST_ERR(err);

	a.peer = &b;
	b.peer = &a;

	rtcp_start(a.rtp_sock, "cname", &b.laddr_rtcp);
	rtcp_start(b.rtp_sock, "cname", &a.laddr_rtcp);

	mb = mbuf_alloc(RTP_HEADER_SIZE + 1);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	mbuf_fill(mb, 0x00, RTP_HEADER_SIZE + 1);

	/* Send some RTP-packets to enable RTCP-SR */
	for (unsigned i=0; i<4; i++) {

		uint64_t jfs = tmr_jiffies_rt_usec();

		mb->pos = RTP_HEADER_SIZE;

		err = rtp_send(a.rtp_sock, &b.laddr_rtp, false,
			       false, 0, 160, jfs, mb);
		TEST_ERR(err);

		mb->pos = RTP_HEADER_SIZE;

		err = rtp_send(b.rtp_sock, &a.laddr_rtp, false,
			       false, 0, 160, jfs, mb);
		TEST_ERR(err);
	}

	err = re_main_timeout(1000);
	TEST_ERR(err);

	ASSERT_EQ(0, a.err);
	ASSERT_EQ(0, b.err);

	ASSERT_TRUE(a.rtp_count >= 1);
	ASSERT_EQ(2, a.psfb_count);
	ASSERT_EQ(1, a.app_count);

	ASSERT_TRUE(b.rtp_count >= 1);
	ASSERT_EQ(2, b.psfb_count);
	ASSERT_EQ(2, b.rtpfb_count);
	ASSERT_EQ(1, b.gnack_count);
	ASSERT_EQ(1, b.app_count);

 out:
	mem_deref(b.rtp_sock);
	mem_deref(a.rtp_sock);
	mem_deref(mb);

	return err;
}


int test_rtcp_loop(void)
{
	int err;

	err = test_rtcp_loop_param(false);
	TEST_ERR(err);

	err = test_rtcp_loop_param(true);
	TEST_ERR(err);

 out:
	return err;
}


static int rrtr_encode_handler(struct mbuf *mb, void *arg)
{
	int err = 0;
	(void)arg;

	err |= mbuf_write_u8(mb, RTCP_XR_RRTR);
	err |= mbuf_write_u8(mb, 0);  /* reserved */
	err |= mbuf_write_u16(mb, htons(2));
	err |= mbuf_write_u32(mb, htonl(0x01020304));
	err |= mbuf_write_u32(mb, htonl(0x05060708));

	return err;
}


static int test_rtcp_xr_rrtr(void)
{
	const uint8_t packet[] = {
		/* header */
		0x80, 0xcf, 0x00, 0x04,

		/* RTCP-XR */
		0x00, 0x00, 0x00, 0x01,
		0x04, 0x00, 0x00, 0x02,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08
	};

	struct mbuf *buf = mbuf_alloc(sizeof(packet));
	if (!buf)
		return ENOMEM;

	struct rtcp_msg *msg = NULL;
	const uint32_t ssrc = 1;
	int err = 0;

	err = rtcp_encode(buf, RTCP_XR, 0, ssrc, rrtr_encode_handler, NULL);
	TEST_ERR(err);

	mbuf_set_pos(buf, 0);

	TEST_MEMCMP(packet, sizeof(packet), mbuf_buf(buf), mbuf_get_left(buf));

	err = rtcp_decode(&msg, buf);
	TEST_ERR(err);

	ASSERT_EQ(RTCP_XR,      msg->hdr.pt);
	ASSERT_EQ(4,            msg->hdr.length);
	ASSERT_EQ(ssrc,         msg->r.xr.ssrc);
	ASSERT_EQ(RTCP_XR_RRTR, msg->r.xr.bt);
	ASSERT_EQ(2,            msg->r.xr.block_len);
	ASSERT_EQ(0x01020304,   msg->r.xr.rb.rrtrb.ntp_msw);
	ASSERT_EQ(0x05060708,   msg->r.xr.rb.rrtrb.ntp_lsw);

out:
	mem_deref(buf);
	mem_deref(msg);
	return err;
}


static int dlrr_encode_handler(struct mbuf *mb, void *arg)
{
	const uint16_t block_length = 3;
	const uint32_t ssrc = 0xa534b254;
	const uint32_t lrr = 0x03040506;
	const uint32_t dlrr = 0x00008376;
	int err;
	(void)arg;

	err  = mbuf_write_u8(mb, RTCP_XR_DLRR);
	err |= mbuf_write_u8(mb, 0); /* reserved */
	err |= mbuf_write_u16(mb, htons(block_length));
	err |= mbuf_write_u32(mb, htonl(ssrc));
	err |= mbuf_write_u32(mb, htonl(lrr));
	err |= mbuf_write_u32(mb, htonl(dlrr));

	return err;
}


static int test_rtcp_xr_dlrr(void)
{
	/* RTCP-XR packet from Chrome 126 */
	static const uint8_t packet[] = {

		/* header */
		0x80, 0xcf, 0x00, 0x05,

		/* RTCP-XR */
		0x62, 0x8e, 0x09, 0xbd,
		0x05, 0x00, 0x00, 0x03,
		0xa5, 0x34, 0xb2, 0x54,
		0x03, 0x04, 0x05, 0x06,
		0x00, 0x00, 0x83, 0x76,
	};

	struct mbuf *mb = mbuf_alloc(sizeof(packet));
	if (!mb)
		return ENOMEM;

	struct rtcp_msg *msg = NULL;
	const uint32_t ssrc = 0x628e09bd;

	int err = rtcp_encode(mb, RTCP_XR, 0, ssrc, dlrr_encode_handler, NULL);
	TEST_ERR(err);

	mbuf_set_pos(mb, 0);

	TEST_MEMCMP(packet, sizeof(packet), mbuf_buf(mb), mbuf_get_left(mb));

	err = rtcp_decode(&msg, mb);
	TEST_ERR(err);

	ASSERT_EQ(RTCP_XR,      msg->hdr.pt);
	ASSERT_EQ(ssrc,         msg->r.xr.ssrc);
	ASSERT_EQ(RTCP_XR_DLRR, msg->r.xr.bt);
	ASSERT_EQ(3,            msg->r.xr.block_len);
	ASSERT_EQ(0xa534b254,   msg->r.xr.rb.dlrrb.ssrc);
	ASSERT_EQ(0x03040506,   msg->r.xr.rb.dlrrb.lrr);
	ASSERT_EQ(0x00008376,   msg->r.xr.rb.dlrrb.dlrr);

 out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


int test_rtcp_xr(void)
{
	int err;

	err = test_rtcp_xr_dlrr();
	TEST_ERR(err);

	err = test_rtcp_xr_rrtr();
	TEST_ERR(err);

 out:
	return err;
}
