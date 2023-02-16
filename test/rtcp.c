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


#define GENERATOR_SSRC 0x00000001


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
		goto out;
	}

	/* in OOM-test, detect if member/sender was not allocated */
	if (stats.rx.sent == 0 &&
	    stats.rx.lost == 0 &&
	    stats.rx.jit == 0) {

		err = ENOMEM;
		goto out;
	}

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

	err |= test_loss(seqv1, RE_ARRAY_SIZE(seqv1), 0);
	err |= test_loss(seqv2, RE_ARRAY_SIZE(seqv2), 0);
	err |= test_loss(seqv3, RE_ARRAY_SIZE(seqv3), 0);
	err |= test_loss(seqv4, RE_ARRAY_SIZE(seqv4), 1);
	err |= test_loss(seqv5, RE_ARRAY_SIZE(seqv5), 2);
	err |= test_loss(seqv6, RE_ARRAY_SIZE(seqv6), 1);
	err |= test_loss(seqv7, RE_ARRAY_SIZE(seqv7), 5);

	return err;
}
