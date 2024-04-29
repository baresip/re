/**
 * @file rtp.c RTP/RTCP Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "rtptest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {PAYLOAD_SIZE = 160};


int test_rtp(void)
{
	struct rtp_sock *rtp = NULL;
	struct mbuf *mb = NULL;
	static const uint8_t payload[PAYLOAD_SIZE];
	int j;
	int err;

	mb = mbuf_alloc(RTP_HEADER_SIZE);
	if (!mb)
		return ENOMEM;

	err = rtp_alloc(&rtp);
	if (err)
		goto out;

	for (j=0; j<100; j++) {
		struct rtp_header hdr, hdr2;

		memset(&hdr, 0, sizeof(hdr));

		hdr.m  = j & 0x01;
		hdr.pt = j & 0x7f;
		hdr.ts = 160 + j;

		mb->pos = mb->end = RTP_HEADER_SIZE;
		err = mbuf_write_mem(mb, payload, sizeof(payload));
		if (err)
			break;

		mb->pos = 0;
		err = rtp_encode(rtp, false, hdr.m, hdr.pt, hdr.ts, mb);
		if (err)
			break;

		mb->pos = 0;

		err = rtp_decode(rtp, mb, &hdr2);
		if (err)
			break;

		if (hdr.m != hdr2.m) {
			DEBUG_WARNING("marker bit mismatch (%d != %d)\n",
				      hdr.m, hdr2.m);
			err = EBADMSG;
			break;
		}

		if (hdr.pt != hdr2.pt) {
			DEBUG_WARNING("payload type mismatch (%u != %u)\n",
				      hdr.pt, hdr2.pt);
			err = EBADMSG;
			break;
		}

		if (hdr.ts != hdr2.ts) {
			DEBUG_WARNING("timestamp mismatch (%lu != %lu)\n",
				      hdr.ts, hdr2.ts);
			err = EBADMSG;
			break;
		}

		if (hdr2.pad) {
			DEBUG_WARNING("unexpected padding bit\n");
			err = EBADMSG;
			break;
		}

		if (hdr2.ext) {
			DEBUG_WARNING("unexpected extension bit\n");
			err = EBADMSG;
			break;
		}

		if (RTP_HEADER_SIZE != mb->pos ||
		    (RTP_HEADER_SIZE + PAYLOAD_SIZE) != mb->end) {
			DEBUG_WARNING("invalid mbuf size (pos=%u end=%u)\n",
				      mb->pos, mb->end);
			err = EBADMSG;
			break;
		}

		if (0 != memcmp(mbuf_buf(mb), payload, sizeof(payload))) {
			DEBUG_WARNING("RTP payload mismatch\n");
			err = EBADMSG;
			break;
		}
	}

 out:
	mem_deref(rtp);
	mem_deref(mb);

	return err;
}


static const uint8_t rtcp_msg[] =
	/* SR */
	"\x81\xc8\x00\x0c"
	"\x12\x34\x56\x78"
	"\x00\x11\x22\x33"
	"\x44\x55\x66\x77"
	"\x22\x33\x22\x33"
	"\x00\x00\x11\x11"
	"\x00\x00\x22\x22"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"

	/* RR */
	"\x81\xc9\x00\x07"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"
	"\x12\x34\x56\x78"

	/* SDES */
	"\x81\xca\x00\x03"
	"\xde\xad\xbe\xef"
	"\x01\x03\x61\x62"
	"\x63\x00\x00\x00"

	/* BYE */
	"\x82\xcb\x00\x04"
	"\x12\x34\x56\x78"
	"\x00\xab\xcd\xef"
	"\x04\x63\x69\x61"
	"\x6f\x00\x00\x00"

	/* APP */
	"\x80\xcc\x00\x03"
	"\x12\x34\x56\x78"
	"\x6e\x61\x6d\x65"
	"\x64\x61\x74\x61"

	/* FIR */
	"\x80\xc0\x00\x01"
	"\x12\x34\x56\x78"

	/* NACK */
	"\x80\xc1\x00\x02"
	"\x12\x34\x56\x78"
	"\x89\xab\xcd\xef"

	/* RTPFB */
	"\x81\xcd\x00\x05"
	"\x12\x34\x56\x78"
	"\xfe\xdc\xba\x98"
	"\x01\x23\x04\x56"
	"\x01\x23\x04\x56"
	"\x01\x23\x04\x56"

	/* PSFB - PLI */
	"\x81\xce\x00\x02"
	"\x12\x34\x56\x78"
	"\xfe\xdc\xba\x98"

	/* PSFB - SLI */
	"\x82\xce\x00\x04"
	"\x12\x34\x56\x78"
	"\xfe\xdc\xba\x98"
	"\xca\xfe\xca\xfe"
	"\xca\xfe\xca\xfe"

	"";


static int encode_handler(struct mbuf *mb, void *arg)
{
	int err = 0;
	size_t i;

	(void)arg;

	for (i=0; i<6 && !err; i++)
		err = mbuf_write_u32(mb, htonl(0x12345678));

	return err;
}


static int sdes_encode_handler(struct mbuf *mb, void *arg)
{
	(void)arg;
	return rtcp_sdes_encode(mb, 0xdeadbeef, 1, RTCP_SDES_CNAME, "abc");
}


static int gnack_encode(struct mbuf *mb, void *arg)
{
	int err = 0, n=3;
	(void)arg;

	while (n--) {
		err |= mbuf_write_u16(mb, htons(0x0123));
		err |= mbuf_write_u16(mb, htons(0x0456));
	}

	return err;
}


static int sli_encode(struct mbuf *mb, void *arg)
{
	int err = 0, n=2;
	(void)arg;

	while (n--) {
		err |= mbuf_write_u32(mb, htonl(0xcafecafe));
	}

	return err;
}


int test_rtcp_encode(void)
{
	struct mbuf *mb;
	const size_t sz = sizeof(rtcp_msg) - 1;
	const uint32_t srcv[2] = {0x12345678, 0x00abcdef};
	char debug_buf[512];
	int err = 0;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;


	err |= rtcp_encode(mb, RTCP_SR, 1, 0x12345678, 0x00112233,
			   0x44556677, 0x22332233, 0x00001111, 0x00002222,
			   encode_handler, 0);
	err |= rtcp_encode(mb, RTCP_RR, 1, 0x12345678, encode_handler, 0);
	err |= rtcp_encode(mb, RTCP_SDES, 1, sdes_encode_handler, 0);
	err |= rtcp_encode(mb, RTCP_BYE, 2, srcv, "ciao");
	err |= rtcp_encode(mb, RTCP_APP, 0, 0x12345678, "name", "data",
			   (size_t)4);
	err |= rtcp_encode(mb, RTCP_FIR, 0, 0x12345678);
	err |= rtcp_encode(mb, RTCP_NACK, 0, 0x12345678, 0x89ab, 0xcdef);
	err |= rtcp_encode(mb, RTCP_RTPFB, RTCP_RTPFB_GNACK,
			   0x12345678, 0xfedcba98, gnack_encode, 0);
	err |= rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_PLI,
			   0x12345678, 0xfedcba98, NULL, 0);
	err |= rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_SLI,
			   0x12345678, 0xfedcba98, sli_encode, 0);
	if (err)
		goto out;

	if (mb->end != sz) {
		err = EPROTO;
	}
	if (0 != memcmp(mb->buf, rtcp_msg, mb->end)) {
		err = EBADMSG;
	}

	if (err) {
		DEBUG_WARNING("encode error: %m\n", err);
		hexdump(stderr, mb->buf, mb->end);
	}

	mb->pos = 0;
	while (mbuf_get_left(mb) >= 4 && !err) {
		struct rtcp_msg *msg = NULL;
		err = rtcp_decode(&msg, mb);
		if (err)
			break;

		/* Check that debug print works */
		debug_buf[0] = '\0';
		re_snprintf(debug_buf, sizeof(debug_buf),
			    "%H", rtcp_msg_print, msg);

		msg = mem_deref(msg);

		ASSERT_TRUE(str_isset(debug_buf));
	}
	if (err)
		goto out;

	/* verify that rtcp_decode() read the whole buffer */
	TEST_EQUALS(mb->end, mb->pos);

 out:
	mem_deref(mb);
	return err;
}


static const uint8_t rtcp_sdes[] =
	/* SDES */
	"\x83\xca\x00\x09"
	"\x11\x22\x33\x44"
	"\x01\x02\x41\x61"  /* cname */
	"\x00\x00\x00\x00"
	"\x55\x66\x77\x88"
	"\x07\x02\x42\x62"  /* note */
	"\x02\x01\x43\x00"  /* name */
	"\xaa\xbb\xcc\xdd"
	"\x04\x05\x31\x32"  /* phone */
	"\x33\x34\x35\x00"

	/* APP */
	"\x80\xcc\x00\x03"
	"\x12\x34\x56\x78"
	"\x6e\x61\x6d\x65"
	"\x64\x61\x74\x61"
	"";


int test_rtcp_decode_badmsg(void)
{
	struct rtcp_msg *msg = NULL;
	uint32_t ssrc = 0xcafebabe;

	struct mbuf *mb = mbuf_alloc(128);
	if (!mb)
		return ENOMEM;

	int err = rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_SLI,
			      ssrc, ssrc, NULL, NULL);
	if (err)
		goto out;

	/* simulate a corrupt RTCP packet */
	mb->pos = 2;
	(void)mbuf_write_u16(mb, htons(0));

	mb->pos = 0;

	int ret = rtcp_decode(&msg, mb);
	if (EBADMSG != ret && ret != ENOMEM) {
		err = EBADMSG;
		goto out;
	}

 out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


int test_rtcp_decode(void)
{
	struct rtcp_msg *msg = NULL;
	struct mbuf *mb;
	int err = 0;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err |= mbuf_write_u8(mb, 0x55); /* overhead -- test padding */
	err |= mbuf_write_mem(mb, rtcp_sdes, sizeof(rtcp_sdes));
	err |= mbuf_write_u8(mb, 0xaa); /* junk */
	TEST_ERR(err);
	mb->pos = 1;

	/* SDES */
	err = rtcp_decode(&msg, mb);
	TEST_ERR(err);

	ASSERT_EQ(  2, msg->hdr.version);
	ASSERT_EQ(  0, msg->hdr.p);
	ASSERT_EQ(  3, msg->hdr.count);
	ASSERT_EQ(202, msg->hdr.pt);
	ASSERT_EQ(  9, msg->hdr.length);

	const struct rtcp_sdes *sdes = &msg->r.sdesv[0];

	ASSERT_EQ(0x11223344, sdes->src);
	ASSERT_EQ(1, sdes->n);

	const struct rtcp_sdes_item *item = &sdes->itemv[0];

	ASSERT_EQ(1, item->type);
	ASSERT_EQ(2, item->length);
	TEST_STRCMP("Aa", 2, item->data, item->length);

	msg = mem_deref(msg);

	/* APP */
	err = rtcp_decode(&msg, mb);
	TEST_ERR(err);

	ASSERT_EQ(  2, msg->hdr.version);
	ASSERT_EQ(  0, msg->hdr.p);
	ASSERT_EQ(  0, msg->hdr.count);
	ASSERT_EQ(204, msg->hdr.pt);
	ASSERT_EQ(  3, msg->hdr.length);

	ASSERT_EQ(  0x12345678, msg->r.app.src);
	TEST_STRCMP("name", 4, msg->r.app.name, 4);
	TEST_STRCMP("data", 4, msg->r.app.data, msg->r.app.data_len);

	if (err)
		goto out;

 out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


static int afb_encode_handler(struct mbuf *mb, void *arg)
{
	return mbuf_write_str(mb, arg);
}


int test_rtcp_encode_afb(void)
{
	uint32_t ssrc_packet_sender, ssrc_media_source;
	const char *afb_payload = "AFB tull";
	struct rtcp_msg *msg = NULL;
	struct mbuf *mb;
	int err = 0;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	ssrc_packet_sender = 0xbad00bad;
	ssrc_media_source = 0; /* always 0 */
	err = rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_AFB,
			  ssrc_packet_sender, ssrc_media_source,
			  afb_encode_handler, afb_payload);
	if (err)
		goto out;

	mb->pos = 0;
	err = rtcp_decode(&msg, mb);
	if (err)
		goto out;

	if (msg->hdr.count != RTCP_PSFB_AFB) {
		DEBUG_WARNING("expected AFB, got fmt=%u\n", msg->hdr.count);
		err = EPROTO;
		goto out;
	}

	if (msg->r.fb.ssrc_packet != ssrc_packet_sender ||
	    msg->r.fb.ssrc_media  != ssrc_media_source) {
		DEBUG_WARNING("error in SSRC encoding\n");
		err = EBADMSG;
		goto out;
	}

	if (!msg->r.fb.fci.afb ||
	    mbuf_get_left(msg->r.fb.fci.afb) != strlen(afb_payload)) {
		DEBUG_WARNING("error in AFB mbuf (left=%u, size=%u)\n",
			      mbuf_get_left(msg->r.fb.fci.afb),
			      strlen(afb_payload));
		err = EBADMSG;
		goto out;
	}

	if (0 != memcmp(mbuf_buf(msg->r.fb.fci.afb),
			afb_payload,
			strlen(afb_payload))) {
		DEBUG_WARNING("error in AFB mbuf content\n");
		err = EBADMSG;
		goto out;
	}

	/* verify that rtcp_decode() read the whole buffer */
	TEST_EQUALS(mb->end, mb->pos);

 out:
	mem_deref(mb);
	mem_deref(msg);
	return err;
}


struct rtp_test {
	struct rtp_sock *rtp;
	struct mbuf *mb;
	uint32_t n;
	uint32_t f;
};


static void rtp_recv_handler(const struct sa *src,
			     const struct rtp_header *hdr, struct mbuf *mb,
			     void *arg)
{
	struct rtp_test *test = arg;
	char bufs[5];
	char bufr[5];
	(void) src;
	(void) hdr;

	mbuf_read_str(test->mb, bufs, sizeof(bufs));
	mbuf_read_str(mb, bufr, sizeof(bufr));

	if (!strncmp(bufr, bufs, sizeof(bufs)))
		test->n++;
	else
		test->f++;

	if (test->n + test->f == 2)
		re_cancel();
	else
		mbuf_advance(test->mb, RTP_HEADER_SIZE);
}


static int test_rtp_listen_priv(bool clear)
{
	struct rtp_test test;
	struct sa sa;
	size_t pos;
	int err;

	sa_init(&sa, AF_INET);
	memset(&test, 0, sizeof(test));
	err = rtp_listen(&test.rtp, IPPROTO_UDP, &sa, 1024, 49152, false,
			 rtp_recv_handler, NULL, &test);
	TEST_ERR(err);

	test.mb = mbuf_alloc(2 * (RTP_HEADER_SIZE + 5));
	if (!test.mb) {
		err = ENOMEM;
		goto out;
	}

	pos = RTP_HEADER_SIZE;
	test.mb->pos = test.mb->end = pos;
	mbuf_write_str(test.mb, "abcd");
	mbuf_write_u8(test.mb, 0);
	test.mb->pos = pos;
	sa_set_str(&sa, "127.0.0.1", sa_port(rtp_local(test.rtp)));
	err = rtp_send(test.rtp, &sa, false, true, 0, 160,
		       tmr_jiffies_rt_usec(), test.mb);
	TEST_ERR(err);

	pos = test.mb->end + RTP_HEADER_SIZE;
	test.mb->pos = test.mb->end = pos;
	mbuf_write_str(test.mb, "bcde");
	mbuf_write_u8(test.mb, 0);
	test.mb->pos = pos;
	err = rtp_send(test.rtp, &sa, false, false, 0, 320,
		       tmr_jiffies_rt_usec(), test.mb);
	TEST_ERR(err);

	if (clear) {
		err = rtp_clear(test.rtp);
		TEST_ERR(err);
	}

	test.mb->pos = RTP_HEADER_SIZE;
	if (!clear)
		(void)re_main_timeout(100);

	TEST_EQUALS(clear ? 0 : 2, test.n);
	TEST_EQUALS(0, test.f);

out:
	mem_deref(test.rtp);
	mem_deref(test.mb);
	return err;
}


int test_rtp_listen(void)
{
	int err;

	err = test_rtp_listen_priv(false);
	TEST_ERR(err);

	err = test_rtp_listen_priv(true);
	TEST_ERR(err);
out:
	return err;
}


int test_rtcp_twcc(void)
{
	/*
	  A RTCP transport-cc parser test. Done as part of WebRtcTransport
	  which uses it. TWCC rtcp packets have been extracted from what
	  Chrome sends using Wireshark and concatenated to form a single
	  compound packet.
	*/
	uint8_t packets[] = {

		/* First packet */
		0xaf, 0xcd, 0x00, 0x07, 0xfa, 0x17,
		0xfa, 0x17, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x03, 0x00, 0x09, 0x00,
		0x42, 0x6d, 0x00, 0xad, 0xe0,
		0x14, 0x18, 0x18, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,

		/* Second packet */
		0xaf, 0xcd, 0x00, 0x0c, 0xfa, 0x17,
		0xfa, 0x17, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x0c, 0x00, 0x1e, 0x00, 0x42, 0x6d,
		0x01, 0x96, 0xf7, 0xbb, 0xf3, 0x20, 0x02,
		0xb0, 0x14, 0x08, 0x58, 0x18, 0x00,
		0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,

		/* Third packet */
		0xaf, 0xcd, 0x00, 0x07, 0xfa, 0x17,
		0xfa, 0x17, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x2a, 0x00, 0x0b, 0x00,
		0x42, 0x6e, 0x02, 0x9b, 0xf8,
		0xb8, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

		/* Chrome 114 */
		0x8f, 0xcd, 0x00, 0x08,
		0xfa, 0x17, 0xfa, 0x17,
		0x4f, 0x10, 0x01, 0x6f,
		0x00, 0x08, 0x00, 0x0e,
		0x25, 0x27, 0x0c, 0x02,
		0x20, 0x0e, 0xb9, 0x0b,
		0x27, 0x00, 0x15, 0x0b,
		0x0a, 0x00, 0x00, 0x10,
		0x0b, 0x10, 0x10, 0x1d
	};

	struct mbuf *buf = mbuf_alloc(sizeof(packets));
	if (!buf)
		return ENOMEM;

	struct rtcp_msg *msg = NULL;
	int err = 0;

	mbuf_write_mem(buf, packets, sizeof(packets));
	mbuf_set_pos(buf, 0);

	/* TWCC n=5 base=3 count=9 reftime=17005 fbcount=0 chunks=2 deltas=7
	   (with padding 00 00 03) */
	err = rtcp_decode(&msg, buf);
	TEST_ERR(err);
	ASSERT_EQ(err, 0);
	ASSERT_EQ(msg->hdr.count, RTCP_RTPFB_TWCC);
	ASSERT_EQ(msg->r.fb.n, 5);
	ASSERT_TRUE(msg->r.fb.fci.twccv != NULL);
	ASSERT_EQ(msg->r.fb.fci.twccv->seq, 3);
	ASSERT_EQ(msg->r.fb.fci.twccv->count, 9);
	ASSERT_EQ(msg->r.fb.fci.twccv->reftime, 17005);
	ASSERT_EQ(msg->r.fb.fci.twccv->fbcount, 0);
	ASSERT_EQ(mbuf_get_left(msg->r.fb.fci.twccv->chunks), 2);
	ASSERT_EQ(mbuf_get_left(msg->r.fb.fci.twccv->deltas), 7);
	msg = mem_deref(msg);

	/* TWCC n=10 base=12 count=30 reftime=17005 fbcount=1 chunks=6
	   deltas=23 (with padding 00 00 03) */
	err = rtcp_decode(&msg, buf);
	TEST_ERR(err);
	ASSERT_EQ(err, 0);
	ASSERT_EQ(msg->hdr.count, RTCP_RTPFB_TWCC);
	ASSERT_EQ(msg->r.fb.n, 10);
	ASSERT_EQ(msg->r.fb.fci.twccv->seq, 12);
	ASSERT_EQ(msg->r.fb.fci.twccv->count, 30);
	ASSERT_EQ(msg->r.fb.fci.twccv->reftime, 17005);
	ASSERT_EQ(msg->r.fb.fci.twccv->fbcount, 1);
	ASSERT_EQ(mbuf_get_left(msg->r.fb.fci.twccv->chunks), 6);
	ASSERT_EQ(mbuf_get_left(msg->r.fb.fci.twccv->deltas), 23);
	msg = mem_deref(msg);

	/* TWCC n=5 base=42 count=11 reftime=17006 fbcount=2 chunks=2
	   deltas=9 (with padding 01) */
	err = rtcp_decode(&msg, buf);
	TEST_ERR(err);
	ASSERT_EQ(err, 0);
	ASSERT_EQ(msg->hdr.count, RTCP_RTPFB_TWCC);
	ASSERT_EQ(msg->r.fb.n, 5);
	ASSERT_EQ(msg->r.fb.fci.twccv->seq, 42);
	ASSERT_EQ(msg->r.fb.fci.twccv->count, 11);
	ASSERT_EQ(msg->r.fb.fci.twccv->reftime, 17006);
	ASSERT_EQ(msg->r.fb.fci.twccv->fbcount, 2);
	ASSERT_EQ(mbuf_get_left(msg->r.fb.fci.twccv->chunks), 2);
	ASSERT_EQ(mbuf_get_left(msg->r.fb.fci.twccv->deltas), 9);
	msg = mem_deref(msg);

	/* Chrome 114 */
	err = rtcp_decode(&msg, buf);
	TEST_ERR(err);
	ASSERT_TRUE(!msg->hdr.p);
	ASSERT_EQ(RTCP_RTPFB_TWCC, msg->hdr.count);
	ASSERT_EQ(205, msg->hdr.pt);
	ASSERT_EQ(8, msg->hdr.length);
	ASSERT_EQ(0xfa17fa17, msg->r.fb.ssrc_packet);
	ASSERT_EQ(0x4f10016f, msg->r.fb.ssrc_media);
	ASSERT_EQ(6, msg->r.fb.n);
	const struct twcc *twcc = msg->r.fb.fci.twccv;
	ASSERT_TRUE(twcc != NULL);
	ASSERT_EQ(8, twcc->seq);
	ASSERT_EQ(14, twcc->count);
	ASSERT_EQ(2434828, twcc->reftime);
	ASSERT_EQ(2, twcc->fbcount);
	ASSERT_EQ(2, mbuf_get_left(twcc->chunks));
	ASSERT_EQ(14, mbuf_get_left(twcc->deltas));
	msg = mem_deref(msg);

	/* Assert we have processed everything. */
	ASSERT_EQ(mbuf_get_left(buf), 0);

 out:
	mem_deref(buf);
	mem_deref(msg);
	return err;
}
