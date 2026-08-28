/**
 * @file t140.c  Testcode for ITU-T T.140 Real-Time Text (RFC 4103)
 *
 * Copyright (C) 2026 Emmanuel BUU
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "t140test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	PT_T140 = 98,
	PT_RED  = 100,
	NGEN    = 2
};


/*
 * A loopback that carries the packets built by one T.140 session into
 * another one, with an RTP header of its own and an optional packet
 * dropper, so that recovery and loss marking can be exercised without a
 * socket.
 */
struct loop {
	struct t140 *tx;
	struct t140 *rx;
	struct mbuf *out;    /**< Text delivered on the receive side */
	uint16_t seq;
	unsigned drop;       /**< Packets still to be dropped        */
	unsigned sent;
	unsigned delivered;
	int err;
};


static void recv_handler(const char *txt, size_t len, void *arg)
{
	struct loop *l = arg;

	++l->delivered;
	l->err |= mbuf_write_mem(l->out, (const uint8_t *)txt, len);
}


/**
 * Drive one transmission interval and feed the result to the receiver
 */
static int tick(struct loop *l)
{
	struct t140_pkt pkt;
	struct rtp_header hdr;
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err = t140_poll(l->tx, &pkt, mb);
	if (err) {
		/* nothing to send on this interval */
		if (ENOENT == err)
			err = 0;
		goto out;
	}

	++l->sent;

	if (l->drop) {
		--l->drop;
		++l->seq;
		goto out;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.ver = RTP_VERSION;
	hdr.m   = pkt.marker;
	hdr.pt  = pkt.pt;
	hdr.seq = l->seq++;
	hdr.ts  = pkt.ts;

	mb->pos = 0;

	t140_pkt_rtp(&pkt, &hdr, mb);

	err = t140_recv(l->rx, &pkt);

 out:
	mem_deref(mb);
	return err;
}


static int loop_alloc(struct loop *l, const struct t140_conf *conf)
{
	int err;

	memset(l, 0, sizeof(*l));

	l->out = mbuf_alloc(256);
	if (!l->out)
		return ENOMEM;

	err  = t140_alloc(&l->tx, conf, NULL, NULL, l);
	err |= t140_alloc(&l->rx, conf, NULL, recv_handler, l);

	return err;
}


static void loop_free(struct loop *l)
{
	mem_deref(l->tx);
	mem_deref(l->rx);
	mem_deref(l->out);
}


static int loop_cmp(const struct loop *l, const char *expect)
{
	size_t len = str_len(expect);
	int err = 0;

	TEST_ERR(l->err);
	TEST_STRCMP(expect, len, l->out->buf, l->out->end);

 out:
	return err;
}


/*
 * Text goes in one side and comes out the other, unchanged.
 */
static int test_t140_loopback(bool redundancy)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime  = 10,
		.cps    = 1000,
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = redundancy ? PT_RED : 0,
			.ngen   = redundancy ? NGEN : 0,
		},
	};
	struct t140_stats stats;
	struct loop l;
	unsigned i;
	int err;

	err = loop_alloc(&l, &conf);
	if (err)
		goto out;

	err = t140_send(l.tx, "bonjour", 7);
	if (err)
		goto out;

	TEST_ASSERT(!t140_is_empty(l.tx));

	for (i=0; i<8 && !err; i++)
		err = tick(&l);
	if (err)
		goto out;

	err = loop_cmp(&l, "bonjour");
	if (err)
		goto out;

	TEST_ASSERT(t140_is_empty(l.tx));

	t140_stats_get(l.rx, &stats);
	TEST_EQUALS(7, (int)stats.rx_chars);
	TEST_EQUALS(0, (int)stats.rx_lost);

 out:
	loop_free(&l);
	return err;
}


/*
 * A packet that never arrives is recovered from the redundancy carried by
 * the next one.
 */
static int test_t140_recover(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime  = 10,
		.cps    = 100,   /* one character per interval */
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct t140_stats stats;
	struct loop l;
	unsigned i;
	int err;

	err = loop_alloc(&l, &conf);
	if (err)
		goto out;

	err = t140_send(l.tx, "abcdef", 6);
	if (err)
		goto out;

	for (i=0; i<12 && !err; i++) {

		/* lose the third packet, which carries 'c' */
		if (2 == l.sent)
			l.drop = 1;

		err = tick(&l);
	}
	if (err)
		goto out;

	err = loop_cmp(&l, "abcdef");
	if (err)
		goto out;

	t140_stats_get(l.rx, &stats);

	TEST_EQUALS(0, (int)stats.rx_lost);
	TEST_ASSERT(stats.rx_recovered > 0);

 out:
	loop_free(&l);
	return err;
}


/*
 * A gap wider than the redundancy cannot be recovered, and T.140 marks
 * what was lost with a single U+FFFD.
 */
static int test_t140_loss(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime  = 10,
		.cps    = 100,   /* one character per interval */
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct t140_stats stats;
	struct loop l;
	unsigned i;
	int err;

	err = loop_alloc(&l, &conf);
	if (err)
		goto out;

	err = t140_send(l.tx, "abcdef", 6);
	if (err)
		goto out;

	for (i=0; i<12 && !err; i++) {

		/* lose three in a row, one more than the redundancy */
		if (1 == l.sent)
			l.drop = 3;

		err = tick(&l);
	}
	if (err)
		goto out;

	/* 'b' is gone for good, 'c' and 'd' come back as redundancy */
	err = loop_cmp(&l, "a\xef\xbf\xbd" "cdef");
	if (err)
		goto out;

	t140_stats_get(l.rx, &stats);

	TEST_EQUALS(1, (int)stats.rx_lost);

 out:
	loop_free(&l);
	return err;
}


/*
 * The same block arriving twice must be delivered once.
 */
static int test_t140_duplicate(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime  = 10,
		.cps    = 1000,
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct t140_stats stats;
	struct t140_pkt pkt;
	struct rtp_header hdr;
	struct t140 *tx = NULL;
	struct t140 *rx = NULL;
	struct mbuf *mb = NULL;
	struct loop l;
	int err;

	memset(&l, 0, sizeof(l));

	l.out = mbuf_alloc(64);
	if (!l.out)
		return ENOMEM;

	mb = mbuf_alloc(256);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err  = t140_alloc(&tx, &conf, NULL, NULL, &l);
	err |= t140_alloc(&rx, &conf, NULL, recv_handler, &l);
	if (err)
		goto out;

	err = t140_send(tx, "hei", 3);
	if (err)
		goto out;

	err = t140_poll(tx, &pkt, mb);
	if (err)
		goto out;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ver = RTP_VERSION;
	hdr.m   = pkt.marker;
	hdr.pt  = pkt.pt;
	hdr.seq = 1;
	hdr.ts  = pkt.ts;

	mb->pos = 0;
	t140_pkt_rtp(&pkt, &hdr, mb);

	err = t140_recv(rx, &pkt);
	if (err)
		goto out;

	/* the very same packet again */
	mb->pos = 0;
	pkt.mb = mb;
	err = t140_recv(rx, &pkt);
	if (err)
		goto out;

	err = loop_cmp(&l, "hei");
	if (err)
		goto out;

	t140_stats_get(rx, &stats);
	TEST_EQUALS(1, (int)stats.rx_dup);

 out:
	mem_deref(tx);
	mem_deref(rx);
	mem_deref(mb);
	mem_deref(l.out);
	return err;
}


/*
 * Multi-byte text survives the round trip, and a BOM opening the stream is
 * not delivered as text.
 */
static int test_t140_utf8_stream(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime  = 10,
		.cps    = 100,   /* one character per interval, splits it up */
		.bom    = true,
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct loop l;
	unsigned i;
	int err;

	err = loop_alloc(&l, &conf);
	if (err)
		goto out;

	/* accented latin, a line separator, and an emoji */
	err = t140_send(l.tx, "\xc3\xa9t\xc3\xa9", 5);
	err |= t140_send_nl(l.tx);
	err |= t140_send(l.tx, "\xf0\x9f\x93\x9e", 4);
	if (err)
		goto out;

	for (i=0; i<16 && !err; i++)
		err = tick(&l);
	if (err)
		goto out;

	err = loop_cmp(&l, "\xc3\xa9t\xc3\xa9\xe2\x80\xa8\xf0\x9f\x93\x9e");

 out:
	loop_free(&l);
	return err;
}


/*
 * A backspace is a character like any other on the wire.
 */
static int test_t140_backspace(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime = 10,
		.cps   = 1000,
		.u.rtp     = {
			.pt    = PT_T140,
		},
	};
	struct loop l;
	unsigned i;
	int err;

	err = loop_alloc(&l, &conf);
	if (err)
		goto out;

	err  = t140_send(l.tx, "hei", 3);
	err |= t140_send_bs(l.tx, 2);
	if (err)
		goto out;

	for (i=0; i<4 && !err; i++)
		err = tick(&l);
	if (err)
		goto out;

	err = loop_cmp(&l, "hei\x08\x08");

 out:
	loop_free(&l);
	return err;
}


/*
 * The character rate is shaped over the transmission interval, and no
 * packet ever splits a code point.
 */
static int test_t140_cps(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime = 100,
		.cps   = 30,     /* 3 characters per 100 ms interval */
		.u.rtp     = {
			.pt    = PT_T140,
		},
	};
	struct t140 *t = NULL;
	struct mbuf *mb = NULL;
	struct t140_pkt pkt;
	int err;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = t140_alloc(&t, &conf, NULL, NULL, NULL);
	if (err)
		goto out;

	/* six two-byte code points */
	err = t140_send(t, "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9",
			12);
	if (err)
		goto out;

	err = t140_poll(t, &pkt, mb);
	if (err)
		goto out;

	TEST_ASSERT(pkt.marker);
	TEST_EQUALS(PT_T140, pkt.pt);
	TEST_ASSERT(mb == pkt.mb);
	TEST_EQUALS(6, (int)mb->end);

	mbuf_rewind(mb);

	err = t140_poll(t, &pkt, mb);
	if (err)
		goto out;

	TEST_ASSERT(!pkt.marker);
	TEST_EQUALS(6, (int)mb->end);

	TEST_ASSERT(t140_is_empty(t));

 out:
	mem_deref(t);
	mem_deref(mb);
	return err;
}


/*
 * Direction attributes gate both sides, which is what lets a relay
 * operator mute one leg of a call.
 */
static int test_t140_dir(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime = 10,
		.u.rtp     = {
			.pt    = PT_T140,
		},
	};
	struct t140 *t = NULL;
	int err;

	err = t140_alloc(&t, &conf, NULL, NULL, NULL);
	if (err)
		return err;

	t140_set_dir(t, SDP_RECVONLY);
	TEST_EQUALS(EPERM, t140_send(t, "x", 1));

	t140_set_dir(t, SDP_INACTIVE);
	TEST_EQUALS(EPERM, t140_send(t, "x", 1));

	t140_set_dir(t, SDP_SENDRECV);
	TEST_ERR(t140_send(t, "x", 1));

 out:
	mem_deref(t);
	return err;
}


/*
 * Text arriving from the network is not to be trusted: ill-formed UTF-8
 * must never be handed on to the application.
 */
static int test_t140_utf8_badmsg(void)
{
	static const struct {
		const char *name;
		const char *in;
		size_t inlen;
		const char *out;
	} testv[] = {
		{
			"lone continuation byte",
			"a\x80" "b", 3, "a\xef\xbf\xbd" "b"
		},
		{
			"truncated three-byte sequence",
			"a\xe2\x80" "b", 4, "a\xef\xbf\xbd" "b"
		},
		{
			"overlong two-byte encoding of '/'",
			"\xc0\xaf", 2, "\xef\xbf\xbd\xef\xbf\xbd"
		},
		{
			"surrogate half U+D800",
			"\xed\xa0\x80", 3, "\xef\xbf\xbd\xef\xbf\xbd"
			"\xef\xbf\xbd"
		},
		{
			"code point above U+10FFFF",
			"\xf4\x90\x80\x80", 4, "\xef\xbf\xbd\xef\xbf\xbd"
			"\xef\xbf\xbd\xef\xbf\xbd"
		},
		{
			"invalid lead byte 0xff",
			"\xff", 1, "\xef\xbf\xbd"
		},
	};
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime = 10,
		.u.rtp     = {
			.pt    = PT_T140,
		},
	};
	struct t140_pkt pkt;
	struct rtp_header hdr;
	struct t140 *t = NULL;
	struct mbuf *mb = NULL;
	struct loop l;
	size_t i;
	int err = 0;

	memset(&l, 0, sizeof(l));

	l.out = mbuf_alloc(64);
	if (!l.out)
		return ENOMEM;

	mb = mbuf_alloc(64);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		mem_deref(t);
		t = NULL;

		err = t140_alloc(&t, &conf, NULL, recv_handler, &l);
		if (err)
			goto out;

		mbuf_rewind(l.out);
		mbuf_rewind(mb);

		err = mbuf_write_mem(mb, (const uint8_t *)testv[i].in,
				     testv[i].inlen);
		if (err)
			goto out;

		memset(&hdr, 0, sizeof(hdr));
		hdr.ver = RTP_VERSION;
		hdr.m   = true;
		hdr.pt  = PT_T140;
		hdr.seq = 1;
		hdr.ts  = 1000;

		mb->pos = 0;
		t140_pkt_rtp(&pkt, &hdr, mb);

		err = t140_recv(t, &pkt);
		if (err)
			goto out;

		if (str_len(testv[i].out) != l.out->end ||
		    0 != memcmp(testv[i].out, l.out->buf, l.out->end)) {

			DEBUG_WARNING("t140: utf8 '%s' failed\n",
				      testv[i].name);
			test_hexdump_dual(stderr,
					  testv[i].out,
					  str_len(testv[i].out),
					  l.out->buf, l.out->end);
			err = EBADMSG;
			goto out;
		}

		/* whatever comes out must itself be well-formed */
		TEST_ERR(l.err);
	}

 out:
	mem_deref(t);
	mem_deref(mb);
	mem_deref(l.out);
	return err;
}


/*
 * The internal transmission timer drives the whole path on its own, which
 * is how an application that is not clocked by an audio thread uses this.
 */
struct timerloop {
	struct t140 *rx;
	struct mbuf *out;
	uint16_t seq;
	size_t expect;
	int err;
};


static int timer_send_handler(const struct t140_pkt *pkt, void *arg)
{
	struct timerloop *tl = arg;
	struct t140_pkt in;
	struct rtp_header hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ver = RTP_VERSION;
	hdr.m   = pkt->marker;
	hdr.pt  = pkt->pt;
	hdr.seq = tl->seq++;
	hdr.ts  = pkt->ts;

	t140_pkt_rtp(&in, &hdr, pkt->mb);

	return t140_recv(tl->rx, &in);
}


static void timer_recv_handler(const char *txt, size_t len, void *arg)
{
	struct timerloop *tl = arg;

	tl->err |= mbuf_write_mem(tl->out, (const uint8_t *)txt, len);

	if (tl->out->end >= tl->expect)
		re_cancel();
}


static int test_t140_timer(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime  = 20,
		.cps    = 100,   /* two characters per interval */
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct timerloop tl;
	struct t140 *tx = NULL;
	int err;

	memset(&tl, 0, sizeof(tl));

	tl.expect = 5;

	tl.out = mbuf_alloc(64);
	if (!tl.out)
		return ENOMEM;

	err  = t140_alloc(&tl.rx, &conf, NULL, timer_recv_handler, &tl);
	err |= t140_alloc(&tx, &conf, timer_send_handler, NULL, &tl);
	if (err)
		goto out;

	/* a session with no send handler has nothing to drive */
	TEST_EQUALS(EINVAL, t140_start(tl.rx));

	err = t140_start(tx);
	if (err)
		goto out;

	TEST_EQUALS(EALREADY, t140_start(tx));

	err = t140_send(tx, "salut", 5);
	if (err)
		goto out;

	err = re_main_timeout(2000);
	if (err)
		goto out;

	t140_stop(tx);

	TEST_ERR(tl.err);
	TEST_STRCMP("salut", 5, tl.out->buf, tl.out->end);

 out:
	mem_deref(tx);
	mem_deref(tl.rx);
	mem_deref(tl.out);
	return err;
}


/*
 * The debug output is only ever read by a human, which is exactly why
 * nothing else would notice a broken format string in it.
 */
static int test_t140_debug_print(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime  = 10,
		.cps    = 1000,
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct loop l;
	char *str = NULL;
	unsigned i;
	int err;

	err = loop_alloc(&l, &conf);
	if (err)
		goto out;

	err = t140_send(l.tx, "hei", 3);
	if (err)
		goto out;

	for (i=0; i<4 && !err; i++)
		err = tick(&l);
	if (err)
		goto out;

	err = re_sdprintf(&str, "%H%H", t140_debug, l.tx, t140_debug, l.rx);
	if (err)
		goto out;

	TEST_ASSERT(NULL != strstr(str, "pt=98"));
	TEST_ASSERT(NULL != strstr(str, "red: pt=98 ngen=2"));

 out:
	mem_deref(str);
	loop_free(&l);
	return err;
}


/*
 * The data channel of RFC 8865 is a parameter of t140_alloc(), not a
 * second API. This pins the contract: allocating it answers ENOSYS, and
 * the two transport-specific helpers answer EINVAL when handed a
 * configuration naming the other transport.
 */
static int test_t140_transport(void)
{
	struct t140_conf rtpconf = {
		.transport = T140_TRANSPORT_RTP,
		.u.rtp     = {.pt = PT_T140},
	};
	struct t140_conf dcconf = {
		.transport = T140_TRANSPORT_DC,
		.u.dc      = {.lang = "fr"},
	};
	struct sdp_session *sess = NULL;
	struct sdp_media *m = NULL;
	struct t140 *t = NULL;
	struct mbuf *mb = NULL;
	enum sdp_dir dir = SDP_SENDRECV;
	struct sa laddr;
	int err;

	(void)sa_set_str(&laddr, "127.0.0.1", 11000);

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = sdp_session_alloc(&sess, &laddr);
	if (err)
		goto out;

	/* the data channel is declared but not built */
	TEST_EQUALS(ENOSYS, t140_alloc(&t, &dcconf, NULL, NULL, NULL));
	TEST_ASSERT(NULL == t);

	err = t140_alloc(&t, &rtpconf, NULL, NULL, NULL);
	if (err)
		goto out;

	TEST_EQUALS(T140_TRANSPORT_RTP, t140_transport(t));
	TEST_EQUALS(T140_TRANSPORT_RTP, t140_transport(NULL));

	/* the transport of a session cannot be changed underneath it */
	TEST_EQUALS(EINVAL, t140_update(t, &dcconf));
	TEST_ERR(t140_update(t, &rtpconf));

	/* the RTP helpers refuse a data-channel configuration */
	TEST_EQUALS(EINVAL,
		    t140_sdp_media_add(&m, sess, &laddr, &dcconf));
	TEST_ASSERT(NULL == m);
	TEST_ASSERT(!t140_red_fmtp_cmp(NULL, "98", &dcconf));
	TEST_ASSERT(!t140_fmtp_cmp(NULL, NULL, &dcconf));

	/* and the data-channel helpers refuse an RTP one, before ENOSYS */
	TEST_EQUALS(EINVAL, t140_dc_sdp_encode(mb, 1, &rtpconf, dir));
	TEST_EQUALS(EINVAL, t140_dc_sdp_decode(&rtpconf, &dir, NULL, NULL));

	TEST_EQUALS(ENOSYS, t140_dc_sdp_encode(mb, 1, &dcconf, dir));
	TEST_EQUALS(ENOSYS, t140_dc_sdp_decode(&dcconf, &dir, NULL, NULL));

	/* the subprotocol name is the one RFC 8865 registers */
	TEST_STRCMP("t140", 4, t140_dc_subproto, str_len(t140_dc_subproto));

 out:
	mem_deref(t);
	mem_deref(sess);
	mem_deref(mb);
	return err;
}


/*
 * The redundancy of RFC 2198 is the module's business, not the
 * application's: naming a payload type for "red" and a number of
 * generations is the whole of what a caller does. The RED codec below is
 * used only to look at what actually went on the wire.
 */
struct redblocks {
	uint32_t ts[8];
	char txt[8][16];
	size_t len[8];
	uint8_t pt[8];
	unsigned n;
};


static void red_block_handler(uint8_t pt, uint32_t ts, const uint8_t *buf,
			      size_t len, void *arg)
{
	struct redblocks *b = arg;

	if (b->n >= RE_ARRAY_SIZE(b->pt) || len >= sizeof(b->txt[0]))
		return;

	b->pt[b->n]  = pt;
	b->ts[b->n]  = ts;
	b->len[b->n] = len;

	if (len)
		memcpy(b->txt[b->n], buf, len);

	++b->n;
}


static int test_t140_red_auto(void)
{
	static const char *primary[] = {"a", "b", "c"};
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime     = 10,
		.cps       = 100,   /* one character per interval */
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct t140_pkt pkt;
	struct redblocks b;
	struct t140 *t = NULL;
	struct mbuf *mb = NULL;
	unsigned i, j;
	int err;

	mb = mbuf_alloc(256);
	if (!mb)
		return ENOMEM;

	err = t140_alloc(&t, &conf, NULL, NULL, NULL);
	if (err)
		goto out;

	err = t140_send(t, "abc", 3);
	if (err)
		goto out;

	for (i=0; i<RE_ARRAY_SIZE(primary); i++) {

		unsigned nred = min(i, (unsigned)NGEN);

		mbuf_rewind(mb);

		err = t140_poll(t, &pkt, mb);
		if (err)
			goto out;

		/* the module picked the "red" payload type on its own */
		TEST_EQUALS(PT_RED, pkt.pt);

		memset(&b, 0, sizeof(b));
		mb->pos = 0;

		err = red_decode(mb, pkt.ts, red_block_handler, &b);
		if (err)
			goto out;

		/* nred redundant generations, then the primary block */
		TEST_EQUALS((int)(nred + 1), (int)b.n);

		/* every block inside carries "t140", not "red" */
		for (j=0; j<b.n; j++)
			TEST_EQUALS(PT_T140, (int)b.pt[j]);

		/* the last block is what was just typed */
		TEST_STRCMP(primary[i], 1, b.txt[b.n - 1], b.len[b.n - 1]);

		/* the one before it is the previous character, resent */
		if (nred) {
			TEST_STRCMP(primary[i - 1], 1,
				    b.txt[b.n - 2], b.len[b.n - 2]);

			/* redundant blocks are older than the packet */
			TEST_ASSERT(b.ts[b.n - 2] < b.ts[b.n - 1]);
		}
	}

	/*
	 * Once the buffer runs dry the transmitter keeps going for as many
	 * intervals as there are generations, so the tail of a burst is
	 * protected too. Those packets carry an empty primary block.
	 */
	mbuf_rewind(mb);

	err = t140_poll(t, &pkt, mb);
	if (err)
		goto out;

	TEST_ASSERT(!t140_is_empty(t));

	memset(&b, 0, sizeof(b));
	mb->pos = 0;

	err = red_decode(mb, pkt.ts, red_block_handler, &b);
	if (err)
		goto out;

	TEST_EQUALS(NGEN + 1, (int)b.n);
	TEST_EQUALS(0, (int)b.len[b.n - 1]);
	TEST_STRCMP("c", 1, b.txt[b.n - 2], b.len[b.n - 2]);

	/* without a "red" payload type the payload is a bare T140 block */
	conf.u.rtp.pt_red = 0;
	conf.u.rtp.ngen   = 0;

	err = t140_update(t, &conf);
	if (err)
		goto out;

	err = t140_send(t, "z", 1);
	if (err)
		goto out;

	mbuf_rewind(mb);

	err = t140_poll(t, &pkt, mb);
	if (err)
		goto out;

	TEST_EQUALS(PT_T140, pkt.pt);
	TEST_STRCMP("z", 1, mb->buf, mb->end);

 out:
	mem_deref(t);
	mem_deref(mb);
	return err;
}


/*
 * Text that is not well-formed UTF-8 must be refused at the API, not
 * dragged onto the wire.
 */
static int test_t140_send_badmsg(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.ptime = 10,
		.u.rtp     = {
			.pt    = PT_T140,
		},
	};
	struct t140 *t = NULL;
	int err;

	err = t140_alloc(&t, &conf, NULL, NULL, NULL);
	if (err)
		return err;

	TEST_EQUALS(EBADMSG, t140_send(t, "\xc3", 1));
	TEST_EQUALS(EBADMSG, t140_send(t, "\x80", 1));
	TEST_EQUALS(EBADMSG, t140_send(t, "\xed\xa0\x80", 3));
	TEST_ERR(t140_send(t, "\xc3\xa9", 2));

 out:
	mem_deref(t);
	return err;
}


int test_t140(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.u.rtp     = {.pt = PT_T140},
	};
	struct t140 *t = NULL;
	int err;

	TEST_EQUALS(EINVAL, t140_alloc(NULL, &conf, NULL, NULL, NULL));
	TEST_EQUALS(EINVAL, t140_alloc(&t, NULL, NULL, NULL, NULL));

	/* payload type 0 is not a dynamic one */
	conf.u.rtp.pt = 0;
	TEST_EQUALS(EINVAL, t140_alloc(&t, &conf, NULL, NULL, NULL));

	/* redundancy without generations makes no sense */
	conf.u.rtp.pt = PT_T140;
	conf.u.rtp.pt_red = PT_RED;
	TEST_EQUALS(EINVAL, t140_alloc(&t, &conf, NULL, NULL, NULL));

	conf.u.rtp.ngen = RED_MAX_GEN + 1;
	TEST_EQUALS(EINVAL, t140_alloc(&t, &conf, NULL, NULL, NULL));

	/* an unknown transport is refused too */
	conf.transport = (enum t140_transport)42;
	TEST_EQUALS(EINVAL, t140_alloc(&t, &conf, NULL, NULL, NULL));

	err = test_t140_loopback(false);
	TEST_ERR(err);

	err = test_t140_loopback(true);
	TEST_ERR(err);

	err = test_t140_red_auto();
	TEST_ERR(err);

	err = test_t140_recover();
	TEST_ERR(err);

	err = test_t140_loss();
	TEST_ERR(err);

	err = test_t140_duplicate();
	TEST_ERR(err);

	err = test_t140_utf8_stream();
	TEST_ERR(err);

	err = test_t140_backspace();
	TEST_ERR(err);

	err = test_t140_cps();
	TEST_ERR(err);

	err = test_t140_dir();
	TEST_ERR(err);

	err = test_t140_timer();
	TEST_ERR(err);

	err = test_t140_debug_print();
	TEST_ERR(err);

	err = test_t140_transport();
	TEST_ERR(err);

	err = test_t140_send_badmsg();
	TEST_ERR(err);

	err = test_t140_utf8_badmsg();
	TEST_ERR(err);

 out:
	return err;
}


int test_t140_sdp(void)
{
	struct t140_conf conf = {
		.transport = T140_TRANSPORT_RTP,
		.cps    = 20,
		.u.rtp     = {
			.pt     = PT_T140,
			.pt_red = PT_RED,
			.ngen   = NGEN,
		},
	};
	struct sdp_session *sess = NULL;
	struct sdp_media *m = NULL;
	struct mbuf *mb = NULL;
	struct sa laddr;
	char *sdp = NULL;
	int err;

	(void)sa_set_str(&laddr, "127.0.0.1", 11000);

	err = sdp_session_alloc(&sess, &laddr);
	if (err)
		return err;

	err = t140_sdp_media_add(&m, sess, &laddr, &conf);
	if (err)
		goto out;

	sdp_media_set_ldir(m, SDP_SENDRECV);

	err = sdp_encode(&mb, sess, true);
	if (err)
		goto out;

	err = mbuf_strdup(mb, &sdp, mb->end);
	if (err)
		goto out;

	TEST_ASSERT(NULL != strstr(sdp, "m=text 11000 RTP/AVP 100 98"));
	TEST_ASSERT(NULL != strstr(sdp, "a=rtpmap:100 red/1000"));
	TEST_ASSERT(NULL != strstr(sdp, "a=fmtp:100 98/98/98"));
	TEST_ASSERT(NULL != strstr(sdp, "a=rtpmap:98 t140/1000"));
	TEST_ASSERT(NULL != strstr(sdp, "a=fmtp:98 cps=20"));

	/* every generation of a "red" offer must resolve to our t140 */
	TEST_ASSERT(t140_red_fmtp_cmp(NULL, "98/98/98", &conf));
	TEST_ASSERT(t140_red_fmtp_cmp(NULL, "98", &conf));
	TEST_ASSERT(!t140_red_fmtp_cmp(NULL, "99/98/98", &conf));
	TEST_ASSERT(!t140_red_fmtp_cmp(NULL, "", &conf));
	TEST_ASSERT(!t140_red_fmtp_cmp(NULL, "abc", &conf));

	/* the character rate is a hint, never a reason to reject */
	TEST_ASSERT(t140_fmtp_cmp("cps=30", "cps=5", &conf));

 out:
	mem_deref(sdp);
	mem_deref(mb);
	mem_deref(sess);
	return err;
}
