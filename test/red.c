/**
 * @file red.c  Testcode for RTP Redundant Payload (RFC 2198)
 *
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "redtest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum { PT = 98, MAX_BLOCKS = 8 };


struct block {
	uint8_t pt;
	uint32_t ts;
	uint8_t buf[64];
	size_t len;
};


struct collect {
	struct block blockv[MAX_BLOCKS];
	unsigned n;
	bool overflow;
};


static void block_handler(uint8_t pt, uint32_t ts, const uint8_t *buf,
			  size_t len, void *arg)
{
	struct collect *c = arg;
	struct block *b;

	if (c->n >= RE_ARRAY_SIZE(c->blockv) ||
	    len > sizeof(c->blockv[0].buf)) {
		c->overflow = true;
		return;
	}

	b = &c->blockv[c->n++];

	b->pt  = pt;
	b->ts  = ts;
	b->len = len;

	if (len)
		memcpy(b->buf, buf, len);
}


static int decode(struct collect *c, struct mbuf *mb, uint32_t ts)
{
	memset(c, 0, sizeof(*c));

	mb->pos = 0;

	return red_decode(mb, ts, block_handler, c);
}


static int cmp_block(const struct block *b, uint32_t ts, const char *txt)
{
	size_t len = str_len(txt);
	int err = 0;

	TEST_EQUALS(PT, b->pt);
	TEST_EQUALS((int)ts, (int)b->ts);
	TEST_EQUALS((int)len, (int)b->len);

	if (len)
		TEST_MEMCMP(txt, len, b->buf, b->len);

 out:
	return err;
}


/*
 * Encode a known payload and compare it byte by byte against a hand-built
 * buffer, so that a refactor cannot silently change the wire format.
 */
static int test_red_vector(void)
{
	static const uint8_t expect[] = {

		/* header block: F=1, PT=98, tsoff=300, len=2 */
		0x80 | 98,
		300 >> 6,
		((300 & 0x3f) << 2) | (2 >> 8),
		2 & 0xff,

		/* final header block: F=0, PT=98 */
		98,

		/* redundant data */
		'h', 'i',

		/* primary data */
		't', 'h', 'e', 'r', 'e',
	};
	struct red *red = NULL;
	struct mbuf *mb = NULL;
	int err;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = red_alloc(&red, PT, 1);
	if (err)
		goto out;

	err = red_encode(red, mb, 1000, (const uint8_t *)"hi", 2);
	if (err)
		goto out;

	/* first packet has no redundancy yet */
	TEST_EQUALS(1 + 2, (int)mb->end);

	mbuf_rewind(mb);

	err = red_encode(red, mb, 1300, (const uint8_t *)"there", 5);
	if (err)
		goto out;

	TEST_MEMCMP(expect, sizeof(expect), mb->buf, mb->end);

 out:
	mem_deref(red);
	mem_deref(mb);
	return err;
}


/*
 * Round trip over a number of generations, checking that every packet
 * carries the expected history.
 */
static int test_red_roundtrip(unsigned ngen)
{
	static const char *txtv[] = {"a", "bb", "ccc", "dddd", "eeeee"};
	struct red *red = NULL;
	struct mbuf *mb = NULL;
	struct collect c;
	unsigned i, j;
	int err;

	mb = mbuf_alloc(256);
	if (!mb)
		return ENOMEM;

	err = red_alloc(&red, PT, ngen);
	if (err)
		goto out;

	for (i=0; i<RE_ARRAY_SIZE(txtv); i++) {

		unsigned nred = min(i, ngen);

		mbuf_rewind(mb);

		err = red_encode(red, mb, 1000 + i * 300,
				 (const uint8_t *)txtv[i], str_len(txtv[i]));
		if (err)
			goto out;

		err = decode(&c, mb, 1000 + i * 300);
		if (err)
			goto out;

		TEST_ASSERT(!c.overflow);
		TEST_EQUALS((int)(nred + 1), (int)c.n);

		/* redundant blocks, oldest first */
		for (j=0; j<nred; j++) {

			unsigned gen = i - nred + j;

			err = cmp_block(&c.blockv[j], 1000 + gen * 300,
					txtv[gen]);
			if (err)
				goto out;
		}

		/* primary block last */
		err = cmp_block(&c.blockv[nred], 1000 + i * 300, txtv[i]);
		if (err)
			goto out;
	}

 out:
	mem_deref(red);
	mem_deref(mb);
	return err;
}


/*
 * An empty primary block is legal and is how the tail of a burst stays
 * protected once the source has gone idle.
 */
static int test_red_empty_primary(void)
{
	struct red *red = NULL;
	struct mbuf *mb = NULL;
	struct collect c;
	int err;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = red_alloc(&red, PT, 2);
	if (err)
		goto out;

	err  = red_encode(red, mb, 1000, (const uint8_t *)"x", 1);
	mbuf_rewind(mb);
	err |= red_encode(red, mb, 1300, NULL, 0);
	if (err)
		goto out;

	err = decode(&c, mb, 1300);
	if (err)
		goto out;

	TEST_EQUALS(2, (int)c.n);
	err  = cmp_block(&c.blockv[0], 1000, "x");
	err |= cmp_block(&c.blockv[1], 1300, "");
	if (err)
		goto out;

	/* the empty block is recorded as a generation of its own */
	TEST_EQUALS(2, (int)red_gen_count(red));

 out:
	mem_deref(red);
	mem_deref(mb);
	return err;
}


/*
 * A generation older than the 14-bit timestamp offset can no longer be
 * expressed and must be dropped rather than encoded with a wrong offset.
 */
static int test_red_expire(void)
{
	struct red *red = NULL;
	struct mbuf *mb = NULL;
	struct collect c;
	int err;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = red_alloc(&red, PT, 2);
	if (err)
		goto out;

	err = red_encode(red, mb, 1000, (const uint8_t *)"old", 3);
	if (err)
		goto out;

	TEST_EQUALS(1, (int)red_gen_count(red));

	mbuf_rewind(mb);

	err = red_encode(red, mb, 1000 + RED_MAX_TSOFF + 1,
			 (const uint8_t *)"new", 3);
	if (err)
		goto out;

	err = decode(&c, mb, 1000 + RED_MAX_TSOFF + 1);
	if (err)
		goto out;

	TEST_EQUALS(1, (int)c.n);
	err = cmp_block(&c.blockv[0], 1000 + RED_MAX_TSOFF + 1, "new");

 out:
	mem_deref(red);
	mem_deref(mb);
	return err;
}


/*
 * With padding enabled the header count is constant from the first packet
 * on, which some legacy peers expect.
 */
static int test_red_pad(void)
{
	struct red *red = NULL;
	struct mbuf *mb = NULL;
	struct collect c;
	int err;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = red_alloc(&red, PT, 2);
	if (err)
		goto out;

	red_set_pad(red, true);

	err = red_encode(red, mb, 1000, (const uint8_t *)"x", 1);
	if (err)
		goto out;

	/* 2 padding headers + final header + 1 byte of primary data */
	TEST_EQUALS(2 * RED_HDR_SIZE + 1 + 1, (int)mb->end);

	err = decode(&c, mb, 1000);
	if (err)
		goto out;

	TEST_EQUALS(3, (int)c.n);
	TEST_EQUALS(0, (int)c.blockv[0].len);
	TEST_EQUALS(0, (int)c.blockv[1].len);
	err = cmp_block(&c.blockv[2], 1000, "x");

 out:
	mem_deref(red);
	mem_deref(mb);
	return err;
}


/*
 * A payload without any redundancy is a single primary block.
 */
static int test_red_nogen(void)
{
	struct red *red = NULL;
	struct mbuf *mb = NULL;
	struct collect c;
	int err;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = red_alloc(&red, PT, 0);
	if (err)
		goto out;

	err  = red_encode(red, mb, 1000, (const uint8_t *)"one", 3);
	mbuf_rewind(mb);
	err |= red_encode(red, mb, 1300, (const uint8_t *)"two", 3);
	if (err)
		goto out;

	TEST_EQUALS(0, (int)red_gen_count(red));

	err = decode(&c, mb, 1300);
	if (err)
		goto out;

	TEST_EQUALS(1, (int)c.n);
	err = cmp_block(&c.blockv[0], 1300, "two");

 out:
	mem_deref(red);
	mem_deref(mb);
	return err;
}


int test_red(void)
{
	unsigned ngen;
	int err;

	err = red_alloc(NULL, PT, 1);
	TEST_EQUALS(EINVAL, err);

	err = test_red_vector();
	TEST_ERR(err);

	for (ngen=0; ngen<=RED_MAX_GEN; ngen++) {

		err = test_red_roundtrip(ngen);
		if (err) {
			DEBUG_WARNING("roundtrip failed for ngen=%u\n", ngen);
			goto out;
		}
	}

	err = test_red_empty_primary();
	TEST_ERR(err);

	err = test_red_expire();
	TEST_ERR(err);

	err = test_red_pad();
	TEST_ERR(err);

	err = test_red_nogen();
	TEST_ERR(err);

	err = 0;

 out:
	return err;
}


/*
 * Every field of a RED payload comes off the network, so a truncated or
 * hostile packet must be rejected without ever reading past the buffer.
 */
int test_red_decode_badmsg(void)
{
	static const struct {
		const char *name;
		uint8_t buf[16];
		size_t len;
	} testv[] = {
		{
			"empty payload",
			{0}, 0
		},
		{
			"header chain truncated after the F bit",
			{0x80 | PT}, 1
		},
		{
			"header block one byte short",
			{0x80 | PT, 0x00, 0x00}, 3
		},
		{
			"final header block missing",
			{0x80 | PT, 0x00, 0x00, 0x01, 'a'}, 5
		},
		{
			"block length beyond the payload",
			{0x80 | PT, 0x00, 0x00, 0x08, PT, 'a', 'b'}, 7
		},
		{
			"block length beyond the payload, no data at all",
			{0x80 | PT, 0x00, 0x00, 0x01, PT}, 5
		},
	};
	struct collect c;
	struct mbuf *mb;
	size_t i;
	int err = 0;

	mb = mbuf_alloc(32);
	if (!mb)
		return ENOMEM;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		int e;

		mbuf_rewind(mb);

		if (testv[i].len) {
			err = mbuf_write_mem(mb, testv[i].buf, testv[i].len);
			if (err)
				goto out;
		}

		e = decode(&c, mb, 1000);

		if (EBADMSG != e) {
			DEBUG_WARNING("red: expected EBADMSG for '%s',"
				      " got %m\n", testv[i].name, e);
			err = EINVAL;
			goto out;
		}

		/* the read position must be left untouched on error */
		TEST_EQUALS(0, (int)mb->pos);
	}

	/* too many header blocks */
	{
		static const uint8_t hdr[RED_HDR_SIZE] = {
			0x80 | PT, 0x00, 0x00, 0x00
		};

		mbuf_rewind(mb);

		for (i=0; i<RED_MAX_BLOCKS + 1; i++) {
			err = mbuf_write_mem(mb, hdr, sizeof(hdr));
			if (err)
				goto out;
		}
	}

	TEST_EQUALS(EBADMSG, decode(&c, mb, 1000));

	err = 0;

 out:
	mem_deref(mb);
	return err;
}
