/**
 * @file src/av1.c AV1 testcode
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <re_av1.h>
#include "test.h"


#define DEBUG_MODULE "av1test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int test_leb128(void)
{
	struct mbuf *mb = NULL;
	int err = 0;

	static const uint64_t valuev[] = {

		0,

		/* from random.org */
		449787982,
		435590144,
		64565769,
		698509268,
		524090268,

		0x000000ff,     /* max  8-bit */
		0x0000ffff,     /* max 16-bit */
		0xffffffff      /* max 32-bit */
	};

	for (size_t i=0; i<RE_ARRAY_SIZE(valuev); i++) {

		uint64_t val = valuev[i];
		uint64_t val_dec;

		mb = mbuf_alloc(64);
		if (!mb)
			return ENOMEM;

		err = av1_leb128_encode(mb, val);
		if (err)
			goto out;

		mb->pos = 0;

		err = av1_leb128_decode(mb, &val_dec);
		ASSERT_EQ(0, err);

		ASSERT_EQ(val, val_dec);

		mb = mem_deref(mb);
	}

 out:
	mem_deref(mb);

	return err;
}


static int test_av1_aggr(void)
{
	static const struct test {
		uint8_t byte;
		unsigned z;
		unsigned y;
		unsigned w;
		unsigned n;
	} testv[] = {

		/* Sample aggregation headers from Chrome 102 */
		{0x28, 0, 0, 2, 1},
		{0x50, 0, 1, 1, 0},
	};
	int err = 0;

	for (size_t i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct test *test = &testv[i];
		struct av1_aggr_hdr hdr;
		struct mbuf mb = {
			.buf  = (uint8_t *)&test->byte,
			.size = 1,
			.pos  = 0,
			.end  = 1
		};

		err = av1_aggr_hdr_decode(&hdr, &mb);
		if (err)
			break;

		ASSERT_EQ(test->z, hdr.z);
		ASSERT_EQ(test->y, hdr.y);
		ASSERT_EQ(test->w, hdr.w);
		ASSERT_EQ(test->n, hdr.n);
	}

 out:
	return err;
}


static int test_av1_obu(void)
{
	struct av1_obu_hdr hdr;
	static const uint8_t buf[] = {

		/* libaom OBU_TEMPORAL_DELIMITER [type=2 x=0 s=1 size=0] */
		0x12, 0x00,

		/* libaom OBU_SEQUENCE_HEADER [type=1 x=0 s=1 size=12] */
		0x0a, 0x0c, 0x00, 0x00,
		0x00, 0x04, 0x3c, 0xff,
		0xbf, 0x81, 0xb5, 0x32,
		0x00, 0x80
	};
	struct mbuf mb = {
		.buf  = (uint8_t *)buf,
		.size = sizeof(buf),
		.pos  = 0,
		.end  = sizeof(buf)
	};
	int err;

	err = av1_obu_decode(&hdr, &mb);
	if (err)
		goto out;

	ASSERT_EQ(2, hdr.type);
	ASSERT_EQ(0, hdr.x);
	ASSERT_EQ(1, hdr.s);
	ASSERT_EQ(0, hdr.size);

	err = av1_obu_decode(&hdr, &mb);
	if (err)
		goto out;

	ASSERT_EQ(1, hdr.type);
	ASSERT_EQ(0, hdr.x);
	ASSERT_EQ(1, hdr.s);
	ASSERT_EQ(12, hdr.size);

	ASSERT_EQ(2, av1_obu_count(buf, sizeof(buf)));

 out:
	return err;
}


static const uint64_t dummy_ts = 0x0102030405060708ULL;

#define MAX_OBUS 10

struct test {
	/* input: */
	size_t pktsize;

	/* output: */
	struct mbuf *obus[MAX_OBUS];
	size_t obu_index;
	unsigned marker_count;
	unsigned new_count;
};


static int av1_packet_handler(bool marker, uint64_t rtp_ts,
			      const uint8_t *hdr, size_t hdr_len,
			      const uint8_t *pld, size_t pld_len,
			      void *arg)
{
	struct test *test = arg;
	struct mbuf *mb = mbuf_alloc(hdr_len + pld_len);
	struct av1_aggr_hdr aggr_hdr;
	int err = 0;
	unsigned count = 0;
	size_t size = 0;

	if (!mb)
		return ENOMEM;

	ASSERT_EQ(dummy_ts, rtp_ts);
	ASSERT_TRUE((hdr_len + pld_len) <= test->pktsize);

	err  = mbuf_write_mem(mb, hdr, hdr_len);
	err |= mbuf_write_mem(mb, pld, pld_len);
	if (err)
		goto out;

	mb->pos = 0;

	err = av1_aggr_hdr_decode(&aggr_hdr, mb);
	if (err)
		goto out;

	if (aggr_hdr.n)
		++test->new_count;

	if (aggr_hdr.z) {
		ASSERT_TRUE(test->obus[test->obu_index]->pos > 0);
	}
	else {
		ASSERT_EQ(0, test->obus[test->obu_index]->pos);
	}

	while (mbuf_get_left(mb) > 0) {
		++count;
		if (aggr_hdr.w == 0 || count < aggr_hdr.w) {
			uint64_t decoded_size = 0;
			err = av1_leb128_decode(mb, &decoded_size);
			if (err) {
				goto out;
			}
			/* Note: av1_leb128_decode always uses uint64_t,
			 * but mbuf uses size_t, which can be 32 bits */
			ASSERT_TRUE(decoded_size <= SIZE_MAX);
			size = (size_t)decoded_size;
			ASSERT_TRUE(size <= mbuf_get_left(mb));
		}
		else {
			size = mbuf_get_left(mb);
		}
		err = mbuf_write_mem(test->obus[test->obu_index],
			mbuf_buf(mb), size);
		if (err) {
			goto out;
		}
		mbuf_advance(mb, size);

		if (mbuf_get_left(mb) > 0 || !aggr_hdr.y) {
			mbuf_set_pos(test->obus[test->obu_index], 0);
			++test->obu_index;
		}
	}

	ASSERT_TRUE(aggr_hdr.w == 0 || count == aggr_hdr.w);

	if (marker) {
		++test->marker_count;
	}

 out:
	mem_deref(mb);
	return err;
}


static int copy_obu(struct mbuf *mb_bs, const uint8_t *buf, size_t size)
{
	struct av1_obu_hdr hdr;
	struct mbuf wrap = {
		.buf = (uint8_t *)buf,
		.size = size,
		.pos = 0,
		.end = size
	};
	bool has_size = true;

	int err = av1_obu_decode(&hdr, &wrap);
	if (err) {
		DEBUG_WARNING("av1: decode: could not decode OBU"
			" [%zu bytes]: %m\n", size, err);
		return err;
	}

	switch (hdr.type) {

	case AV1_OBU_SEQUENCE_HEADER:
	case AV1_OBU_FRAME_HEADER:
	case AV1_OBU_METADATA:
	case AV1_OBU_FRAME:
	case AV1_OBU_REDUNDANT_FRAME_HEADER:
	case AV1_OBU_TILE_GROUP:

		err = av1_obu_encode(mb_bs, hdr.type, has_size,
				     hdr.size, mbuf_buf(&wrap));
		if (err)
			return err;
		break;

	case AV1_OBU_TEMPORAL_DELIMITER:
	case AV1_OBU_TILE_LIST:
	case AV1_OBU_PADDING:
		/* MUST be ignored by receivers. */
		DEBUG_WARNING("av1: decode: copy: unexpected obu type %u (%s)"
			" [x=%d, s=%d, size=%zu]\n",
			      hdr.type, av1_obu_name(hdr.type),
			hdr.x, hdr.s, hdr.size);
		return EPROTO;

	default:
		DEBUG_WARNING("av1: decode: copy: unknown obu type %u (%s)"
			" [x=%d, s=%d, size=%zu]\n",
			hdr.type, av1_obu_name(hdr.type),
			hdr.x, hdr.s, hdr.size);
		return EPROTO;
	}

	return 0;
}


static int test_av1_packetize_base(unsigned count_bs, unsigned count_rtp,
				   size_t pktsize, const uint8_t *buf,
				   size_t size, const uint8_t *expected_buf,
				   size_t expected_size)
{
	struct test test;
	struct mbuf *mb_bs = mbuf_alloc(1024);
	bool new_flag = true;
	int err;

	if (!mb_bs)
		return ENOMEM;

	memset(&test, 0, sizeof(test));

	ASSERT_EQ(count_bs, av1_obu_count(buf, size));
	ASSERT_EQ(count_rtp, av1_obu_count_rtp(buf, size));

	test.pktsize = pktsize;

	for (size_t i = 0; i < MAX_OBUS; ++i) {
		test.obus[i] = mbuf_alloc(1024);
		if (!test.obus[i]) {
			err = ENOMEM;
			goto out;
		}
	}

	err = av1_packetize(&new_flag, true, dummy_ts,
			    buf, size, test.pktsize,
			    av1_packet_handler, &test);
	if (err)
		goto out;

	ASSERT_EQ(1, test.marker_count);
	ASSERT_EQ(1, test.new_count);

	/* prepend Temporal Delimiter */
	err = av1_obu_encode(mb_bs, AV1_OBU_TEMPORAL_DELIMITER, true, 0, NULL);
	TEST_ERR(err);

	for (size_t i = 0; i < test.obu_index; ++i) {
		err = copy_obu(mb_bs,
			mbuf_buf(test.obus[i]), mbuf_get_left(test.obus[i]));
		TEST_ERR(err);
	}

	/* compare bitstream with test-vector */
	TEST_MEMCMP(expected_buf, expected_size, mb_bs->buf, mb_bs->end);

 out:
	for (size_t i = 0; i < MAX_OBUS; ++i) {
		mem_deref(test.obus[i]);
	}
	mem_deref(mb_bs);

	return err;
}


static const uint8_t pkt_aom[] = {

	/* Temporal Delimiter */
	0x12, 0x00,

	/* Sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,
};

static const uint8_t pkt_aom5[] = {

	/* Temporal Delimiter */
	0x12, 0x00,

	/* Sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,
};

static const uint8_t pkt_aom_metadata[] = {

	/* Temporal Delimiter */
	0x12, 0x00,

	/* Sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,

	/* OBU frame header */
	0x1a, 0x1b,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x80,

	/* OBU metadata */
	0x2a, 0x1a,
	0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x80,

	/* OBU metadata */
	0x2a, 0x06,
	0x01, 0x01, 0x02, 0x03, 0x04, 0x80,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,
};

static const uint8_t pkt_multi_seq[] = {

	/* Temporal Delimiter */
	0x12, 0x00,

	/* Padding */
	0x7a, 0x04,
	0x01, 0x02, 0x03, 0x04,

	/* Sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,

	/* Padding */
	0x7a, 0x04,
	0x05, 0x06, 0x07, 0x08,

	/* Padding */
	0x7a, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,

	/* Duplicate sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,
};

static const uint8_t pkt_multi_seq_expected[] = {

	/* Temporal Delimiter */
	0x12, 0x00,

	/* Sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,

	/* Duplicate sequence header */
	0x0a, 0x0a,
	0x00, 0x00,  0x00, 0x01, 0x9f, 0xfb, 0xff, 0xf3, 0x00, 0x80,

	/* Frame */
	0x32, 0x17,
	0x10, 0x01, 0x92, 0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x57, 0xb6, 0xd3, 0xfb,
	0x3b, 0xe3, 0xe1, 0x31, 0xeb, 0x4f, 0x36,
};


/*
 * https://dl8.webmfiles.org/BeachDrone-AV1.webm
 *
 * frame   3:  size=320     pts=134  (0.134000 sec)
 * obu:  type=2,OBU_TEMPORAL_DELIMITER   x=0 s=1 size=0
 * obu:  type=3,OBU_FRAME_HEADER         x=0 s=1 size=23
 * obu:  type=4,OBU_TILE_GROUP           x=0 s=1 size=290
 *
 */
static const char pkt_beach[] =
	"12001a17301a2049648406a21a47fbdf"
	"cbb4180c4002041157404022a202001c"
	"64b538c87ccb8807fc1658bcd98ada85"
	"6a35745f32824a2ee8d5e11d80476188"
	"917a6662c19f0ca9eace86b8ac3ae880"
	"0561949ecbbc26f800d904d1714219a1"
	"0d1d0410370c6e0b8dead1bf1e8a291b"
	"fd0a1254a6e038998e091c7d5233b138"
	"68acf6225840618dcbfd948ed99943dd"
	"93df6037f6fda997cd2f8467b601d94e"
	"09169d57f8fa9c8d6abfcab091366231"
	"48c89c7d5a8b86544140a827f48a2b0b"
	"15d6836f4ceab733dd2f2ebbb20cb69a"
	"684dafb9403610e0560bad66b728c8fd"
	"38c315a1f63ac3d2fca0da95fdbfb9f8"
	"e61b4f18b90a455dad2fc91a32401007"
	"2942753e34c95c6d3693a555e660e6ca"
	"628a22fed94f3618d912b84a272e00da"
	"44b8cf62a7abfd5d0396e8848d8bd56d"
	"195bb21814c15700e825a4d9fe2a64f8"
	;


static int test_av1_packetize_range(
		unsigned count_bs, unsigned count_rtp,
		const uint8_t *buf, size_t size,
		const uint8_t *expected_buf, size_t expected_size) {
	int err = 0;
	for (size_t i = 10; i <= 120; ++i) {
		err = test_av1_packetize_base(count_bs, count_rtp, i,
			buf, size, expected_buf, expected_size);
		if (err) {
			return err;
		}
	}
	return err;
}


static int test_av1_packetize(void)
{
	uint8_t buf[320];
	int err;

	err = test_av1_packetize_range(2, 1,
		pkt_aom, sizeof(pkt_aom),
		pkt_aom, sizeof(pkt_aom));
	if (err)
		return err;

	err = test_av1_packetize_range(5, 4,
		pkt_aom5, sizeof(pkt_aom5),
		pkt_aom5, sizeof(pkt_aom5));
	if (err)
		return err;

	err = test_av1_packetize_range(6, 5,
		pkt_aom_metadata, sizeof(pkt_aom_metadata),
		pkt_aom_metadata, sizeof(pkt_aom_metadata));
	if (err)
		return err;

	err = test_av1_packetize_range(7, 3,
		pkt_multi_seq, sizeof(pkt_multi_seq),
		pkt_multi_seq_expected, sizeof(pkt_multi_seq_expected));
	if (err)
		return err;

	err = str_hex(buf, sizeof(buf), pkt_beach);
	if (err)
		return err;

	err = test_av1_packetize_range(3, 2,
		buf, sizeof(buf),
		buf, sizeof(buf));
	if (err)
		return err;

	return 0;
}


#define AV1_PACKET1_SIZE 1188
#define AV1_PACKET2_SIZE 231


struct state {
	uint8_t buf_packet1[AV1_PACKET1_SIZE];
	uint8_t buf_packet2[AV1_PACKET2_SIZE];
	unsigned count;
};


static int interop_packet_handler(bool marker, uint64_t rtp_ts,
				  const uint8_t *hdr, size_t hdr_len,
				  const uint8_t *pld, size_t pld_len,
				  void *arg)
{
	struct state *state = arg;
	struct mbuf *mb = mbuf_alloc(hdr_len + pld_len);
	int err = 0;
	(void)marker;
	(void)rtp_ts;

	if (!mb)
		return ENOMEM;

	err  = mbuf_write_mem(mb, hdr, hdr_len);
	err |= mbuf_write_mem(mb, pld, pld_len);
	if (err)
		goto out;

	switch (state->count) {

	case 0:
		TEST_MEMCMP(state->buf_packet1, sizeof(state->buf_packet1),
			    mb->buf, mb->end);
		break;

	case 1:
		TEST_MEMCMP(state->buf_packet2, sizeof(state->buf_packet2),
			    mb->buf, mb->end);
		break;

	default:
		err = EPROTO;
		break;
	}

 out:
	state->count = state->count + 1;

	mem_deref(mb);
	return err;
}


/*
 * Test AV1 interop with Chrome.
 */
static int test_av1_interop(void)
{
#define AV1_FRAME_SIZE 1421

	static const char frame[] =

		"12000a0a00000024cf7f0d80340132fc"
		"0a10717800ffffff16e6180000000b01"
		"bbc1318ad86995cba97034ff8767d6fd"
		"ade65542dbc40b9e44cc8e479f68b4b9"
		"5c7e78cabd7344021a5d99d51918f3e9"
		"b6a0afe14686c45b6dc9ff25d4dddd91"
		"8a4dcc3998be6af61811000b0d886601"
		"53036febf3c7fef1defb75b3ba396cb6"
		"f6a8bb84def6603617a995f270102f87"
		"a1eccaadac954247c9a116a1343ce905"
		"2aa5b90dba23bc7299b85dd829523aa0"
		"0a15a2db9e24dc34622ff7c772f4b0dd"
		"dff7afdbc95748c68d3ab706ffc4b772"
		"f44fd1bcbe20309a908a0dbdba8ce5db"
		"1dc9de2d75f48c5976e6fb941b5da795"
		"e96c5a8a70b5e55d0d8d8d3b084bb09d"
		"d32e83d121087052ee4597b17f1ac46d"
		"8b284742c095534146fd6dd6161e67cd"
		"58ef8f092a75b32585e7efecd001b4ad"
		"292804ce0aa4318fd7b5824497f39f19"
		"82174ed1ff800416f565393cfadc7c9e"
		"0140a4140ab96ac5d7e4b7891e2ff6d7"
		"6c789d81e28645f3873d1ddbb9e3152c"
		"4137cc1f13c743fa6454c849e7fe703e"
		"1e7ee19e5ea3b728b460a67b009fa952"
		"0608ed4dea672a6df720a892f42203c1"
		"13cc56903148e249e3b5f5f7266b0cf0"
		"539ffdac040ef551b589ee92bd4b081a"
		"652af89d56e7546b2b8ea35300324e2a"
		"3a74af972642454c5d3ba8caef3fe19c"
		"a2a31729113858d8f13fbde793ba7834"
		"b6e855f60b4302e42f8c7d32ed48e50d"
		"b9a87aa57ec0384293cd7fa4c02f2909"
		"b68d4f07afbe22059f52efaaab98d170"
		"ba612e8c05a68e048c3f66b7452269f6"
		"704346897559ab38dcc4f138e3796217"
		"02c0661a8f09ab7d57c1e2bbb3d58899"
		"28d2d189f7d33900c7fe606579a77709"
		"551254e1d2301f5445857e1d132edc01"
		"605128705cb22ff1184e70dc8985169e"
		"aafc996f81116ce8007f141f1908eb9c"
		"707c415ada0923e42f6e822453b1e330"
		"385b377e7f19f1d36a93a404affef91b"
		"6587849ef244940c636f3c458986f104"
		"174cb6af58160c28c0929aee986da31c"
		"1a0596ccecedf2dad9202ade93c4010e"
		"b39462aaf111aa53444fdf654e82a454"
		"909f97e361026a265c37a0616407589d"
		"01bb068ece454ba616612a29d67f61a7"
		"2aac84871f0503752525137a3b189c5e"
		"34cffb6d600c868eb54125f8861c9bac"
		"a580ef457eacd68b8dc30f32aa4cb7cb"
		"d3e20ced165b71c0617024f5423ee017"
		"3aad3af71a30f33609fcef771c3810b9"
		"fb61a350cfa97d6e5f219d593d28f4e4"
		"66590f89ad0851149852225eb07a042f"
		"9d8fb97f0f2437fb37e3102f6010794b"
		"e0ad882519f913c8db117aa093e663dd"
		"2183ac731449e62f803ba24086ea28f3"
		"814c33bdf9863927b544e1a74ebf6b20"
		"64dcb92efd8e8b71aab354601f0e75d7"
		"5686fe86984e6735c4ed2eef2b919236"
		"4c46a963e88661c5ea8f278fc1efa306"
		"67046926a2a75c23a5d63af373478cb8"
		"c55e11f9de4a61d77c5b11080fe258e4"
		"8509d86aa93249012678d1c40056e9f3"
		"44261079a1729a7b7853322b016847f4"
		"6ca4cdd0b107c7aa6024889ccd4b4002"
		"e2f69b53ed0d0063bf80936fb970bc12"
		"0fcabeb82b41b2c75bcb5211b6b5d404"
		"cbdcc175adeaad1ebac4e026989e3365"
		"d676ff62e674595509f48a43ee2ba010"
		"f12f8799e4c357fd369a108aa2f1a073"
		"e7a25e0cdb92be13e5267fe9d8d5e6b5"
		"31b8cb9f0549ad56e586670133ab39ed"
		"7124d942c2742f5e78c52f10c009bb48"
		"13b26fb55217f369c33400976663b912"
		"c1bd389762be20a040cee498411c47a0"
		"4c1e53d7b36c958dbdb56b58ebfc5a88"
		"faca07c3739c9bf28bfb8d7cd50f1fc5"
		"82d54aee4a17073b0552d989e51d6501"
		"35bcca12fc5f4c92924912d7a5a91b82"
		"edb8c0fda7e43526658c4ddd15a0d3e4"
		"d24a996aa902f9e51b43e67974fd59ed"
		"3ea2a6ede7ea3033d8d6f2d2dc624204"
		"558433c6a0a7315e970bba563c0dcb15"
		"879b64ff57418984b998bd4c70f33c95"
		"29d1184ad74cbcf14927771f562ae036"
		"fac2e439966307e5d9ae4d5984"
		;


	static const char packet1[] =

		/* NOTE: W=2 */
		"68"

		"0b0800000024cf7f0d80340130107178"
		"00ffffff16e6180000000b01bbc1318a"
		"d86995cba97034ff8767d6fdade65542"
		"dbc40b9e44cc8e479f68b4b95c7e78ca"
		"bd7344021a5d99d51918f3e9b6a0afe1"
		"4686c45b6dc9ff25d4dddd918a4dcc39"
		"98be6af61811000b0d88660153036feb"
		"f3c7fef1defb75b3ba396cb6f6a8bb84"
		"def6603617a995f270102f87a1eccaad"
		"ac954247c9a116a1343ce9052aa5b90d"
		"ba23bc7299b85dd829523aa00a15a2db"
		"9e24dc34622ff7c772f4b0dddff7afdb"
		"c95748c68d3ab706ffc4b772f44fd1bc"
		"be20309a908a0dbdba8ce5db1dc9de2d"
		"75f48c5976e6fb941b5da795e96c5a8a"
		"70b5e55d0d8d8d3b084bb09dd32e83d1"
		"21087052ee4597b17f1ac46d8b284742"
		"c095534146fd6dd6161e67cd58ef8f09"
		"2a75b32585e7efecd001b4ad292804ce"
		"0aa4318fd7b5824497f39f1982174ed1"
		"ff800416f565393cfadc7c9e0140a414"
		"0ab96ac5d7e4b7891e2ff6d76c789d81"
		"e28645f3873d1ddbb9e3152c4137cc1f"
		"13c743fa6454c849e7fe703e1e7ee19e"
		"5ea3b728b460a67b009fa9520608ed4d"
		"ea672a6df720a892f42203c113cc5690"
		"3148e249e3b5f5f7266b0cf0539ffdac"
		"040ef551b589ee92bd4b081a652af89d"
		"56e7546b2b8ea35300324e2a3a74af97"
		"2642454c5d3ba8caef3fe19ca2a31729"
		"113858d8f13fbde793ba7834b6e855f6"
		"0b4302e42f8c7d32ed48e50db9a87aa5"
		"7ec0384293cd7fa4c02f2909b68d4f07"
		"afbe22059f52efaaab98d170ba612e8c"
		"05a68e048c3f66b7452269f670434689"
		"7559ab38dcc4f138e379621702c0661a"
		"8f09ab7d57c1e2bbb3d5889928d2d189"
		"f7d33900c7fe606579a77709551254e1"
		"d2301f5445857e1d132edc0160512870"
		"5cb22ff1184e70dc8985169eaafc996f"
		"81116ce8007f141f1908eb9c707c415a"
		"da0923e42f6e822453b1e330385b377e"
		"7f19f1d36a93a404affef91b6587849e"
		"f244940c636f3c458986f104174cb6af"
		"58160c28c0929aee986da31c1a0596cc"
		"ecedf2dad9202ade93c4010eb39462aa"
		"f111aa53444fdf654e82a454909f97e3"
		"61026a265c37a0616407589d01bb068e"
		"ce454ba616612a29d67f61a72aac8487"
		"1f0503752525137a3b189c5e34cffb6d"
		"600c868eb54125f8861c9baca580ef45"
		"7eacd68b8dc30f32aa4cb7cbd3e20ced"
		"165b71c0617024f5423ee0173aad3af7"
		"1a30f33609fcef771c3810b9fb61a350"
		"cfa97d6e5f219d593d28f4e466590f89"
		"ad0851149852225eb07a042f9d8fb97f"
		"0f2437fb37e3102f6010794be0ad8825"
		"19f913c8db117aa093e663dd2183ac73"
		"1449e62f803ba24086ea28f3814c33bd"
		"f9863927b544e1a74ebf6b2064dcb92e"
		"fd8e8b71aab354601f0e75d75686fe86"
		"984e6735c4ed2eef2b9192364c46a963"
		"e88661c5ea8f278fc1efa30667046926"
		"a2a75c23a5d63af373478cb8c55e11f9"
		"de4a61d77c5b11080fe258e48509d86a"
		"a93249012678d1c40056e9f344261079"
		"a1729a7b7853322b016847f46ca4cdd0"
		"b107c7aa6024889ccd4b4002e2f69b53"
		"ed0d0063bf80936fb970bc120fcabeb8"
		"2b41b2c75bcb5211b6b5d404cbdcc175"
		"adeaad1ebac4e026989e3365d676ff62"
		"e674595509f48a43ee2ba010f12f8799"
		"e4c357fd369a108aa2f1a073e7a25e0c"
		"db92be13e5267fe9d8d5e6b531b8cb9f"
		"0549ad"
		;


	static const char packet2[] =

		/* NOTE: W=1 */

		"90"

		"56e586670133ab39ed7124d942c2742f"
		"5e78c52f10c009bb4813b26fb55217f3"
		"69c33400976663b912c1bd389762be20"
		"a040cee498411c47a04c1e53d7b36c95"
		"8dbdb56b58ebfc5a88faca07c3739c9b"
		"f28bfb8d7cd50f1fc582d54aee4a1707"
		"3b0552d989e51d650135bcca12fc5f4c"
		"92924912d7a5a91b82edb8c0fda7e435"
		"26658c4ddd15a0d3e4d24a996aa902f9"
		"e51b43e67974fd59ed3ea2a6ede7ea30"
		"33d8d6f2d2dc624204558433c6a0a731"
		"5e970bba563c0dcb15879b64ff574189"
		"84b998bd4c70f33c9529d1184ad74cbc"
		"f14927771f562ae036fac2e439966307"
		"e5d9ae4d5984"
		;

	struct state state;
	uint8_t buf[AV1_FRAME_SIZE];
	bool new_flag = true;
	int err;

	state.count = 0;

	err = str_hex(buf, sizeof(buf), frame);
	TEST_ERR(err);

	err = str_hex(state.buf_packet1, sizeof(state.buf_packet1), packet1);
	TEST_ERR(err);

	err = str_hex(state.buf_packet2, sizeof(state.buf_packet2), packet2);
	TEST_ERR(err);

	err = av1_packetize(&new_flag, true, dummy_ts,
			    buf, sizeof(buf), 1188,
			    interop_packet_handler, &state);
	if (err)
		goto out;

 out:
	return err;
}


int test_av1(void)
{
	int err;

	err = test_leb128();
	TEST_ERR(err);

	err = test_av1_aggr();
	TEST_ERR(err);

	err = test_av1_obu();
	TEST_ERR(err);

	err = test_av1_packetize();
	TEST_ERR(err);

	err = test_av1_interop();
	TEST_ERR(err);

out:
	return err;
}
