/**
 * @file h264.c H.264 Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "h264test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum { DUMMY_TS = 36000 };


#if 0
static void dump_annexb(const uint8_t *start, size_t size)
{
	const uint8_t *end = start + size;
	unsigned count = 0;

	re_printf("---- H.264 Annex-B: ----\n");

	const uint8_t *r = h264_find_startcode(start, end);

	while (r < end) {

		struct h264_nal_header hdr;

		/* skip zeros */
		while (!*(r++))
			;

		const uint8_t *r1 = h264_find_startcode(r, end);
		size_t nal_len = r1 - r;

		h264_nal_header_decode_buf(&hdr, r);

		re_printf(".... nal:  len=%2zu  nri=%u  type=%s\n",
			  nal_len,
			  hdr.nri, h264_nal_unit_name(hdr.type));

		r = r1;

		++count;
	}

	re_printf("Total NAL units: %u\n", count);
	re_printf("\n");
}


static void dump_rtp(const uint8_t *p, size_t size)
{
	struct h264_nal_header hdr;

	h264_nal_header_decode_buf(&hdr, p);

	re_printf("RTP NAL: size=%zu nri=%u type=%u(%s)\n",
		  size,
		  hdr.nri, hdr.type, h264_nal_unit_name(hdr.type));
	re_printf("\n");
}
#endif


static int test_h264_stap_a_encode_base(const uint8_t *frame, size_t len,
				   bool long_startcode)
{
	enum { MAX_NRI = 3 };
	struct mbuf *mb_pkt   = mbuf_alloc(256);
	struct mbuf *mb_frame = mbuf_alloc(256);
	struct h264_nal_header hdr;
	int err;

	if (!mb_pkt || !mb_frame) {
		err = ENOMEM;
		goto out;
	}

	err = h264_stap_encode(mb_pkt, frame, len);
	if (err)
		goto out;

	mb_pkt->pos = 0;

	err = h264_nal_header_decode(&hdr, mb_pkt);
	ASSERT_EQ(0, err);

	ASSERT_EQ(MAX_NRI,          hdr.nri);              /* NOTE: max NRI */
	ASSERT_EQ(H264_NALU_STAP_A, hdr.type);

	if (long_startcode) {
		err = h264_stap_decode_annexb_long(mb_frame, mb_pkt);
		ASSERT_EQ(0, err);
	}
	else {
		err = h264_stap_decode_annexb(mb_frame, mb_pkt);
		ASSERT_EQ(0, err);
	}

	TEST_MEMCMP(frame, len, mb_frame->buf, mb_frame->end);

 out:
	mem_deref(mb_frame);
	mem_deref(mb_pkt);

	return err;
}


static int test_h264_stap_a_encode(void)
{
	static const uint8_t frame[] = {

		/* AUD */
		0x00, 0x00, 0x01,
		0x09, 0x10,

		/* SPS */
		0x00, 0x00, 0x01,
		0x67, 0x42, 0xc0, 0x1f, 0x8c, 0x8d, 0x40,

		/* PPS */
		0x00, 0x00, 0x01,
		0x68, 0xce, 0x3c, 0x80,

		/* IDR_SLICE */
		0x00, 0x00, 0x01,
		0x65, 0xb8, 0x00, 0x04, 0x00, 0x00, 0x05, 0x39,
	};
	static const uint8_t frame_long[] = {

		/* AUD */
		0x00, 0x00, 0x00, 0x01,
		0x09, 0x10,

		/* SPS */
		0x00, 0x00, 0x00, 0x01,
		0x67, 0x42, 0xc0, 0x1f, 0x8c, 0x8d, 0x40,

		/* PPS */
		0x00, 0x00, 0x00, 0x01,
		0x68, 0xce, 0x3c, 0x80,

		/* IDR_SLICE */
		0x00, 0x00, 0x00, 0x01,
		0x65, 0xb8, 0x00, 0x04, 0x00, 0x00, 0x05, 0x39,
	};
	int err;

	err = test_h264_stap_a_encode_base(frame, sizeof(frame), false);
	TEST_ERR(err);

	err = test_h264_stap_a_encode_base(frame_long, sizeof(frame_long),
					   true);
	TEST_ERR(err);

 out:
	return err;
}


static int test_h264_stap_a_decode(void)
{
	static const uint8_t pkt[] = {

		/* SPS */
		0x00, 0x0e,
		0x67, 0x42, 0xc0, 0x1f, 0x8c, 0x8d,
		0x40, 0x50, 0x1e, 0xd0, 0x0f, 0x08,
		0x84, 0x6a,

		/* PPS */
		0x00, 0x04,
		0x68, 0xce, 0x3c, 0x80,

		/* AUD */
		0x00, 0x02,
		0x09, 0x10,
	};
	struct mbuf *mb_pkt   = mbuf_alloc(256);
	struct mbuf *mb_frame = mbuf_alloc(256);
	struct mbuf *mb_pkt2  = mbuf_alloc(256);
	int err;

	if (!mb_pkt || !mb_frame || !mb_pkt2) {
		err = ENOMEM;
		goto out;
	}

	err = mbuf_write_mem(mb_pkt, pkt, sizeof(pkt));
	ASSERT_EQ(0, err);

	mb_pkt->pos = 0;

	err = h264_stap_decode_annexb(mb_frame, mb_pkt);
	TEST_ERR(err);

	err = h264_stap_encode(mb_pkt2, mb_frame->buf, mb_frame->end);
	ASSERT_EQ(0, err);

	TEST_MEMCMP(pkt, sizeof(pkt), mb_pkt2->buf+1, mb_pkt2->end-1);

 out:
	mem_deref(mb_frame);
	mem_deref(mb_pkt2);
	mem_deref(mb_pkt);

	return err;
}


int test_h264(void)
{
	struct h264_nal_header hdr, hdr2;
	static const uint8_t nal = 0x25;
	int err;

	struct mbuf *mb = mbuf_alloc(1);
	if (!mb)
		return ENOMEM;

	hdr.f = 0;
	hdr.nri = 1;
	hdr.type = H264_NALU_IDR_SLICE;

	err = h264_nal_header_encode(mb, &hdr);
	if (err)
		goto out;

	TEST_EQUALS(1, mb->pos);
	TEST_EQUALS(1, mb->end);
	TEST_EQUALS(nal, mb->buf[0]);

	mb->pos = 0;

	err = h264_nal_header_decode(&hdr2, mb);
	if (err)
		goto out;

	TEST_EQUALS(1, mb->pos);
	TEST_EQUALS(1, mb->end);

	TEST_EQUALS(0, hdr2.f);
	TEST_EQUALS(1, hdr2.nri);
	TEST_EQUALS(5, hdr2.type);

	err = test_h264_stap_a_encode();
	if (err)
		goto out;

	err = test_h264_stap_a_decode();
	if (err)
		goto out;

 out:
	mem_deref(mb);
	return err;
}


int test_h264_sps(void)
{
	static const struct test {
		const char *buf;
		struct h264_sps sps;
		struct vidsz size;
	} testv[] = {

		/* sony 1920 x 1080 (scaling list)
		 *
		 * sps:0 profile:122/41 poc:0 ref:0 120x68 MB-AFF 8B8
		 *       crop:0/0/0/8 VUI 422 1/50 b10 reo:-1
		 *
		 */
		{
			.buf =
			"7a1029b6d420223319c6632321011198ce33191821033a46"
			"656a6524ade91232141a2634ada441822301502b1a246948"
			"30402e111208c68c0441284c34f01e0113f2e03c60202028"
			"0000030008000003019420",
			.sps = {
				122,41,0,2,
				4,0,0,120,68,
				0,0,0,8
			},
			.size = {1920, 1080}
		},

		/* rv
		 *
		 * sps:0 profile:66/52 poc:2 ref:1 120x68 FRM 8B8
		 * crop:0/0/0/8 VUI 420 1/360 b8 reo:0
		 */
		{
			.buf = "42c034da01e0089f961000000300",
			.sps = {
				66,52,0,1,
				4,2,1,120,68,
				0,0,0,8
			},
			.size = {1920, 1080}
		},

		/* confcall
		 *
		 * sps:0 profile:100/40 poc:0 ref:3 120x68 FRM
		 * 8B8 crop:0/0/0/8 VUI 420 1/60 b8 reo:1
		 */

		{
			.buf =
			"640028acd100780227e5c05a808080"
			"a0000003002000000781e3062240",
			.sps = {
				100,40,0,1,
				4,0,3,120,68,
				0,0,0,8
			},
			.size = {1920, 1080}
		},

		/* expert
		 *
		 * sps:0 profile:100/31 poc:0 ref:4 80x45 FRM
		 */
		{
			.buf =
			"64001facd9405005bb011000000300100000030320f1831960",
			.sps = {
				100,31,0,1,
				4,0,4,80,45,
				0,0,0,0
			},
			.size = {1280, 720}
		},

		/* px
		 *
		 * sps:0 profile:66/31 poc:2 ref:1 80x45 FRM
		 *       crop:0/0/0/0 VUI 420 2000/120000 b8 reo:0
		 */
		{
			.buf =
			"42c01f95a014016c8400001f40000753023c2211a8",
			.sps = {
				66,31,0,1,
				8,2,1,80,45,
				0,0,0,0
			},
			.size = {1280, 720}
		},

		/* allonsy 854x480
		 *
		 * sps:0 profile:77/30 poc:0 ref:3 54x30 FRM 8B8
		 *       crop:0/10/0/0 VUI 420 1/50 b8 reo:1
		 *
		 */
		{
			.buf =
			"4d401ee8806c1ef37808800000030080000019078b1689",
			.sps = {
				77,30,0,1,
				4,0,3,54,30,
				0,10,0,0
			},
			.size = {854, 480}
		},

		/* sony 1920x1080
		 *
		 * sps:0 profile:122/40 poc:0 ref:4 120x68 FRM 8B8
		 *       crop:0/0/0/8 VUI 422 1/50 b10 reo:2
		 *
		 */
		{
			.buf =
			"7a0028b6cd940780227e2701100"
			"0000300100000030320f1831960",
			.sps = {
				122,40,0,2,
				4,0,4,120,68,
				0,0,0,8
			},
			.size = {1920, 1080}
		},

		/* testsrc2 yuv444 400x200
		 *
		 * sps:0 profile:244/13 poc:0 ref:4 25x13 FRM 8B8
		 *       crop:0/0/0/8 VUI 444 1/50 b8 reo:2
		 *
		 */
		{
			.buf =
			"f4000d919b283237f13808800000030080000019078a14cb",
			.sps = {
				244,13,0,3,
				4,0,4,25,13,
				0,0,0,8
			},
			.size = {400, 200}
		},

		/* jellyfish 4K 3840 x 2160
		 *
		 * sps:0 profile:100/51 poc:0 ref:3 240x135 FRM 8B8
		 *       crop:0/0/0/0 VUI 420 1001/60000 b8 reo:1
		 *
		 */
		{
			.buf =
			"640033ac2ca400f0010fbff0001000152020202800001f"
			"4800075307510001cd9400000568bc37e31c1da162d120",
			.sps = {
				100,51,0,1,
				8,0,3,240,135,
				0,0,0,0
			},
			.size = {3840, 2160}
		},
	};
	const struct test *test_short;
	struct h264_sps sps;
	uint8_t buf[256];
	size_t i;
	size_t max_len;
	int e, err;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct test *test = &testv[i];
		struct h264_sps ref = test->sps;
		size_t len = str_len(test->buf)/2;
		struct vidsz size;

		err = str_hex(buf, len, test->buf);
		if (err)
			return err;

		err = h264_sps_decode(&sps, buf, len);
		if (err)
			return err;

		h264_sps_resolution(&sps, &size.w, &size.h);

		TEST_EQUALS(ref.profile_idc, sps.profile_idc);

		TEST_EQUALS(ref.level_idc, sps.level_idc);

		TEST_EQUALS(ref.seq_parameter_set_id,
			    sps.seq_parameter_set_id);

		TEST_EQUALS(ref.chroma_format_idc,
			    sps.chroma_format_idc);

		TEST_EQUALS(ref.log2_max_frame_num,
			    sps.log2_max_frame_num);

		TEST_EQUALS(ref.pic_order_cnt_type,
			    sps.pic_order_cnt_type);

		TEST_EQUALS(ref.max_num_ref_frames,
			    sps.max_num_ref_frames);

		TEST_EQUALS(ref.pic_width_in_mbs,
			    sps.pic_width_in_mbs);

		TEST_EQUALS(ref.pic_height_in_map_units,
			    sps.pic_height_in_map_units);

		TEST_EQUALS(ref.frame_crop_left_offset,
			    sps.frame_crop_left_offset);
		TEST_EQUALS(ref.frame_crop_right_offset,
			    sps.frame_crop_right_offset);
		TEST_EQUALS(ref.frame_crop_top_offset,
			    sps.frame_crop_top_offset);
		TEST_EQUALS(ref.frame_crop_bottom_offset,
			    sps.frame_crop_bottom_offset);

		/* verify correct resolution */
		TEST_EQUALS(test->size.w, size.w);
		TEST_EQUALS(test->size.h, size.h);
	}

	test_short = &testv[0];
	max_len = str_len(test_short->buf) / 2;

	err = str_hex(buf, max_len, test_short->buf);
	if (err)
		return err;

	for (i = 1; i <= max_len; i++) {

		size_t len = i;

		e = h264_sps_decode(&sps, buf, len);

		switch (e) {

		case EBADMSG:
		case EINVAL:
		case 0:
			break;

		default:
			DEBUG_WARNING("unexpected error code %d (%m)\n",
				      e, e);
			return EINVAL;
		}
	}

 out:
	return err;
}


struct state {

	/* depacketizer */
	struct mbuf *mb;
	size_t frag_start;
	bool frag;
	bool long_startcode;

	/* test */
	uint8_t buf[256];
	size_t len;
	unsigned count;
	bool complete;
};


static void fragment_rewind(struct state *vds)
{
	vds->mb->pos = vds->frag_start;
	vds->mb->end = vds->frag_start;
}


static int depack_handle_h264(struct state *st, bool marker,
			      struct mbuf *src)
{
	static const uint8_t nal_seq3[3] = {0, 0, 1};
	static const uint8_t nal_seq4[4] = {0, 0, 0, 1};
	struct h264_nal_header h264_hdr;
	size_t nal_seq_len = st->long_startcode ?
		sizeof(nal_seq4) : sizeof(nal_seq3);
	int err;

	err = h264_nal_header_decode(&h264_hdr, src);
	if (err)
		return err;

#if 0
	re_printf("decode: %s %s type=%2d %s  \n",
		  marker ? "[M]" : "   ",
		  h264_is_keyframe(h264_hdr.type) ? "<KEY>" : "     ",
		  h264_hdr.type,
		  h264_nal_unit_name(h264_hdr.type));
#endif

	if (h264_hdr.f) {
		DEBUG_WARNING("H264 forbidden bit set!\n");
		return EBADMSG;
	}

	/* handle NAL types */
	if (1 <= h264_hdr.type && h264_hdr.type <= 23) {

		--src->pos;

		/* prepend H.264 NAL start sequence */
		err  = mbuf_write_mem(st->mb,
				      st->long_startcode ? nal_seq4 : nal_seq3,
				      nal_seq_len);

		err |= mbuf_write_mem(st->mb, mbuf_buf(src),
				      mbuf_get_left(src));
		if (err)
			goto out;
	}
	else if (H264_NALU_FU_A == h264_hdr.type) {

		struct h264_fu fu;

		err = h264_fu_hdr_decode(&fu, src);
		if (err)
			return err;

		h264_hdr.type = fu.type;

		if (fu.s) {
			if (st->frag) {
				DEBUG_WARNING("start: lost fragments;"
					      " ignoring previous NAL\n");
				fragment_rewind(st);
			}

			st->frag_start = st->mb->pos;
			st->frag = true;

			/* prepend H.264 NAL start sequence */
			mbuf_write_mem(st->mb,
			       st->long_startcode ? nal_seq4 : nal_seq3,
			       nal_seq_len);

			/* encode NAL header back to buffer */
			err = h264_nal_header_encode(st->mb, &h264_hdr);
			if (err)
				goto out;
		}
		else {
			if (!st->frag) {
				re_printf("ignoring fragment"
				      " (nal=%u)\n", fu.type);
				return 0;
			}
		}

		err = mbuf_write_mem(st->mb, mbuf_buf(src),
				     mbuf_get_left(src));
		if (err)
			goto out;

		if (fu.e)
			st->frag = false;
	}
	else if (H264_NALU_STAP_A == h264_hdr.type) {

		if (st->long_startcode)
			err = h264_stap_decode_annexb_long(st->mb, src);
		else
			err = h264_stap_decode_annexb(st->mb, src);
		if (err)
			goto out;
	}
	else {
		DEBUG_WARNING("decode: unknown NAL type %u\n",
			      h264_hdr.type);
		return EBADMSG;
	}

	if (!marker)
		return 0;

	/* verify complete packet */
	st->complete = true;
	TEST_MEMCMP(st->buf, st->len, st->mb->buf, st->mb->end);

 out:
	mbuf_rewind(st->mb);
	st->frag = false;

	return err;
}


static int packet_handler(bool marker, uint64_t rtp_ts,
			  const uint8_t *hdr, size_t hdr_len,
			  const uint8_t *pld, size_t pld_len,
			  void *arg)
{
	struct state *state = arg;
	struct mbuf *mb_pkt = mbuf_alloc(hdr_len + pld_len);
	int err = 0;

	if (!mb_pkt)
		return ENOMEM;

	ASSERT_EQ(DUMMY_TS, rtp_ts);

	++state->count;

	if (hdr && hdr_len)
		err |= mbuf_write_mem(mb_pkt, hdr, hdr_len);

	if (pld && pld_len)
		err |= mbuf_write_mem(mb_pkt, pld, pld_len);

	if (err)
		goto out;

	mb_pkt->pos = 0;

	err = depack_handle_h264(state, marker, mb_pkt);

 out:
	mem_deref(mb_pkt);
	return err;
}


static int test_h264_packet_base(const char *bs, bool long_startcode,
				 size_t max_pktsize)
{
	struct state state;
	int err;

	memset(&state, 0, sizeof(state));

	state.long_startcode = long_startcode;
	state.len = strlen(bs)/2;

	err = str_hex(state.buf, state.len, bs);
	if (err)
		return err;

	state.mb = mbuf_alloc(1024);
	if (!state.mb)
		return ENOMEM;

	err = h264_packetize(DUMMY_TS, state.buf, state.len, max_pktsize,
			     packet_handler, &state);
	if (err)
		goto out;

	ASSERT_TRUE(state.count >= 1);
	ASSERT_TRUE(state.complete);

 out:
	mem_deref(state.mb);

	return err;
}


/* bitstream in Annex-B format (with startcode 00 00 01) */
static const char *bitstream =
	"0000016701020304"
	"0000016801020304"
	"000001650010e2238712983719283719823798";


/* bitstream in Annex-B format (with startcode 00 00 00 01) */
static const char *bitstream_long =
	"000000016701020304"
	"000000016801020304"
	"00000001650010e2238712983719283719823798";


int test_h264_packet(void)
{
	const size_t MAX_PKTSIZE = 8;
	int err;

	err = test_h264_packet_base(bitstream, false, MAX_PKTSIZE);
	TEST_ERR(err);

	err = test_h264_packet_base(bitstream_long, true, MAX_PKTSIZE);
	TEST_ERR(err);

 out:
	return err;
}
