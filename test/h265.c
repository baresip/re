/**
 * @file h265.c H.265 Testcode
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <re_h265.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "h265test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_h265(void)
{
	uint8_t buf[H265_HDR_SIZE];
	struct h265_nal hdr;
	enum {TID = 1};
	int err;

	h265_nal_encode(buf, H265_NAL_VPS_NUT, TID);

	err = h265_nal_decode(&hdr, buf);
	if (err)
		goto out;

	ASSERT_EQ(32, hdr.nal_unit_type);
	ASSERT_EQ(TID, hdr.nuh_temporal_id_plus1);

	ASSERT_TRUE(!h265_is_keyframe(H265_NAL_VPS_NUT));
	ASSERT_TRUE( h265_is_keyframe(H265_NAL_IDR_W_RADL));

 out:
	return err;
}


enum {
	H265_FU_HDR_SIZE = 1
};

struct h265_fu {
	unsigned s:1;
	unsigned e:1;
	unsigned type:6;
};


static inline int h265_fu_decode(struct h265_fu *fu, struct mbuf *mb)
{
	uint8_t v;

	if (mbuf_get_left(mb) < 1)
		return EBADMSG;

	v = mbuf_read_u8(mb);

	fu->s    = v>>7 & 0x1;
	fu->e    = v>>6 & 0x1;
	fu->type = v>>0 & 0x3f;

	return 0;
}


struct state {

	/* depacketizer */
	struct mbuf *mb;
	size_t frag_start;
	bool frag;

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


static int depack_handle_h265(struct state *st, bool marker,
			      struct mbuf *mb)
{
	static const uint8_t nal_seq[3] = {0, 0, 1};
	struct h265_nal hdr;
	int err;

	if (mbuf_get_left(mb) < H265_HDR_SIZE)
		return EBADMSG;

	err = h265_nal_decode(&hdr, mbuf_buf(mb));
	if (err)
		return err;

	mbuf_advance(mb, H265_HDR_SIZE);

#if 0
	re_printf("h265: decode:  [%s]  %s  type=%2d  %s\n",
	      marker ? "M" : " ",
	      h265_is_keyframe(hdr.nal_unit_type) ? "<KEY>" : "     ",
	      hdr.nal_unit_type,
	      h265_nalunit_name(hdr.nal_unit_type));
#endif

	if (st->frag && hdr.nal_unit_type != H265_NAL_FU) {
		re_printf("h265: lost fragments; discarding previous NAL\n");
		fragment_rewind(st);
		st->frag = false;
	}

	/* handle NAL types */
	if (hdr.nal_unit_type <= 40) {

		mb->pos -= H265_HDR_SIZE;

		err  = mbuf_write_mem(st->mb, nal_seq, 3);
		err |= mbuf_write_mem(st->mb, mbuf_buf(mb),mbuf_get_left(mb));
		if (err)
			goto out;
	}
	else if (H265_NAL_FU == hdr.nal_unit_type) {

		struct h265_fu fu;

		err = h265_fu_decode(&fu, mb);
		if (err)
			return err;

		if (fu.s) {
			if (st->frag) {
				DEBUG_WARNING("h265: lost fragments;"
					      " ignoring NAL\n");
				fragment_rewind(st);
			}

			st->frag_start = st->mb->pos;
			st->frag = true;

			hdr.nal_unit_type = fu.type;

			err  = mbuf_write_mem(st->mb, nal_seq, 3);
			err |= h265_nal_encode_mbuf(st->mb, &hdr);
			if (err)
				goto out;
		}
		else {
			if (!st->frag) {
				re_printf("h265: ignoring fragment\n");
				return 0;
			}
		}

		err = mbuf_write_mem(st->mb, mbuf_buf(mb), mbuf_get_left(mb));
		if (err)
			goto out;

		if (fu.e)
			st->frag = false;
	}
	else if (hdr.nal_unit_type == H265_NAL_AP) {

		while (mbuf_get_left(mb) >= 2) {

			const uint16_t len = ntohs(mbuf_read_u16(mb));

			if (mbuf_get_left(mb) < len)
				return EBADMSG;

			err  = mbuf_write_mem(st->mb, nal_seq, 3);
			err |= mbuf_write_mem(st->mb, mbuf_buf(mb), len);
			if (err)
				goto out;

                        mb->pos += len;
		}
	}
	else {
		DEBUG_WARNING("unknown H265 NAL type %u (%s) [%zu bytes]\n",
			hdr.nal_unit_type,
			h265_nalunit_name(hdr.nal_unit_type),
			mbuf_get_left(mb));
		return EPROTO;
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


enum { DUMMY_TS = 36000 };


static int packet_handler(bool marker, uint64_t rtp_ts,
			  const uint8_t *hdr, size_t hdr_len,
			  const uint8_t *pld, size_t pld_len,
			  void *arg)
{
	struct state *state = arg;
	struct mbuf *mb_pkt = mbuf_alloc(hdr_len + pld_len);
	int err;

	if (!mb_pkt)
		return ENOMEM;

	ASSERT_EQ(DUMMY_TS, rtp_ts);

	++state->count;

	err  = mbuf_write_mem(mb_pkt, hdr, hdr_len);
	err |= mbuf_write_mem(mb_pkt, pld, pld_len);
	if (err)
		goto out;

	mb_pkt->pos = 0;

	err = depack_handle_h265(state, marker, mb_pkt);

 out:
	mem_deref(mb_pkt);
	return err;
}


/* bitstream in Annex-B format (with startcode 00 00 01) */
/* H265_NAL_VPS_NUT */
static const char *bitstream =
	"00000140010c01ffff01600000030090000003000003003cba024000000001";


int test_h265_packet(void)
{
	struct state state;
	const size_t pktsize = 8;
	int err;

	memset(&state, 0, sizeof(state));

	state.len = strlen(bitstream)/2;

	err = str_hex(state.buf, state.len, bitstream);
	if (err)
		return err;

	state.mb = mbuf_alloc(1024);
	if (!state.mb)
		return ENOMEM;

	err = h265_packetize(DUMMY_TS, state.buf, state.len, pktsize,
			     packet_handler, &state);
	if (err)
		goto out;

	ASSERT_TRUE(state.count >= 1);
	ASSERT_TRUE(state.complete);

 out:
	mem_deref(state.mb);

	return err;
}
