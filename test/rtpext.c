/**
 * @file rtpext.c  RTP Header Extensions
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "rtpext"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static const uint8_t packet_bytes[] = {

	/* Header */
	0xbe, 0xde, 0x00, 0x01,

	/* First Extension */
	0x40, 0x30,

	/* Second Extension */
	0x10, 0xe0
};


int test_rtpext(void)
{
	struct mbuf *mb = mbuf_alloc(sizeof(packet_bytes));
	if (!mb)
		return ENOMEM;

	int err = mbuf_write_mem(mb, packet_bytes, sizeof(packet_bytes));
	ASSERT_EQ(0, err);

	mb->pos = 0;

	/* decode header */
	uint16_t type  = ntohs(mbuf_read_u16(mb));
	uint16_t words = ntohs(mbuf_read_u16(mb));

	ASSERT_EQ(RTPEXT_TYPE_MAGIC, type);
	ASSERT_EQ(1, words);

	size_t num_bytes = words * sizeof(uint32_t);

	ASSERT_EQ(num_bytes, mbuf_get_left(mb));

	struct rtpext ext;

	/* First extension */
	err = rtpext_decode(&ext, mb);
	ASSERT_EQ(0, err);
	ASSERT_EQ(4, ext.id);
	ASSERT_EQ(1, ext.len);
	ASSERT_EQ(0x30, ext.data[0]);

	/* Second extension */
	err = rtpext_decode(&ext, mb);
	ASSERT_EQ(0, err);
	ASSERT_EQ(1, ext.id);
	ASSERT_EQ(1, ext.len);
	ASSERT_EQ(0xe0, ext.data[0]);

 out:
	mem_deref(mb);
	return err;
}
