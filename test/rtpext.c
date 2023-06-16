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


struct rtpext_header {
	uint16_t type;
	uint16_t num_bytes;
};


/* Common for One-Byte and Two-Byte headers */
static int rtpext_hdr_decode(struct rtpext_header *hdr, struct mbuf *mb)
{
	if (mbuf_get_left(mb) < RTPEXT_HDR_SIZE)
		return EBADMSG;

	hdr->type      = ntohs(mbuf_read_u16(mb));
	hdr->num_bytes = ntohs(mbuf_read_u16(mb)) * 4;

	if (mbuf_get_left(mb) < hdr->num_bytes)
		return EBADMSG;

	return 0;
}


static int test_rtpext_long(void)
{
	static const uint8_t TEST_EXTENSION_ID_TWOBYTE = 0xf0;
#define TEST_DATA_LENGTH 3
#define NUM_BYTES_LONG 8
	static const uint8_t packet[RTPEXT_HDR_SIZE + NUM_BYTES_LONG] = {
		0x10, 0x00, 0x00, 0x02,
		0xf0, 0x03, 0x01, 0x02,
		0x03, 0x00, 0x00, 0x00
	};

	static const uint8_t data[TEST_DATA_LENGTH] = { 0x01, 0x02, 0x03 };

	struct mbuf *mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	struct rtpext_header hdr;
	struct rtpext ext;

	/* Encode packet */

	int err = rtpext_hdr_encode_long(mb, NUM_BYTES_LONG);
	ASSERT_EQ(0, err);

	err = rtpext_encode_long(mb, TEST_EXTENSION_ID_TWOBYTE,
				 TEST_DATA_LENGTH, data);
	ASSERT_EQ(0, err);

	/* padding */
	mbuf_fill(mb, 0x00, 3);

	TEST_MEMCMP(packet, sizeof(packet), mb->buf, mb->end);

	mb->pos = 0;

	/* Decode packet */

	err = rtpext_hdr_decode(&hdr, mb);
	ASSERT_EQ(0, err);

	ASSERT_EQ(RTPEXT_TYPE_MAGIC_LONG, hdr.type);
	ASSERT_EQ(NUM_BYTES_LONG,         hdr.num_bytes);

	err = rtpext_decode_long(&ext, mb);
	ASSERT_EQ(0, err);

	ASSERT_EQ(TEST_EXTENSION_ID_TWOBYTE, ext.id);
	ASSERT_EQ(TEST_DATA_LENGTH,          ext.len);
	TEST_MEMCMP(data, sizeof(data), ext.data, ext.len);

 out:
	mem_deref(mb);

	return err;
}


/*
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |       0x10    |    0x00       |           length=3            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      ID       |     L=0       |     ID        |     L=1       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |       data    |    0 (pad)    |       ID      |      L=4      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          data                                 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int test_rtpext_long_rfc(void)
{
#define NUM_BYTES_RFC (12)
	struct mbuf *mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	int err = rtpext_hdr_encode_long(mb, NUM_BYTES_RFC);
	ASSERT_EQ(0, err);

	/* Encode */

	err = rtpext_encode_long(mb, 0x80, 0, NULL);
	ASSERT_EQ(0, err);

	err = rtpext_encode_long(mb, 0x81, 1, (uint8_t *)"A" );
	ASSERT_EQ(0, err);

	/* padding */
	mbuf_write_u8(mb, 0x00);

	err = rtpext_encode_long(mb, 0x82, 4, (uint8_t *)"ABCD" );
	ASSERT_EQ(0, err);

	static const uint8_t packet[RTPEXT_HDR_SIZE + NUM_BYTES_RFC] = {
		0x10, 0x00, 0x00, 0x03,
		0x80, 0x00, 0x81, 0x01,
		0x41, 0x00, 0x82, 0x04,
		0x41, 0x42, 0x43, 0x44,
	};

	TEST_MEMCMP(packet, sizeof(packet), mb->buf, mb->end);

	mb->pos = 0;

	/* Decode */

	struct rtpext_header hdr;

	err = rtpext_hdr_decode(&hdr, mb);
	ASSERT_EQ(0, err);

	ASSERT_EQ(RTPEXT_TYPE_MAGIC_LONG, hdr.type);
	ASSERT_EQ(NUM_BYTES_RFC,          hdr.num_bytes);

	struct rtpext ext;

	err = rtpext_decode_long(&ext, mb);
	ASSERT_EQ(0, err);

	ASSERT_EQ(0x80, ext.id);
	ASSERT_EQ(0,    ext.len);

	err = rtpext_decode_long(&ext, mb);
	ASSERT_EQ(0, err);

	ASSERT_EQ(0x81, ext.id);
	ASSERT_EQ(1,    ext.len);
	ASSERT_EQ(0x41,    ext.data[0]);

	err = rtpext_decode_long(&ext, mb);
	ASSERT_EQ(0, err);

	ASSERT_EQ(0x82, ext.id);
	ASSERT_EQ(4,    ext.len);
	TEST_MEMCMP(&packet[12], 4, ext.data, ext.len);

 out:
	mem_deref(mb);
	return err;
}


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

	err = test_rtpext_long();
	if (err)
		goto out;

	err = test_rtpext_long_rfc();
	if (err)
		goto out;

 out:
	mem_deref(mb);
	return err;
}
