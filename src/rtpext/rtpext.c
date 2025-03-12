/**
 * @file rtpext.c  RTP Header Extensions
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re_types.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_fmt.h>
#include <re_rtpext.h>


#define DEBUG_MODULE "rtpext"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * RFC 8285 A General Mechanism for RTP Header Extensions
 *
 * - One-Byte Header:  Supported
 * - Two-Byte Header:  Supported
 *
 * https://datatracker.ietf.org/doc/html/rfc8285
 */


/**
 * Encode the One-Byte header for all RTP extensions
 *
 * @param mb        Buffer to encode into
 * @param num_bytes Total size for all RTP extensions
 *
 * @return 0 if success, otherwise errorcode
 */
int rtpext_hdr_encode(struct mbuf *mb, size_t num_bytes)
{
	int err = 0;

	if (!mb || !num_bytes)
		return EINVAL;

	if (num_bytes & 0x3) {
		DEBUG_WARNING("hdr_encode: num_bytes (%zu) must be multiple"
			      " of 4\n", num_bytes);
		return EINVAL;
	}

	err |= mbuf_write_u16(mb, htons(RTPEXT_TYPE_MAGIC));
	err |= mbuf_write_u16(mb, htons((uint16_t)(num_bytes / 4)));

	return err;
}


/**
 * Encode the Two-Byte header for all RTP extensions
 *
 * @param mb        Buffer to encode into
 * @param num_bytes Total size for all RTP extensions (multiple of 4)
 *
 * @return 0 if success, otherwise errorcode
 */
int rtpext_hdr_encode_long(struct mbuf *mb, size_t num_bytes)
{
	int err = 0;

	if (!mb || !num_bytes)
		return EINVAL;

	if (num_bytes & 0x3) {
		DEBUG_WARNING("hdr_encode: num_bytes (%zu) must be multiple"
			      " of 4\n", num_bytes);
		return EINVAL;
	}

	err |= mbuf_write_u16(mb, htons(RTPEXT_TYPE_MAGIC_LONG));
	err |= mbuf_write_u16(mb, htons((uint16_t)(num_bytes / 4)));

	return err;
}


/**
 * Encode an RTP header extension with One-Byte header
 *
 * @param mb   Buffer to encode into
 * @param id   Identifier
 * @param len  Length of data field
 * @param data Data bytes
 *
 * @return 0 if success, otherwise errorcode
 */
int rtpext_encode(struct mbuf *mb, uint8_t id, size_t len,
		  const uint8_t *data)
{
	size_t start;
	int err;

	if (!mb || !data)
		return EINVAL;

	if (id < RTPEXT_ID_MIN || id > RTPEXT_ID_MAX)
		return EINVAL;
	if (len < RTPEXT_LEN_MIN || len > RTPEXT_LEN_MAX)
		return EINVAL;

	start = mb->pos;

	err  = mbuf_write_u8(mb, (uint8_t)(id << 4 | (len-1)));
	err |= mbuf_write_mem(mb, data, len);
	if (err)
		return err;

	/* padding */
	while ((mb->pos - start) & 0x03)
		err |= mbuf_write_u8(mb, 0x00);

	return err;
}


/**
 * Decode an RTP header extension with One-Byte header
 *
 * @param ext RTP Extension object
 * @param mb  Buffer to decode from
 *
 * @return 0 if success, otherwise errorcode
 */
int rtpext_decode(struct rtpext *ext, struct mbuf *mb)
{
	uint8_t v;
	int err;

	if (!ext || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < 1)
		return EBADMSG;

	memset(ext, 0, sizeof(*ext));

	v = mbuf_read_u8(mb);

	ext->id  = v >> 4;
	ext->len = (v & 0x0f) + 1;

	if (ext->id < RTPEXT_ID_MIN || ext->id > RTPEXT_ID_MAX) {
		DEBUG_WARNING("decode: invalid ID %u\n", ext->id);
		return EBADMSG;
	}
	if (ext->len > mbuf_get_left(mb)) {
		DEBUG_WARNING("decode: short read\n");
		return ENODATA;
	}

	err = mbuf_read_mem(mb, ext->data, ext->len);
	if (err)
		return err;

	/* skip padding */
	while (mbuf_get_left(mb)) {
		uint8_t pad = mbuf_buf(mb)[0];

		if (pad != 0x00)
			break;

		mbuf_advance(mb, 1);
	}

	return 0;
}


/**
 * Encode an RTP header extension with Two-Byte header
 *
 * @param mb   Buffer to encode into
 * @param id   Identifier
 * @param len  Length of data field
 * @param data Data bytes
 *
 * @return 0 if success, otherwise errorcode
 */
int rtpext_encode_long(struct mbuf *mb, uint8_t id, uint8_t len,
		       const uint8_t *data)
{
	if (!mb)
		return EINVAL;

	int err  = mbuf_write_u8(mb, id);
	err     |= mbuf_write_u8(mb, len);

	if (data && len)
		err |= mbuf_write_mem(mb, data, len);

	return err;
}


/**
 * Decode an RTP header extension with Two-Byte header
 *
 * @param ext RTP Extension object
 * @param mb  Buffer to decode from
 *
 * @return 0 if success, otherwise errorcode
 */
int rtpext_decode_long(struct rtpext *ext, struct mbuf *mb)
{
	if (!ext || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < 2)
		return EBADMSG;

	memset(ext, 0, sizeof(*ext));

	ext->id  = mbuf_read_u8(mb);
	ext->len = mbuf_read_u8(mb);

	if (ext->id == 0) {
		DEBUG_WARNING("decode_long: invalid ID %u\n", ext->id);
		return EBADMSG;
	}
	if (ext->len > mbuf_get_left(mb)) {
		DEBUG_WARNING("decode_long: short read (%zu > %zu)\n",
			      ext->len, mbuf_get_left(mb));
		return ENODATA;
	}

	int err = mbuf_read_mem(mb, ext->data, ext->len);
	if (err)
		return err;

	/* skip padding */
	while (mbuf_get_left(mb)) {
		uint8_t pad = mbuf_buf(mb)[0];

		if (pad != 0x00)
			break;

		mbuf_advance(mb, 1);
	}

	return 0;
}


/**
 * Finds an RTP extension by its ID
 *
 * @param extv Pointer to an array of RTP extensions
 * @param extc Number of elements in the RTP extension array
 * @param id   The ID of the RTP extension to find
 *
 * @return Pointer to the matching RTP extension on success, otherwise NULL
 */
const struct rtpext *rtpext_find(const struct rtpext *extv, size_t extc,
				 uint8_t id)
{
	for (size_t i = 0; i < extc; i++) {
		const struct rtpext *rtpext = &extv[i];

		if (rtpext->id == id)
			return rtpext;
	}

	return NULL;
}
