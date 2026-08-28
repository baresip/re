/**
 * @file utf8.c  UTF-8 handling for ITU-T T.140 Real-Time Text
 *
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_sdp.h>
#include <re_red.h>
#include <re_t140.h>
#include "t140.h"


/*
 * T.140 text is a UTF-8 stream. On the wire a code point may in principle
 * be split across two packets, and a hostile or broken peer may send
 * sequences that are truncated, overlong, or outside the Unicode range.
 *
 * The decoder here is incremental and never emits anything but well-formed
 * UTF-8: an ill-formed sequence is replaced by U+FFFD, which is also what
 * T.140 uses to mark text lost in transmission.
 */


/**
 * Get the length of the UTF-8 sequence introduced by a lead byte
 *
 * @param b Lead byte
 *
 * @return Length in bytes, or 0 if b is not a valid lead byte
 */
unsigned t140_utf8_seqlen(uint8_t b)
{
	if (b < 0x80)
		return 1;
	else if (b < 0xc2)
		return 0;        /* continuation byte or overlong lead */
	else if (b < 0xe0)
		return 2;
	else if (b < 0xf0)
		return 3;
	else if (b < 0xf5)
		return 4;
	else
		return 0;
}


/**
 * Get the legal range of the byte following a lead byte
 *
 * The range of the second byte is narrower than 0x80..0xbf for some lead
 * bytes, which is what rules out overlong encodings, the surrogate range,
 * and code points above U+10FFFF.
 */
static void seq_range(uint8_t lead, uint8_t *lo, uint8_t *hi)
{
	switch (lead) {

	case 0xe0: *lo = 0xa0; *hi = 0xbf; break;
	case 0xed: *lo = 0x80; *hi = 0x9f; break;
	case 0xf0: *lo = 0x90; *hi = 0xbf; break;
	case 0xf4: *lo = 0x80; *hi = 0x8f; break;
	default:   *lo = 0x80; *hi = 0xbf; break;
	}
}


/**
 * Check that a buffer holds complete and well-formed UTF-8
 *
 * @param buf Buffer to check
 * @param len Length of the buffer
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_utf8_check(const uint8_t *buf, size_t len)
{
	size_t i = 0;

	if (!buf && len)
		return EINVAL;

	while (i < len) {

		unsigned need = t140_utf8_seqlen(buf[i]);
		uint8_t lo, hi;
		unsigned j;

		if (!need || i + need > len)
			return EBADMSG;

		seq_range(buf[i], &lo, &hi);

		for (j=1; j<need; j++) {

			if (buf[i+j] < lo || buf[i+j] > hi)
				return EBADMSG;

			lo = 0x80;
			hi = 0xbf;
		}

		i += need;
	}

	return 0;
}


/**
 * Count the code points in a buffer of well-formed UTF-8
 *
 * @param buf Buffer to count
 * @param len Length of the buffer
 *
 * @return Number of code points
 */
unsigned t140_utf8_chars(const uint8_t *buf, size_t len)
{
	unsigned n = 0;
	size_t i;

	if (!buf)
		return 0;

	for (i=0; i<len; i++) {

		if ((buf[i] & 0xc0) != 0x80)
			++n;
	}

	return n;
}


/**
 * Get the length of the longest prefix of a buffer that holds at most a
 * given number of complete code points and stays within a byte budget
 *
 * @param buf      Buffer of well-formed UTF-8
 * @param len      Length of the buffer
 * @param maxbytes Byte budget
 * @param maxchars Maximum number of code points
 * @param charsp   Number of code points taken, set on return (optional)
 *
 * @return Length in bytes of the prefix
 */
size_t t140_utf8_take(const uint8_t *buf, size_t len, size_t maxbytes,
		      unsigned maxchars, unsigned *charsp)
{
	unsigned chars = 0;
	size_t n = 0;

	if (!buf)
		goto out;

	while (n < len && chars < maxchars) {

		unsigned need = t140_utf8_seqlen(buf[n]);

		if (!need || n + need > len || n + need > maxbytes)
			break;

		n += need;
		++chars;
	}

 out:
	if (charsp)
		*charsp = chars;

	return n;
}


/**
 * Encode one code point as UTF-8
 *
 * @param mb Buffer to encode into
 * @param cp Code point
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_utf8_encode(struct mbuf *mb, uint32_t cp)
{
	int err;

	if (!mb)
		return EINVAL;

	if (cp < 0x80) {
		err = mbuf_write_u8(mb, (uint8_t)cp);
	}
	else if (cp < 0x800) {
		err  = mbuf_write_u8(mb, (uint8_t)(0xc0 | (cp >> 6)));
		err |= mbuf_write_u8(mb, (uint8_t)(0x80 | (cp & 0x3f)));
	}
	else if (cp < 0x10000) {
		err  = mbuf_write_u8(mb, (uint8_t)(0xe0 | (cp >> 12)));
		err |= mbuf_write_u8(mb, (uint8_t)(0x80 | ((cp >> 6) & 0x3f)));
		err |= mbuf_write_u8(mb, (uint8_t)(0x80 | (cp & 0x3f)));
	}
	else if (cp < 0x110000) {
		err  = mbuf_write_u8(mb, (uint8_t)(0xf0 | (cp >> 18)));
		err |= mbuf_write_u8(mb, (uint8_t)(0x80 | ((cp >> 12) & 0x3f)));
		err |= mbuf_write_u8(mb, (uint8_t)(0x80 | ((cp >> 6) & 0x3f)));
		err |= mbuf_write_u8(mb, (uint8_t)(0x80 | (cp & 0x3f)));
	}
	else {
		err = EINVAL;
	}

	return err;
}


/**
 * Reset an incremental UTF-8 decoder, discarding any partial sequence
 *
 * @param d Decoder state
 */
void t140_utf8_reset(struct t140_utf8 *d)
{
	if (!d)
		return;

	d->n = 0;
	d->need = 0;
}


/**
 * Decode a chunk of a UTF-8 stream
 *
 * A sequence split across two chunks is held until the rest of it arrives.
 * An ill-formed sequence is replaced by a single U+FFFD and the offending
 * byte is then reconsidered as a lead byte, so that a single bad byte
 * cannot swallow the text that follows it.
 *
 * @param d   Decoder state
 * @param mb  Buffer to write the decoded text to
 * @param buf Chunk to decode
 * @param len Length of the chunk
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_utf8_decode(struct t140_utf8 *d, struct mbuf *mb,
		     const uint8_t *buf, size_t len)
{
	size_t i = 0;
	int err = 0;

	if (!d || !mb || (len && !buf))
		return EINVAL;

	while (i < len && !err) {

		uint8_t b = buf[i];

		if (!d->n) {

			unsigned need = t140_utf8_seqlen(b);

			++i;

			if (!need) {
				err = t140_utf8_encode(mb, T140_LOSS);
				continue;
			}

			if (need == 1) {
				err = mbuf_write_u8(mb, b);
				continue;
			}

			d->buf[0] = b;
			d->n      = 1;
			d->need   = need;

			seq_range(b, &d->lo, &d->hi);
			continue;
		}

		if (b < d->lo || b > d->hi) {

			/* the byte is not consumed, it may be a lead byte */
			err = t140_utf8_encode(mb, T140_LOSS);
			d->n = 0;
			continue;
		}

		d->buf[d->n++] = b;
		d->lo = 0x80;
		d->hi = 0xbf;
		++i;

		if (d->n == d->need) {
			err = mbuf_write_mem(mb, d->buf, d->n);
			d->n = 0;
		}
	}

	return err;
}
