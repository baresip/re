/**
 * @file wrap.c  SHA256 wrappers
 *
 */
#ifdef USE_OPENSSL
#include <stddef.h>
#include <openssl/sha.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sha.h>

/**
 * Calculate the SHA256 hash from a buffer
 *
 * @param d  Data buffer (input)
 * @param n  Number of input bytes
 * @param md Calculated SHA256 hash (output)
 */
void sha256(const uint8_t *d, size_t n, uint8_t *md)
{
	(void)SHA256(d, n, md);
}


/**
 * Calculate the SHA256 hash from a formatted string
 *
 * @param md  Calculated SHA256 hash
 * @param fmt Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int sha256_printf(uint8_t *md, const char *fmt, ...)
{
	struct mbuf mb;
	va_list ap;
	int err;

	mbuf_init(&mb);

	va_start(ap, fmt);
	err = mbuf_vprintf(&mb, fmt, ap);
	va_end(ap);

	if (!err)
		sha256(mb.buf, mb.end, md);

	mbuf_reset(&mb);

	return err;
}

#endif
