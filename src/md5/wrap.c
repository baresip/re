/**
 * @file wrap.c  MD5 wrappers
 *
 * Copyright (C) 2010 Creytiv.com
 */
#if defined(USE_OPENSSL)
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#elif defined(USE_MBEDTLS)
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_md5.h>


/**
 * Calculate the MD5 hash from a buffer
 *
 * @param d  Data buffer (input)
 * @param n  Number of input bytes
 * @param md Calculated MD5 hash (output)
 */
void md5(const uint8_t *d, size_t n, uint8_t *md)
{
#if defined(USE_OPENSSL)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx, d, n);
	EVP_DigestFinal_ex(ctx, md, NULL);
	EVP_MD_CTX_free(ctx);
#else
	(void)MD5(d, n, md);
#endif
#elif defined(USE_MBEDTLS)
#else
#error missing MD5 backend
#endif
}


/**
 * Calculate the MD5 hash from a formatted string
 *
 * @param md  Calculated MD5 hash
 * @param fmt Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int md5_printf(uint8_t *md, const char *fmt, ...)
{
	struct mbuf mb;
	va_list ap;
	int err;

	mbuf_init(&mb);

	va_start(ap, fmt);
	err = mbuf_vprintf(&mb, fmt, ap);
	va_end(ap);

	if (!err)
		md5(mb.buf, mb.end, md);

	mbuf_reset(&mb);

	return err;
}
