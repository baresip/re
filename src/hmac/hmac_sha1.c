/**
 * @file hmac_sha1.c  Implements HMAC-SHA1 as of RFC 2202
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#ifdef USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#elif defined (__APPLE__)
#include <CommonCrypto/CommonHMAC.h>
#endif
#include <re_hmac.h>


/**
 * Function to compute the digest
 *
 * @param k   Secret key
 * @param lk  Length of the key in bytes
 * @param d   Data
 * @param ld  Length of data in bytes
 * @param out Digest output
 * @param t   Size of digest output
 */
void hmac_sha1(const uint8_t *k,  /* secret key */
	       size_t   lk,       /* length of the key in bytes */
	       const uint8_t *d,  /* data */
	       size_t   ld,       /* length of data in bytes */
	       uint8_t *out,      /* output buffer, at least "t" bytes */
	       size_t   t)
{
#ifdef USE_OPENSSL
	(void)t;

	if (!HMAC(EVP_sha1(), k, (int)lk, d, ld, out, NULL))
		ERR_clear_error();
#elif defined (__APPLE__)
	(void)t;

	CCHmac(kCCHmacAlgSHA1, k, lk, d, ld, out);
#else
	(void)k;
	(void)lk;
	(void)d;
	(void)ld;
	(void)out;
	(void)t;

#error missing HMAC-SHA1 backend


#endif
}


void hmac_sha256(const uint8_t *key, size_t key_len,
		 const uint8_t *data, size_t data_len,
		 uint8_t *out, size_t out_len)
{
#ifdef USE_OPENSSL

	(void)out_len;

	if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, NULL))
		ERR_clear_error();

#elif defined (__APPLE__)
	(void)out_len;

	CCHmac(kCCHmacAlgSHA256, key, key_len, data, data_len, out);
#else
	(void)key;
	(void)key_len;
	(void)data;
	(void)data_len;
	(void)out;
	(void)out_len;

#error missing HMAC-SHA256 backend


#endif
}
