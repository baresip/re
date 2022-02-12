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


/** SHA-1 Block size */
#ifndef SHA_BLOCKSIZE
#define SHA_BLOCKSIZE   64
#endif


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
