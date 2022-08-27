/**
 * @file wrap.c  SHA wrappers
 *
 * Copyright (C) 2022 Alfred E. Heggestad
 * Copyright (C) 2022 Sebastian Reimers <hallo@studio-link.de>
 */

#include <re_types.h>
#if defined(USE_OPENSSL)
#include <openssl/sha.h>
#elif defined (__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif defined (USE_MBEDTLS)
#include <mbedtls/md.h>
#endif
#include <re_sha.h>


/**
 * Calculate the SHA1 hash from a buffer
 *
 * @param d  Data buffer (input)
 * @param n  Number of input bytes
 * @param md Calculated SHA1 hash (output)
 */
void sha1(const uint8_t *d, size_t n, uint8_t *md)
{
#if defined(USE_OPENSSL)
	(void)SHA1(d, n, md);
#elif defined (__APPLE__)
	CC_SHA1(d, (uint32_t)n, md);
#elif defined (USE_MBEDTLS)
	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), d, n, md);
#else
	(void)d;
	(void)n;
	(void)md;
#error missing SHA-1 backend
#endif
}


/**
 * Calculate the SHA256 hash from a buffer
 *
 * @param d  Data buffer (input)
 * @param n  Number of input bytes
 * @param md Calculated SHA1 hash (output)
 */
void sha256(const uint8_t *d, size_t n, uint8_t *md)
{
#if defined(USE_OPENSSL)
	(void)SHA256(d, n, md);
#elif defined (__APPLE__)
	CC_SHA256(d, (uint32_t)n, md);
#elif defined (USE_MBEDTLS)
	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), d, n, md);
#else
	(void)d;
	(void)n;
	(void)md;
#error missing SHA-256 backend
#endif
}
