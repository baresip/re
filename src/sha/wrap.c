/**
 * @file wrap.c  SHA wrappers
 *
 * Copyright (C) 2022 Alfred E. Heggestad
 * Copyright (C) 2022 Sebastian Reimers <hallo@studio-link.de>
 */

#include <re_types.h>
#include <re_mbuf.h>
#ifdef USE_OPENSSL
#include <openssl/sha.h>
#elif defined (__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif defined (WIN32)
#include <windows.h>
#include <wincrypt.h>
#elif defined (USE_MBEDTLS)
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>
#endif
#include <re_sha.h>


#define DEBUG_MODULE "sha"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#if !defined (USE_OPENSSL) && defined (WIN32)
static void compute_hash(ALG_ID alg_id, const void *data, size_t data_size,
			 uint8_t *md, DWORD hash_size)
{
	HCRYPTPROV context;
	HCRYPTHASH hash;

	CryptAcquireContext(&context, 0, 0, PROV_RSA_AES,CRYPT_VERIFYCONTEXT);

	CryptCreateHash(context, alg_id, 0, 0, &hash);
	CryptHashData(hash, (BYTE*)data, (DWORD)data_size, 0);
	CryptGetHashParam(hash, HP_HASHVAL, md, &hash_size, 0);

	CryptDestroyHash(hash);
	CryptReleaseContext(context, 0);
}
#endif


/**
 * Calculate the SHA1 hash from a buffer
 *
 * @param d  Data buffer (input)
 * @param n  Number of input bytes
 * @param md Calculated SHA1 hash (output)
 */
void sha1(const uint8_t *d, size_t n, uint8_t *md)
{
#ifdef USE_OPENSSL
	(void)SHA1(d, n, md);
#elif defined (__APPLE__)
	CC_SHA1(d, (uint32_t)n, md);
#elif defined (WIN32)
	compute_hash(CALG_SHA1, d, n, md, SHA1_DIGEST_SIZE);
#elif defined (MBEDTLS_MD_C)
	int err;

	err = mbedtls_sha1(d, n, md);
	if (err)
		DEBUG_WARNING("mbedtls_sha1: %s\n",
			      mbedtls_high_level_strerr(err));
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
#ifdef USE_OPENSSL
	(void)SHA256(d, n, md);
#elif defined (__APPLE__)
	CC_SHA256(d, (uint32_t)n, md);
#elif defined (WIN32)
	compute_hash(CALG_SHA_256, d, n, md, SHA256_DIGEST_SIZE);
#elif defined (MBEDTLS_MD_C)
	int err;

	err = mbedtls_sha256(d, n, md, 0);
	if (err)
		DEBUG_WARNING("mbedtls_sha256: %s\n",
			      mbedtls_high_level_strerr(err));
#else
	(void)d;
	(void)n;
	(void)md;
#error missing SHA-256 backend
#endif
}


/**
 * Calculate the SHA-256 hash from a formatted string
 *
 * @param md  Calculated SHA-256 hash
 * @param fmt Formatted string
 *
 * @return 0 if success, otherwise errorcode
 */
int sha256_printf(uint8_t md[32], const char *fmt, ...)
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
