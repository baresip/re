/**
 * @file wrap.c  MD5 wrappers
 *
 * Copyright (C) 2010 Creytiv.com
 */
#ifdef USE_OPENSSL
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#elif defined (__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif defined (WIN32)
#include <windows.h>
#include <wincrypt.h>
#elif defined (USE_MBEDTLS)
#include <mbedtls/md5.h>
#include <mbedtls/error.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_md5.h>


#define DEBUG_MODULE "md5"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

/**
 * Calculate the MD5 hash from a buffer
 *
 * @param d  Data buffer (input)
 * @param n  Number of input bytes
 * @param md Calculated MD5 hash (output)
 */
void md5(const uint8_t *d, size_t n, uint8_t *md)
{
#ifdef USE_OPENSSL
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx, d, n);
	EVP_DigestFinal_ex(ctx, md, NULL);
	EVP_MD_CTX_free(ctx);
#elif defined (__APPLE__)
	CC_MD5(d, (unsigned int)n, md);

#elif defined (WIN32)
	HCRYPTPROV context;
	HCRYPTHASH hash;
	DWORD hash_size = MD5_SIZE;

	CryptAcquireContext(&context, 0, 0, PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);

	CryptCreateHash(context, CALG_MD5, 0, 0, &hash);
	CryptHashData(hash, d, (DWORD)n, 0);
	CryptGetHashParam(hash, HP_HASHVAL, md, &hash_size, 0);

	CryptDestroyHash(hash);
	CryptReleaseContext(context, 0);
#elif defined (MBEDTLS_MD_C)
	int err;

	err = mbedtls_md5(d, n, md);
	if (err)
		DEBUG_WARNING("mbedtls_md5: %s\n",
			      mbedtls_high_level_strerr(err));
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
