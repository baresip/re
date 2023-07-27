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
#elif defined (WIN32)
#include <windows.h>
#include <wincrypt.h>
#elif defined (USE_MBEDTLS)
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#endif
#include <re_hmac.h>


#define DEBUG_MODULE "hmac"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#if !defined (USE_OPENSSL) && defined (WIN32)
static void compute_hash(ALG_ID alg_id, const void* data, size_t dataSize,
			 uint8_t hashBuf[64], DWORD hashSize,
			 const void *hmacSecret, size_t hmacSecretSize)
{
	DWORD hashSizeSize = sizeof(hashSize);
	HCRYPTPROV context;
	HCRYPTKEY hmackey = 0;

	CryptAcquireContext(&context, 0, 0, PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);

	struct HmacSecretBlob {
		BLOBHEADER header;
		DWORD hmacSecretSize;
		BYTE hmacSecret[1];
	};
	size_t hmacSecretBlobSize =
		MAX(offsetof(struct HmacSecretBlob, hmacSecret) +
		    hmacSecretSize, sizeof(struct HmacSecretBlob));
	uint8_t blobData[256];
	struct HmacSecretBlob* hmacSecretBlob
		= (struct HmacSecretBlob*) ( blobData );

	hmacSecretBlob->header.bType = PLAINTEXTKEYBLOB;
	hmacSecretBlob->header.bVersion = CUR_BLOB_VERSION;
	hmacSecretBlob->header.reserved = 0;
	hmacSecretBlob->header.aiKeyAlg = CALG_RC2;
	hmacSecretBlob->hmacSecretSize = (DWORD)hmacSecretSize;
	memcpy(hmacSecretBlob->hmacSecret, hmacSecret, hmacSecretSize);

	CryptImportKey(context, blobData, (DWORD)hmacSecretBlobSize, 0,
		       CRYPT_IPSEC_HMAC_KEY, &hmackey);

	HCRYPTHASH hash;

	if (CryptCreateHash(context, CALG_HMAC, hmackey, 0, &hash)) {

		HMAC_INFO info = { 0 };
		info.HashAlgid = alg_id;

		CryptSetHashParam(hash, HP_HMAC_INFO, (BYTE *)&info, 0);

		CryptGetHashParam(hash, HP_HASHSIZE,
				  (BYTE *)&hashSize, &hashSizeSize, 0);
		if (hashSize == 0) {
			DEBUG_WARNING("INVALID HASHSIZE\n");
		}

		CryptHashData(hash, (BYTE*)data, (DWORD)dataSize, 0);
		CryptGetHashParam(hash, HP_HASHVAL, hashBuf, &hashSize, 0);

		CryptDestroyHash(hash);
	}

	CryptDestroyKey(hmackey);
	CryptReleaseContext(context, 0);
}
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

#elif defined (WIN32)
	compute_hash(CALG_SHA1, d, ld,
		     out, (DWORD)t, k, lk);
#elif defined (MBEDTLS_MD_C)
	int err;
	(void)t;

	err = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
			      k, lk, d, ld, out);
	if (err)
		DEBUG_WARNING("mbedtls_md_hmac: %s\n",
			      mbedtls_high_level_strerr(err));

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

#elif defined (WIN32)
	compute_hash(CALG_SHA_256, data, data_len,
		     out, (DWORD)out_len, key, key_len);
#elif defined (MBEDTLS_MD_C)
	int err;
	(void)out_len;

	err = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			      key, key_len, data, data_len, out);
	if (err)
		DEBUG_WARNING("mbedtls_md_hmac: %s\n",
			      mbedtls_high_level_strerr(err));
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
