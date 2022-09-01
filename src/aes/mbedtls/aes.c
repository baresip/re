/**
 * @file mbedtls/aes.c  AES (Advanced Encryption Standard) using MbedTLS
 *
 * Copyright (C) 2022 Dmitry Ilyin
 */
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_aes.h>

/* only 96-bits IV for now */
#define IV_LEN  12

struct aes {
	enum aes_mode mode;

	union {
		struct {
			mbedtls_aes_context ctx;
			size_t nc_off;
			unsigned char nonce_counter[16];
			unsigned char stream_block[16];
		} ctr;

		struct {
			mbedtls_gcm_context ctx;
			bool encr;
			uint8_t iv[IV_LEN];
		} gcm;
	};
};


static inline bool set_crypt_dir(struct aes *aes, bool encr)
{
	if (aes->gcm.encr != encr) {

		/* update the encrypt/decrypt direction */
		int mode = encr ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT;
		if (mbedtls_gcm_starts(&aes->gcm.ctx, mode,
				aes->gcm.iv, IV_LEN, NULL, 0)) {
			return false;
		}

		aes->gcm.encr = encr;
	}

	return true;
}

static void destructor(void *arg)
{
	struct aes *st = arg;

	switch (st->mode) {
		case AES_MODE_CTR:
			mbedtls_aes_free(&st->ctr.ctx);
			break;
		case AES_MODE_GCM:
			mbedtls_gcm_free(&st->gcm.ctx);
			break;
	}
}


int aes_alloc(struct aes **aesp, enum aes_mode mode,
	      const uint8_t *key, size_t key_bits,
	      const uint8_t *iv)
{
	struct aes *st;
	int err = 0;

	if (!aesp || !key)
		return EINVAL;

	st = mem_zalloc(sizeof(*st), destructor);
	if (!st)
		return ENOMEM;

	st->mode = mode;

	switch (mode) {
		case AES_MODE_CTR:
			mbedtls_aes_init(&st->ctr.ctx);
			err = mbedtls_aes_setkey_enc(&st->ctr.ctx, key,
				key_bits);
			if (err)
				goto out;
			break;
		case AES_MODE_GCM:
			st->gcm.encr = true;
			mbedtls_gcm_init(&st->gcm.ctx);
			err = mbedtls_gcm_setkey(&st->gcm.ctx,
				MBEDTLS_CIPHER_ID_AES, key, key_bits);
			if (err)
				goto out;
			if (iv != NULL) {
				memcpy(st->gcm.iv, iv, IV_LEN);
			}
			if (mbedtls_gcm_starts(&st->gcm.ctx,
					MBEDTLS_GCM_ENCRYPT,
					st->gcm.iv, IV_LEN, NULL, 0))
				goto out;
			break;
	}

 out:
	if (err)
		mem_deref(st);
	else
		*aesp = st;

	return err;
}


void aes_set_iv(struct aes *aes, const uint8_t *iv)
{
	int mode = aes->gcm.encr ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT;

	if (!aes || !iv)
		return;

	switch (aes->mode) {
		case AES_MODE_GCM:
			if (iv != NULL) {
				memcpy(aes->gcm.iv, iv, IV_LEN);
			}
			mbedtls_gcm_starts(&aes->gcm.ctx, mode,
					aes->gcm.iv, IV_LEN, NULL, 0);
		default:
			;
	}
}


int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	if (!aes || !in)
		return EINVAL;


	switch (aes->mode) {
		case AES_MODE_CTR:
			mbedtls_aes_crypt_ctr(&aes->ctr.ctx, len,
				&aes->ctr.nc_off, aes->ctr.nonce_counter,
				aes->ctr.stream_block, in, out);
			break;
		case AES_MODE_GCM:
			if (!set_crypt_dir(aes, true))
				return EPROTO;

			mbedtls_gcm_update(&aes->gcm.ctx, len, in, out);
			break;
	}

	return 0;
}


int aes_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	if (!aes || !in)
		return EINVAL;

	switch (aes->mode) {
		case AES_MODE_CTR:
			mbedtls_aes_crypt_ctr(&aes->ctr.ctx, len,
				&aes->ctr.nc_off, aes->ctr.nonce_counter,
				aes->ctr.stream_block, in, out);
			break;
		case AES_MODE_GCM:
			if (!set_crypt_dir(aes, false))
				return EPROTO;

			mbedtls_gcm_update(&aes->gcm.ctx, len, in, out);
			break;
	}

	return 0;
}


/**
 * Get the authentication tag for an AEAD cipher (e.g. GCM)
 *
 * @param aes    AES Context
 * @param tag    Authentication tag
 * @param taglen Length of Authentication tag
 *
 * @return 0 if success, otherwise errorcode
 */
int aes_get_authtag(struct aes *aes, uint8_t *tag, size_t taglen)
{
	if (!aes || !tag || !taglen)
		return EINVAL;

	switch (aes->mode) {

	case AES_MODE_GCM:
		mbedtls_gcm_finish(&aes->gcm.ctx, tag, taglen);
		return 0;

	default:
		return ENOTSUP;
	}
}

/**
 * Authenticate a decryption tag for an AEAD cipher (e.g. GCM)
 *
 * @param aes    AES Context
 * @param tag    Authentication tag
 * @param taglen Length of Authentication tag
 *
 * @return 0 if success, otherwise errorcode
 *
 * @retval EAUTH if authentication failed
 */
int aes_authenticate(struct aes *aes, const uint8_t *tag, size_t taglen)
{
	unsigned char check_tag[16];

	if (!aes || !tag || !taglen)
		return EINVAL;

	switch (aes->mode) {

	case AES_MODE_GCM:
		mbedtls_gcm_finish(&aes->gcm.ctx, check_tag, taglen);
		if (memcpy(check_tag, tag, taglen) != 0)
			return EAUTH;
		return 0;

	default:
		return ENOTSUP;
	}
}
