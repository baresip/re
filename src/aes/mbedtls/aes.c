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
#define GCM_IV_LEN  12

enum crypt_mode {
	ENCRYPT = 0,
	DECRYPT = 1,
};

enum options {
	FORCE = 1,
};

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
			enum crypt_mode encr;
			uint8_t iv[GCM_IV_LEN];
			uint8_t* aad;
			size_t aad_len;
		} gcm;
	};
};


static inline bool set_crypt_dir(struct aes *aes, enum crypt_mode encr,
		enum options opts)
{
	if (opts & FORCE && aes->gcm.encr != encr) {

		/* update the encrypt/decrypt direction */
		int mode = encr ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT;
		if (mbedtls_gcm_starts(&aes->gcm.ctx, mode, aes->gcm.iv,
				GCM_IV_LEN, aes->gcm.aad, aes->gcm.aad_len)) {
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
			if (st->gcm.aad) {
				mem_deref(st->gcm.aad);
			}
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
			if (mbedtls_aes_setkey_enc(&st->ctr.ctx, key,
				key_bits))
				goto out;
			if (iv)
				memcpy(st->ctr.nonce_counter, iv,
						sizeof(st->ctr.nonce_counter));
			break;
		case AES_MODE_GCM:
			st->gcm.encr = true;
			mbedtls_gcm_init(&st->gcm.ctx);
			err = mbedtls_gcm_setkey(&st->gcm.ctx,
				MBEDTLS_CIPHER_ID_AES, key, key_bits);
			if (err)
				goto out;
			if (iv != NULL) {
				memcpy(st->gcm.iv, iv, GCM_IV_LEN);
			}
			if (mbedtls_gcm_starts(&st->gcm.ctx,
					MBEDTLS_GCM_ENCRYPT,
					st->gcm.iv, GCM_IV_LEN, st->gcm.aad,
					st->gcm.aad_len))
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
				memcpy(aes->gcm.iv, iv, GCM_IV_LEN);
			}
			mbedtls_gcm_starts(&aes->gcm.ctx, mode,
					aes->gcm.iv, GCM_IV_LEN,
					aes->gcm.aad, aes->gcm.aad_len);
		default:
			;
	}
}


static int add_aad(struct aes *aes, const uint8_t *in, size_t len) {
	void* new_alloc;

	if (aes->gcm.aad) {
		new_alloc = mem_realloc(aes->gcm.aad, aes->gcm.aad_len + len);
		if (new_alloc == NULL)
			return ENOMEM;
		aes->gcm.aad = new_alloc;
	} else
		aes->gcm.aad = mem_alloc(len, NULL);
	if (!aes->gcm.aad)
		return ENOMEM;
	memcpy(aes->gcm.aad + aes->gcm.aad_len, in, len);
	aes->gcm.aad_len += len;

	return 0;
}


int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int ret;

	if (!aes || !in)
		return EINVAL;


	switch (aes->mode) {
		case AES_MODE_CTR:
			if (mbedtls_aes_crypt_ctr(&aes->ctr.ctx, len,
				&aes->ctr.nc_off, aes->ctr.nonce_counter,
				aes->ctr.stream_block, in, out))
				return EPROTO;
			break;
		case AES_MODE_GCM:
			if (out == NULL) {
				ret = add_aad(aes, in, len);
				if (ret)
					return ret;
				if (!set_crypt_dir(aes, ENCRYPT, FORCE))
					return EPROTO;
				return 0;
			}

			if (!set_crypt_dir(aes, ENCRYPT, 0))
				return EPROTO;

			if (mbedtls_gcm_update(&aes->gcm.ctx, len, in, out))
				return EPROTO;
			break;
	}

	return 0;
}


int aes_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int ret;

	if (!aes || !in)
		return EINVAL;

	switch (aes->mode) {
		case AES_MODE_CTR:
			if (mbedtls_aes_crypt_ctr(&aes->ctr.ctx, len,
				&aes->ctr.nc_off, aes->ctr.nonce_counter,
				aes->ctr.stream_block, in, out))
				return EPROTO;
			break;
		case AES_MODE_GCM:
			if (out == NULL) {
				ret = add_aad(aes, in, len);
				if (ret)
					return ret;
				if (!set_crypt_dir(aes, DECRYPT, FORCE))
					return EPROTO;
				return 0;
			}

			if (!set_crypt_dir(aes, DECRYPT, 0))
				return EPROTO;

			if (mbedtls_gcm_update(&aes->gcm.ctx, len, in, out))
				return EPROTO;
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
