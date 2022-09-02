/**
 * @file mbedtls/aes.c  AES (Advanced Encryption Standard) using MbedTLS
 *
 * Copyright (C) 2022 Dmitry Ilyin
 */
#include <string.h>
#include <mbedtls/version.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_aes.h>

/* only 96-bits IV for now */
#define GCM_IV_LEN  12

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
			bool started;
			int direction;
			uint8_t iv[GCM_IV_LEN];
			uint8_t* aad;
			size_t aad_len;
		} gcm;
	};
};


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
				(unsigned)key_bits))
				goto out;
			if (iv)
				memcpy(st->ctr.nonce_counter, iv,
						sizeof(st->ctr.nonce_counter));
			break;
		case AES_MODE_GCM:
			st->gcm.direction = -1;
			mbedtls_gcm_init(&st->gcm.ctx);
			if (mbedtls_gcm_setkey(&st->gcm.ctx,
				MBEDTLS_CIPHER_ID_AES, key,
				(unsigned)key_bits))
				goto out;
			if (iv)
				memcpy(st->gcm.iv, iv, GCM_IV_LEN);
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
	if (!aes || !iv)
		return;

	switch (aes->mode) {
		case AES_MODE_CTR:
			memcpy(aes->ctr.nonce_counter, iv,
				sizeof(aes->ctr.nonce_counter));
			break;
		case AES_MODE_GCM:
			memcpy(aes->gcm.iv, iv, GCM_IV_LEN);
			break;
	}
}


static int add_aad(struct aes *aes, const uint8_t *in, size_t len,
	int direction)
{
	void* new_alloc;

	if (aes->gcm.started && aes->gcm.direction != direction) {
		if (aes->gcm.aad) {
			mem_deref(aes->gcm.aad);
			aes->gcm.aad = NULL;
			aes->gcm.aad_len = 0;
		}
		aes->gcm.started = false;
	}

	if (aes->gcm.aad) {
		new_alloc = mem_realloc(aes->gcm.aad, aes->gcm.aad_len + len);
		if (new_alloc == NULL)
			return ENOMEM;
		aes->gcm.aad = new_alloc;
	}
	else {
		aes->gcm.aad = mem_alloc(len, NULL);
		if (!aes->gcm.aad)
			return ENOMEM;
	}
	memcpy(aes->gcm.aad + aes->gcm.aad_len, in, len);
	aes->gcm.aad_len += len;

	return 0;
}

static int check_started(struct aes *aes, int direction) {
	if (aes->gcm.started)
		return 0;

#if MBEDTLS_VERSION_MAJOR >= 3
	if (mbedtls_gcm_starts(&aes->gcm.ctx, direction, aes->gcm.iv,
			GCM_IV_LEN))
		return EPROTO;
	if (mbedtls_gcm_update_ad(&aes->gcm.ctx, aes->gcm.aad,
			aes->gcm.aad_len))
		return EPROTO;
#else
	if (mbedtls_gcm_starts(&aes->gcm.ctx, mode, aes->gcm.iv,
				GCM_IV_LEN, aes->gcm.aad, aes->gcm.aad_len))
		return EPROTO;
#endif
	aes->gcm.started = true;
	aes->gcm.direction = direction;

	return 0;
}

int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int ret;
	size_t output_length;

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
				ret = add_aad(aes, in, len,
					MBEDTLS_GCM_ENCRYPT);
				if (ret)
					return ret;
				return 0;
			}

			if (check_started(aes, MBEDTLS_GCM_ENCRYPT))
				return EPROTO;

#if MBEDTLS_VERSION_MAJOR >= 3
			if (mbedtls_gcm_update(&aes->gcm.ctx, in, len, out,
						len, &output_length))
#else
			if (mbedtls_gcm_update(&aes->gcm.ctx, len, in, out))
#endif
				return EPROTO;
			break;
	}

	return 0;
}


int aes_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int ret;
	size_t output_length;

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
				ret = add_aad(aes, in, len,
					MBEDTLS_GCM_DECRYPT);
				if (ret)
					return ret;
				return 0;
			}

			if (check_started(aes, MBEDTLS_GCM_DECRYPT))
				return EPROTO;

#if MBEDTLS_VERSION_MAJOR >= 3
			if (mbedtls_gcm_update(&aes->gcm.ctx, in, len, out,
						len, &output_length))
#else
			if (mbedtls_gcm_update(&aes->gcm.ctx, len, in, out))
#endif
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
	size_t output_length;

	if (!aes || !tag || !taglen)
		return EINVAL;

	switch (aes->mode) {

	case AES_MODE_GCM:
		if (check_started(aes, MBEDTLS_GCM_ENCRYPT))
			return EPROTO;

#if MBEDTLS_VERSION_MAJOR >= 3
		if (mbedtls_gcm_finish(&aes->gcm.ctx, NULL, 0, &output_length,
					tag, taglen))
#else
		if (mbedtls_gcm_finish(&aes->gcm.ctx, tag, taglen))
#endif
			return EPROTO;
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
	size_t output_length;

	if (!aes || !tag || !taglen)
		return EINVAL;

	switch (aes->mode) {

	case AES_MODE_GCM:
#if MBEDTLS_VERSION_MAJOR >= 3
		if (mbedtls_gcm_finish(&aes->gcm.ctx, NULL, 0, &output_length,
			check_tag, taglen))
#else
		if (mbedtls_gcm_finish(&aes->gcm.ctx, check_tag, taglen))
#endif
			return EPROTO;
		if (memcmp(check_tag, tag, taglen) != 0)
			return EAUTH;
		return 0;

	default:
		return ENOTSUP;
	}
}
