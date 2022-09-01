/**
 * @file openssl/hmac.c  HMAC using MbedTLS
 *
 * Copyright (C) 2022 Dmitry Ilyin
 */

#include <mbedtls/md.h>
#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_hmac.h>


struct hmac {
	const mbedtls_md_info_t *type;
	uint8_t *key;
	int key_len;
};


static void destructor(void *arg)
{
	struct hmac *hmac = arg;

	mem_deref(hmac->key);
}


int hmac_create(struct hmac **hmacp, enum hmac_hash hash, const uint8_t *key,
		size_t key_len)
{
	struct hmac *hmac;
	int err = 0;

	if (!hmacp || !key || !key_len)
		return EINVAL;

	hmac = mem_zalloc(sizeof(*hmac), destructor);
	if (!hmac)
		return ENOMEM;

	hmac->key = mem_zalloc(key_len, NULL);
	if (!hmac->key) {
		err = ENOMEM;
		goto error;
	}

	memcpy(hmac->key, key, key_len);
	hmac->key_len = (int)key_len;

	switch (hash) {

	case HMAC_HASH_SHA1:
		hmac->type = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
		break;

	case HMAC_HASH_SHA256:
		hmac->type = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		break;

	default:
		err = ENOTSUP;
		goto error;
	}

	*hmacp = hmac;

	return 0;

error:
	mem_deref(hmac);
	return err;
}


int hmac_digest(struct hmac *hmac, uint8_t *md, size_t md_len,
		const uint8_t *data, size_t data_len)
{
	int ret;

	if (!hmac || !md || !md_len || !data || !data_len)
		return EINVAL;

	ret = mbedtls_md_hmac(hmac->type, hmac->key, hmac->key_len,
			data, data_len, md);
	if (!ret) {
		return EPROTO;
	}

	return 0;
}
