/**
 * @file aes.c AES (Advanced Encryption Standard) Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "aestest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * http://www.inconteam.com/software-development/41-encryption/
 *  55-aes-test-vectors#aes-crt
 *
 * AES CTR 128-bit encryption mode
 */
static int test_aes_ctr_loop(void)
{
	const char *init_vec_str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	uint8_t encr_key[16];
	uint8_t iv_enc[AES_BLOCK_SIZE];
	uint8_t iv_dec[AES_BLOCK_SIZE];
	size_t i;
	int err = 0;
	struct aes *enc = NULL, *dec = NULL;

	static const struct {
		char test_str[33];
		char *ciph_str;
	} testv[] = {

		{"6bc1bee22e409f96e93d7e117393172a",
		 "874d6191b620e3261bef6864990db6ce"},

		{"ae2d8a571e03ac9c9eb76fac45af8e51",
		 "9806f66b7970fdff8617187bb9fffdff"},

		{"30c81c46a35ce411e5fbc1191a0a52ef",
		 "5ae4df3edbd5d35e5b4f09020db03eab"},

		{"f69f2445df4f9b17ad2b417be66c3710",
		 "1e031dda2fbe03d1792170a0f3009cee"},
	};

	err |= str_hex(encr_key, sizeof(encr_key),
		       "2b7e151628aed2a6abf7158809cf4f3c");
	err |= str_hex(iv_enc, sizeof(iv_enc), init_vec_str);
	err |= str_hex(iv_dec, sizeof(iv_dec), init_vec_str);
	if (err)
		return err;

	err  = aes_alloc(&enc, AES_MODE_CTR, encr_key, 128, iv_enc);
	err |= aes_alloc(&dec, AES_MODE_CTR, encr_key, 128, iv_dec);
	if (err)
		goto out;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		uint8_t test_vector[16];
		uint8_t cipher_text[16];
		uint8_t out[16];
		uint8_t clear[16];

		err |= str_hex(test_vector, sizeof(test_vector),
			       testv[i].test_str);
		err |= str_hex(cipher_text, sizeof(cipher_text),
			       testv[i].ciph_str);
		if (err)
			break;

		err = aes_encr(enc, out, test_vector, 16);
		if (err)
			break;

		TEST_MEMCMP(cipher_text, sizeof(cipher_text),
			    out, sizeof(out));

		err = aes_decr(dec, clear, out, 16);
		if (err)
			break;

		TEST_MEMCMP(test_vector, sizeof(test_vector),
			    clear, sizeof(clear));
	}

 out:
	mem_deref(enc);
	mem_deref(dec);

	return err;
}


static bool have_aes(enum aes_mode mode)
{
	static const uint8_t nullkey[AES_BLOCK_SIZE];
	struct aes *aes = NULL;
	int err;

	err = aes_alloc(&aes, mode, nullkey, 128, NULL);

	mem_deref(aes);

	return err != ENOSYS;
}


int test_aes(void)
{
	int err;

	if (!have_aes(AES_MODE_CTR)) {
		(void)re_printf("skipping aes ctr test\n");
		return ESKIPPED;
	}

	err = test_aes_ctr_loop();
	TEST_ERR(err);

out:
	return err;
}


#define KEY_LEN 32    /* 256 bits */
#define IV_LEN  12    /*  96 bits */
#define MSG_LEN 16    /* 128 bits */
#define AAD_LEN 16    /* 128 bits */
#define TAG_LEN 16    /* 128 bits */


/**
 * Testcases for AES GCM (Galois Counter Mode)
 *
 * NOTE: only 96-bits IV for now
 */
int test_aes_gcm(void)
{
	struct aes *enc = NULL, *dec = NULL;
	size_t i;
	int err = 0;

	static const struct test {
		const char *encr_key_str;
		const char *iv_str;
		const char *plain_str;         /* optional */
		const char *aad_str;           /* optional */
		const char *ciph_str;          /* optional */
		const char *tag_str;
		bool success;
	} testv[] = {

		/* no payload*/
		{"b52c505a37d78eda5dd34f20c22540ea"
		 "1b58963cf8e5bf8ffa85f9f2492505b4",

		 "516c33929df5a3284ff463d7",
		 NULL,
		 NULL,
		 NULL,
		 "bdc1ac884d332457a1d2664f168c76f0",
		 true
		},

		/* no AAD */
		{"31bdadd96698c204aa9ce1448ea94ae1"
		 "fb4a9a0b3c9d773b51bb1822666b8f22",

		 "0d18e06c7c725ac9e362e1ce",

		 "2db5168e932556f8089a0622981d017d",

		 "",

		 "fa4362189661d163fcd6a56d8bf0405a",

		 "d636ac1bbedd5cc3ee727dc2ab4a9489",

		 true
		},

		/* with AAD */
		{"92e11dcdaa866f5ce790fd24501f9250"
		 "9aacf4cb8b1339d50c9c1240935dd08b",

		 "ac93a1a6145299bde902f21a",

		 "2d71bcfa914e4ac045b2aa60955fad24",

		 "1e0889016f67601c8ebea4943bc23ad6",

		 "8995ae2e6df3dbf96fac7b7137bae67f",

		 "eca5aa77d51d4a0a14d9c51e1da474ab",
		 true
		},

		/* from openssl code */
		{"eebc1f57487f51921c0465665f8ae6d1"
		 "658bb26de6f8a069a3520293a572078f",

		 "99aa3e68ed8173a0eed06684",

		 "f56e87055bc32d0eeb31b2eacc2bf2a5",

		 "4d23c3cec334b49bdb370c437fec78de",

		 "f7264413a84c0e7cd536867eb9f21736",

		 "67ba0510262ae487d737ee6298f77e0c",
		 true
		},

		/* authentication failure */
		{"92e11dcdaa866f5ce790fd24501f9250"
		 "9aacf4cb8b1339d50c9c1240935dd08b",

		 "ac93a1a6145299bde902f21a",

		 "2d71bcfa914e4ac045b2aa60955fad24",

		 "1e0889016f67601c8ebea4943bc23ad6",

		 "8995ae2e6df3dbf96fac7b7137bae67f",

		 "eca5aa77d51d4a0a14d9c51e1da47400", /* wrong */
		 false
		},
	};

	if (!have_aes(AES_MODE_GCM)) {
		(void)re_printf("skipping aes gcm test\n");
		return ESKIPPED;
	}

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct test *test = &testv[i];
		uint8_t test_vector[MSG_LEN] = {0};
		uint8_t cipher_text[MSG_LEN] = {0};
		uint8_t tag_ref[TAG_LEN];
		uint8_t out[MSG_LEN];
		uint8_t clear[MSG_LEN];
		uint8_t tag[TAG_LEN];
		size_t tagsz = sizeof(tag);
		uint8_t iv[IV_LEN];
		uint8_t encr_key[KEY_LEN];
		const size_t key_bits = KEY_LEN * 8;
		uint8_t aad[AAD_LEN];
		size_t clen;
		int e;

		err = str_hex(encr_key, sizeof(encr_key), test->encr_key_str);
		if (err) {
			DEBUG_WARNING("could not set key\n");
			break;
		}

		err |= str_hex(iv, sizeof(iv), test->iv_str);
		if (err) {
			DEBUG_WARNING("could not set IV\n");
			return err;
		}

		err = aes_alloc(&enc, AES_MODE_GCM, encr_key, key_bits, iv);
		if (err)
			goto out;

		if (str_isset(test->aad_str)) {

			err = str_hex(aad, sizeof(aad), test->aad_str);
			if (err) {
				DEBUG_WARNING("could not set aad\n");
				break;
			}
		}

		if (str_isset(test->plain_str)) {
			err |= str_hex(test_vector, sizeof(test_vector),
				       test->plain_str);
			clen = sizeof(test_vector);
		}
		else {
			clen = 0;
		}

		if (str_isset(test->ciph_str)) {
			err |= str_hex(cipher_text, sizeof(cipher_text),
				       test->ciph_str);
			if (err) {
				DEBUG_WARNING("str_hex error\n");
				break;
			}
		}

		err |= str_hex(tag_ref, sizeof(tag_ref), testv[i].tag_str);
		if (err) {
			DEBUG_WARNING("tag size mismatch\n");
			break;
		}

		/* Encrypt */
		if (str_isset(test->aad_str)) {
			err = aes_encr(enc, NULL, aad, sizeof(aad));
			TEST_ERR(err);
		}
		if (clen) {
			err = aes_encr(enc, out, test_vector, clen);
			TEST_ERR(err);

			TEST_MEMCMP(cipher_text, sizeof(cipher_text),
				    out, sizeof(out));
		}

		err = aes_get_authtag(enc, tag, tagsz);
		TEST_ERR(err);

		if (test->success) {
			TEST_MEMCMP(tag_ref, sizeof(tag_ref), tag, tagsz);
		}
		enc = mem_deref(enc);

		/* Decrypt */
		err = aes_alloc(&dec, AES_MODE_GCM, encr_key, key_bits, iv);
		if (err)
			goto out;

		if (str_isset(test->aad_str)) {
			err = aes_decr(dec, NULL, aad, sizeof(aad));
			TEST_ERR(err);
		}

		err = aes_decr(dec, clear, out, clen);
		TEST_ERR(err);

		e = aes_authenticate(dec, tag_ref, tagsz);
		if (test->success) {
			if (e) {
				err = e;
				DEBUG_WARNING("aes_authenticate error\n");
				break;
			}

			if (clen) {
				TEST_MEMCMP(test_vector, sizeof(test_vector),
					    clear, sizeof(clear));
			}
		}
		else {
			TEST_EQUALS(EAUTH, e);
		}

		dec = mem_deref(dec);
	}

 out:
	mem_deref(enc);
	mem_deref(dec);

	return err;
}
