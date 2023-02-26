/**
 * @file hmac.c HMAC Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <re_sha.h>
#include "test.h"


#define DEBUG_MODULE "testhmac"
#define DEBUG_LEVEL 4
#include <re_dbg.h>


#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH    32
#endif


int test_hmac_sha1(void)
{
	/* RFC 2202 */
	const struct {
		const void *key;
		uint32_t key_len;
		const void *data;
		uint32_t data_len;
		char digest[40 + 1];
	} testv[] = {
		{"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		 "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
		 "Hi There", 8,
		 "b617318655057264e28bc0b6fb378c8ef146be00"},

		{"Jefe", 4,
		 "what do ya want for nothing?", 28,
		 "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"},

		{"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		 "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
		 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50,
		 "125d7342b9ac11cd91a39af48aa17b4f63f175d3"},

		{"01234567890123456789", 20,
 		 "dalskdmlkasndoiqwjeoi3hjoijqweolk6y52fsdfsfgh66h"
		 "91928ha8shdoalijelwjeoriwjeorijwe98fj98j98j384jo"
		 "dalskdmlkasndoiqwjeoi3hjoijqweolk6y52fsdfsfgh66h"
		 "91928ha8shdoalijelwjeoriwjeorijwe98fj98j98j38s4f"
		 "dalskdmlkasndoiqwjeoi3hjoijqweolk6y52fsdfsfghsda"
		 "91928ha8shdoalijelwjeoriwjeorijwe98fj98j98j384jo"
		 "dalskdmlkasndoiqwjeoi3hjoijqweolk6y52fsdfsfgh66h"
		 "91928ha8shdoalijelwjeoriwjeorijwe98fj98jqwe98j38", 384,
		 "4b00628735c763b3c0dc398deb4370e99f822490"}
	};
	struct hmac *hmac = NULL;
	uint32_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		char buf[43];
		uint8_t md[SHA_DIGEST_LENGTH];
		uint32_t md_len = SHA_DIGEST_LENGTH;
		uint8_t md2[SHA_DIGEST_LENGTH], md_ref[SHA_DIGEST_LENGTH];

		hmac_sha1(testv[i].key,      /* secret key */
			  testv[i].key_len,  /* length of the key in bytes */
			  testv[i].data,     /* data */
			  testv[i].data_len, /* length of data in bytes */
			  md,          /* output buffer, at least "t" bytes */
			  md_len);

		(void)re_snprintf(buf, sizeof(buf), "%02w", md, sizeof(md));
		if (0 != strcmp(testv[i].digest, buf)) {
			DEBUG_WARNING("testcase %u: HMAC failed"
				      " (expected %s, got %s)\n",
				      i, testv[i].digest, buf);
			return EINVAL;
		}

		/*
		 * This part is testing the Stateful API
		 */
		err = hmac_create(&hmac, HMAC_HASH_SHA1,
				  testv[i].key, testv[i].key_len);
		if (err)
			break;

		err = hmac_digest(hmac, md2, sizeof(md2),
				  testv[i].data, testv[i].data_len);
		if (err)
			break;

		err = str_hex(md_ref, sizeof(md_ref), testv[i].digest);
		if (err)
			break;

		TEST_MEMCMP(md_ref, sizeof(md_ref), md2, sizeof(md2));

		hmac = mem_deref(hmac);
	}

 out:
	mem_deref(hmac);

	return err;
}


/*
 * RFC 4231 -- Identifiers and Test Vectors for HMAC-SHA-256
 */
int test_hmac_sha256(void)
{
#define MAX_KEY_LEN  132
#define MAX_DATA_LEN 152
	const struct test {
		const char *key;
		const char *data;
		const char *digest;
	} testv[] = {

		/* Test Case 1 */
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
			"0b0b0b0b"
			,
			"4869205468657265"
			,
			"b0344c61d8db38535ca8afceaf0bf12b"
			"881dc200c9833da726e9376c2e32cff7"
		},

		/* Test Case 2 */
		{
			"4a656665"
			,
			"7768617420646f2079612077616e7420"
			"666f72206e6f7468696e673f"
			,
			"5bdcc146bf60754e6a042426089575c7"
			"5a003f089d2739839dec58b964ec3843"
		},

		/* Test Case 3 */
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaa"
			,
			"dddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddd"
			"dddd"
			,
			"773ea91e36800e46854db8ebd09181a7"
			"2959098b3ef8c122d9635514ced565fe"
		},

		/* Test Case 4 */
		{
			"0102030405060708090a0b0c0d0e0f10"
			"111213141516171819"
			,
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcd"
			,
			"82558a389a443c0ea4cc819899f2083a"
			"85f0faa3e578f8077a2e3ff46729665b"
		},

		/* Test Case 6 */
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa"
			,
			"54657374205573696e67204c61726765"
			"72205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579"
			"204669727374"
			,
			"60e431591ee0b67f0d8a26aacbf5b77f"
			"8e0bc6213728c5140546040f0ee37f54"
		},

		/* Test Case 7 */
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa"
			,
			"54686973206973206120746573742075"
			"73696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b65"
			"7920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a652064"
			"6174612e20546865206b6579206e6565"
			"647320746f2062652068617368656420"
			"6265666f7265206265696e6720757365"
			"642062792074686520484d414320616c"
			"676f726974686d2e"
			,
			"9b09ffa71b942fcb27635fbcd5b0e944"
			"bfdc63644f0713938a7f51535c3a35e2"
		},
	};
	struct hmac *hmac = NULL;
	size_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		const struct test *test = &testv[i];
		uint8_t key[MAX_KEY_LEN];
		size_t key_len = str_len(test->key) / 2;
		uint8_t data[MAX_DATA_LEN];
		size_t data_len = str_len(test->data) / 2;
		uint8_t digest[SHA256_DIGEST_LENGTH];
		uint8_t md[SHA256_DIGEST_LENGTH];

		TEST_ASSERT(key_len <= sizeof(key));
		TEST_ASSERT(data_len <= sizeof(data));

		err |= str_hex(key, key_len, test->key);
		err |= str_hex(data, data_len, test->data);
		err |= str_hex(digest, sizeof(digest), test->digest);
		TEST_ERR(err);

		err = hmac_create(&hmac, HMAC_HASH_SHA256, key, key_len);
		if (err)
			break;

		err = hmac_digest(hmac, md, sizeof(md), data, data_len);
		if (err)
			break;

		TEST_MEMCMP(digest, sizeof(digest), md, sizeof(md));

		hmac = mem_deref(hmac);

		/* Test Stateless API */

		uint8_t md2[SHA256_DIGEST_LENGTH];

		hmac_sha256(key, key_len,
			    data, data_len,
			    md2, sizeof(md2));

		TEST_MEMCMP(digest, sizeof(digest), md2, sizeof(md2));
	}

 out:
	mem_deref(hmac);

	if (err == ENOTSUP)
		err = ESKIPPED;

	return err;
}
