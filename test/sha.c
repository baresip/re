/**
 * @file sha.c SHA Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <re_sha.h>
#include "test.h"


#define DEBUG_MODULE "testsha1"
#define DEBUG_LEVEL 4
#include <re_dbg.h>


static const char *test_data[] = {
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",

	/* 64 bytes */
	"9293haoijsdlasjd9ehr98wehrlsihdflskidjflaisjdlaisdjalsdkjasdlsda",

	/* 96 bytes */
	"9293haoijsdlasjd9ehr98wehrlsihdflskidjflaisjdlaisdjalsdkjasdlsda"
	"9293haoijsdlasjd9ehr98wehrlsihdf",

	/* 128 bytes */
	"9293haoijsdlasjd9ehr98wehrlsihdflskidjflaisjdlaisdjalsdkjasdlsda"
	"9293haoijsdlasjd82halsdlkajsdlkjasldkjasldjlskjd9ehr98wehrlsihdd",

	/* 256 bytes */
	"9293haoijsdlasjd9ehr98wehrlsihdflskidjflaisjdlaisdjalsdkjasdlsda"
	"9293haoijsdlasjd82halsdlkajsdlkjasldkjasldjlskjd9ehr98wehrlsihdd"
	"9293haoijsdlasjd9ehr98wehrlsihdflskidjflaisjdlaisdjalsdkjasdlsda"
	"9293haoijsdlasjd82halsdlkajsdlkjasldkjasldjlskjd9ehr98wehrlsihdd",
};
static const char *test_results[] = {
	"a9993e364706816aba3e25717850c26c9cd0d89d",
	"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
	"105104a6ee22de58c0888d2f9cdd56d95c14d4e7",
	"9962f530d85f354304efcf35ceaa29a279a3208d",
	"17307171329ed5aeaccf4cd4f6d02223a69af9fb",
	"4f051b5c4fcd0916df00f9c9dbab8608cd3355a7"};


int test_sha1(void)
{
	uint32_t k;
	uint8_t digest[20];
	char output[80];

	for (k = 0; k < RE_ARRAY_SIZE(test_data); k++) {

		sha1((uint8_t *)test_data[k], strlen(test_data[k]), digest);

		(void)re_snprintf(output, sizeof(output), "%02w", digest,
				  sizeof(digest));
		if (strcmp(output, test_results[k])) {
			DEBUG_WARNING("* hash of \"%s\" incorrect:\n",
				      test_data[k]);
			DEBUG_WARNING("\t%s returned\n", output);
			DEBUG_WARNING("\t%s is correct\n", test_results[k]);
			return EINVAL;
		}
	}

	/* success */
	return 0;
}
