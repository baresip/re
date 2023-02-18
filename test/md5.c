/**
 * @file md5.c MD5 Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "testmd5"
#define DEBUG_LEVEL 4
#include <re_dbg.h>


int test_md5(void)
{
	const struct pl str = PL("a93akjshdla81mx.kjda09sdkjl12jdlksaldkjas");
	const uint8_t ref[16] = {
		0x9d, 0x97, 0xa5, 0xf8, 0x8d, 0x1b, 0x09, 0x7c,
		0x9f, 0xf9, 0xe2, 0x9d, 0xd5, 0x43, 0xb1, 0x1d
	};
	uint8_t digest[16];
	int err;

	/* Test constants */
	if (16 != MD5_SIZE) {
		DEBUG_WARNING("MD5_SIZE is %u (should be 16)\n", MD5_SIZE);
		return EINVAL;
	}
	if (33 != MD5_STR_SIZE) {
		DEBUG_WARNING("MD5_STR_SIZE is %u (should be 33)\n",
			      MD5_STR_SIZE);
		return EINVAL;
	}

	/* Test md5() */
	md5((const uint8_t *)str.p, str.l, digest);

	if (0 != memcmp(digest, ref, sizeof(digest))) {
		DEBUG_WARNING("md5 b0Rken: %02w\n", digest, sizeof(digest));
		return EINVAL;
	}

	/* Test md5_printf() */
	err = md5_printf(digest, "%r", &str);
	if (err)
		goto out;

	if (0 != memcmp(digest, ref, sizeof(digest))) {
		DEBUG_WARNING("md5_printf() is b0Rken: %02w\n", digest,
			      sizeof(digest));
		return EINVAL;
	}

 out:
	return err;
}
