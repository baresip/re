/**
 * @file base64.c Base64 Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_base64"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_base64(void)
{
	const struct {
		struct pl pl;
		struct pl b64;
		struct pl b64url;
	} testv[] = {
		{PL(""),       PL(""),         PL("")},
		{PL("f"),      PL("Zg=="),     PL("Zg")},
		{PL("fo"),     PL("Zm8="),     PL("Zm8")},
		{PL("foo"),    PL("Zm9v"),     PL("Zm9v")},
		{PL("foob"),   PL("Zm9vYg=="), PL("Zm9vYg")},
		{PL("fooba"),  PL("Zm9vYmE="), PL("Zm9vYmE")},
		{PL("foobar"), PL("Zm9vYmFy"), PL("Zm9vYmFy")},
		{PL("\xff\x01\xfe\x02"), PL("/wH+Ag=="), PL("_wH-Ag")},

		{PL("asdlkjqopinzidfj84r77fsgljsdf9823r"),
		 PL("YXNkbGtqcW9waW56aWRmajg0cjc3ZnNnbGpzZGY5ODIzcg=="),
		 PL("YXNkbGtqcW9waW56aWRmajg0cjc3ZnNnbGpzZGY5ODIzcg")},
		{PL("918nvbakishdl8317237dlakskdkaldj"),
		 PL("OTE4bnZiYWtpc2hkbDgzMTcyMzdkbGFrc2tka2FsZGo="),
		 PL("OTE4bnZiYWtpc2hkbDgzMTcyMzdkbGFrc2tka2FsZGo")},
		{PL("very10long..testxyzstring/.,-=-3029===7823#'];'#';]#'"),
		 PL("dmVyeTEwbG9uZy4udGVzdHh5enN0cmluZy8uLC0"
		    "9LTMwMjk9PT03ODIzIyddOycjJztdIyc="),
		 PL("dmVyeTEwbG9uZy4udGVzdHh5enN0cmluZy8uLC0"
		    "9LTMwMjk9PT03ODIzIyddOycjJztdIyc")},
	};
	uint32_t i;
	int err = 0;
	uint8_t b64_buf[128];
	size_t olen;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		const struct pl *pl = &testv[i].pl;
		const struct pl *b;
		char buf[128];

		/* Encode */
		olen = sizeof(buf);
		err = base64_encode((uint8_t *)pl->p, pl->l, buf, &olen);
		TEST_ERR(err);

		if (olen != testv[i].b64.l) {
			DEBUG_WARNING("b64_encode %u failed: l=%u olen=%u\n",
				      i, testv[i].b64.l, olen);
			err = EINVAL;
			TEST_ERR(err);
		}
		if (0 != memcmp(testv[i].b64.p, buf, olen)) {
			DEBUG_WARNING("b64_encode %u failed: ref=%r, enc=%b\n",
				      i, &testv[i].b64, buf, olen);
			err = EINVAL;
			TEST_ERR(err);
		}

		/* Encode URL */
		olen = sizeof(buf);
		err = base64url_encode((uint8_t *)pl->p, pl->l, buf, &olen);
		TEST_ERR(err);

		if (olen != testv[i].b64url.l) {
			DEBUG_WARNING("b64_encode %u failed: l=%u olen=%u\n",
				      i, testv[i].b64url.l, olen);
			err = EINVAL;
			TEST_ERR(err);
		}
		if (0 != memcmp(testv[i].b64url.p, buf, olen)) {
			DEBUG_WARNING("b64_encode %u failed: ref=%r, enc=%b\n",
				      i, &testv[i].b64url, buf, olen);
			err = EINVAL;
			TEST_ERR(err);
		}

		/* Decode */
		b = &testv[i].b64;
		olen = sizeof(b64_buf);
		err = base64_decode(b->p, b->l, b64_buf, &olen);
		TEST_ERR(err);

		if (olen != testv[i].pl.l) {
			DEBUG_WARNING("b64_decode %u failed: l=%u olen=%u\n",
				      i, testv[i].pl.l, olen);
			err = EINVAL;
			TEST_ERR(err);
		}
		if (0 != memcmp(testv[i].pl.p, b64_buf, olen)) {
			DEBUG_WARNING("b64_decode %u failed: ref=%r, enc=%b\n",
				      i, &testv[i].pl, b64_buf, olen);
			err = EINVAL;
			TEST_ERR(err);
		}

		/* Decode Url */
		b = &testv[i].b64url;
		olen = sizeof(b64_buf);
		err = base64_decode(b->p, b->l, b64_buf, &olen);
		TEST_ERR(err);

		if (olen != testv[i].pl.l) {
			DEBUG_WARNING(
				"b64_decode url %u failed: l=%u olen=%u\n", i,
				testv[i].pl.l, olen);
			err = EINVAL;
			TEST_ERR(err);
		}
		if (0 != memcmp(testv[i].pl.p, b64_buf, olen)) {
			DEBUG_WARNING(
				"b64_decode url %u failed: ref=%r, enc=%b\n",
				i, &testv[i].pl, b64_buf, olen);
			err = EINVAL;
			TEST_ERR(err);
		}
	}

	/* Invalid checks */
	char c = 'A';
	olen   = sizeof(b64_buf);
	err    = base64_decode(&c, sizeof(c), b64_buf, &olen);
	TEST_ERR(err);

	struct pl inv;
	pl_set_str(&inv, "Zm8=");
	olen = 1;
	err  = base64_decode(inv.p, inv.l, b64_buf, &olen);
	TEST_EQUALS(EOVERFLOW, err);

	err = 0;
out:
	return err;
}
