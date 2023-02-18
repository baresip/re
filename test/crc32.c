/**
 * @file crc32.c CRC32 Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "testcrc32"
#define DEBUG_LEVEL 4
#include <re_dbg.h>


int test_crc32(void)
{
	const struct {
		const char *str;
		uint32_t crc;
	} testv[] = {
		{"string",                          0x9ebeb2a9 },
		{"hei",                             0x95610594 },
		{"0ndka98d198aloidks9zaz1oqs5jilk", 0x92a398f6 },
	};
	size_t i;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		uint32_t crc;

		crc = re_crc32(0L, (uint8_t *)testv[i].str,
			       (unsigned int)str_len(testv[i].str));

		if (testv[i].crc != crc) {
			DEBUG_WARNING("testcase %u: CRC-32 failed"
				      " (expected 0x%08x, got 0x%08x)\n",
				      i, testv[i].crc, crc);
			return EINVAL;
		}
	}

	return 0;
}
