/**
 * @file aac.c AAC (Advanced Audio Coding) Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "aactest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_aac(void)
{
	static const uint8_t buf[2] = {0x12, 0x10};
	struct aac_header hdr;
	int err;

	err = aac_header_decode(&hdr, buf, sizeof(buf));
	if (err)
		return err;

	TEST_EQUALS(44100, hdr.sample_rate);
	TEST_EQUALS(2,     hdr.channels);
	TEST_EQUALS(1024,  hdr.frame_size);

 out:
	return err;
}
