/**
 * @file src/aupos.c audio file setposition test
 *
 * Copyright (C) 2023 Lars Immisch
 */

#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "auposition"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_auposition(void)
{
	struct aufile *af = NULL;
	struct aufile_prm prm;
	char path[256];
	uint8_t buffer[512];

	re_snprintf(path, sizeof(path), "%s/beep.wav", test_datapath());

	int err = aufile_open(&af, &prm, path, AUFILE_READ);
	TEST_ERR(err);

	err = aufile_set_position(af, &prm, 67);
	TEST_ERR(err);

	/* That file is exactly 67 ms long, so we shouldn't read anything */
	size_t size = sizeof(buffer);
	err = aufile_read(af, buffer, &size);
	TEST_ERR(err);

	/* It's possible we read data up to a ms */
	TEST_ASSERT(size < 16);

	af = mem_deref(af);

	err = aufile_open(&af, &prm, path, AUFILE_READ);
	TEST_ERR(err);

	err = aufile_set_position(af, &prm, 37);
	TEST_ERR(err);

	size = sizeof(buffer);
	err = aufile_read(af, buffer, &size);
	TEST_ERR(err);

	/* 30 ms should be left, at 8000Hz/s, one channels and 16 bit samples
	   that's 480 bytes */
	TEST_ASSERT(size - 480 < 16);


out:
	mem_deref(af);

	return err;
}
