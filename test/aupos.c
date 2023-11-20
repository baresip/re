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
	uint8_t buffer[128];

	re_snprintf(path, sizeof(path), "%s/beep.wav", test_datapath());

	int err = aufile_open(&af, &prm, path, AUFILE_READ);
	if (err)
		TEST_ERR(err);

	err = aufile_set_position(af, &prm, 67);
	if (err)
		TEST_ERR(err);

	/* That file is 67 ms long, so we shouldn't read anything */
	size_t size = sizeof(buffer);
	err = aufile_read(af, buffer, &size);
	if (err)
		TEST_ERR(err);

	TEST_EQUALS(0, size);

out:
	mem_deref(af);

	return err;
}
