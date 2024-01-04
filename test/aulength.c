/**
 * @file src/aulength.c audio file duration test
 *
 * Copyright (C) 2023 Lars Immisch
 */

#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "aulength"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_aulength(void)
{
	struct aufile *af = NULL;
	struct aufile_prm prm;
	char path[256];

	re_snprintf(path, sizeof(path), "%s/beep.wav", test_datapath());

	int err = aufile_open(&af, &prm, path, AUFILE_READ);
	TEST_ERR(err);

	size_t length = aufile_get_length(af, &prm);
	TEST_EQUALS(67, length);

out:
	mem_deref(af);

	return err;
}
