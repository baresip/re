/**
 * @file dbg.c Testcode for debug module
 *
 * Copyright (C) 2025 Alfred E. Heggestad
 */

#include <re.h>
#include "test.h"


#define DEBUG_MODULE "dbg"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_dbg(void)
{
	int err = 0;

	for (int level=0; level<8; level++) {
		const char *str = dbg_level_str(level);
		ASSERT_TRUE(str_isset(str));
	}

 out:
	return err;
}
