/**
 * @file au.c Audio testcode
 *
 * Copyright (C) 2024 Alfred E. Heggestad
 */

#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "au"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_au(void)
{
	int err = 0;

	uint32_t nsamp = au_calc_nsamp(8000, 1, 20);
	ASSERT_EQ(160, nsamp);

 out:
	return err;
}
