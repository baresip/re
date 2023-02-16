/**
 * @file tmr.c  Timers testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "testtmr"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_tmr_jiffies(void)
{
	uint64_t tmr_start, tmr_end, diff;
	int err = 0;

	tmr_start = tmr_jiffies();
	sys_msleep(1);
	tmr_end = tmr_jiffies();
	diff = tmr_end - tmr_start;

	TEST_ASSERT(diff >= 1);
	TEST_ASSERT(diff < 50);

out:
	return err;
}


int test_tmr_jiffies_usec(void)
{
	uint64_t tmr_start, diff;
	int i;
	int err = 0;

	tmr_start = tmr_jiffies_usec();
	diff = 0;
	for (i = 0; i < 100000 && !diff; i++)
		diff = tmr_jiffies_usec() - tmr_start;

	TEST_ASSERT(diff >= 1);
	TEST_ASSERT(diff < 1000);

out:
	return err;
}
