/**
 * @file btrace.c  Backtrace testcode
 *
 * Copyright (C) 2025 Alfred E. Heggestad
 */

#include <re.h>
#include "test.h"


#define DEBUG_MODULE "btrace"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int devnull_handler(const char *p, size_t size, void *arg)
{
	(void)p;
	(void)size;
	(void)arg;

	return 0;
}


int test_btrace(void)
{
	if (test_mode == TEST_THREAD)
		return ESKIPPED;

	static struct re_printf pf_devnull = {
		.vph = devnull_handler
	};
	struct btrace btraces = {0};

	int err = btrace(&btraces);
	TEST_ERR(err);

	err = btrace_print(&pf_devnull, &btraces);
	TEST_ERR(err);

	err = btrace_println(&pf_devnull, &btraces);
	TEST_ERR(err);

	err = btrace_print_json(&pf_devnull, &btraces);
	TEST_ERR(err);

 out:
	return err;
}
