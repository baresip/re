/**
 * @file src/thread.c re threads
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#include <re.h>
#include "test.h"

#define DEBUG_MODULE "thread"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int thread(void *id)
{
	int n = *(int *)id;

	if (n != 42)
		return thrd_error;

	return EPROTO;
}


int test_thread(void)
{
	thrd_t thr;
	int err;
	int id;

	err = thread_create_name(&thr, "test1", NULL, NULL);
	TEST_EQUALS(EINVAL, err);

	id = 23;
	err = thread_create_name(&thr, "test2", thread, (void *)&id);
	TEST_ERR(err);
	thrd_join(thr, &err);
	TEST_EQUALS(thrd_error, err);

	id = 42;
	err = thread_create_name(&thr, "test3", thread, (void *)&id);
	TEST_ERR(err);
	thrd_join(thr, &err);
	TEST_EQUALS(EPROTO, err);

	err = 0;

out:
	return err;
}
