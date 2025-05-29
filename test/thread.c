/**
 * @file src/thread.c re threads
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#include <time.h>
#include <re.h>
#include "test.h"

#define DEBUG_MODULE "thread"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int thread_equal(void *thrd)
{
	thrd_t t = *(thrd_t *)thrd;

	if (thrd_equal(t, thrd_current()))
		return 0;

	return EINVAL;
}


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
	thrd_t thr_main = thrd_current();
	int err;
	int id;

	err = thread_create_name(&thr, "test1", NULL, NULL);
	TEST_EQUALS(EINVAL, err);

	id  = 23;
	err = thread_create_name(&thr, "test2", thread, (void *)&id);
	TEST_ERR(err);
	thrd_join(thr, &err);
	TEST_EQUALS(thrd_error, err);

	id  = 42;
	err = thread_create_name(&thr, "test3", thread, (void *)&id);
	TEST_ERR(err);
	thrd_join(thr, &err);
	TEST_EQUALS(EPROTO, err);

	err = thread_create_name(&thr, "test_not_equal", thread_equal,
				 &thr_main);
	TEST_ERR(err);
	thrd_join(thr, &err);
	TEST_EQUALS(EINVAL, err);

	err = thread_create_name(&thr, "test_equal", thread_equal, &thr);
	TEST_ERR(err);
	TEST_EQUALS(0, thrd_equal(thr, thrd_current()));
	thrd_join(thr, &err);
	TEST_EQUALS(0, err);

	err = 0;

out:
	return err;
}


int test_thread_cnd_timedwait(void)
{
	cnd_t cnd;
	mtx_t mtx;
	struct timespec tp;
	int err = 0;

	cnd_init(&cnd);
	mtx_init(&mtx, mtx_plain);

	err = tmr_timespec_get(&tp, 100);
	TEST_ERR(err);

	mtx_lock(&mtx);

	uint64_t start = tmr_jiffies();
	int ret = cnd_timedwait(&cnd, &mtx, &tp);
	TEST_EQUALS(thrd_timedout, ret);
	uint64_t end = tmr_jiffies();

	/* This tests can fail if a spurious wake-up occurs */
	if (end - start < 100) {
		DEBUG_WARNING("cnd_timedwait: early wake-up!\n");
		goto out;
	}

	if (end - start > 500) {
		err = ETIMEDOUT;
		TEST_ERR(err);
	}

out:
	mtx_unlock(&mtx);
	return err;
}


int test_thread_tss(void)
{
	int err = 0;
	int val = 1234;
	tss_t key;

	TEST_EQUALS(thrd_success, tss_create(&key, NULL));

	TEST_EQUALS(thrd_success, tss_set(key, &val));

	TEST_EQUALS(&val, tss_get(key));

	TEST_EQUALS(thrd_success, tss_set(key, NULL));

	TEST_EQUALS(NULL, tss_get(key));

out:
	tss_delete(key);
	return err;
}
