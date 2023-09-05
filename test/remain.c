/**
 * @file remain.c Testcode for re main loop
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "remain"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct data {
	thrd_t tid;
	mtx_t *mutex;
	struct mqueue *mq;
	bool thread_started;
	bool thread_exited;
	unsigned tmr_called;
	unsigned mqueue_called;
	int err;
};


static void tmr_handler(void *arg)
{
	struct data *data = arg;
	int err = 0;

	mtx_lock(data->mutex);

	/* verify that timer is called from the new thread */
	TEST_ASSERT(0 != thrd_equal(data->tid, thrd_current()));

	++data->tmr_called;

 out:
	if (err)
		data->err = err;

	mtx_unlock(data->mutex);

	re_cancel();
}


static int thread_handler(void *arg)
{
	struct data *data = arg;
	struct tmr tmr;
	int err;

	data->thread_started = true;

	tmr_init(&tmr);

	err = re_thread_init();
	if (err) {
		DEBUG_WARNING("re thread init: %m\n", err);
		data->err = err;
		return 0;
	}

#ifndef WIN32
	err = fd_setsize(-1);
	TEST_ERR(err);
#endif
	err = re_thread_init();
	ASSERT_TRUE(err == 0 || err == EALREADY);

	tmr_start(&tmr, 1, tmr_handler, data);

	/* run the main loop now */
	err = re_main(NULL);

out:
	if (err)
		data->err = err;
	tmr_cancel(&tmr);

	/* cleanup */
	tmr_debug();
	re_thread_close();

	data->thread_exited = true;

	return 0;
}


static int test_remain_thread(void)
{
	struct data data;
	int i, err;

	memset(&data, 0, sizeof(data));

	err = mutex_alloc(&data.mutex);
	if (err)
		return err;

	err = thread_create_name(&data.tid, "remain", thread_handler, &data);
	TEST_ERR(err);

	/* wait for timer to be called */
	for (i=0; i<500; i++) {
		mtx_lock(data.mutex);

		if (data.tmr_called || data.err) {
			mtx_unlock(data.mutex);
			break;
		}

		mtx_unlock(data.mutex);

		sys_msleep(1);
	}

	data.mutex = mem_deref(data.mutex);

	/* wait for thread to end */
	thrd_join(data.tid, NULL);

	if (data.err)
		return data.err;

	TEST_ASSERT(data.thread_started);
	TEST_ASSERT(data.thread_exited);
	TEST_EQUALS(1, data.tmr_called);
	TEST_EQUALS(0, data.err);

 out:
	mem_deref(data.mutex);
	return err;
}


static void mqueue_handler(int id, void *dat, void *arg)
{
	struct data *data = arg;
	(void)id;
	(void)dat;

	DEBUG_NOTICE("mqueue_handler\n");

	++data->mqueue_called;

	/* Stop re_main loop */
	re_cancel();
}


static int enterleave_thread_handler(void *arg)
{
	struct data *data = arg;
	int err;

	DEBUG_NOTICE("thread start\n");

	/* Enter an 're' thread */
	re_thread_enter();

	/* note: allocated from this thread */
	err = mqueue_alloc(&data->mq, mqueue_handler, data);

	/* Leave an 're' thread */
	re_thread_leave();

	if (err)
		return err;

	err = mqueue_push(data->mq, 0, NULL);

	DEBUG_NOTICE("thread stop\n");

	return err;
}


static int test_remain_enterleave(void)
{
	/*
	 * re_thread_enter() and re_thread_leave() works only
	 * with one re poll thread (re_global).
	 */
	if (test_mode == TEST_THREAD)
		return ESKIPPED;

	struct data data = {0};

	int err = thread_create_name(&data.tid, "enter-leave",
				     enterleave_thread_handler, &data);
	TEST_ERR(err);

	DEBUG_NOTICE("starting re_main loop..\n");

	/* run re_main event loop */
	err = re_main_timeout(1000);
	TEST_ERR(err);

	/* wait for thread to end */
	thrd_join(data.tid, &err);

	TEST_EQUALS(1, data.mqueue_called);

 out:
	mem_deref(data.mq);
	return err;
}


int test_remain(void)
{
	int err = 0;

	err = test_remain_thread();
	TEST_ERR(err);

	err = test_remain_enterleave();
	TEST_ERR(err);

 out:
	return err;
}
