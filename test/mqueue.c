/**
 * @file mqueue.c Message queue testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mqueue_test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define NUM_EVENTS 3


struct test {
	int idv[NUM_EVENTS];
	void *datav[NUM_EVENTS];
	unsigned idc;
};


static void mqueue_handler(int id, void *data, void *arg)
{
	struct test *test = arg;

	test->idv  [test->idc] = id;
	test->datav[test->idc] = data;

	test->idc++;

	if (test->idc >= NUM_EVENTS)
		re_cancel();
}


int test_mqueue(void)
{
	struct mqueue *mq;
	struct test test;
	int i;
	int err;

	memset(&test, 0, sizeof(test));

	err = mqueue_alloc(&mq, mqueue_handler, &test);
	if (err)
		return err;

	for (i=0; i<NUM_EVENTS; i++) {
		err = mqueue_push(mq, 42+i, &test);
		if (err)
			goto out;
	}

	err = re_main_timeout(100);
	if (err)
		goto out;

	TEST_EQUALS(NUM_EVENTS, test.idc);
	for (i=0; i<NUM_EVENTS; i++) {
		TEST_EQUALS(42+i, test.idv[i]);
		TEST_EQUALS(&test, test.datav[i]);
	}

 out:
	mem_deref(mq);

	return err;
}
