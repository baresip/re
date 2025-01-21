/**
 * @file mem_pool.c Memory Pool Testcode
 *
 * Copyright (C) 2025 Sebastian Reimers
 */
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_mem_pool"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

struct object {
	int a;
};

enum {
	NUM_OBJECTS = 10,
};


int test_mem_pool(void)
{
	int err;

	struct mem_pool *pool = NULL;
	err = mem_pool_alloc(&pool, NUM_OBJECTS, sizeof(struct object), NULL);
	TEST_ERR(err);

	struct mem_pool_entry *e;
	struct object *o;

	for (int i = 0; i < NUM_OBJECTS; i++) {
		e = mem_pool_borrow(pool);
		TEST_ASSERT(e);

		o = mem_pool_member(e);
		TEST_NOT_EQUALS(o->a, i + 1);

		o->a = i + 1;
	}

	TEST_ASSERT(!mem_pool_borrow(pool));

	e = mem_pool_release(pool, e);
	TEST_ASSERT(!e);

	e = mem_pool_borrow(pool);
	TEST_ASSERT(e);

	TEST_ASSERT(!mem_pool_borrow(pool));

	mem_pool_flush(pool);

	for (int i = 0; i < NUM_OBJECTS; i++) {
		e = mem_pool_borrow(pool);
		TEST_ASSERT(e);
	}

	TEST_ASSERT(!mem_pool_borrow(pool));

	err = mem_pool_extend(pool, 1);
	TEST_ERR(err);

	e = mem_pool_borrow(pool);
	TEST_ASSERT(e);

out:
	mem_deref(pool);
	return err;
}
