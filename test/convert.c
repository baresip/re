/**
 * @file convert.c Conversion Testcode
 *
 * Copyright (C) 2022 Sebastian Reimers
 */
#include <re.h>
#include "test.h"

#define DEBUG_MODULE "testconvert"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_try_into(void)
{
	int err = 0;
	size_t size;
	uint16_t u16 = 0;
	int i;

	/* Testing size_t -> uint16_t */
	size = SIZE_MAX;
	err  = try_into(u16, size);
	TEST_EQUALS(ERANGE, err);

	size = 5000;
	err  = try_into(u16, size);
	TEST_ERR(err);
	TEST_EQUALS(size, u16);

	size = SIZE_MAX;
	err  = try_into(u16, size);
	TEST_EQUALS(ERANGE, err);

	/* Testing int -> uint16_t */
	i   = INT_MAX;
	err = try_into(u16, i);
	TEST_EQUALS(ERANGE, err);

	i   = -50;
	err = try_into(u16, i);
	TEST_EQUALS(ERANGE, err);

	/* Testing size_t -> int */
	size = SIZE_MAX;
	err  = try_into(i, size);
	TEST_EQUALS(ERANGE, err);

	size = INT_MAX;
	err  = try_into(i, size);
	TEST_ERR(err);
	TEST_EQUALS(INT_MAX, i);

out:
	return err;
}
