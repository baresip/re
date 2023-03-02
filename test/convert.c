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

#if __STDC_VERSION__ >= 201112L /* Needs C11 support */
	size = SIZE_MAX;
	err  = try_into(u16, size);
	TEST_EQUALS(ERANGE, err);
#endif
	size = 5000;
	err  = try_into_u16_from_size(&u16, size);
	TEST_ERR(err);
	TEST_EQUALS(size, u16);

	size = SIZE_MAX;
	err  = try_into_u16_from_size(&u16, size);
	TEST_EQUALS(ERANGE, err);

	/* Testing int -> uint16_t */
	i   = INT_MAX;
	err = try_into_u16_from_int(&u16, i);
	TEST_EQUALS(ERANGE, err);

	i   = -50;
	err = try_into_u16_from_int(&u16, i);
	TEST_EQUALS(ERANGE, err);

	/* Testing size_t -> int */
	size = SIZE_MAX;
	err  = try_into_int_from_size(&i, size);
	TEST_EQUALS(ERANGE, err);

	size = INT_MAX;
	err  = try_into_int_from_size(&i, size);
	TEST_ERR(err);
	TEST_EQUALS(INT_MAX, i);

out:
	return err;
}
