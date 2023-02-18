/**
 * @file dsp.c Testcode for librem's DSP module
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "test/dsp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int test_saturate(void)
{
	int err = 0;

	/* saturate_u8 */
	TEST_EQUALS(  0, saturate_u8(-100));
	TEST_EQUALS(  0, saturate_u8(   0));
	TEST_EQUALS( 42, saturate_u8(  42));
	TEST_EQUALS(255, saturate_u8( 255));
	TEST_EQUALS(255, saturate_u8( 355));
	TEST_EQUALS(255, saturate_u8(9692));

	/* saturate_s16 */
	TEST_EQUALS(-32768, saturate_s16(-65535));
	TEST_EQUALS(-32768, saturate_s16(-32768));
	TEST_EQUALS(     0, saturate_s16(     0));
	TEST_EQUALS( 32767, saturate_s16( 32767));
	TEST_EQUALS( 32767, saturate_s16( 65535));

	/* saturate_add16 */
	TEST_EQUALS(-32768, saturate_add16(-30000, -30000));
	TEST_EQUALS( -2000, saturate_add16( -1000,  -1000));
	TEST_EQUALS(     2, saturate_add16(     1,      1));
	TEST_EQUALS( 32767, saturate_add16( 32766,      1));
	TEST_EQUALS( 32767, saturate_add16( 30000,  30000));

	/* saturate_sub16 */
	TEST_EQUALS(-32768, saturate_sub16(-50000, -10000));
	TEST_EQUALS( -2000, saturate_sub16( -1000,   1000));
	TEST_EQUALS(     0, saturate_sub16(     1,      1));
	TEST_EQUALS( 32765, saturate_sub16( 32766,      1));
	TEST_EQUALS( 32767, saturate_sub16( 50000,  10000));

 out:
	return err;
}


int test_dsp(void)
{
	int err;

	err = test_saturate();
	TEST_ERR(err);

out:
	return err;
}
