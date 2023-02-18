/**
 * @file src/aulevel.c audio levels
 *
 * Copyright (C) 2010 - 2017 Alfred E. Heggestad
 */

#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "aulevel"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define PREC .6


int test_aulevel(void)
{
	double level;
	struct auframe af;
	int err = 0;

	static struct {
		int16_t sampv[2];
		double level;
	} testv[] = {

		{  {    0,     -0},    -96.0  },
		{  {    0,      1},    -93.0  },
		{  {    1,     -1},    -90.0  },
		{  {    2,     -2},    -84.0  },
		{  {    4,     -4},    -78.0  },
		{  {    8,     -8},    -72.0  },
		{  {   16,    -16},    -66.0  },
		{  {   32,    -32},    -60.0  },
		{  {   64,    -64},    -54.0  },
		{  {  128,   -128},    -48.0  },
		{  {  256,   -256},    -42.0  },
		{  {  512,   -512},    -36.0  },
		{  { 1024,  -1024},    -30.0  },
		{  { 2048,  -2048},    -24.0  },
		{  { 4096,  -4096},    -18.0  },
		{  { 8192,  -8192},    -12.0  },
		{  {16384, -16384},     -6.0  },
		{  {32767, -32768},      0.0  },
	};

	static struct {
		int16_t sampv[4];
		double level;
	} testv4[] = {
		{  {32767, -32768, 16384, -16384},  -2.0  },
	};

	auframe_init(&af, AUFMT_RAW, testv[0].sampv,
		     RE_ARRAY_SIZE(testv[0].sampv), 48000, 2);
	TEST_EQUALS(AULEVEL_UNDEF, af.level);

	level = auframe_level(&af);
	TEST_EQUALS(AULEVEL_UNDEF, level);

	auframe_init(&af, AUFMT_S16LE, NULL, 0, 48000, 2);
	level = auframe_level(&af);
	TEST_EQUALS(AULEVEL_UNDEF, level);

	for (size_t i = 0; i < RE_ARRAY_SIZE(testv); i++) {
		auframe_init(&af, AUFMT_S16LE, testv[i].sampv,
			     RE_ARRAY_SIZE(testv[i].sampv), 48000, 2);

		level = auframe_level(&af);

		ASSERT_DOUBLE_EQ(testv[i].level, level, PREC);
	}

	for (size_t i = 0; i < RE_ARRAY_SIZE(testv4); i++) {
		auframe_init(&af, AUFMT_S16LE, testv4[i].sampv,
			     RE_ARRAY_SIZE(testv4[i].sampv), 48000, 2);

		level = auframe_level(&af);

		ASSERT_DOUBLE_EQ(testv4[i].level, level, PREC);
	}

out:
	return err;
}
