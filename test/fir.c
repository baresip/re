/**
 * @file fir.c FIR-filter Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "fir"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/* 48kHz sample-rate, 8kHz cutoff (pass 0-7kHz, stop 9-24kHz) */
static const int16_t fir_48_8[] = {
	238,    198,   -123,   -738,  -1268,  -1204,   -380,    714,
       1164,    376,  -1220,  -2206,  -1105,   2395,   6909,  10069,
      10069,   6909,   2395,  -1105,  -2206,  -1220,    376,   1164,
	714,   -380,  -1204,  -1268,   -738,   -123,    198,    238
};


int test_fir(void)
{
#define NUM_SAMPLES 8
	struct fir fir;
	static const int16_t samp_in[NUM_SAMPLES] =
		{-8000, -4000, -2000, 0, 2000, 4000, 8000, 4000};
	static const int16_t samp_out_exp[NUM_SAMPLES] =
		{ -59, -78, -9, 183, 421, 534, 391, -38};
	int16_t samp_out[NUM_SAMPLES];
	int err = 0;

	fir_reset(&fir);

	/* verify FIR-filter state */
	TEST_EQUALS(0, fir.index);

	/* process the FIR filter */
	fir_filter(&fir, samp_out, samp_in, RE_ARRAY_SIZE(samp_in),
		   1, fir_48_8, RE_ARRAY_SIZE(fir_48_8));

	/* verify FIR-filter state */
	TEST_EQUALS(NUM_SAMPLES, fir.index);
	TEST_ASSERT(NUM_SAMPLES <= RE_ARRAY_SIZE(fir.history));
	TEST_MEMCMP(samp_in, sizeof(samp_in), fir.history, sizeof(samp_in));

	/* verify output samples */
	TEST_MEMCMP(samp_out_exp, sizeof(samp_out_exp),
		    samp_out, sizeof(samp_out));

 out:
	return err;
}
