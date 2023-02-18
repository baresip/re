/**
 * @file auresamp.c Audio-resampler Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "test_auresamp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define SRATE        44100
#define CHANNELS_IN      1
#define CHANNELS_OUT     2


#define SAMPLES 8


/* samples from random.org with atmospheric noise */
static const int16_t inv[CHANNELS_IN * SAMPLES] = {
	0x513a,
	0x3f11,
	0x4224,
	0x601d,
	0x1dc6,
	0x2fb1,
	0x66ee,
	0x7d53
};

static const int16_t ref_outv[CHANNELS_OUT * SAMPLES] = {
	0x513a,
	0x513a,
	0x3f11,
	0x3f11,
	0x4224,
	0x4224,
	0x601d,
	0x601d,
	0x1dc6,
	0x1dc6,
	0x2fb1,
	0x2fb1,
	0x66ee,
	0x66ee,
	0x7d53,
	0x7d53
};


int test_auresamp(void)
{
	struct auresamp rs;
	int16_t outv[CHANNELS_OUT * SAMPLES];
	size_t outc = RE_ARRAY_SIZE(outv);
	int err;

	auresamp_init(&rs);

	err = auresamp_setup(&rs, SRATE, CHANNELS_IN, SRATE, CHANNELS_OUT);
	TEST_ERR(err);

	/* resample from mono to stereo */
	err = auresamp(&rs, outv, &outc, inv, RE_ARRAY_SIZE(inv));
	TEST_ERR(err);

	TEST_EQUALS(RE_ARRAY_SIZE(outv), outc);

#if 0
	re_printf("\nInput samples:\n");
	hexdump(stdout, inv, sizeof(inv));
	re_printf("Output samples:\n");
	hexdump(stdout, outv, sizeof(outv));
#endif

	TEST_MEMCMP(ref_outv, sizeof(ref_outv), outv, sizeof(outv));

 out:
	return err;
}
