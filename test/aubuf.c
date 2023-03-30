/**
 * @file aubuf.c Audio-buffer Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "test_aubuf"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#define AUDIO_TIMEBASE 1000000U

enum {
	FRAMES = 80,
};


static int test_aubuf_raw(void)
{
	struct aubuf *ab = NULL;
	int16_t sampv_in[2 * FRAMES];
	int16_t sampv_out[2 * FRAMES];
	struct mbuf *mb;
	unsigned i;
	int err;

	mb = mbuf_alloc(FRAMES * sizeof(int16_t));
	if (!mb)
		return ENOMEM;

	for (i=0; i<RE_ARRAY_SIZE(sampv_in); i++)
		sampv_in[i] = i;
	memset(sampv_out, 0, sizeof(sampv_out));

	err = aubuf_alloc(&ab, 4 * FRAMES, 0);
	TEST_ERR(err);
	TEST_EQUALS(0, aubuf_cur_size(ab));

	err = aubuf_write(ab, (uint8_t *)sampv_in, FRAMES * sizeof(int16_t));
	TEST_ERR(err);
	TEST_EQUALS(2 * FRAMES, aubuf_cur_size(ab));

	(void)mbuf_write_mem(mb, (uint8_t *)&sampv_in[FRAMES],
			     FRAMES * sizeof(int16_t));
	mb->pos = 0;

	err = aubuf_append(ab, mb);
	TEST_ERR(err);
	TEST_EQUALS(4 * FRAMES, aubuf_cur_size(ab));

	memset(sampv_out, 0, sizeof(sampv_out));
	aubuf_read(ab, (uint8_t *)sampv_out, 2 * FRAMES * sizeof(int16_t));
	TEST_MEMCMP(sampv_in, sizeof(sampv_in), sampv_out, sizeof(sampv_out));
	TEST_EQUALS(0, aubuf_cur_size(ab));

 out:
	mem_deref(ab);
	mem_deref(mb);
	return err;
}


static int test_aubuf_samp(void)
{
	struct aubuf *ab = NULL;
	int16_t sampv_in[2 * FRAMES];
	int16_t sampv_out[2 * FRAMES];
	unsigned i;
	int err;

	for (i=0; i<RE_ARRAY_SIZE(sampv_in); i++)
		sampv_in[i] = i;
	memset(sampv_out, 0, sizeof(sampv_out));

	err = aubuf_alloc(&ab, 4 * FRAMES, 0);
	TEST_ERR(err);

	TEST_EQUALS(0, aubuf_cur_size(ab));

	err |= aubuf_write_samp(ab,  sampv_in, FRAMES);
	err |= aubuf_write_samp(ab, &sampv_in[FRAMES], FRAMES);
	TEST_ERR(err);

	TEST_EQUALS(4 * FRAMES, aubuf_cur_size(ab));

	aubuf_read_samp(ab, sampv_out, RE_ARRAY_SIZE(sampv_out));
	TEST_MEMCMP(sampv_in, sizeof(sampv_in), sampv_out, sizeof(sampv_out));
	TEST_EQUALS(0, aubuf_cur_size(ab));

 out:
	mem_deref(ab);
	return err;
}


static int test_aubuf_auframe(void)
{
	struct aubuf *ab = NULL;
	float sampv_in[3 * FRAMES + (FRAMES / 2)];
	float sampv_out[3 * FRAMES + (FRAMES / 2)];
	uint64_t dt;

	struct auframe af;
	struct auframe af_in;
	struct auframe af_out;
	int err;

	for (unsigned i = 0; i < RE_ARRAY_SIZE(sampv_in); i++)
		sampv_in[i] = (float)i;
	memset(sampv_out, 0, sizeof(sampv_out));

	err = aubuf_alloc(&ab, FRAMES * sizeof(float),
			  4 * FRAMES * sizeof(float));
	TEST_ERR(err);

	TEST_EQUALS(0, aubuf_cur_size(ab));

	/* write first frame (filling with wish_sz) */
	auframe_init(&af, AUFMT_FLOAT, sampv_in, FRAMES, 48000, 2);
	af_in = af;

	dt = FRAMES * AUDIO_TIMEBASE / (af_in.srate * af_in.ch);

	err = aubuf_write_auframe(ab, &af_in);
	TEST_ERR(err);
	TEST_EQUALS(FRAMES * sizeof(float), aubuf_cur_size(ab));
	TEST_EQUALS(auframe_size(&af), aubuf_cur_size(ab));

	/* first read after filling should start aubuf */
	af_out.fmt   = AUFMT_FLOAT;
	af_out.sampv = sampv_out;
	af_out.sampc = FRAMES;
	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(0, aubuf_cur_size(ab));
	TEST_EQUALS(0, af_out.timestamp);

	/* write one frame */
	af_in.sampv	= &sampv_in[FRAMES];
	af_in.sampc	= FRAMES;
	af_in.timestamp = dt;

	err = aubuf_write_auframe(ab, &af_in);
	TEST_ERR(err);
	TEST_EQUALS(auframe_size(&af), aubuf_cur_size(ab));

	/* read half frame */
	af_out.sampc = FRAMES / 2;
	af_out.sampv = &sampv_out[FRAMES];
	aubuf_read_auframe(ab, &af_out);

	/* the first read drops old data: 80 - 40 = 40 */
	TEST_EQUALS(auframe_size(&af)/2, aubuf_cur_size(ab));
	TEST_EQUALS(dt, af_out.timestamp);

	/* write one frame */
	af_in.sampv	= &sampv_in[2 * FRAMES];
	af_in.sampc	= FRAMES;
	af_in.timestamp = 2 * dt;

	err = aubuf_write_auframe(ab, &af_in);
	TEST_ERR(err);
	TEST_EQUALS(auframe_size(&af) * 3 / 2, aubuf_cur_size(ab));

	/* write half frame */
	af_in.sampv	= &sampv_in[3 * FRAMES];
	af_in.sampc	= FRAMES / 2;
	af_in.timestamp = 3 * dt;

	err = aubuf_write_auframe(ab, &af_in);
	TEST_ERR(err);
	TEST_EQUALS(auframe_size(&af) * 2, aubuf_cur_size(ab));

	/* read half frame */
	af_out.sampv = &sampv_out[(FRAMES + (FRAMES / 2))];
	af_out.sampc = FRAMES / 2;
	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(auframe_size(&af) * 3 / 2, aubuf_cur_size(ab));
	TEST_EQUALS(3 * (dt / 2) + 1, af_out.timestamp);

	/* read one and a half frame */
	af_out.sampv = &sampv_out[2 * FRAMES];
	af_out.sampc = FRAMES + (FRAMES / 2);
	aubuf_read_auframe(ab, &af_out);

	TEST_EQUALS(2, af_out.ch);
	TEST_EQUALS(48000, af_out.srate);
	TEST_EQUALS(2 * dt, af_out.timestamp);

	TEST_MEMCMP(sampv_in, sizeof(sampv_in), sampv_out, sizeof(sampv_out));
	TEST_EQUALS(0, aubuf_cur_size(ab));

	/* test automatic timestamps */
	mem_deref(ab);
	err = aubuf_alloc(&ab, 0, 0);
	TEST_ERR(err);

	dt = 24 * AUDIO_TIMEBASE / (af_in.srate * af_in.ch);
	auframe_init(&af_in,  AUFMT_FLOAT, sampv_in,  24, 48000, 2);
	auframe_init(&af_out, AUFMT_FLOAT, sampv_out, 24, 48000, 2);

	af_in.timestamp = 0;

	err |= aubuf_write_auframe(ab, &af_in);
	err |= aubuf_write_auframe(ab, &af_in);
	err |= aubuf_write_auframe(ab, &af_in);
	err |= aubuf_write_auframe(ab, &af_in);
	TEST_ERR(err);

	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(0, af_out.timestamp);

	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(dt, af_out.timestamp);

	af_out.sampc = 12;
	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(2*dt, af_out.timestamp);

	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(2*dt + dt/2, af_out.timestamp);

	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(3*dt, af_out.timestamp);

 out:
	mem_deref(ab);
	return err;
}


static int test_aubuf_sort_auframe(void)
{
	int err;
	struct aubuf *ab = NULL;
	int16_t sampv_in[2 * FRAMES];
	int16_t sampv_out[2 * FRAMES];
	struct auframe af[3] = {
		{
		 .fmt	    = AUFMT_S16LE,
		 .sampv	    = sampv_in,
		 .sampc	    = 2 * FRAMES,
		 .timestamp = 1
		},
		{
		 .fmt	    = AUFMT_S16LE,
		 .sampv	    = sampv_in,
		 .sampc	    = 2 * FRAMES,
		 .timestamp = 2
		},
		{
		 .fmt	    = AUFMT_S16LE,
		 .sampv	    = sampv_in,
		 .sampc	    = 2 * FRAMES,
		 .timestamp = 3
		},
	};
	struct auframe af_out = {
		 .fmt	    = AUFMT_S16LE,
		 .sampv	    = sampv_out,
		 .sampc	    = 2 * FRAMES,
		 .timestamp = 0
	};

	err = aubuf_alloc(&ab, 3 * sizeof(sampv_in), 0);
	TEST_ERR(err);

	/* Write auframes disordered */
	err = aubuf_write_auframe(ab, &af[0]);
	TEST_ERR(err);

	err = aubuf_write_auframe(ab, &af[2]);
	TEST_ERR(err);

	err = aubuf_write_auframe(ab, &af[1]);
	TEST_ERR(err);

	/* Check sorted */
	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(1, af_out.timestamp);

	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(2, af_out.timestamp);

	aubuf_read_auframe(ab, &af_out);
	TEST_EQUALS(3, af_out.timestamp);

	/* Test zero af.timestamp */
	err = aubuf_write_samp(ab, sampv_in, FRAMES);
	err |= aubuf_write_samp(ab, sampv_in, FRAMES);
	err |= aubuf_write_samp(ab, sampv_in, 2 * FRAMES);
	TEST_ERR(err);

	/* Sort - test not stuck */
	aubuf_sort_auframe(ab);
	TEST_EQUALS(8 * FRAMES, aubuf_cur_size(ab));

out:
	mem_deref(ab);
	return err;
}


static int test_aubuf_resize(void)
{
	struct aubuf *ab      = NULL;
	int16_t sampv_in[2 * FRAMES] = {1};
	int16_t sampv_out[2 * FRAMES];
	struct auframe af_out = {
		 .fmt	    = AUFMT_S16LE,
		 .sampv	    = sampv_out,
		 .sampc	    = FRAMES,
		 .timestamp = 0
	};
	int err;

	err = aubuf_alloc(&ab, 2 * FRAMES, 2 * FRAMES);
	TEST_ERR(err);

	TEST_EQUALS(0, aubuf_cur_size(ab));

	err = aubuf_write_samp(ab, sampv_in, FRAMES);
	TEST_ERR(err);

	err = aubuf_write_samp(ab, sampv_in, FRAMES);
	TEST_ERR(err);

	TEST_EQUALS(2 * FRAMES, aubuf_cur_size(ab));

	err = aubuf_resize(ab, 2 * FRAMES, 4 * FRAMES);
	TEST_ERR(err);

	TEST_EQUALS(0, aubuf_cur_size(ab));

	err  = aubuf_write_samp(ab, sampv_in, FRAMES);
	aubuf_read_auframe(ab, &af_out);
	err |= aubuf_write_samp(ab, sampv_in, FRAMES);
	TEST_ERR(err);

	err = aubuf_write_samp(ab, sampv_in, FRAMES);
	TEST_ERR(err);

	TEST_EQUALS(4 * FRAMES, aubuf_cur_size(ab));

out:
	mem_deref(ab);
	return err;
}


int test_aubuf(void)
{
	int err;

	err = test_aubuf_raw();
	TEST_ERR(err);

	err = test_aubuf_samp();
	TEST_ERR(err);

	err = test_aubuf_auframe();
	TEST_ERR(err);

	err = test_aubuf_sort_auframe();
	TEST_ERR(err);

	err = test_aubuf_resize();
	TEST_ERR(err);

out:
	return err;
}
