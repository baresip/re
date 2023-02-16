/**
 * @file auconv.c  Audio sample format converter
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <math.h>
#include <re.h>
#include <rem_au.h>
#include <rem_auconv.h>


static inline float ausamp_short2float(int16_t in)
{
	float out;

	out = (float) (in / (1.0 * 0x8000));

	return out;
}


static inline int16_t ausamp_float2short(float in)
{
	double value;
	int16_t out;

	value = in * (8.0 * 0x10000000);

	if (value >= (1.0 * 0x7fffffff)) {
		out = 32767;
	}
	else if (value <= (-8.0 * 0x10000000)) {
		out = -32768;
	}
	else
		out = (short) (lrint (value) >> 16);

	return out;
}


void auconv_from_s16(enum aufmt dst_fmt, void *dst_sampv,
		     const int16_t *src_sampv, size_t sampc)
{
	float *f;
	uint8_t *b;
	size_t i;

	if (!dst_sampv || !src_sampv || !sampc)
		return;

	switch (dst_fmt) {

	case AUFMT_FLOAT:
		f = dst_sampv;
		for (i=0; i<sampc; i++) {
			f[i] = ausamp_short2float(src_sampv[i]);
		}
		break;

	case AUFMT_S24_3LE:
		b = dst_sampv;
		for (i=0; i<sampc; i++) {
			int16_t s = src_sampv[i];
			b[3*i+2] = s >> 8;
			b[3*i+1] = s & 0xff;
			b[3*i+0] = 0;
		}
		break;

	default:
		(void)re_fprintf(stderr, "auconv: sample format %d (%s)"
				 " not supported\n",
				 dst_fmt, aufmt_name(dst_fmt));
		return;
	}
}


void auconv_to_s16(int16_t *dst_sampv, enum aufmt src_fmt,
		   void *src_sampv, size_t sampc)
{
	float *f;
	uint8_t *b;
	size_t i;

	if (!dst_sampv || !src_sampv || !sampc)
		return;

	switch (src_fmt) {

	case AUFMT_FLOAT:
		f = src_sampv;
		for (i=0; i<sampc; i++) {
			dst_sampv[i] = ausamp_float2short(f[i]);
		}
		break;

	case AUFMT_S24_3LE:
		b = src_sampv;
		for (i=0; i<sampc; i++) {
			int16_t s;
			s = b[3*i+1] | b[3*i+2] << 8;
			dst_sampv[i] = s;
		}
		break;

	default:
		(void)re_fprintf(stderr, "auconv: sample format %d (%s)"
				 " not supported\n",
				 src_fmt, aufmt_name(src_fmt));
		return;
	}
}


void auconv_to_float(float *dst_sampv, enum aufmt src_fmt,
		     const void *src_sampv, size_t sampc)
{
	const int16_t *s16;

	if (!dst_sampv || !src_sampv || !sampc)
		return;

	switch (src_fmt) {

	case AUFMT_S16LE:
		s16 = src_sampv;
		for (size_t i=0; i<sampc; i++) {
			dst_sampv[i] = ausamp_short2float(s16[i]);
		}
		break;

	default:
		re_fprintf(stderr, "auconv: sample format %d (%s)"
			   " not supported\n",
			   src_fmt, aufmt_name(src_fmt));
		break;
	}
}
