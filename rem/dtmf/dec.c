/**
 * @file dtmf/dec.c  DTMF Decoder
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re.h>
#include <rem_goertzel.h>
#include <rem_dtmf.h>


#define BLOCK_SIZE    102         /* At 8kHz sample rate */
#define THRESHOLD     16439.10631 /* -42dBm0 / bsize^2 */
#define NORMAL_TWIST  6.309573    /*   8dB   */
#define REVERSE_TWIST 2.511886    /*   4dB   */
#define RELATIVE_KEY  6.309573    /*   8dB   */
#define RELATIVE_SUM  0.822243    /* -0.85dB */


static const double fx[4] = { 1209.0, 1336.0, 1477.0, 1633.0 };
static const double fy[4] = {  697.0,  770.0,  852.0,  941.0 };

static const char keyv[4][4] = {{'1', '2', '3', 'A'},
				{'4', '5', '6', 'B'},
				{'7', '8', '9', 'C'},
				{'*', '0', '#', 'D'}};


struct dtmf_dec {
	struct goertzel gx[4], gy[4];
	dtmf_dec_h *dech;
	void *arg;
	double threshold;
	double energy;
	double efac;
	unsigned bsize;
	unsigned bidx;
	char digit, digit1;
};


static char decode_digit(struct dtmf_dec *dec)
{
	unsigned i, x = 0, y = 0;
	double ex[4], ey[4];

	for (i=0; i<4; i++) {

		ex[i] = goertzel_result(&dec->gx[i]);
		ey[i] = goertzel_result(&dec->gy[i]);

		if (ex[i] > ex[x])
			x = i;

		if (ey[i] > ey[y])
			y = i;
	}

	if (ex[x] < dec->threshold ||
	    ey[y] < dec->threshold)
		return 0;

	if (ex[x] > ey[y] * NORMAL_TWIST ||
	    ey[y] > ex[x] * REVERSE_TWIST)
		return 0;

	for (i=0; i<4; i++) {

		if ((i != x && ex[i] * RELATIVE_KEY > ex[x]) ||
		    (i != y && ey[i] * RELATIVE_KEY > ey[y]))
			return 0;
	}

	if ((ex[x] + ey[y]) < dec->efac * dec->energy)
		return 0;

	return keyv[y][x];
}


/**
 * Allocate a DTMF decoder instance
 *
 * @param decp  Pointer to allocated decoder
 * @param srate Sample rate
 * @param ch    Number of channels
 * @param dech  Decode handler
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int dtmf_dec_alloc(struct dtmf_dec **decp, unsigned srate, unsigned ch,
		   dtmf_dec_h *dech, void *arg)
{
	struct dtmf_dec *dec;

	if (!decp || !dech || !srate || !ch)
		return EINVAL;

	dec = mem_zalloc(sizeof(*dec), NULL);
	if (!dec)
		return ENOMEM;

	dtmf_dec_reset(dec, srate, ch);

	dec->dech = dech;
	dec->arg  = arg;

	*decp = dec;

	return 0;
}


/**
 * Reset and configure DTMF decoder state
 *
 * @param dec   DTMF decoder
 * @param srate Sample rate
 * @param ch    Number of channels
 */
void dtmf_dec_reset(struct dtmf_dec *dec, unsigned srate, unsigned ch)
{
	unsigned i;

	if (!dec || !srate || !ch)
		return;

	srate *= ch;

	for (i=0; i<4; i++) {
		goertzel_init(&dec->gx[i], fx[i], srate);
		goertzel_init(&dec->gy[i], fy[i], srate);
	}

	dec->bsize     = (BLOCK_SIZE * srate) / 8000;
	dec->threshold = THRESHOLD * dec->bsize * dec->bsize;
	dec->efac      = RELATIVE_SUM * dec->bsize;

	dec->energy = 0.0;
	dec->bidx   = 0;
	dec->digit  = 0;
	dec->digit1 = 0;
}


/**
 * Decode DTMF from input audio samples
 *
 * @param dec   DTMF decoder
 * @param sampv Buffer with audio samples
 * @param sampc Number of samples
 */
void dtmf_dec_probe(struct dtmf_dec *dec, const int16_t *sampv, size_t sampc)
{
	size_t i;

	if (!dec || !sampv)
		return;

	for (i=0; i<sampc; i++) {

		char digit0;
		unsigned j;

		for (j=0; j<4; j++) {
			goertzel_update(&dec->gx[j], sampv[i]);
			goertzel_update(&dec->gy[j], sampv[i]);
		}

		dec->energy += sampv[i] * sampv[i];

		if (++dec->bidx < dec->bsize)
			continue;

		digit0 = decode_digit(dec);

		if (digit0 != dec->digit && dec->digit1 != dec->digit) {

			dec->digit = digit0;

			if (digit0 != dec->digit1)
				dec->digit = 0;

			if (dec->digit)
				dec->dech(dec->digit, dec->arg);
		}

		dec->digit1 = digit0;
		dec->energy = 0.0;
		dec->bidx   = 0;
	}
}
