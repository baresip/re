/**
 * @file aulevel/aulevel.c  Audio level
 *
 * Copyright (C) 2017 Creytiv.com
 */

#include <math.h>
#include <re.h>
#include <rem.h>


/**
 * Generic routine to calculate RMS (Root-Mean-Square) from
 * a set of signed 16-bit values
 *
 * \verbatim

	     .---------------
	     |   N-1
	     |  ----.
	     |  \
	     |   \        2
	     |    |   s[n]
	     |   /
	     |  /
	 _   |  ----'
	  \  |   n=0
	   \ |  ------------
	    \|       N

   \endverbatim
 *
 * @param data Array of signed 16-bit values
 * @param len  Number of values
 *
 * @return RMS value from 0 to 32768
 */
static double calc_rms_s16(const int16_t *data, size_t len)
{
	int64_t sum = 0;
	size_t i;

	if (!data || !len)
		return .0;

	for (i = 0; i < len; i++) {
		sum += data[i] * data[i];
	}

	return sqrt(sum / (double)len);
}


static double calc_rms_s32(const int32_t *data, size_t len)
{
	double sum = 0;
	size_t i;

	if (!data || !len)
		return .0;

	for (i = 0; i < len; i++) {
		const double sample = data[i];

		sum += sample * sample;
	}

	return sqrt(sum / (double)len);
}


static double calc_rms_float(const float *data, size_t len)
{
	double sum = 0;
	size_t i;

	if (!data || !len)
		return .0;

	for (i = 0; i < len; i++) {
		const double sample = data[i];

		sum += sample * sample;
	}

	return sqrt(sum / (double)len);
}


/**
 * Calculate the audio level in dBov from a set of audio samples.
 * dBov is the level, in decibels, relative to the overload point
 * of the system
 *
 * @param fmt   Sample format (enum aufmt)
 * @param sampv Audio samples
 * @param sampc Number of audio samples
 *
 * @return Audio level expressed in dBov on success and AULEVEL_UNDEF on error
 */
double aulevel_calc_dbov(int fmt, const void *sampv, size_t sampc)
{
	static const double peak_s16 = 32767.0;
	static const double peak_s32 = 2147483647.0;
	double rms, dbov;

	if (!sampv || !sampc)
		return AULEVEL_UNDEF;

	switch (fmt) {

	case AUFMT_S16LE:
		rms = calc_rms_s16(sampv, sampc) / peak_s16;
		break;

	case AUFMT_S32LE:
		rms = calc_rms_s32(sampv, sampc) / peak_s32;
		break;

	case AUFMT_FLOAT:
		rms = calc_rms_float(sampv, sampc) / 1.0;
		break;

	default:
		re_printf("aulevel: sample format not supported (%s)\n",
			aufmt_name(fmt));
		return AULEVEL_UNDEF;
	}

	dbov = 20 * log10(rms);

	if (dbov < AULEVEL_MIN)
		dbov = AULEVEL_MIN;
	else if (dbov > AULEVEL_MAX)
		dbov = AULEVEL_MAX;

	return dbov;
}
