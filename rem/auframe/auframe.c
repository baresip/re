/**
 * @file auframe.c  Audio frame
 *
 * Copyright (C) 2010 - 2020 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <rem_au.h>
#include <rem_aulevel.h>
#include <rem_auframe.h>


/**
 * Initialize an audio frame
 *
 * @param af       Audio frame
 * @param fmt      Sample format (enum aufmt)
 * @param sampv    Audio samples
 * @param sampc    Total number of audio samples
 * @param srate    Samplerate
 * @param ch       Channels
 */
void auframe_init(struct auframe *af, enum aufmt fmt, void *sampv,
		  size_t sampc, uint32_t srate, uint8_t ch)
{
	if (!af)
		return;

	if (0 == aufmt_sample_size(fmt)) {
		re_printf("auframe: init: unsupported sample format %d (%s)\n",
			fmt, aufmt_name(fmt));
	}

	memset(af, 0, sizeof(*af));

	af->fmt = fmt;
	af->sampv = sampv;
	af->sampc = sampc;
	af->srate = srate;
	af->level = AULEVEL_UNDEF;
	af->ch = ch;
	af->id = 0;
}


/**
 * Get the size of an audio frame
 *
 * @param af Audio frame
 *
 * @return Number of bytes
 */
size_t auframe_size(const struct auframe *af)
{
	size_t sz;

	if (!af)
		return 0;

	sz = aufmt_sample_size(af->fmt);
	if (sz == 0) {
		re_printf("auframe: size: illegal format %d (%s)\n",
			af->fmt, aufmt_name(af->fmt));
		sz = 1;
	}

	return af->sampc * sz;
}


/**
 * Silence all samples in an audio frame
 *
 * @param af Audio frame
 */
void auframe_mute(struct auframe *af)
{
	if (!af)
		return;

	memset(af->sampv, 0, auframe_size(af));
}


/**
 * Get audio level (only calculated once)
 *
 * @note Set af->level = AULEVEL_UNDEF to force re-calculation
 *
 * @param af  Audio frame
 *
 * @return Audio level expressed in dBov on success and AULEVEL_UNDEF on error
 */
double auframe_level(struct auframe *af)
{
	if (!af)
		return AULEVEL_UNDEF;

	if (af->fmt == AUFMT_RAW)
		return AULEVEL_UNDEF;

	if (af->level == AULEVEL_UNDEF)
		af->level = aulevel_calc_dbov(af->fmt, af->sampv, af->sampc);

	return af->level;
}


uint64_t auframe_bytes_to_timestamp(const struct auframe *af, size_t n)
{
	size_t sample_size = aufmt_sample_size(af->fmt);

	return ((uint64_t) n) * AUDIO_TIMEBASE /
		(af->srate * af->ch * sample_size);
}


uint64_t auframe_bytes_to_ms(const struct auframe *af, size_t n)
{
	size_t sample_size = aufmt_sample_size(af->fmt);

	return ((uint64_t)n * 1000) / (af->srate * af->ch * sample_size);
}
