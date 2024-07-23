/**
 * @file aumix.c Audio Mixer
 *
 * Copyright (C) 2010 Creytiv.com
 */

#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <re.h>
#include <rem_au.h>
#include <rem_aulevel.h>
#include <rem_auframe.h>
#include <rem_aubuf.h>
#include <rem_aufile.h>
#include <rem_aumix.h>


/** Defines an Audio mixer */
struct aumix {
	mtx_t *mutex;
	cnd_t cond;
	struct list srcl;
	thrd_t thread;
	struct aufile *af;
	uint32_t ptime;
	uint32_t frame_size;
	uint32_t srate;
	uint8_t ch;
	aumix_record_h *recordh;
	aumix_record_h *record_sumh;
	struct auframe rec_sum;
	bool run;
};

/** Defines an Audio mixer source */
struct aumix_source {
	struct le le;
	struct auframe af;
	int16_t *frame;
	struct aubuf *aubuf;
	struct aumix *mix;
	aumix_frame_h *fh;
	aumix_read_h *readh;
	void *arg;
	bool muted;
};


static void dummy_frame_handler(const int16_t *sampv, size_t sampc, void *arg)
{
	(void)sampv;
	(void)sampc;
	(void)arg;
}


static void destructor(void *arg)
{
	struct aumix *mix = arg;

	mtx_lock(mix->mutex);
	bool run = mix->run;
	mtx_unlock(mix->mutex);

	if (run) {

		mtx_lock(mix->mutex);
		mix->run = false;
		cnd_signal(&mix->cond);
		mtx_unlock(mix->mutex);

		thrd_join(mix->thread, NULL);
	}

	mem_deref(mix->af);
	mem_deref(mix->mutex);
}


static void source_destructor(void *arg)
{
	struct aumix_source *src = arg;

	if (src->le.list) {
		mtx_lock(src->mix->mutex);
		list_unlink(&src->le);
		mtx_unlock(src->mix->mutex);
	}

	mem_deref(src->aubuf);
	mem_deref(src->frame);
	mem_deref(src->mix);
}


static int aumix_thread(void *arg)
{
	uint8_t *silence, *frame, *base_frame;
	struct aumix *mix = arg;
	int16_t *mix_frame;
	uint64_t ts = 0;

	silence   = mem_zalloc(mix->frame_size*2, NULL);
	frame     = mem_alloc(mix->frame_size*2, NULL);
	mix_frame = mem_alloc(mix->frame_size*2, NULL);

	if (!silence || !frame || !mix_frame)
		goto out;

	mtx_lock(mix->mutex);

	while (mix->run) {

		struct le *le;
		uint64_t now;

		if (!mix->srcl.head) {
			mix->af = mem_deref(mix->af);
			cnd_wait(&mix->cond, mix->mutex);
			ts = 0;
		}
		else {
			mtx_unlock(mix->mutex);
			sys_usleep(4000);
			mtx_lock(mix->mutex);
		}

		now = tmr_jiffies();
		if (!ts)
			ts = now;

		if (ts > now)
			continue;

		if (mix->af) {

			size_t n = mix->frame_size*2;

			if (aufile_read(mix->af, frame, &n) || n == 0) {
				mix->af = mem_deref(mix->af);
				base_frame = silence;
			}
			else if (n < mix->frame_size*2) {
				memset(frame + n, 0, mix->frame_size*2 - n);
				mix->af = mem_deref(mix->af);
				base_frame = frame;
			}
			else {
				base_frame = frame;
			}
		}
		else {
			base_frame = silence;
		}

		for (le = mix->srcl.head; le; le = le->next) {

			struct aumix_source *src = le->data;

			if (src->muted)
				continue;

			if (src->readh)
				src->readh(&src->af, src->arg);
			else
				aubuf_read_auframe(src->aubuf, &src->af);

			if (mix->recordh)
				mix->recordh(&src->af);
		}

		for (le = mix->srcl.head; le; le = le->next) {

			struct aumix_source *src = le->data;
			struct le *cle;

			memcpy(mix_frame, base_frame, mix->frame_size * 2);

			LIST_FOREACH(&mix->srcl, cle)
			{

				struct aumix_source *csrc = cle->data;
				int32_t sample;

				/* skip self */
				if (csrc == src)
					continue;

				if (csrc->muted)
					continue;

				for (size_t i = 0; i < mix->frame_size; i++) {
					sample = mix_frame[i] + csrc->frame[i];

					/* hard clipping */
					if (sample >= 32767)
						sample = 32767;
					if (sample <= -32767)
						sample = -32767;

					mix_frame[i] = (int16_t)sample;
				}
			}

			src->fh(mix_frame, mix->frame_size, src->arg);
		}

		if (mix->record_sumh) {
			struct le *cle;

			memcpy(mix_frame, base_frame, mix->frame_size * 2);

			LIST_FOREACH(&mix->srcl, cle)
			{
				struct aumix_source *csrc = cle->data;
				int32_t sample;

				if (csrc->muted)
					continue;

				for (size_t i = 0; i < mix->frame_size; i++) {
					sample = mix_frame[i] + csrc->frame[i];

					/* hard clipping */
					if (sample >= 32767)
						sample = 32767;
					if (sample <= -32767)
						sample = -32767;

					mix_frame[i] = (int16_t)sample;
				}
			}

			mix->rec_sum.timestamp = now;
			mix->rec_sum.sampv     = mix_frame;

			mix->record_sumh(&mix->rec_sum);
		}

		ts += mix->ptime;
	}

	mtx_unlock(mix->mutex);

 out:
	mem_deref(mix_frame);
	mem_deref(silence);
	mem_deref(frame);

	return 0;
}


/**
 * Allocate a new Audio mixer
 *
 * @param mixp  Pointer to allocated audio mixer
 * @param srate Sample rate in [Hz]
 * @param ch    Number of channels
 * @param ptime Packet time in [ms]
 *
 * @return 0 for success, otherwise error code
 */
int aumix_alloc(struct aumix **mixp, uint32_t srate,
		uint8_t ch, uint32_t ptime)
{
	struct aumix *mix;
	int err;

	if (!mixp || !srate || !ch || !ptime)
		return EINVAL;

	mix = mem_zalloc(sizeof(*mix), destructor);
	if (!mix)
		return ENOMEM;

	mix->ptime      = ptime;
	mix->frame_size = srate * ch * ptime / 1000;
	mix->srate      = srate;
	mix->ch         = ch;
	mix->recordh    = NULL;

	mix->rec_sum.ch	  = ch;
	mix->rec_sum.srate = srate;
	mix->rec_sum.sampc = mix->frame_size;

	err = mutex_alloc(&mix->mutex);
	if (err) {
		goto out;
	}

	err = cnd_init(&mix->cond) != thrd_success;
	if (err) {
		err = ENOMEM;
		goto out;
	}

	mix->run = true;

	err = thread_create_name(&mix->thread, "aumix", aumix_thread, mix);
	if (err) {
		mix->run = false;
		goto out;
	}

 out:
	if (err)
		mem_deref(mix);
	else
		*mixp = mix;

	return err;
}


/**
 * Add multitrack record handler (each source can be identified by auframe->id)
 *
 * @param mix      Audio mixer
 * @param recordh  Record Handler
 */
void aumix_recordh(struct aumix *mix, aumix_record_h *recordh)
{
	if (!mix)
		return;

	mtx_lock(mix->mutex);
	mix->recordh = recordh;
	mtx_unlock(mix->mutex);
}


/**
 * Add sum record handler
 *
 * @param mix      Audio mixer
 * @param recordh  Record Handler
 */
void aumix_record_sumh(struct aumix *mix, aumix_record_h *recordh)
{
	if (!mix)
		return;

	mtx_lock(mix->mutex);
	mix->record_sumh = recordh;
	mtx_unlock(mix->mutex);
}


/**
 * Load audio file for mixer announcements
 *
 * @param mix      Audio mixer
 * @param filepath Filename of audio file with complete path
 *
 * @return 0 for success, otherwise error code
 */
int aumix_playfile(struct aumix *mix, const char *filepath)
{
	struct aufile_prm prm;
	struct aufile *af;
	int err;

	if (!mix || !filepath)
		return EINVAL;

	err = aufile_open(&af, &prm, filepath, AUFILE_READ);
	if (err)
		return err;

	if (prm.fmt != AUFMT_S16LE || prm.srate != mix->srate ||
	    prm.channels != mix->ch) {
		mem_deref(af);
		return EINVAL;
	}

	mtx_lock(mix->mutex);
	mem_deref(mix->af);
	mix->af = af;
	mtx_unlock(mix->mutex);

	return 0;
}


/**
 * Count number of audio sources in the audio mixer
 *
 * @param mix Audio mixer
 *
 * @return Number of audio sources
 */
uint32_t aumix_source_count(const struct aumix *mix)
{
	if (!mix)
		return 0;

	mtx_lock(mix->mutex);
	uint32_t count = list_count(&mix->srcl);
	mtx_unlock(mix->mutex);

	return count;
}


/**
 * Allocate an audio mixer source
 *
 * @param srcp Pointer to allocated audio source
 * @param mix  Audio mixer
 * @param fh   Mixer frame handler
 * @param arg  Handler argument
 *
 * @return 0 for success, otherwise error code
 */
int aumix_source_alloc(struct aumix_source **srcp, struct aumix *mix,
		       aumix_frame_h *fh, void *arg)
{
	struct aumix_source *src;
	size_t sz;
	int err;

	if (!srcp || !mix)
		return EINVAL;

	src = mem_zalloc(sizeof(*src), source_destructor);
	if (!src)
		return ENOMEM;

	src->mix = mem_ref(mix);
	src->fh  = fh ? fh : dummy_frame_handler;
	src->arg = arg;
	src->muted = false;

	sz = mix->frame_size*2;

	src->frame = mem_alloc(sz, NULL);
	if (!src->frame) {
		err = ENOMEM;
		goto out;
	}

	auframe_init(&src->af, AUFMT_S16LE, src->frame, mix->frame_size,
		     mix->srate, mix->ch);

	err = aubuf_alloc(&src->aubuf, sz * 6, sz * 12);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(src);
	else
		*srcp = src;

	return err;
}


/**
 * Add source read handler (alternative to aumix_source_put)
 *
 * @param src    Audio mixer source
 * @param readh  Read Handler
 */
void aumix_source_readh(struct aumix_source *src, aumix_read_h *readh)
{
	if (!src || !src->mix)
		return;

	mtx_lock(src->mix->mutex);
	src->readh = readh;
	mtx_unlock(src->mix->mutex);
}


/**
 * Mute/unmute aumix source
 *
 * @param src    Audio mixer source
 * @param mute   True to mute, false to unmute
 */
void aumix_source_mute(struct aumix_source *src, bool mute)
{
	if (!src)
		return;

	src->muted = mute;
}


/**
 * Enable/disable aumix source
 *
 * @param src    Audio mixer source
 * @param enable True to enable, false to disable
 */
void aumix_source_enable(struct aumix_source *src, bool enable)
{
	struct aumix *mix;

	if (!src)
		return;

	if (src->le.list && enable)
		return;

	if (!src->le.list && !enable)
		return;

	mix = src->mix;

	mtx_lock(mix->mutex);

	if (enable) {
		list_append(&mix->srcl, &src->le, src);
		cnd_signal(&mix->cond);
	}
	else {
		list_unlink(&src->le);
	}

	mtx_unlock(mix->mutex);
}


/**
 * Write PCM samples for a given source to the audio mixer
 *
 * @param src   Audio mixer source
 * @param sampv PCM samples
 * @param sampc Number of samples
 *
 * @return 0 for success, otherwise error code
 */
int aumix_source_put(struct aumix_source *src, const int16_t *sampv,
		     size_t sampc)
{
	if (!src || !sampv)
		return EINVAL;

	return aubuf_write_samp(src->aubuf, sampv, sampc);
}


/**
 * Flush the audio buffer of a given audio mixer source
 *
 * @param src Audio mixer source
 */
void aumix_source_flush(struct aumix_source *src)
{
	if (!src)
		return;

	aubuf_flush(src->aubuf);
}


/**
 * Audio mixer debug handler
 *
 * @param pf  Print function
 * @param mix Audio mixer
 *
 * @return 0 if success, otherwise errorcode
 */
int aumix_debug(struct re_printf *pf, const struct aumix *mix)
{
	struct le *le;
	int err = 0;

	if (!pf || !mix)
		return EINVAL;

	re_hprintf(pf, "aumix debug:\n");
	mtx_lock(mix->mutex);
	LIST_FOREACH(&mix->srcl, le)
	{
		struct aumix_source *src = le->data;
		re_hprintf(pf, "\tsource: %p muted=%d ", src, src->muted);
		err = aubuf_debug(pf, src->aubuf);
		if (err)
			goto out;
		re_hprintf(pf, "\n");
	}

out:
	mtx_unlock(mix->mutex);
	return err;
}
