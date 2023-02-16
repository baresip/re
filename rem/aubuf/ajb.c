/**
 * @file ajb.c  Adaptive Jitter Buffer algorithm
 *
 * Copyright (C) 2022 Commend.com - c.spielberger@commend.com
 */
#include <stdlib.h>
#include <re.h>
#include <rem_au.h>
#include <rem_aulevel.h>
#include <rem_auframe.h>
#include <rem_aubuf.h>
#include "ajb.h"

#define DEBUG_LEVEL 5

/**
 * @brief The adaptive jitter computation is done by means of an exponential
 * moving average (EMA).
 *￼j_i = j_{i-1} + a (c - j_{i-1})
 *
 * Where $a$ ist the EMA coefficient and $c$ is the current value.
 */
enum {
	JITTER_EMA_COEFF   = 512,  /* Divisor for jitter EMA coefficient */
	JITTER_UP_SPEED    = 64,   /* 64 times faster up than down       */
	BUFTIME_EMA_COEFF  = 128,  /* Divisor for Buftime EMA coeff.     */
	BUFTIME_LO         = 125,  /* 125% of jitter                     */
	BUFTIME_HI         = 175,  /* 175% of jitter                     */
	SKEW_MAX           = 10,   /* Max skew in [ms]                   */
};


/** Adaptive jitter buffer statistics */
struct ajb {
	int32_t jitter;      /**< Jitter in [us]                  */
	mtx_t *lock;

	uint64_t ts;         /**< previous timestamp              */
	uint64_t ts0;        /**< reference timestamp             */
	uint64_t tr0;        /**< reference time of arrival       */
	uint64_t tr00;       /**< arrival of first packet         */
#if DEBUG_LEVEL >= 6
	struct {
		int32_t d;
		uint32_t buftime;
		uint32_t bufmin;
		uint32_t bufmax;
		enum ajb_state as;
	} plot;

	char buf[136];       /**< Buffer for trace                */
#endif

	enum ajb_state as;   /**< computed jitter buffer state    */

	int32_t avbuftime;   /**< average buffered time [us]      */
	bool started;        /**< Started flag                    */
	size_t wish_sz;      /**< Wish size of buffer [Bytes]     */
	struct auframe af;   /**< Audio frame of last ajb_get()   */
	uint32_t dropped;    /**< Dropped audio frames counter    */
	double silence;      /**< Silence audio level             */
};


static void destructor(void *arg)
{
	struct ajb *ajb = arg;

	mem_deref(ajb->lock);
#if DEBUG_LEVEL >= 6
	(void)re_trace_close();
#endif
}


#if DEBUG_LEVEL >= 6
static void plot_ajb(struct ajb *ajb, uint64_t tr)
{
	uint32_t treal;

	if (!ajb->tr00)
		ajb->tr00 = tr;

	treal = (uint32_t) (tr - ajb->tr00);
	re_snprintf(ajb->buf, sizeof(ajb->buf),
		    "%s, 0x%p, %u, %i, %u, %u, %u, %i, %i, %u",
			__func__,               /* row 1  - grep */
			ajb,                    /* row 2  - grep optional */
			treal,                  /* row 3  - plot x-axis */
			ajb->plot.d,            /* row 4  - plot */
			ajb->jitter,            /* row 5  - plot */
			ajb->plot.buftime,      /* row 6  - plot */
			ajb->avbuftime,         /* row 7  - plot */
			ajb->plot.bufmin,       /* row 8  - plot */
			ajb->plot.bufmax,       /* row 9  - plot */
			ajb->plot.as);          /* row 10 - plot */
	re_trace_event("ajb", "plot", 'P', NULL, 0, RE_TRACE_ARG_STRING_COPY,
		       "line", ajb->buf);
}
#endif


#if DEBUG_LEVEL >= 6
void plot_underrun(struct ajb *ajb)
{
	uint64_t tr;
	uint32_t treal;
	if (!ajb)
		return;

	tr = tmr_jiffies();
	if (!ajb->tr00)
		ajb->tr00 = tr;

	treal = (uint32_t) (tr - ajb->tr00);
	re_snprintf(ajb->buf, sizeof(ajb->buf), "%s, 0x%p, %u, %i",
			__func__,               /* row 1  - grep */
			ajb,                    /* row 2  - grep optional */
			treal,                  /* row 3  - plot optional */
			1);                     /* row 4  - plot */
	re_trace_event("ajb", "plot", 'U', NULL, 0, RE_TRACE_ARG_STRING_COPY,
		       "line", ajb->buf);
}
#else
void plot_underrun(struct ajb *ajb)
{
	(void)ajb;
}
#endif


/**
 * Initializes the adaptive jitter buffer statistics
 *
 * @param silence Silence audio level
 * @param wish_sz Wish size of buffer [Bytes]
 *
 * @return ajb    Adaptive jitter buffer statistics
 */
struct ajb *ajb_alloc(double silence, size_t wish_sz)
{
	struct ajb *ajb;
	int err;

	ajb = mem_zalloc(sizeof(*ajb), destructor);
	if (!ajb)
		return NULL;

	err = mutex_alloc(&ajb->lock);
	if (err)
		goto out;

	ajb->ts0 = 0;
	ajb->tr0 = 0;
	ajb->as = AJB_GOOD;
	ajb->silence = silence;
	ajb->wish_sz = wish_sz;
#if DEBUG_LEVEL >= 6
	(void)re_trace_init("ajb.json");
#endif

out:
	if (err)
		ajb = mem_deref(ajb);

	return ajb;
}


void ajb_reset(struct ajb *ajb)
{
	if (!ajb)
		return;

	mtx_lock(ajb->lock);
	ajb->ts  = 0;
	ajb->ts0 = 0;
	ajb->tr0 = 0;

	/* We start with wish size. */
	ajb->started = false;
	ajb->as = AJB_GOOD;
	mtx_unlock(ajb->lock);
}


/**
 * Computes the jitter for audio frame arrival.
 *
 * @param ajb     Adaptive jitter buffer statistics
 * @param af      Audio frame
 * @param cur_sz  Current aubuf size
 */
void ajb_calc(struct ajb *ajb, const struct auframe *af, size_t cur_sz)
{
	uint64_t tr;                       /**< Real time in [us]            */
	uint32_t buftime, bufmax, bufmin;  /**< Buffer time in [us]          */
	uint32_t bufwish;                  /**< Buffer wish time in [us]     */
	int32_t d;                         /**< Time shift in [us]           */
	int32_t da;                        /**< Absolut time shift in [us]   */
	int32_t s;                         /**< EMA coefficient              */
	uint64_t ts;                       /**< Time stamp                   */
	uint64_t ds;                       /**< Time stamp duration          */
	uint32_t ptime;                    /**< Packet time [us]             */
	size_t szdiv;

	if (!ajb || !af || !af->srate)
		return;

	mtx_lock(ajb->lock);
	ts = af->timestamp;
	tr = tmr_jiffies_usec();
	if (!ajb->ts0)
		goto out;

	ds = ts - ajb->ts0;
	d = (int32_t) (int64_t) ( (tr - ajb->tr0) - ds );
	da = abs(d);

	szdiv = af->srate * af->ch *  aufmt_sample_size(af->fmt) / 1000;
	buftime = (uint32_t) (cur_sz * 1000 / szdiv);
	bufwish = (uint32_t) (ajb->wish_sz * 1000 / szdiv);
	if (ajb->started) {
		ajb->avbuftime += ((int32_t) buftime - ajb->avbuftime) /
				  BUFTIME_EMA_COEFF;
		if (ajb->avbuftime < 0)
			ajb->avbuftime = 0;
	}
	else {
		/* Directly after "filling" of aubuf compute a good start value
		 * fitting to wish size. */
		ajb->avbuftime = buftime;
		ajb->jitter = ajb->avbuftime * 100 * 2 /
			(BUFTIME_LO + BUFTIME_HI);
		ajb->started = true;
	}

	s = da > ajb->jitter ? JITTER_UP_SPEED : 1;

	ajb->jitter += (da - ajb->jitter) * s / JITTER_EMA_COEFF;
	if (ajb->jitter < 0)
		ajb->jitter = 0;

	bufmin = (uint32_t) ajb->jitter * BUFTIME_LO / 100;
	bufmax = (uint32_t) ajb->jitter * BUFTIME_HI / 100;

	ptime = (uint32_t) (af->sampc * AUDIO_TIMEBASE / (af->srate * af->ch));
	bufmin = MAX(bufmin, ptime * 2 / 3);
	if (bufwish >= ptime)
		bufmin = MAX(bufmin, bufwish - ptime / 3);

	bufmax = MAX(bufmax, bufmin + 7 * ptime / 6);

	/* reset time base if a frame is missing or skew is too high */
	if (ts - ajb->ts > ptime || da > SKEW_MAX * 1000)
		ajb->ts0 = 0;

	if ((uint32_t) ajb->avbuftime < bufmin)
		ajb->as = AJB_LOW;
	else if ((uint32_t) ajb->avbuftime > bufmax)
		ajb->as = AJB_HIGH;
	else
		ajb->as = AJB_GOOD;

#if DEBUG_LEVEL >= 6
	ajb->plot.d = d;
	ajb->plot.buftime = buftime;
	ajb->plot.bufmin  = bufmin;
	ajb->plot.bufmax  = bufmax;
	plot_ajb(ajb, tr / 1000);
#endif
out:
	ajb->ts = ts;
	if (!ajb->ts0) {
		ajb->ts0 = ts;
		ajb->tr0 = tr;
	}
	mtx_unlock(ajb->lock);
}


void ajb_set_ts0(struct ajb *ajb, uint64_t timestamp)
{
	if (!ajb)
		return;

	mtx_lock(ajb->lock);
	ajb->ts  = timestamp;
	ajb->ts0 = timestamp;
	ajb->tr0 = tmr_jiffies_usec();
	mtx_unlock(ajb->lock);
}


/**
 * Get the state of the Adaptive Jitter Buffer
 *
 * @param ajb Adaptive Jitter Buffer state
 * @param af  Audio frame
 *
 * @return Computed jitter buffer state
 */
enum ajb_state ajb_get(struct ajb *ajb, struct auframe *af)
{
	enum ajb_state as = AJB_GOOD;
	uint32_t ptime;      /**< Packet time [us]                */

	if (!ajb || !af || !af->srate || !af->sampc)
		return AJB_GOOD;

	mtx_lock(ajb->lock);
	ajb->af = *af;

	/* ptime in [us] */
	ptime = (uint32_t) (af->sampc * AUDIO_TIMEBASE / (af->srate * af->ch));
	if (!ajb->avbuftime)
		goto out;

	if (ajb->as == AJB_GOOD ||
	    (ajb->silence < 0. && auframe_level(af) > ajb->silence))
		goto out;

	as = ajb->as;
	if (as == AJB_HIGH) {
		/* early adjustment of avbuftime */
		ajb->avbuftime -= ptime;
		ajb->as = AJB_GOOD;
#if DEBUG_LEVEL >= 6
		ajb->plot.as = AJB_HIGH;
		plot_ajb(ajb, tmr_jiffies());
		ajb->plot.as = AJB_GOOD;
#endif
	}
	else if (as == AJB_LOW) {
		/* early adjustment */
		ajb->avbuftime += ptime;
		ajb->as = AJB_GOOD;
#if DEBUG_LEVEL >= 6
		ajb->plot.as = AJB_LOW;
		plot_ajb(ajb, tmr_jiffies());
		ajb->plot.as = AJB_GOOD;
#endif
	}

out:
	mtx_unlock(ajb->lock);
	return as;
}


int32_t ajb_debug(const struct ajb *ajb)
{
	int32_t jitter;

	if (!ajb)
		return 0;

	mtx_lock(ajb->lock);
	jitter = ajb->jitter;
	mtx_unlock(ajb->lock);
	re_printf("  ajb jitter: %d, ajb avbuftime: %d\n", jitter / 1000,
		  ajb->avbuftime);

	return jitter;
}
