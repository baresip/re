/**
 * @file jbuf.c  Jitter Buffer implementation
 *
 * This is an adaptive jitter buffer implementation. See doc/jbuf for further
 * details!
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <stdint.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_mbuf.h>
#include <re_mem.h>
#include <re_rtp.h>
#include <re_lock.h>
#include <re_tmr.h>
#include <re_jbuf.h>

#include <stdlib.h>

#define DEBUG_MODULE "jbuf"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#ifndef RELEASE
#define JBUF_STAT 1  /**< Jitter buffer statistics */
#endif


#if JBUF_STAT
#define STAT_ADD(var, value)  (jb->stat.var) += (value) /**< Stats add */
#define STAT_INC(var)         ++(jb->stat.var)          /**< Stats inc */
#else
#define STAT_ADD(var, value)
#define STAT_INC(var)
#endif

enum {
	JBUF_RDIFF_EMA_COEFF = 1024,
	JBUF_RDIFF_UP_SPEED  = 512,
	JBUF_PUT_TIMEOUT     = 400,
};


/** Defines a packet frame */
struct frame {
	struct le le;           /**< Linked list element       */
	struct rtp_header hdr;  /**< RTP Header                */
	void *mem;              /**< Reference counted pointer */
};


/**
 * Defines a jitter buffer
 *
 * The jitter buffer is for incoming RTP packets, which are sorted by
 * sequence number.
 */
struct jbuf {
	struct list pooll;   /**< List of free frames in pool               */
	struct list framel;  /**< List of buffered frames                   */
	uint32_t n;          /**< [# frames] Current # of frames in buffer  */
	uint32_t min;        /**< [# frames] Minimum # of frames to buffer  */
	uint32_t max;        /**< [# frames] Maximum # of frames to buffer  */
	uint32_t wish;       /**< [# frames] Wish size for adaptive mode    */
	uint16_t seq_put;    /**< Sequence number for last jbuf_put()       */
	uint16_t seq_get;    /**< Sequence number of last played frame      */
	uint32_t ssrc;       /**< Previous ssrc                             */
	uint64_t tr;         /**< Time of previous jbuf_put()               */
	int pt;              /**< Payload type                              */
	bool running;        /**< Jitter buffer is running                  */
	int32_t rdiff;       /**< Average out of order reverse diff         */
	struct tmr tmr;      /**< Rdiff down timer                          */

	struct lock *lock;   /**< Makes jitter buffer thread safe           */
	enum jbuf_type jbtype;     /**< Jitter buffer type                  */
#if JBUF_STAT
	struct jbuf_stat stat; /**< Jitter buffer Statistics       */
#endif
};


/** Is x less than y? */
static inline bool seq_less(uint16_t x, uint16_t y)
{
	return ((int16_t)(x - y)) < 0;
}


/**
 * Get a frame from the pool
 */
static void frame_alloc(struct jbuf *jb, struct frame **f)
{
	struct le *le;

	le = jb->pooll.head;
	if (le) {
		list_unlink(le);
		++jb->n;
	}
	else {
		struct frame *f0;

		/* Steal an old frame */
		le = jb->framel.head;
		f0 = le->data;

#if JBUF_STAT
		STAT_INC(n_overflow);
		DEBUG_INFO("drop 1 old frame seq=%u (total dropped %u)\n",
			   f0->hdr.seq, jb->stat.n_overflow);
#endif

		f0->mem = mem_deref(f0->mem);
		list_unlink(le);
	}

	*f = le->data;
}


/**
 * Release a frame, put it back in the pool
 */
static void frame_deref(struct jbuf *jb, struct frame *f)
{
	f->mem = mem_deref(f->mem);
	list_unlink(&f->le);
	list_append(&jb->pooll, &f->le, f);
	--jb->n;
}


static void jbuf_destructor(void *data)
{
	struct jbuf *jb = data;

	tmr_cancel(&jb->tmr);
	jbuf_flush(jb);

	/* Free all frames in the pool list */
	list_flush(&jb->pooll);
	mem_deref(jb->lock);
}


/**
 * Allocate a new jitter buffer
 *
 * @param jbp    Pointer to returned jitter buffer
 * @param min    Minimum delay in [frames]
 * @param max    Maximum delay in [frames]
 *
 * @return 0 if success, otherwise errorcode
 */
int jbuf_alloc(struct jbuf **jbp, uint32_t min, uint32_t max)
{
	struct jbuf *jb;
	uint32_t i;
	int err = 0;

	if (!jbp || ( min > max))
		return EINVAL;

	/* self-test: x < y (also handle wrap around) */
	if (!seq_less(10, 20) || seq_less(20, 10) || !seq_less(65535, 0)) {
		DEBUG_WARNING("seq_less() is broken\n");
		return ENOSYS;
	}

	jb = mem_zalloc(sizeof(*jb), jbuf_destructor);
	if (!jb)
		return ENOMEM;

	list_init(&jb->pooll);
	list_init(&jb->framel);

	jb->jbtype = JBUF_FIXED;
	jb->min  = min;
	jb->max  = max;
	jb->wish = min;
	tmr_init(&jb->tmr);

	DEBUG_INFO("alloc: delay=%u-%u frames\n", min, max);

	jb->pt = -1;
	err = lock_alloc(&jb->lock);
	if (err)
		goto out;

	/* Allocate all frames now */
	for (i=0; i<jb->max; i++) {
		struct frame *f = mem_zalloc(sizeof(*f), NULL);
		if (!f) {
			err = ENOMEM;
			break;
		}

		list_append(&jb->pooll, &f->le, f);
		DEBUG_INFO("alloc: adding to pool list %u\n", i);
	}

out:
	if (err)
		mem_deref(jb);
	else
		*jbp = jb;

	return err;
}


/**
 * Set jitter buffer type.
 *
 * @param jb      The jitter buffer.
 * @param jbtype  The jitter buffer type.
 *
 * @return 0 if success, otherwise errorcode
 */
int  jbuf_set_type(struct jbuf *jb, enum jbuf_type jbtype)
{
	if (!jb)
		return EINVAL;

	jb->jbtype = jbtype;

	return 0;
}


static void wish_down(void *arg)
{
	struct jbuf *jb = arg;

	if (jb->wish > jb->min) {
		DEBUG_INFO("wish size changed %u --> %u\n", jb->wish,
			   jb->wish - 1);
		--jb->wish;
	}
}


static void calc_rdiff(struct jbuf *jb, uint16_t seq)
{
	int32_t rdiff;
	int32_t adiff;
	int32_t s;                         /**< EMA coefficient              */
	uint32_t wish;
	bool down = false;

	if (jb->jbtype != JBUF_ADAPTIVE)
		return;

	if (!jb->seq_get)
		return;

	rdiff = (int16_t)(jb->seq_put + 1 - seq);
	adiff = abs(rdiff * JBUF_RDIFF_EMA_COEFF);
	s = adiff > jb->rdiff ? JBUF_RDIFF_UP_SPEED :
		jb->wish > 2  ? 1 :
		jb->wish > 1  ? 2 : 3;
	jb->rdiff += (adiff - jb->rdiff) * s / JBUF_RDIFF_EMA_COEFF;

	wish = (uint32_t) (jb->rdiff / JBUF_RDIFF_EMA_COEFF);
	if (wish < jb->min)
		wish = jb->min;

	if (wish >= jb->max)
		wish = jb->max - 1;

	if (wish > jb->wish) {
		DEBUG_INFO("wish size changed %u --> %u\n", jb->wish, wish);
		jb->wish = wish;
	}
	else if (wish < jb->wish) {
		uint32_t dt = wish + 1 == jb->wish ? 6000 : 1000;
		if (!tmr_isrunning(&jb->tmr) || tmr_get_expire(&jb->tmr) > dt)
			tmr_start(&jb->tmr, dt, wish_down, jb);

		down = true;
	}

	if (!down && tmr_isrunning(&jb->tmr))
		tmr_cancel(&jb->tmr);
}


/**
 * Put one frame into the jitter buffer
 *
 * @param jb   Jitter buffer
 * @param hdr  RTP Header
 * @param mem  Memory pointer - will be referenced
 *
 * @return 0 if success, otherwise errorcode
 */
int jbuf_put(struct jbuf *jb, const struct rtp_header *hdr, void *mem)
{
	struct frame *f;
	struct le *le, *tail;
	uint16_t seq;
	uint64_t tr, dt;
	int err = 0;

	if (!jb || !hdr)
		return EINVAL;

	seq = hdr->seq;
	if (jb->pt == -1)
		jb->pt = hdr->pt;

	if (jb->ssrc && jb->ssrc != hdr->ssrc) {
		DEBUG_INFO("ssrc changed %u %u\n", jb->ssrc, hdr->ssrc);
		jbuf_flush(jb);
	}

	tr = tmr_jiffies();
	dt = tr - jb->tr;
	if (jb->tr && dt > JBUF_PUT_TIMEOUT) {
		DEBUG_INFO("put timeout %lu ms, marker %d\n", dt, hdr->m);
		if (hdr->m)
			jbuf_flush(jb);
	}

	jb->tr = tr;

	lock_write_get(jb->lock);
	jb->ssrc = hdr->ssrc;

	if (jb->running) {

		if (jb->jbtype == JBUF_ADAPTIVE)
			calc_rdiff(jb, seq);

		/* Packet arrived too late to be put into buffer */
		if (jb->seq_get && seq_less(seq, jb->seq_get + 1)) {
			STAT_INC(n_late);
			DEBUG_INFO("packet too late: seq=%u "
				   "(seq_put=%u seq_get=%u)\n",
				   seq, jb->seq_put, jb->seq_get);
			err = ETIMEDOUT;
			goto out;
		}

	}

	STAT_INC(n_put);

	frame_alloc(jb, &f);

	tail = jb->framel.tail;

	/* If buffer is empty -> append to tail
	   Frame is later than tail -> append to tail
	*/
	if (!tail || seq_less(((struct frame *)tail->data)->hdr.seq, seq)) {
		list_append(&jb->framel, &f->le, f);
		goto success;
	}

	/* Out-of-sequence, find right position */
	for (le = tail; le; le = le->prev) {
		const uint16_t seq_le = ((struct frame *)le->data)->hdr.seq;

		if (seq_less(seq_le, seq)) { /* most likely */
			DEBUG_PRINTF("put: out-of-sequence"
				   " - inserting after seq=%u (seq=%u)\n",
				   seq_le, seq);
			list_insert_after(&jb->framel, le, &f->le, f);
			break;
		}
		else if (seq == seq_le) { /* less likely */
			/* Detect duplicates */
			DEBUG_INFO("duplicate: seq=%u\n", seq);
			STAT_INC(n_dups);
			list_insert_after(&jb->framel, le, &f->le, f);
			frame_deref(jb, f);
			err = EALREADY;
			goto out;
		}

		/* sequence number less than current seq, continue */
	}

	/* no earlier timestamps found, put in head */
	if (!le) {
		DEBUG_PRINTF("put: out-of-sequence"
			   " - put in head (seq=%u)\n", seq);
		list_prepend(&jb->framel, &f->le, f);
	}

	STAT_INC(n_oos);

success:
	/* Update last timestamp */
	jb->running = true;
	jb->seq_put = seq;

	/* Success */
	f->hdr = *hdr;
	f->mem = mem_ref(mem);

out:
	lock_rel(jb->lock);
	return err;
}


/**
 * Get one frame from the jitter buffer
 *
 * @param jb   Jitter buffer
 * @param hdr  Returned RTP Header
 * @param mem  Pointer to memory object storage - referenced on success
 *
 * @return 0 if success, EAGAIN if it should be called again in order to avoid
 * a jitter buffer overflow, otherwise errorcode
 */
int jbuf_get(struct jbuf *jb, struct rtp_header *hdr, void **mem)
{
	struct frame *f;
	int err = 0;

	if (!jb || !hdr || !mem)
		return EINVAL;

	lock_write_get(jb->lock);
	STAT_INC(n_get);

	if (jb->n <= jb->wish || !jb->framel.head) {
		DEBUG_INFO("not enough buffer frames - wait.. "
			   "(n=%u wish=%u)\n", jb->n, jb->wish);
		STAT_INC(n_underflow);
		err = ENOENT;
		goto out;
	}

	/* When we get one frame F[i], check that the next frame F[i+1]
	   is present and have a seq no. of seq[i] + 1.
	   If not, we should consider that packet lost. */

	f = jb->framel.head->data;

#if JBUF_STAT
	/* Check timestamp of previously played frame */
	if (jb->seq_get) {
		const int16_t seq_diff = f->hdr.seq - jb->seq_get;
		if (seq_less(f->hdr.seq, jb->seq_get)) {
			DEBUG_WARNING("get: seq=%u too late\n", f->hdr.seq);
		}
		else if (seq_diff > 1) {
			STAT_ADD(n_lost, 1);
			DEBUG_INFO("get: n_lost: diff=%d,seq=%u,seq_get=%u\n",
				   seq_diff, f->hdr.seq, jb->seq_get);
		}
	}
#endif

	/* Update sequence number for 'get' */
	jb->seq_get = f->hdr.seq;

	*hdr = f->hdr;
	*mem = mem_ref(f->mem);

	frame_deref(jb, f);

	if (jb->jbtype == JBUF_ADAPTIVE && jb->n > jb->wish) {
		DEBUG_INFO("reducing jitter buffer "
			   "(n=%u min=%u wish=%u max=%u)\n",
			   jb->n, jb->min, jb->wish, jb->max);
		err = EAGAIN;
	}

out:
	lock_rel(jb->lock);
	return err;
}


/**
 * Flush all frames in the jitter buffer
 *
 * @param jb   Jitter buffer
 */
void jbuf_flush(struct jbuf *jb)
{
	struct le *le;
#if JBUF_STAT
	uint32_t n_flush;
#endif

	if (!jb)
		return;

	lock_write_get(jb->lock);
	if (jb->framel.head) {
		DEBUG_INFO("flush: %u frames\n", jb->n);
	}

	/* put all buffered frames back in free list */
	for (le = jb->framel.head; le; le = jb->framel.head) {
		DEBUG_INFO(" flush frame: seq=%u\n",
			   ((struct frame *)(le->data))->hdr.seq);

		frame_deref(jb, le->data);
	}

	jb->n       = 0;
	jb->running = false;

	jb->seq_get = 0;
#if JBUF_STAT
	n_flush = STAT_INC(n_flush);
	memset(&jb->stat, 0, sizeof(jb->stat));
	jb->stat.n_flush = n_flush;
#endif
	lock_rel(jb->lock);
}


/**
 * Get jitter buffer statistics
 *
 * @param jb    Jitter buffer
 * @param jstat Pointer to statistics storage
 *
 * @return 0 if success, otherwise errorcode
 */
int jbuf_stats(const struct jbuf *jb, struct jbuf_stat *jstat)
{
	if (!jb || !jstat)
		return EINVAL;

#if JBUF_STAT
	*jstat = jb->stat;

	return 0;
#else
	return ENOSYS;
#endif
}


/**
 * Debug the jitter buffer
 *
 * @param pf Print handler
 * @param jb Jitter buffer
 *
 * @return 0 if success, otherwise errorcode
 */
int jbuf_debug(struct re_printf *pf, const struct jbuf *jb)
{
	int err = 0;

	if (!jb)
		return 0;

	err |= re_hprintf(pf, "--- jitter buffer debug---\n");

	err |= re_hprintf(pf, " running=%d", jb->running);
	err |= re_hprintf(pf, " min=%u cur=%u max=%u [frames]\n",
			  jb->min, jb->n, jb->max);
	err |= re_hprintf(pf, " seq_put=%u\n", jb->seq_put);

#if JBUF_STAT
	err |= re_hprintf(pf, " Stat: put=%u", jb->stat.n_put);
	err |= re_hprintf(pf, " get=%u", jb->stat.n_get);
	err |= re_hprintf(pf, " oos=%u", jb->stat.n_oos);
	err |= re_hprintf(pf, " dup=%u", jb->stat.n_dups);
	err |= re_hprintf(pf, " late=%u", jb->stat.n_late);
	err |= re_hprintf(pf, " or=%u", jb->stat.n_overflow);
	err |= re_hprintf(pf, " ur=%u", jb->stat.n_underflow);
	err |= re_hprintf(pf, " flush=%u", jb->stat.n_flush);
	err |= re_hprintf(pf, "       put/get_ratio=%u%%", jb->stat.n_get ?
			  100*jb->stat.n_put/jb->stat.n_get : 0);
	err |= re_hprintf(pf, " lost=%u (%u.%02u%%)\n",
			  jb->stat.n_lost,
			  jb->stat.n_put ?
			  100*jb->stat.n_lost/jb->stat.n_put : 0,
			  jb->stat.n_put ?
			  10000*jb->stat.n_lost/jb->stat.n_put%100 : 0);
#endif

	return err;
}
