/**
 * @file tmr.c  Timer implementation
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>
#include <re_types.h>
#include <re_list.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_thread.h>
#include <re_tmr.h>
#include <re_net.h>
#include <re_main.h>


#define DEBUG_MODULE "tmr"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif


/** Timer values */
enum {
	MAX_BLOCKING = 500   /**< Maximum time spent in handler [ms] */
};

struct tmrl {
	struct list list;
	mtx_t *lock;
};


static void tmrl_destructor(void *arg)
{
	struct tmrl *tmrl = arg;

	mtx_lock(tmrl->lock);
	list_clear(&tmrl->list);
	mtx_unlock(tmrl->lock);

	mem_deref(tmrl->lock);
}


int tmrl_alloc(struct tmrl **tmrl)
{
	struct tmrl *l;
	int err;

	if (!tmrl)
		return EINVAL;

	l = mem_zalloc(sizeof(struct tmrl), NULL);
	if (!l)
		return ENOMEM;

	list_init(&l->list);

	err = mutex_alloc(&l->lock);
	if (err) {
		mem_deref(l);
		return err;
	}

	mem_destructor(l, tmrl_destructor);

	*tmrl = l;

	return 0;
}


static bool inspos_handler(struct le *le, void *arg)
{
	struct tmr *tmr = le->data;
	const uint64_t now = *(uint64_t *)arg;

	return tmr->jfs <= now;
}


static bool inspos_handler_0(struct le *le, void *arg)
{
	struct tmr *tmr = le->data;
	const uint64_t now = *(uint64_t *)arg;

	return tmr->jfs > now;
}


#if TMR_DEBUG
static void call_handler(tmr_h *th, void *arg)
{
	const uint64_t tick = tmr_jiffies();
	uint32_t diff;

	/* Call handler */
	th(arg);

	diff = (uint32_t)(tmr_jiffies() - tick);

	if (diff > MAX_BLOCKING) {
		DEBUG_WARNING("long async blocking: %u>%u ms (h=%p arg=%p)\n",
			      diff, MAX_BLOCKING, th, arg);
	}
}
#endif


/**
 * Poll all timers in the current thread
 *
 * @param tmrl Timer list
 */
void tmr_poll(struct tmrl *tmrl)
{
	const uint64_t jfs = tmr_jiffies();

	if (!tmrl)
		return;

	for (;;) {
		struct tmr *tmr;
		tmr_h *th;
		void *th_arg;

		mtx_lock(tmrl->lock);
		tmr = list_ledata(tmrl->list.head);

		if (!tmr || (tmr->jfs > jfs)) {
			mtx_unlock(tmrl->lock);
			break;
		}

		th = tmr->th;
		th_arg = tmr->arg;

		tmr->th = NULL;

		list_unlink(&tmr->le);
		mtx_unlock(tmrl->lock);

		if (!th)
			continue;

#if TMR_DEBUG
		call_handler(th, th_arg);
#else
		th(th_arg);
#endif
	}
}


/**
 * Get the timer jiffies in microseconds
 *
 * @return Jiffies in [us]
 */
uint64_t tmr_jiffies_usec(void)
{
	uint64_t jfs;

#if defined(WIN32)
	LARGE_INTEGER li;
	static LARGE_INTEGER freq;

	if (!freq.QuadPart)
		QueryPerformanceFrequency(&freq);

	QueryPerformanceCounter(&li);
	li.QuadPart *= 1000000;
	li.QuadPart /= freq.QuadPart;

	jfs = li.QuadPart;
#else
	struct timespec now;
	clockid_t clock_id;

	/* Use CLOCK_MONOTONIC_RAW, if available,
	   which is not subject to adjustment by NTP */
#ifdef CLOCK_MONOTONIC_RAW
	clock_id = CLOCK_MONOTONIC_RAW;
#else
	clock_id = CLOCK_MONOTONIC;
#endif

	if (0 != clock_gettime(clock_id, &now)) {
		DEBUG_WARNING("jiffies: clock_gettime() failed (%m)\n", errno);
		return 0;
	}

	jfs  = (long)now.tv_sec * (uint64_t)1000000;
	jfs += now.tv_nsec/1000;
#endif

	return jfs;
}


/**
 * Get the timer jiffies in milliseconds
 *
 * @return Jiffies in [ms]
 */
uint64_t tmr_jiffies(void)
{
	return tmr_jiffies_usec() / 1000;
}


/**
 * Obtain the current realtime wallclock time in microseconds since UNIX epoch
 *
 * @return realtime wallclock time in microseconds since UNIX epoch
 */
uint64_t tmr_jiffies_rt_usec(void)
{
	uint64_t jfs_rt;
#if defined(WIN32)
	FILETIME now;
	GetSystemTimeAsFileTime(&now);
	jfs_rt = (((uint64_t)now.dwHighDateTime) << 32u) |
		(uint64_t)now.dwLowDateTime;
	jfs_rt -= 116444736000000000ull;
	jfs_rt /= 10u;
#else
	struct timespec now;
	if (0 != clock_gettime(CLOCK_REALTIME, &now)) {
		DEBUG_WARNING("jiffies_rt: clock_gettime() failed (%m)\n",
			      errno);
		return 0;
	}

	jfs_rt  = (uint64_t)now.tv_sec * (uint64_t)1000000u;
	jfs_rt += now.tv_nsec / 1000;
#endif

	return jfs_rt;
}


/**
 * Modifies the timespec object to current calendar time (TIME_UTC)
 *
 * @param tp     Pointer to timespec object
 * @param offset Offset in [ms]
 *
 * @return 0 if success, otherwise errorcode
 */
int tmr_timespec_get(struct timespec *tp, uint64_t offset)
{
	int err;

	if (!tp)
		return EINVAL;

#if defined(WIN32) && !defined(__MINGW32__)
	err = (timespec_get(tp, TIME_UTC) == TIME_UTC) ? 0 : EINVAL;
#else
	err = (clock_gettime(CLOCK_REALTIME, tp) == 0) ? 0 : errno;
#endif

	if (err)
		return err;

	if (offset) {
		tp->tv_sec += (offset / 1000);
		tp->tv_nsec += ((offset * 1000000) % 1000000000LL);
		while (tp->tv_nsec > 1000000000LL) {
			tp->tv_sec += 1;
			tp->tv_nsec -= 1000000000LL;
		}
	}

	return 0;
}


/**
 * Get number of milliseconds until the next timer expires
 *
 * @param tmrl Timer-list
 *
 * @return Number of [ms], or 0 if no active timers
 */
uint64_t tmr_next_timeout(struct tmrl *tmrl)
{
	const uint64_t jif = tmr_jiffies();
	const struct tmr *tmr;
	uint64_t ret = 0;

	if (!tmrl)
		return 0;

	mtx_lock(tmrl->lock);

	tmr = list_ledata(tmrl->list.head);
	if (!tmr)
		goto out;

	if (tmr->jfs <= jif)
		ret = 1;
	else
		ret = tmr->jfs - jif;

out:
	mtx_unlock(tmrl->lock);

	return ret;
}


int tmr_status(struct re_printf *pf, void *unused)
{
	struct tmrl *tmrl = re_tmrl_get();
	struct le *le;
	uint32_t n;
	int err = 0;

	(void)unused;

	if (!tmrl)
		return EINVAL;

	mtx_lock(tmrl->lock);

	n = list_count(&tmrl->list);
	if (!n)
		goto out;

	err = re_hprintf(pf, "Timers (%u):\n", n);

	for (le = tmrl->list.head; le; le = le->next) {
		const struct tmr *tmr = le->data;
		err |= re_hprintf(pf, "  %p: th=%p expire=%llums file=%s:%d\n",
				  tmr, tmr->th,
				  (unsigned long long)tmr_get_expire(tmr),
				  tmr->file, tmr->line);
	}

	if (n > 100)
		err |= re_hprintf(pf, "    (Dumped Timers: %u)\n", n);

out:
	mtx_unlock(tmrl->lock);
	return err;
}


/**
 * Print timer debug info to stderr
 */
void tmr_debug(void)
{
	(void)re_fprintf(stderr, "%H", tmr_status, NULL);
}


/**
 * Initialise a timer object
 *
 * @param tmr Timer to initialise
 */
void tmr_init(struct tmr *tmr)
{
	if (!tmr)
		return;

	memset(tmr, 0, sizeof(*tmr));
}


static void tmr_startcont_dbg(struct tmr *tmr, uint64_t delay, bool syncnow,
                   tmr_h *th, void *arg,
		   const char *file, int line)
{
	struct tmrl *tmrl = re_tmrl_get();
	struct le *le;
	mtx_t *lock;

	if (!tmr || !tmrl)
		return;

	/* Prevent multiple cancel race conditions */
	if (!re_atomic_acq(&tmr->active) && !th)
		return;

	re_atomic_rls_set(&tmr->active, false);

	if (!tmr->llock || !tmr->le.list)
		lock = tmrl->lock; /* use current list lock */
	else
		lock = tmr->llock; /* use old list lock for unlinking */

	mtx_lock(lock);

	if (tmr->th)
		list_unlink(&tmr->le);

	mtx_unlock(lock);

	lock = tmrl->lock;

	mtx_lock(lock);

	tmr->th	  = th;
	tmr->arg  = arg;
	tmr->file = file;
	tmr->line = line;
	tmr->llock = tmrl->lock;

	if (!th) {
		tmr->llock = NULL;
		mtx_unlock(lock);
		return;
	}

	if (syncnow)
		tmr->jfs = tmr_jiffies();
	tmr->jfs += delay;

	if (delay == 0) {
		le = list_apply(&tmrl->list, true, inspos_handler_0,
				&tmr->jfs);
		if (le) {
			list_insert_before(&tmrl->list, le, &tmr->le, tmr);
		}
		else {
			list_append(&tmrl->list, &tmr->le, tmr);
		}
	}
	else {
		le = list_apply(&tmrl->list, false, inspos_handler, &tmr->jfs);
		if (le) {
			list_insert_after(&tmrl->list, le, &tmr->le, tmr);
		}
		else {
			list_prepend(&tmrl->list, &tmr->le, tmr);
		}
	}

	re_atomic_rls_set(&tmr->active, true);

	mtx_unlock(lock);
}


void tmr_start_dbg(struct tmr *tmr, uint64_t delay, tmr_h *th, void *arg,
		   const char *file, int line)
{
	tmr_startcont_dbg(tmr, delay, true, th, arg, file, line);
}


void tmr_continue_dbg(struct tmr *tmr, uint64_t delay, tmr_h *th, void *arg,
		   const char *file, int line)
{
	tmr_startcont_dbg(tmr, delay, false, th, arg, file, line);
}


/**
 * Cancel an active timer
 *
 * @param tmr Timer to cancel
 */
void tmr_cancel(struct tmr *tmr)
{
	tmr_start(tmr, 0, NULL, NULL);
}


/**
 * Get the time left until timer expires
 *
 * @param tmr Timer object
 *
 * @return Time in [ms] until expiration
 */
uint64_t tmr_get_expire(const struct tmr *tmr)
{
	uint64_t jfs;

	if (!tmr || !tmr->th)
		return 0;

	jfs = tmr_jiffies();

	return (tmr->jfs > jfs) ? (tmr->jfs - jfs) : 0;
}


/**
 * Get current timer list count
 *
 * @param tmrl Timer list object
 *
 * @return timer list count
 */
uint32_t tmrl_count(struct tmrl *tmrl)
{
	uint32_t c;

	if (!tmrl)
		return 0;

	mtx_lock(tmrl->lock);
	c = list_count(&tmrl->list);
	mtx_unlock(tmrl->lock);

	return c;
}
