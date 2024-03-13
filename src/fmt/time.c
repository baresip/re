/**
 * @file time.c  Time formatting
 *
 * Copyright (C) 2010 Creytiv.com
 */

#ifdef __MINGW32__
#define _POSIX_C_SOURCE 200809L
#endif

#include <time.h>

#ifdef WIN32
#include <windows.h>
#endif

#include <re_types.h>
#include <re_fmt.h>


static const char *dayv[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

static const char *monv[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};


/**
 * Print Greenwich Mean Time
 *
 * @param pf Print function for output
 * @param ts Time in seconds since the Epoch or NULL for current time
 *
 * @return 0 if success, otherwise errorcode
 */
int fmt_gmtime(struct re_printf *pf, void *ts)
{
	struct tm tm;
	time_t t;

	if (!ts) {
		t  = time(NULL);
		ts = &t;
	}

#ifdef WIN32
	if (gmtime_s(&tm, ts))
		return EINVAL;
#else
	if (!gmtime_r(ts, &tm))
		return EINVAL;
#endif

	return re_hprintf(pf, "%s, %02u %s %u %02u:%02u:%02u GMT",
			dayv[min((unsigned)tm.tm_wday, RE_ARRAY_SIZE(dayv)-1)],
			tm.tm_mday,
			monv[min((unsigned)tm.tm_mon, RE_ARRAY_SIZE(monv)-1)],
			tm.tm_year + 1900,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
}


/**
 * Print the human readable time
 *
 * @param pf       Print function for output
 * @param seconds  Pointer to number of seconds
 *
 * @return 0 if success, otherwise errorcode
 */
int fmt_human_time(struct re_printf *pf, const uint32_t *seconds)
{
	/* max 136 years */
	const uint32_t sec  = *seconds%60;
	const uint32_t min  = *seconds/60%60;
	const uint32_t hrs  = *seconds/60/60%24;
	const uint32_t days = *seconds/60/60/24;
	int err = 0;

	if (days)
		err |= re_hprintf(pf, "%u day%s ", days, 1==days?"":"s");

	if (hrs) {
		err |= re_hprintf(pf, "%u hour%s ", hrs, 1==hrs?"":"s");
	}

	if (min) {
		err |= re_hprintf(pf, "%u min%s ", min, 1==min?"":"s");
	}

	if (sec) {
		err |= re_hprintf(pf, "%u sec%s", sec, 1==sec?"":"s");
	}

	return err;
}


/**
 * Print local time stamp including milli seconds relative to user's timezone
 *
 * @param pf  Print function for output
 * @param arg Not used
 *
 * @return 0 if success, otherwise errorcode
 */
int fmt_timestamp(struct re_printf *pf, void *arg)
{
	int h, m, s;
	uint64_t ms;
#ifdef WIN32
	SYSTEMTIME st;

	GetSystemTime(&st);

	h  = st.wHour;
	m  = st.wMinute;
	s  = st.wSecond;
	ms = st.wMilliseconds;
#else
	struct timespec tspec;
	struct tm tm;

	(void)clock_gettime(CLOCK_REALTIME, &tspec);
	if (!localtime_r(&tspec.tv_sec, &tm))
		return EINVAL;

	h  = tm.tm_hour;
	m  = tm.tm_min;
	s  = tm.tm_sec;
	ms = tspec.tv_nsec / 1000000;
#endif
	(void)arg;

	return re_hprintf(pf, "%02u:%02u:%02u.%03llu", h, m, s, ms);
}


/**
 * Print local time stamp including microseconds relative to user's timezone
 *
 * @param pf  Print function for output
 * @param arg Not used
 *
 * @return 0 if success, otherwise errorcode
 */
int fmt_timestamp_us(struct re_printf *pf, void *arg)
{
	int h, m, s;
	uint64_t us;
	struct timespec tspec;
	struct tm tm = {0};

#if defined(WIN32) && !defined(__MINGW32__)
	timespec_get(&tspec, TIME_UTC);
	int err = localtime_s(&tm, &tspec.tv_sec);
	if (err)
		return err;
#else
	(void)clock_gettime(CLOCK_REALTIME, &tspec);
	if (!localtime_r(&tspec.tv_sec, &tm))
		return EINVAL;
#endif

	h  = tm.tm_hour;
	m  = tm.tm_min;
	s  = tm.tm_sec;
	us = tspec.tv_nsec / 1000;
	(void)arg;

	return re_hprintf(pf, "%02u:%02u:%02u.%06llu", h, m, s, us);
}
