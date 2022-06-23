/**
 * @file time.c  Time formatting
 *
 * Copyright (C) 2010 Creytiv.com
 */

#define _POSIX_C_SOURCE 200809L
#define __USE_POSIX 1 /**< Use POSIX flag */
#include <time.h>

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
			  dayv[min((unsigned)tm.tm_wday, ARRAY_SIZE(dayv)-1)],
			  tm.tm_mday,
			  monv[min((unsigned)tm.tm_mon, ARRAY_SIZE(monv)-1)],
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
 * @param pf Print function for output
 * @param ts Time in seconds since the Epoch or NULL for current time
 *
 * @return 0 if success, otherwise errorcode
 */
int fmt_timestamp(struct re_printf *pf, void *ts)
{
	int h, m, s;
	uint64_t ms;
#ifdef WIN32
	SYSTEMTIME st;
	GetSystemTime(&st);
	ms = st.wMilliseconds;
	h  = st.wHour;
	m  = st.wMinute;
	s  = st.wSecond;

#else
	struct timespec tspec;
	struct tm tm;

	(void)clock_gettime(CLOCK_REALTIME, &tspec);
	ms = tspec.tv_nsec / 1000000;
	if (!localtime_r(&tspec.tv_sec, &tm))
		return EINVAL;

	h = tm.tm_hour;
	m = tm.tm_min;
	s = tm.tm_sec;
#endif
	(void) ts;

	return re_hprintf(pf, "%02u:%02u:%02u.%03d", h, m, s, ms);
}
