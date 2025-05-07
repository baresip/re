/**
 * @file ntp.c  NTP Routines
 *
 * Copyright (C) 2010 Creytiv.com
 */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_rtp.h>
#include <re_tmr.h>
#include "rtcp.h"


/*
 * Unix time:  seconds relative to 0h January 1, 1970
 * NTP time:   seconds relative to 0h UTC on 1 January 1900
 */


/* Number of seconds from 1900 to 1970 */
#define UNIX_NTP_OFFSET 0x83aa7e80


/**
 * Convert from Unix time to NTP time
 *
 * @param ntp NTP time to convert to (output)
 * @param tv  Unix time to convert from (input)
 */
void unix2ntp(struct rtp_ntp_time *ntp, const struct timeval *tv)
{
	ntp->hi = (uint32_t)(tv->tv_sec + UNIX_NTP_OFFSET);
	ntp->lo = (uint32_t)((double)tv->tv_usec*(double)(1LL<<32)*1.0e-6);
}


/**
 * Obtain the current wallclock time in NTP and jiffies formats
 *
 * @param ntp NTP time
 * @param jfs_rt Microseconds since UNIX epoch. Optional, may be NULL.
 */
void ntp_time_get(struct rtp_ntp_time *ntp, uint64_t *jfs_rt)
{
#if defined(WIN32)
	/* timeval::tv_sec on Windows is 32-bit, and it doesn't
	 * define suseconds_t */
	typedef long tv_sec_t;
	typedef long tv_usec_t;
#else
	typedef time_t tv_sec_t;
	typedef suseconds_t tv_usec_t;
#endif

	struct timeval tv;
	uint64_t jfs = tmr_jiffies_rt_usec();
	if (jfs_rt)
		*jfs_rt = jfs;

	tv.tv_sec  = (tv_sec_t)(jfs / 1000000u);
	tv.tv_usec = (tv_usec_t)(jfs % 1000000u);
	unix2ntp(ntp, &tv);
}


/**
 * Convert NTP time to middle 32-bits (compact representation)
 *
 * @param ntp NTP time
 *
 * @return NTP time in compact representation
 */
uint32_t ntp_compact(const struct rtp_ntp_time *ntp)
{
	return ntp ? ((ntp->hi & 0xffff) << 16 | (ntp->lo >> 16)) : 0;
}


/**
 * Convert NTP compact representation to microseconds
 *
 * @param ntpc  NTP time in compact representation
 *
 * @return NTP time in microseconds
 */
uint64_t ntp_compact2us(uint32_t ntpc)
{
	const uint32_t hi = (ntpc >> 16) & 0xffff;
	const uint32_t lo = (ntpc & 0xffff) << 16;

	return (1000000ULL * hi) + ((1000000ULL * lo) >> 32);
}
