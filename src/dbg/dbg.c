/**
 * @file dbg.c  Debug printing
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sys.h>
#include <re_thread.h>


#define DEBUG_MODULE "dbg"
#define DEBUG_LEVEL 0
#include <re_dbg.h>


/** Debug configuration */
static struct {
	uint64_t tick;         /**< Init ticks             */
	int level;             /**< Current debug level    */
	enum dbg_flags flags;  /**< Debug flags            */
	dbg_print_h *ph;       /**< Optional print handler */
	void *arg;             /**< Handler argument       */
} dbg = {
	0,
	DBG_INFO,
	DBG_ANSI,
	NULL,
	NULL,
};

static once_flag flag = ONCE_FLAG_INIT;
static mtx_t mtx;


static void mem_lock_init(void)
{
	mtx_init(&mtx, mtx_plain);
}


static inline void dbg_lock(void)
{
	call_once(&flag, mem_lock_init);
	mtx_lock(&mtx);
}


static inline void dbg_unlock(void)
{
	mtx_unlock(&mtx);
}


/**
 * Initialise debug printing
 *
 * @param level Debug level
 * @param flags Debug flags
 */
void dbg_init(int level, enum dbg_flags flags)
{
	dbg_lock();
	dbg.tick  = tmr_jiffies();
	dbg.level = level;
	dbg.flags = flags;
	dbg_unlock();
}


/**
 * Close debugging
 */
void dbg_close(void)
{
}


/**
 * Set optional debug print handler
 *
 * @param ph  Print handler
 * @param arg Handler argument
 */
void dbg_handler_set(dbg_print_h *ph, void *arg)
{
	dbg_lock();
	dbg.ph  = ph;
	dbg.arg = arg;
	dbg_unlock();
}


/* NOTE: This function should not allocate memory */
static void dbg_vprintf(int level, const char *fmt, va_list ap)
{
	dbg_lock();

	if (level > dbg.level)
		goto out;

	/* Print handler? */
	if (dbg.ph)
		goto out;

	if (dbg.flags & DBG_ANSI) {

		switch (level) {

		case DBG_WARNING:
			(void)re_fprintf(stderr, "\x1b[31m"); /* Red */
			break;

		case DBG_NOTICE:
			(void)re_fprintf(stderr, "\x1b[33m"); /* Yellow */
			break;

		case DBG_INFO:
			(void)re_fprintf(stderr, "\x1b[32m"); /* Green */
			break;

		default:
			break;
		}
	}

	if (dbg.flags & DBG_TIME) {
		const uint64_t ticks = tmr_jiffies();

		if (0 == dbg.tick)
			dbg.tick = tmr_jiffies();

		(void)re_fprintf(stderr, "[%09llu] ", ticks - dbg.tick);
	}

	(void)re_vfprintf(stderr, fmt, ap);

	if (dbg.flags & DBG_ANSI && level < DBG_DEBUG)
		(void)re_fprintf(stderr, "\x1b[;m");
out:
	dbg_unlock();
}


/* Formatted output to print handler */
static void dbg_fmt_vprintf(int level, const char *fmt, va_list ap)
{
	char buf[256];

	dbg_lock();
	int dbg_level   = dbg.level;
	dbg_print_h *ph = dbg.ph;
	void *arg       = dbg.arg;
	dbg_unlock();

	if (level > dbg_level)
		return;

	/* Print handler? */
	if (ph) {
		int len = re_vsnprintf(buf, sizeof(buf), fmt, ap);
		if (len <= 0)
			return;

		ph(level, buf, len, arg);
	}
}


/**
 * Print a formatted debug message
 *
 * @param level Debug level
 * @param fmt   Formatted string
 */
void dbg_printf(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	dbg_vprintf(level, fmt, ap);
	va_end(ap);

	va_start(ap, fmt);
	dbg_fmt_vprintf(level, fmt, ap);
	va_end(ap);
}


/**
 * Get the name of the debug level
 *
 * @param level Debug level
 *
 * @return String with debug level name
 */
const char *dbg_level_str(int level)
{
	switch (level) {

	case DBG_EMERG:   return "EMERGENCY";
	case DBG_ALERT:   return "ALERT";
	case DBG_CRIT:    return "CRITICAL";
	case DBG_ERR:     return "ERROR";
	case DBG_WARNING: return "WARNING";
	case DBG_NOTICE:  return "NOTICE";
	case DBG_INFO:    return "INFO";
	case DBG_DEBUG:   return "DEBUG";
	default:          return "???";
	}
}
