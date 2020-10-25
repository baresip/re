/**
 * @file sleep.c  System sleep functions
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_sys.h>
#ifdef WIN32
#include <windows.h>
#endif
#ifdef HAVE_UNISTD_H
#define _BSD_SOURCE 1
#include <unistd.h>
#endif
#ifdef HAVE_SELECT_H
#include <sys/select.h>
#endif


/**
 * Blocking sleep for [us] number of microseconds
 *
 * @param us Number of microseconds to sleep
 */
void sys_usleep(unsigned int us)
{
	if (!us)
		return;

#ifdef WIN32
	HANDLE timer;
	LARGE_INTEGER ft;

	ft.QuadPart = -(10 * (int64_t)us);

	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
	WaitForSingleObject(timer, INFINITE);
	CloseHandle(timer);
#elif defined(HAVE_SELECT)
	do {
		struct timeval tv;

		tv.tv_sec  = us / 1000000;
		tv.tv_usec = us % 1000000;

		(void)select(0, NULL, NULL, NULL, &tv);
	} while (0);
#else
	(void)usleep(us);
#endif
}
