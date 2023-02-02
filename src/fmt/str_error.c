/**
 * @file str_error.c System error messages
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>


/**
 * Look up an error message string corresponding to an error number.
 *
 * @param errnum Error Code
 * @param buf    Buffer for storing error message
 * @param sz     Buffer size
 *
 * @return Error message string
 */
const char *str_error(int errnum, char *buf, size_t sz)
{
	const char *s;
	char msg[128] = {0};

	if (!buf || !sz)
		return NULL;

#ifdef HAVE_STRERROR_R

#ifdef __GLIBC__
	s = strerror_r(errnum, msg, sizeof(msg));
#else
	(void)strerror_r(errnum, msg, sizeof(msg));
	s = msg;
#endif

#elif defined (WIN32)
	(void)strerror_s(msg, sizeof(msg), errnum);
	s = msg;
#else
	/* fallback */
	(void)errnum;
	s = "unknown error";
#endif

	re_snprintf(buf, sz, "%s [%d]", s, errnum);

	return buf;
}
