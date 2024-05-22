/**
 * @file openssl.c  OpenSSL initialisation and multi-threading routines
 *
 * Copyright (C) 2010 Creytiv.com
 */
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#include <re_types.h>
#include "main.h"


#ifdef SIGPIPE
static void sigpipe_handler(int x)
{
	(void)x;
	(void)signal(SIGPIPE, sigpipe_handler);
}
#endif


int openssl_init(void)
{
#ifdef SIGPIPE
	(void)signal(SIGPIPE, sigpipe_handler);
#endif

	return 0;
}
