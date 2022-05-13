/**
 * @file openssl.c  OpenSSL initialisation and multi-threading routines
 *
 * Copyright (C) 2010 Creytiv.com
 */
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#include <openssl/ssl.h>
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
	int err;

#ifdef SIGPIPE
	(void)signal(SIGPIPE, sigpipe_handler);
#endif

	err = OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL);
	if (!err)
		return !err;

	return 0;
}
