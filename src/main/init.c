/**
 * @file init.c  Main initialisation routine
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_net.h>
#include <re_sys.h>
#include <re_main.h>
#include <re_btrace.h>
#include "main.h"


#ifdef HAVE_SIGNAL
static void signal_handler(int sig)
{
	struct btrace bt;

	btrace(&bt);
	re_fprintf(stderr, "Signal (%d) %H\n", sig, btrace_println, &bt);

	exit(128 + sig);
}
#endif


/**
 * Initialise main library
 *
 * @return 0 if success, errorcode if failure
 */
int libre_init(void)
{
	int err;

#ifdef HAVE_SIGNAL
	(void)signal(SIGSEGV, signal_handler);
	(void)signal(SIGABRT, signal_handler);
	(void)signal(SIGILL, signal_handler);
#endif

#ifdef USE_OPENSSL
	err = openssl_init();
	if (err)
		return err;
#endif

	err = net_sock_init();
	if (err) {
		net_sock_close();
		return err;
	}

	err = re_thread_init();

	return err;
}


/**
 * Close library and free up all resources
 */
void libre_close(void)
{
	(void)fd_setsize(0);
	net_sock_close();
	re_thread_close();
}
