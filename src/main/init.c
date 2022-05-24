/**
 * @file init.c  Main initialisation routine
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_net.h>
#include <re_sys.h>
#include <re_main.h>
#include "main.h"


/**
 * Initialise main library
 *
 * @return 0 if success, errorcode if failure
 */
int libre_init(void)
{
	int err;

#ifdef USE_OPENSSL
	err = openssl_init();
	if (err)
		return err;
#endif

	err = net_sock_init();
	if (err)
		net_sock_close();

	return err;
}


/**
 * Close library and free up all resources
 */
void libre_close(void)
{
	(void)fd_setsize(0);
	net_sock_close();
}
