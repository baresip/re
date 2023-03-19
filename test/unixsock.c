/**
 * @file src/unixsock.c Unix domain sockets
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <re.h>
#include "test.h"
#ifdef WIN32
#define unlink _unlink
#endif

#define DEBUG_MODULE "unixsock"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#if HAVE_UNIXSOCK
static void http_req_handler(struct http_conn *conn,
			     const struct http_msg *msg, void *arg)
{
	(void)conn;
	(void)msg;
	(void)arg;
}
#endif


int test_unixsock(void)
{
#if HAVE_UNIXSOCK
	struct sa srv;
	re_sock_t fd = RE_BAD_SOCK;
	struct http_sock *sock;
	int err;
	char filename[32];
	char socket[128];

	rand_str(filename, sizeof(filename));
	re_snprintf(socket, sizeof(socket), "unix:http_%s.sock", filename);

	err = sa_set_str(&srv, socket, 0);
	TEST_ERR(err);

	err = unixsock_listen_fd(&fd, &srv);
	TEST_ERR(err);

	err = http_listen_fd(&sock, fd, http_req_handler, NULL);
	TEST_ERR(err);

	mem_deref(sock);

	err = unlink(&socket[5]);
	TEST_ERR(err);

out:
	if (err)
		(void)unlink(&socket[5]);
	return err;
#else
	return ESKIPPED;
#endif
}
