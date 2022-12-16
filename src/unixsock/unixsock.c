/**
 * @file unixsock/unixsock.c  Unix domain sockets
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <re_types.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_unixsock.h>

#define DEBUG_MODULE "unixsock"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#ifdef WIN32
#define close closesocket
#define unlink _unlink
#endif


/**
 * Listen for incoming connections on a Unix domain socket.
 *
 * @param fdp   Pointer to a re_sock_t variable where the listening socket
 *              file descriptor will be stored.
 * @param sock  Pointer to a struct sa containing the address of the
 *              Unix domain socket.
 *
 * @return 0 if success, otherwise errorcode
 */
int unixsock_listen_fd(re_sock_t *fdp, const struct sa *sock)
{
	int err = 0;
	re_sock_t fd;

	if (!fdp || !sock)
		return EINVAL;

	if (sa_af(sock) != AF_UNIX || !sa_isset(sock, SA_ADDR))
		return EINVAL;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == RE_BAD_SOCK) {
		err = RE_ERRNO_SOCK;
		goto err;
	}

	err = net_sockopt_blocking_set(fd, false);
	if (err) {
		DEBUG_WARNING("unix listen: nonblock set: %m\n", err);
		goto err;
	}

	(void)unlink(sock->u.un.sun_path);

	if (bind(fd, &sock->u.sa, sock->len) < 0) {
		err = RE_ERRNO_SOCK;
		DEBUG_WARNING("bind(): %m (%J)\n", err, sock);
		goto err;
	}

	if (listen(fd, SOMAXCONN) < 0) {
		err = RE_ERRNO_SOCK;
		DEBUG_WARNING("listen(): %m (%J)\n", err, sock);
		goto err;
	}

	*fdp = fd;

	return 0;

err:
	if (fd != RE_BAD_SOCK) {
		(void)close(fd);
	}

	return err;
}
