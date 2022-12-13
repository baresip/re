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


int unixsock_listen_fd(re_sock_t *fd, const struct sa *local)
{
	int err = 0;

	if (!fd || !local)
		return EINVAL;

	if (sa_af(local) != AF_UNIX || !sa_isset(local, SA_ADDR))
		return EINVAL;

	*fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*fd == RE_BAD_SOCK) {
		err = RE_ERRNO_SOCK;
		goto out;
	}

	err = net_sockopt_blocking_set(*fd, false);
	if (err) {
		DEBUG_WARNING("unix listen: nonblock set: %m\n", err);
		goto out;
	}

	(void)unlink(local->u.un.sun_path);

	if (bind(*fd, &local->u.sa, local->len) < 0) {
		err = RE_ERRNO_SOCK;
		DEBUG_WARNING("bind(): %m (%J)\n", err, local);
		goto out;
	}

	if (listen(*fd, SOMAXCONN) < 0) {
		err = RE_ERRNO_SOCK;
		DEBUG_WARNING("listen(): %m (%J)\n", err, local);
		goto out;
	}

out:
	if (err && *fd != RE_BAD_SOCK)
		(void)close(*fd);

	return err;
}
