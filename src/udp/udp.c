/**
 * @file udp.c  User Datagram Protocol
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#if !defined(WIN32)
#include <netdb.h>
#endif
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_thread.h>
#include <re_net.h>
#include <re_main.h>
#include <re_sa.h>
#include <re_udp.h>
#ifdef WIN32
#ifndef HAVE_QOS_FLOWID
typedef UINT32 QOS_FLOWID;
#endif

#ifndef HAVE_PQOS_FLOWID
typedef UINT32 *PQOS_FLOWID;
#endif

#include <qos2.h>

#ifndef QOS_NON_ADAPTIVE_FLOW
#define QOS_NON_ADAPTIVE_FLOW 0x00000002
#endif
#endif /*WIN32*/

#define DEBUG_MODULE "udp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/** Platform independent buffer type cast */
#ifdef WIN32
#define BUF_CAST (char *)
#define SIZ_CAST (int)
#define close closesocket
#else
#define BUF_CAST
#define SIZ_CAST
#endif


enum {
	UDP_RXSZ_DEFAULT = 8192
};


/** Defines a UDP socket */
struct udp_sock {
	struct list helpers; /**< List of UDP Helpers         */
	udp_send_h *sendh;
	udp_recv_h *rh;      /**< Receive handler             */
	udp_error_h *eh;     /**< Error handler               */
	void *arg;           /**< Handler argument            */
	struct re_fhs *fhs;
	re_sock_t fd;        /**< Socket file descriptor      */
	bool conn;           /**< Connected socket flag       */
	size_t rxsz;         /**< Maximum receive chunk size  */
	size_t rx_presz;     /**< Preallocated rx buffer size */
#ifdef WIN32
	HANDLE qos;          /**< QOS subsystem handle        */
	QOS_FLOWID qos_id;   /**< QOS flow id                 */
#endif
	mtx_t *lock;         /**< A lock for helpers list     */
};

/** Defines a UDP helper */
struct udp_helper {
	struct le le;
	struct list calll;
	int layer;
	udp_helper_send_h *sendh;
	udp_helper_recv_h *recvh;
	mtx_t *lock;         /**< A lock for the helpers list */
	cnd_t wait;
	void *arg;
	bool closing;
	bool wait_initialized;
};

struct udp_helper_call {
	struct le le;
	struct udp_helper *helper;
	thrd_t thread;
};


static void dummy_udp_recv_handler(const struct sa *src,
				   struct mbuf *mb, void *arg)
{
	(void)src;
	(void)mb;
	(void)arg;
}


static bool helper_send_handler(int *err, struct sa *dst,
				struct mbuf *mb, void *arg)
{
	(void)err;
	(void)dst;
	(void)mb;
	(void)arg;
	return false;
}


static bool helper_recv_handler(struct sa *src,
				struct mbuf *mb, void *arg)
{
	(void)src;
	(void)mb;
	(void)arg;
	return false;
}

static struct udp_helper *helper_reserve(struct le *le, bool reverse,
					 struct udp_helper_call *call)
{
	while (le) {
		struct udp_helper *uh = le->data;

		le = reverse ? le->prev : le->next;
		if (uh->closing)
			continue;

		call->helper = uh;
		call->thread = thrd_current();
		mem_ref(uh);
		list_append(&uh->calll, &call->le, call);
		return uh;
	}

	call->helper = NULL;
	return NULL;
}


static struct udp_helper *helper_release(struct udp_helper_call *call)
{
	struct udp_helper *uh = call->helper;

	if (!uh)
		return NULL;

	list_unlink(&call->le);
	call->helper = NULL;
	if (uh->closing && list_isempty(&uh->calll))
		cnd_broadcast(&uh->wait);

	return uh;
}


static bool helper_called_on_current_thread(const struct udp_helper *uh)
{
	for (struct le *le = uh->calll.head; le; le = le->next) {
		const struct udp_helper_call *call = le->data;

		if (thrd_equal(call->thread, thrd_current()))
			return true;
	}

	return false;
}


static bool udp_helpers_recv(struct udp_sock *us, struct sa *src,
			     struct mbuf *mb, struct udp_helper *boundary)
{
	struct udp_helper_call callv[2];
	struct udp_helper_call *call = &callv[0];
	struct udp_helper *uh;

	memset(callv, 0, sizeof(callv));
	mtx_lock(us->lock);
	if (boundary &&
	    (boundary->closing || boundary->le.list != &us->helpers)) {
		mtx_unlock(us->lock);
		return true;
	}
	uh = helper_reserve(boundary ? boundary->le.next : us->helpers.head,
			    false, call);
	mtx_unlock(us->lock);

	while (uh) {
		struct udp_helper_call *next =
			call == &callv[0] ? &callv[1] : &callv[0];
		bool handled;

		handled = uh->recvh(src, mb, uh->arg);

		mtx_lock(us->lock);
		if (handled) {
			struct udp_helper *released = helper_release(call);

			mtx_unlock(us->lock);
			mem_deref(released);
			return true;
		}
		uh = helper_reserve(uh->le.next, false, next);
		struct udp_helper *released = helper_release(call);

		mtx_unlock(us->lock);
		mem_deref(released);
		call = next;
	}

	return false;
}


static void udp_destructor(void *data)
{
	struct udp_sock *us = data;

	list_flush(&us->helpers);

	mem_deref(us->lock);

#ifdef WIN32
	if (us->qos && us->qos_id)
		(void)QOSRemoveSocketFromFlow(us->qos, 0, us->qos_id, 0);
	if (us->qos)
		(void)QOSCloseHandle(us->qos);
#endif

	if (RE_BAD_SOCK != us->fd) {
		us->fhs = fd_close(us->fhs);
		(void)close(us->fd);
	}
}


static void udp_read(struct udp_sock *us, re_sock_t fd)
{
	struct mbuf *mb = mbuf_alloc(us->rxsz);
	struct sa src;
	int err = 0;
	ssize_t n;

	if (!mb)
		return;
	mem_ref(us);

	src.len = sizeof(src.u);
	n = recvfrom(fd, BUF_CAST mb->buf + us->rx_presz,
		     SIZ_CAST (mb->size - us->rx_presz), 0,
		     &src.u.sa, &src.len);
	if (n < 0) {
		err = RE_ERRNO_SOCK;

		if (EAGAIN == err)
			goto out;

#ifdef WIN32
		if (WSAEWOULDBLOCK == err)
			goto out;
#endif

#if defined (EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
		if (EWOULDBLOCK == err)
			goto out;
#endif
		if (us->eh)
			us->eh(err, us->arg);

		goto out;
	}

	mb->pos = us->rx_presz;
	mb->end = n + us->rx_presz;

	(void)mbuf_resize(mb, mb->end);

	if (udp_helpers_recv(us, &src, mb, NULL))
		goto out;

	us->rh(&src, mb, us->arg);

 out:
	mem_deref(mb);
	mem_deref(us);
}


static void udp_read_handler(int flags, void *arg)
{
	struct udp_sock *us = arg;

	(void)flags;

	udp_read(us, us->fd);
}


static int udp_alloc(struct udp_sock **usp)
{
	int err;
	struct udp_sock *us;

	if (!usp)
		return EINVAL;

	us = mem_zalloc(sizeof(*us), NULL);
	if (!us)
		return ENOMEM;

	list_init(&us->helpers);

	us->fhs	 = NULL;
	us->fd	 = RE_BAD_SOCK;

	err = mutex_alloc(&us->lock);
	if (err) {
		mem_deref(us);
		return err;
	}

	mem_destructor(us, udp_destructor);

	*usp = us;

	return 0;
}


/**
 * Create and listen on a UDP Socket
 *
 * @param usp   Pointer to returned UDP Socket
 * @param local Local network address
 * @param rh    Receive handler
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_listen(struct udp_sock **usp, const struct sa *local,
	       udp_recv_h *rh, void *arg)
{
	struct addrinfo hints, *res = NULL, *r;
	struct udp_sock *us;
	char addr[64] = {0};
	char serv[6] = "0";
	int af, error, err = 0;

	if (!usp)
		return EINVAL;

	err = udp_alloc(&us);
	if (err)
		return err;

	if (local) {
		af = sa_af(local);
		(void)re_snprintf(addr, sizeof(addr), "%H",
				  sa_print_addr, local);
		(void)re_snprintf(serv, sizeof(serv), "%u", sa_port(local));
	}
	else {
		af = AF_UNSPEC;
	}

	memset(&hints, 0, sizeof(hints));
	/* set-up hints structure */
	hints.ai_family   = af;
	hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	error = getaddrinfo(local ? addr : NULL, serv, &hints, &res);
	if (error) {
#ifdef WIN32
		DEBUG_WARNING("listen: getaddrinfo: wsaerr=%d\n",
			      WSAGetLastError());
#endif
		DEBUG_WARNING("listen: getaddrinfo: %s:%s (%s)\n",
			      addr, serv, gai_strerror(error));
		err = EADDRNOTAVAIL;
		goto out;
	}

	for (r = res; r; r = r->ai_next) {
		re_sock_t fd;

		if (us->fd != RE_BAD_SOCK)
			continue;

		DEBUG_INFO("listen: for: af=%d addr=%j\n",
			   r->ai_family, r->ai_addr);

		fd = socket(r->ai_family, SOCK_DGRAM, IPPROTO_UDP);
		if (fd == RE_BAD_SOCK) {
			err = RE_ERRNO_SOCK;
			continue;
		}

		err = net_sockopt_blocking_set(fd, false);
		if (err) {
			DEBUG_WARNING("udp listen: nonblock set: %m\n", err);
			(void)close(fd);
			continue;
		}

		/* use dual socket */
		if (r->ai_family == AF_INET6)
			(void)net_sockopt_v6only(fd, false);

		if (bind(fd, r->ai_addr, SIZ_CAST r->ai_addrlen) < 0) {
			err = RE_ERRNO_SOCK;
			DEBUG_INFO("listen: bind(): %m (%J)\n", err, local);
			(void)close(fd);
			continue;
		}

		/* OK */
		us->fd = fd;
		break;
	}

	freeaddrinfo(res);

	/* We must have at least one socket */
	if (RE_BAD_SOCK == us->fd) {
		if (0 == err)
			err = EADDRNOTAVAIL;
		goto out;
	}

	err = udp_thread_attach(us);
	if (err)
		goto out;

	us->rh   = rh ? rh : dummy_udp_recv_handler;
	us->arg  = arg;
	us->rxsz = UDP_RXSZ_DEFAULT;

 out:
	if (err)
		mem_deref(us);
	else
		*usp = us;

	return err;
}


int udp_alloc_sockless(struct udp_sock **usp,
		       udp_send_h *sendh, udp_recv_h *recvh, void *arg)
{
	struct udp_sock *us;
	int err;

	if (!usp || !sendh)
		return EINVAL;

	err = udp_alloc(&us);
	if (err)
		return err;

	us->sendh = sendh;
	us->rh    = recvh ? recvh : dummy_udp_recv_handler;
	us->arg   = arg;
	us->rxsz  = UDP_RXSZ_DEFAULT;

	*usp = us;

	return 0;
}


int udp_alloc_fd(struct udp_sock **usp, re_sock_t fd,
		  udp_recv_h *recvh, void *arg)
{
	struct udp_sock *us;
	int err;

	if (!usp || fd == RE_BAD_SOCK)
		return EINVAL;

	err = udp_alloc(&us);
	if (err)
		return err;

	us->fd   = fd;
	us->rh   = recvh ? recvh : dummy_udp_recv_handler;
	us->arg  = arg;
	us->rxsz = UDP_RXSZ_DEFAULT;

	*usp = us;
	return 0;
}


/**
 * Create an UDP socket with specified address family.
 *
 * @param usp   Pointer to returned UDP Socket
 * @param af    Address family AF_INET or AF_INET6
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_open(struct udp_sock **usp, int af)
{
	struct udp_sock *us;
	int err = 0;
	re_sock_t fd;

	if (!usp)
		return EINVAL;

	err = udp_alloc(&us);
	if (err)
		return err;

	fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == RE_BAD_SOCK) {
		err = RE_ERRNO_SOCK;
		goto out;
	}

	us->fd = fd;

 out:
	if (err)
		mem_deref(us);
	else
		*usp = us;

	return err;
}


/**
 * Connect a UDP Socket to a specific peer.
 * When connected, this UDP Socket will only receive data from that peer.
 *
 * @param us   UDP Socket
 * @param peer Peer network address
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_connect(struct udp_sock *us, const struct sa *peer)
{
	if (!us || !peer)
		return EINVAL;

	if (0 != connect(us->fd, &peer->u.sa, peer->len))
		return RE_ERRNO_SOCK;

	us->conn = true;

	return 0;
}


static int udp_send_internal(struct udp_sock *us, const struct sa *dst,
			     struct mbuf *mb, struct udp_helper *boundary)
{
	struct udp_helper_call callv[2];
	struct udp_helper_call *call = &callv[0];
	struct udp_helper *uh;
	struct sa hdst;
	int err = 0;
	re_sock_t fd = us->fd;

	mem_ref(us);
	memset(callv, 0, sizeof(callv));
	mtx_lock(us->lock);
	if (boundary &&
	    (boundary->closing || boundary->le.list != &us->helpers)) {
		mtx_unlock(us->lock);
		err = ENOTCONN;
		goto out;
	}
	uh = helper_reserve(boundary ? boundary->le.prev : us->helpers.tail,
			    true, call);
	mtx_unlock(us->lock);

	/* call helpers in reverse order */
	while (uh) {
		struct udp_helper_call *next =
			call == &callv[0] ? &callv[1] : &callv[0];
		bool handled;

		if (dst != &hdst) {
			sa_cpy(&hdst, dst);
			dst = &hdst;
		}

		handled = uh->sendh(&err, &hdst, mb, uh->arg);

		mtx_lock(us->lock);
		if (handled || err) {
			struct udp_helper *released = helper_release(call);

			mtx_unlock(us->lock);
			mem_deref(released);
			goto out;
		}
		uh = helper_reserve(uh->le.prev, true, next);
		struct udp_helper *released = helper_release(call);

		mtx_unlock(us->lock);
		mem_deref(released);
		call = next;
	}

	/* external send handler */
	if (us->sendh) {
		err = us->sendh(dst, mb, us->arg);
		goto out;
	}

	/* Connected socket? */
	if (us->conn) {
		if (send(fd, BUF_CAST mb->buf + mb->pos,
			 SIZ_CAST (mb->end - mb->pos),
			 0) < 0) {
			err = RE_ERRNO_SOCK;
			goto out;
		}
	}
	else {
		if (sendto(fd, BUF_CAST mb->buf + mb->pos,
			   SIZ_CAST (mb->end - mb->pos),
			   0, &dst->u.sa, dst->len) < 0) {
			err = RE_ERRNO_SOCK;
			goto out;
		}
	}

out:
	mem_deref(us);
	return err;
}


/**
 * Send a UDP Datagram to a peer
 *
 * @param us  UDP Socket
 * @param dst Destination network address
 * @param mb  Buffer to send
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_send(struct udp_sock *us, const struct sa *dst, struct mbuf *mb)
{
	if (!us || !dst || !mb)
		return EINVAL;

	return udp_send_internal(us, dst, mb, NULL);
}


/**
 * Get the local network address on the UDP Socket
 *
 * @param us    UDP Socket
 * @param local The returned local network address
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_local_get(const struct udp_sock *us, struct sa *local)
{
	if (!us || !local)
		return EINVAL;

	local->len = sizeof(local->u);

	if (0 == getsockname(us->fd, &local->u.sa, &local->len))
		return 0;

	return RE_ERRNO_SOCK;
}


/**
 * Set socket options on the UDP Socket
 *
 * @param us      UDP Socket
 * @param level   Socket level
 * @param optname Option name
 * @param optval  Option value
 * @param optlen  Option length
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_setsockopt(struct udp_sock *us, int level, int optname,
		   const void *optval, uint32_t optlen)
{
	int err = 0;

	if (!us)
		return EINVAL;

	if (RE_BAD_SOCK != us->fd) {
		if (0 != setsockopt(us->fd, level, optname,
				    BUF_CAST optval, optlen))
			err |= RE_ERRNO_SOCK;
	}

	return err;
}


/**
 * Set the send/receive buffer size on a UDP Socket
 *
 * @param us   UDP Socket
 * @param size Buffer size in bytes
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_sockbuf_set(struct udp_sock *us, int size)
{
	int err = 0;

	if (!us)
		return EINVAL;

	err |= udp_setsockopt(us, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	err |= udp_setsockopt(us, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));

	return err;
}


int udp_settos(struct udp_sock *us, uint8_t tos)
{
	int err = 0;
	int v = tos;
	struct sa sa;
#ifdef WIN32
	QOS_VERSION qos_version = { 1 , 0 };
	QOS_TRAFFIC_TYPE qos_type = QOSTrafficTypeBestEffort;
	if (tos >= 32) /* >= DSCP_CS1 */
		qos_type = QOSTrafficTypeBackground;
	if (tos >= 40) /* >= DSCP_AF11 */
		qos_type = QOSTrafficTypeExcellentEffort;
	if (tos >= 136) /* >= DSCP_AF41 */
		qos_type = QOSTrafficTypeAudioVideo;
	if (tos >= 184) /* >= DSCP_EF */
		qos_type = QOSTrafficTypeVoice;
	if (tos >= 224) /* >= DSCP_CS7 */
		qos_type = QOSTrafficTypeControl;
#endif
	if (!us)
		return EINVAL;

#ifdef WIN32
	err = QOSCreateHandle(&qos_version, &us->qos);
	if (!err)
		return GetLastError();

	us->qos_id = 0;
	if (RE_BAD_SOCK != us->fd) {
		err = QOSAddSocketToFlow(us->qos, us->fd, NULL,
				qos_type,
				QOS_NON_ADAPTIVE_FLOW,
				&us->qos_id);
		if (!err)
			return WSAGetLastError();
	}
#endif
	err = udp_local_get(us, &sa);
	if (err)
		return err;

	if (sa_af(&sa) == AF_INET) {
		err = udp_setsockopt(us, IPPROTO_IP, IP_TOS, &v, sizeof(v));
	}
#if defined(IPV6_TCLASS) && !defined(WIN32)
	else if (sa_af(&sa) == AF_INET6) {
		err = udp_setsockopt(us, IPPROTO_IPV6, IPV6_TCLASS, &v,
				     sizeof(v));
	}
#endif

	return err;
}


/**
 * Set the maximum receive chunk size on a UDP Socket
 *
 * @param us   UDP Socket
 * @param rxsz Maximum receive chunk size
 */
void udp_rxsz_set(struct udp_sock *us, size_t rxsz)
{
	if (!us)
		return;

	us->rxsz = rxsz;
}


/**
 * Set preallocated space on receive buffer.
 *
 * @param us       UDP Socket
 * @param rx_presz Size of preallocate space.
 */
void udp_rxbuf_presz_set(struct udp_sock *us, size_t rx_presz)
{
	if (!us)
		return;

	us->rx_presz = rx_presz;
}


/**
 * Set receive handler on a UDP Socket
 *
 * @param us  UDP Socket
 * @param rh  Receive handler
 * @param arg Handler argument
 */
void udp_handler_set(struct udp_sock *us, udp_recv_h *rh, void *arg)
{
	if (!us)
		return;

	us->rh  = rh ? rh : dummy_udp_recv_handler;
	us->arg = arg;
}


/**
 * Set error handler on a UDP Socket
 *
 * @param us  UDP Socket
 * @param eh  Error handler
 */
void udp_error_handler_set(struct udp_sock *us, udp_error_h *eh)
{
	if (!us)
		return;

	us->eh = eh;
}


/**
 * Get the File Descriptor from a UDP Socket
 *
 * @param us  UDP Socket
 *
 * @return File Descriptor, or RE_BAD_SOCK for errors
 */
re_sock_t udp_sock_fd(const struct udp_sock *us)
{
	return us ? us->fd : RE_BAD_SOCK;
}


/**
 * Attach the current thread to the UDP Socket
 *
 * @param us UDP Socket
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_thread_attach(struct udp_sock *us)
{
	int err = 0;

	if (!us)
		return EINVAL;

	if (RE_BAD_SOCK != us->fd) {
		err = fd_listen(&us->fhs, us->fd, FD_READ, udp_read_handler,
				us);
		if (err)
			goto out;
	}

 out:
	if (err)
		udp_thread_detach(us);

	return err;
}


/**
 * Detach the current thread from the UDP Socket
 *
 * @param us UDP Socket
 */
void udp_thread_detach(struct udp_sock *us)
{
	if (!us)
		return;

	if (RE_BAD_SOCK != us->fd)
		us->fhs = fd_close(us->fhs);
}


static void helper_destructor(void *data)
{
	struct udp_helper *uh = data;
	int err;

	err = udp_helper_quiesce(uh);
	if (err)
		DEBUG_WARNING("helper destroyed from its own callback\n");
	if (uh->wait_initialized)
		cnd_destroy(&uh->wait);
}


static bool sort_handler(struct le *le1, struct le *le2, void *arg)
{
	struct udp_helper *uh1 = le1->data, *uh2 = le2->data;
	(void)arg;

	return uh1->layer <= uh2->layer;
}


/**
 * Register a UDP protocol stack helper
 *
 * @param uhp   Pointer to allocated UDP helper object
 * @param us    UDP socket
 * @param layer Layer number; higher number means higher up in stack
 * @param sh    Send handler
 * @param rh    Receive handler
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_register_helper(struct udp_helper **uhp, struct udp_sock *us,
			int layer,
			udp_helper_send_h *sh, udp_helper_recv_h *rh,
			void *arg)
{
	struct udp_helper *uh;

	if (!us)
		return EINVAL;

	uh = mem_zalloc(sizeof(*uh), helper_destructor);
	if (!uh)
		return ENOMEM;

	list_init(&uh->calll);
	if (cnd_init(&uh->wait) != thrd_success) {
		mem_destructor(uh, NULL);
		mem_deref(uh);
		return ENOMEM;
	}
	uh->wait_initialized = true;

	mtx_lock(us->lock);
	list_append(&us->helpers, &uh->le, uh);

	uh->lock  = us->lock;
	uh->layer = layer;
	uh->sendh = sh ? sh : helper_send_handler;
	uh->recvh = rh ? rh : helper_recv_handler;
	uh->arg   = arg;

	list_sort(&us->helpers, sort_handler, NULL);

	if (uhp)
		*uhp = uh;

	mtx_unlock(us->lock);
	return 0;
}


/**
 * Stop a UDP helper and wait for all of its callbacks to return.
 *
 * No new callback can start after this function marks the helper as closing.
 * The caller may release the callback argument and helper after this function
 * succeeds. Calling it from one of the helper's own callbacks returns
 * EDEADLK without changing the helper state.
 *
 * @param uh UDP helper
 *
 * @return 0 if quiesced, otherwise an errorcode
 */
int udp_helper_quiesce(struct udp_helper *uh)
{
	int err = 0;

	if (!uh)
		return EINVAL;

	mtx_lock(uh->lock);
	if (!list_isempty(&uh->calll) &&
	    helper_called_on_current_thread(uh)) {
		err = EDEADLK;
		goto out;
	}
	uh->closing = true;
	while (!list_isempty(&uh->calll)) {
		if (cnd_wait(&uh->wait, uh->lock) != thrd_success) {
			err = EPROTO;
			goto out;
		}
	}
	list_unlink(&uh->le);

out:
	mtx_unlock(uh->lock);
	return err;
}


/**
 * Send a UDP Datagram to a remote peer bypassing this helper and
 * the helpers above it.
 *
 * @param us  UDP Socket
 * @param dst Destination network address
 * @param mb  Buffer to send
 * @param uh  UDP Helper
 *
 * @return 0 if success, otherwise errorcode
 */
int udp_send_helper(struct udp_sock *us, const struct sa *dst,
		    struct mbuf *mb, struct udp_helper *uh)
{
	if (!us || !dst || !mb || !uh)
		return EINVAL;

	return udp_send_internal(us, dst, mb, uh);
}


/**
 * Receive a UDP Datagram on this UDP helper layer.
 *
 * @param us  UDP Socket
 * @param src Source network address
 * @param mb  Buffer to receive
 * @param uhx UDP Helper
 */
void udp_recv_helper(struct udp_sock *us, const struct sa *src,
		     struct mbuf *mb, struct udp_helper *uhx)
{
	struct sa hsrc;

	if (!us || !src || !mb)
		return;

	mem_ref(us);
	sa_cpy(&hsrc, src);
	if (udp_helpers_recv(us, &hsrc, mb, uhx))
		goto out;

	us->rh(&hsrc, mb, us->arg);

out:
	mem_deref(us);
}


/**
 * Find a UDP-helper on a UDP socket
 *
 * @param us    UDP socket
 * @param layer Layer number
 *
 * @return UDP-helper if found, NULL if not found
 */
struct udp_helper *udp_helper_find(const struct udp_sock *us, int layer)
{
	struct le *le;

	if (!us)
		return NULL;

	mtx_lock(us->lock);
	for (le = us->helpers.head; le; le = le->next) {
		struct udp_helper *uh = le->data;

		if (!uh->closing && layer == uh->layer) {
			mtx_unlock(us->lock);
			return uh;
		}
	}
	mtx_unlock(us->lock);

	return NULL;
}


/**
 * Flush a given UDP socket
 *
 * @param us UDP socket
 */
void udp_flush(const struct udp_sock *us)
{
	if (!us)
		return;

	if (RE_BAD_SOCK != us->fd) {
		uint8_t buf[4096];

		while (recvfrom(us->fd, BUF_CAST buf, sizeof(buf),
				0, NULL, 0) > 0)
			;
	}
}


/**
 * Receive a UDP Datagram on this UDP socket. All helpers are processed.
 *
 * @param us  UDP Socket
 * @param src Source network address
 * @param mb  Buffer to receive
 */
void udp_recv_packet(struct udp_sock *us, const struct sa *src,
		     struct mbuf *mb)
{
	udp_recv_helper(us, src, mb, NULL);
}
