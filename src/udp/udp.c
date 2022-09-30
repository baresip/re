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
#define __USE_POSIX 1  /**< Use POSIX flag */
#define __USE_XOPEN2K 1/**< Use POSIX.1:2001 code */
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
#include <re_net.h>
#include <re_main.h>
#include <re_sa.h>
#include <re_udp.h>
#ifdef WIN32
#if !defined(_MSC_VER)
typedef UINT32 QOS_FLOWID, *PQOS_FLOWID;
#ifndef QOS_NON_ADAPTIVE_FLOW
#define QOS_NON_ADAPTIVE_FLOW 0x00000002
#endif
#endif /*!_MSC_VER*/
#include <qos2.h>
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
	udp_recv_h *rh;      /**< Receive handler             */
	udp_error_h *eh;     /**< Error handler               */
	void *arg;           /**< Handler argument            */
	re_sock_t fd;        /**< Socket file descriptor      */
	re_sock_t fd6;       /**< IPv6 socket file descriptor */
	bool conn;           /**< Connected socket flag       */
	size_t rxsz;         /**< Maximum receive chunk size  */
	size_t rx_presz;     /**< Preallocated rx buffer size */
#ifdef WIN32
	HANDLE qos;          /**< QOS subsystem handle        */
	QOS_FLOWID qos_id;   /**< QOS IPv4 flow id            */
	QOS_FLOWID qos_id6;  /**< QOS IPv6 flow id            */
#endif
};

/** Defines a UDP helper */
struct udp_helper {
	struct le le;
	int layer;
	udp_helper_send_h *sendh;
	udp_helper_recv_h *recvh;
	void *arg;
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


static void udp_destructor(void *data)
{
	struct udp_sock *us = data;

	list_flush(&us->helpers);

#ifdef WIN32
	if (us->qos && us->qos_id)
		(void)QOSRemoveSocketFromFlow(us->qos, 0, us->qos_id, 0);
	if (us->qos && us->qos_id6)
		(void)QOSRemoveSocketFromFlow(us->qos, 0, us->qos_id6, 0);
	if (us->qos)
		(void)QOSCloseHandle(us->qos);
#endif

	if (BAD_SOCK != us->fd) {
		fd_close(us->fd);
		(void)close(us->fd);
	}

	if (BAD_SOCK != us->fd6) {
		fd_close(us->fd6);
		(void)close(us->fd6);
	}
}


static void udp_read(struct udp_sock *us, re_sock_t fd)
{
	struct mbuf *mb = mbuf_alloc(us->rxsz);
	struct sa src;
	struct le *le;
	int err = 0;
	ssize_t n;

	if (!mb)
		return;

	src.len = sizeof(src.u);
	n = recvfrom(fd, BUF_CAST mb->buf + us->rx_presz,
		     SIZ_CAST (mb->size - us->rx_presz), 0,
		     &src.u.sa, &src.len);
	if (n < 0) {
		err = ERRNO_SOCK;

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

	/* call helpers */
	le = us->helpers.head;
	while (le) {
		struct udp_helper *uh = le->data;
		bool hdld;

		le = le->next;

		hdld = uh->recvh(&src, mb, uh->arg);
		if (hdld)
			goto out;
	}

	us->rh(&src, mb, us->arg);

 out:
	mem_deref(mb);
}


static void udp_read_handler(int flags, void *arg)
{
	struct udp_sock *us = arg;

	(void)flags;

	udp_read(us, us->fd);
}


static void udp_read_handler6(int flags, void *arg)
{
	struct udp_sock *us = arg;

	(void)flags;

	udp_read(us, us->fd6);
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
	struct udp_sock *us = NULL;
	char addr[64] = {0};
	char serv[6] = "0";
	int af, error, err = 0;

	if (!usp)
		return EINVAL;

	us = mem_zalloc(sizeof(*us), udp_destructor);
	if (!us)
		return ENOMEM;

	list_init(&us->helpers);

	us->fd  = BAD_SOCK;
	us->fd6 = BAD_SOCK;

	if (local) {
		af = sa_af(local);
		(void)re_snprintf(addr, sizeof(addr), "%H",
				  sa_print_addr, local);
		(void)re_snprintf(serv, sizeof(serv), "%u", sa_port(local));
	}
	else {
#ifdef HAVE_INET6
		af = AF_UNSPEC;
#else
		af = AF_INET;
#endif
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

		if (us->fd != BAD_SOCK)
			continue;

		DEBUG_INFO("listen: for: af=%d addr=%j\n",
			   r->ai_family, r->ai_addr);

		fd = socket(r->ai_family, SOCK_DGRAM, IPPROTO_UDP);
		if (fd == BAD_SOCK) {
			err = ERRNO_SOCK;
			continue;
		}

		err = net_sockopt_blocking_set(fd, false);
		if (err) {
			DEBUG_WARNING("udp listen: nonblock set: %m\n", err);
			(void)close(fd);
			continue;
		}

		if (bind(fd, r->ai_addr, SIZ_CAST r->ai_addrlen) < 0) {
			err = ERRNO_SOCK;
			DEBUG_INFO("listen: bind(): %m (%J)\n", err, local);
			(void)close(fd);
			continue;
		}

		/* Can we do both IPv4 and IPv6 on same socket? */
		if (AF_INET6 == r->ai_family) {
			struct sa sa;
			int on = 1;  /* assume v6only */

#if defined (IPPROTO_IPV6) && defined (IPV6_V6ONLY)
			socklen_t on_len = sizeof(on);
			if (0 != getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
					    (char *)&on, &on_len)) {
				on = 1;
			}
#endif
			/* Extra check for unspec addr - MAC OS X/Solaris */
			if (0==sa_set_sa(&sa, r->ai_addr) && sa_is_any(&sa)) {
				on = 1;
			}
			DEBUG_INFO("socket %d: IPV6_V6ONLY is %d\n", fd, on);
			if (on) {
				us->fd6 = fd;
				continue;
			}
		}

		/* OK */
		us->fd = fd;
		break;
	}

	freeaddrinfo(res);

	/* We must have at least one socket */
	if (BAD_SOCK == us->fd && BAD_SOCK == us->fd6) {
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
	struct udp_sock *us = NULL;
	int err = 0;
	re_sock_t fd;

	if (!usp)
		return EINVAL;

	us = mem_zalloc(sizeof(*us), udp_destructor);
	if (!us)
		return ENOMEM;

	us->fd  = BAD_SOCK;
	us->fd6 = BAD_SOCK;

	fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == BAD_SOCK) {
		err = ERRNO_SOCK;
		goto out;
	}

	if (af == AF_INET)
		us->fd = fd;
	else
		us->fd6 = fd;

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
	re_sock_t fd;

	if (!us || !peer)
		return EINVAL;

	/* choose a socket */
	if (AF_INET6 == sa_af(peer) && BAD_SOCK != us->fd6)
		fd = us->fd6;
	else
		fd = us->fd;

	if (0 != connect(fd, &peer->u.sa, peer->len))
		return ERRNO_SOCK;

	us->conn = true;

	return 0;
}


static int udp_send_internal(struct udp_sock *us, const struct sa *dst,
			     struct mbuf *mb, struct le *le)
{
	struct sa hdst;
	int err = 0;
	re_sock_t fd;

	/* choose a socket */
	if (AF_INET6 == sa_af(dst) && BAD_SOCK != us->fd6)
		fd = us->fd6;
	else
		fd = us->fd;

	/* call helpers in reverse order */
	while (le) {
		struct udp_helper *uh = le->data;

		le = le->prev;

		if (dst != &hdst) {
			sa_cpy(&hdst, dst);
			dst = &hdst;
		}

		if (uh->sendh(&err, &hdst, mb, uh->arg) || err)
			return err;
	}

	/* Connected socket? */
	if (us->conn) {
		if (send(fd, BUF_CAST mb->buf + mb->pos,
			 SIZ_CAST (mb->end - mb->pos),
			 0) < 0)
			return ERRNO_SOCK;
	}
	else {
		if (sendto(fd, BUF_CAST mb->buf + mb->pos,
			   SIZ_CAST (mb->end - mb->pos),
			   0, &dst->u.sa, dst->len) < 0)
			return ERRNO_SOCK;
	}

	return 0;
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

	return udp_send_internal(us, dst, mb, us->helpers.tail);
}


/**
 * Get the local network address on the UDP Socket
 *
 * @param us    UDP Socket
 * @param local The returned local network address
 *
 * @return 0 if success, otherwise errorcode
 *
 * @todo bug no way to specify AF
 */
int udp_local_get(const struct udp_sock *us, struct sa *local)
{
	if (!us || !local)
		return EINVAL;

	local->len = sizeof(local->u);

	if (0 == getsockname(us->fd, &local->u.sa, &local->len))
		return 0;

	if (0 == getsockname(us->fd6, &local->u.sa, &local->len))
		return 0;

	return ERRNO_SOCK;
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

	if (BAD_SOCK != us->fd) {
		if (0 != setsockopt(us->fd, level, optname,
				    BUF_CAST optval, optlen))
			err |= ERRNO_SOCK;
	}

	if (BAD_SOCK != us->fd6) {
		if (0 != setsockopt(us->fd6, level, optname,
				    BUF_CAST optval, optlen))
			err |= ERRNO_SOCK;
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
	if (BAD_SOCK != us->fd) {
		err = QOSAddSocketToFlow(us->qos, us->fd, NULL,
				qos_type,
				QOS_NON_ADAPTIVE_FLOW,
				&us->qos_id);
		if (!err)
			return WSAGetLastError();
	}

	us->qos_id6 = 0;
	if (BAD_SOCK != us->fd6) {
		err = QOSAddSocketToFlow(us->qos, us->fd6, NULL,
				qos_type,
				QOS_NON_ADAPTIVE_FLOW,
				&us->qos_id6);
		if (!err)
			return WSAGetLastError();
	}
#endif
	err = udp_setsockopt(us, IPPROTO_IP, IP_TOS, &v, sizeof(v));
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

	if (BAD_SOCK != us->fd) {
		err = fd_listen(us->fd, FD_READ, udp_read_handler, us);
		if (err)
			goto out;
	}

	if (BAD_SOCK != us->fd6) {
		err = fd_listen(us->fd6, FD_READ, udp_read_handler6, us);
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

	if (BAD_SOCK != us->fd)
		fd_close(us->fd);

	if (BAD_SOCK != us->fd6)
		fd_close(us->fd6);
}


static void helper_destructor(void *data)
{
	struct udp_helper *uh = data;

	list_unlink(&uh->le);
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

	list_append(&us->helpers, &uh->le, uh);

	uh->layer = layer;
	uh->sendh = sh ? sh : helper_send_handler;
	uh->recvh = rh ? rh : helper_recv_handler;
	uh->arg   = arg;

	list_sort(&us->helpers, sort_handler, NULL);

	if (uhp)
		*uhp = uh;

	return 0;
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

	return udp_send_internal(us, dst, mb, uh->le.prev);
}


void udp_recv_helper(struct udp_sock *us, const struct sa *src,
		     struct mbuf *mb, struct udp_helper *uhx)
{
	struct sa hsrc;
	struct le *le;

	if (!us || !src || !mb || !uhx)
		return;

	le = uhx->le.next;
	while (le) {
		struct udp_helper *uh = le->data;
		bool hdld;

		le = le->next;

		if (src != &hsrc) {
			sa_cpy(&hsrc, src);
			src = &hsrc;
		}

		hdld = uh->recvh(&hsrc, mb, uh->arg);
		if (hdld)
			return;
	}

	us->rh(src, mb, us->arg);
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

	for (le = us->helpers.head; le; le = le->next) {

		struct udp_helper *uh = le->data;

		if (layer == uh->layer)
			return uh;
	}

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

	if (BAD_SOCK != us->fd) {
		uint8_t buf[4096];

		while (recvfrom(us->fd, BUF_CAST buf, sizeof(buf),
				0, NULL, 0) > 0)
			;
	}

	if (BAD_SOCK != us->fd6) {
		uint8_t buf[4096];

		while (recvfrom(us->fd6, BUF_CAST buf, sizeof(buf),
				0, NULL, 0) > 0)
			;
	}
}
