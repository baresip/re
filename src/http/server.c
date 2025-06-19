/**
 * @file http/server.c HTTP Server
 *
 * Copyright (C) 2011 Creytiv.com
 */

#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_fmt.h>
#include <re_tmr.h>
#include <re_srtp.h>
#include <re_tcp.h>
#include <re_tls.h>
#include <re_msg.h>
#include <re_http.h>


enum {
	TIMEOUT_IDLE = 600000,
	TIMEOUT_INIT = 10000,
	BUFSIZE_MAX  = 1024 * 1024 * 1, /* 1 MB */
};

struct http_sock {
	struct list connl;
	struct tcp_sock *ts;
	struct tls *tls;
	http_req_h *reqh;
	https_verify_msg_h *verifyh;
	size_t max_body_size;
	void *arg;
};

struct http_conn {
	struct le le;
	struct tmr tmr;
	struct sa peer;
	struct http_sock *sock;
	struct tcp_conn *tc;
	struct tls_conn *sc;
	struct mbuf *mb;
	struct tmr verify_cert_tmr;
};


static void conn_close(struct http_conn *conn);


static void sock_destructor(void *arg)
{
	struct http_sock *sock = arg;
	struct le *le;

	for (le=sock->connl.head; le;) {

		struct http_conn *conn = le->data;

		le = le->next;

		conn_close(conn);
		mem_deref(conn);
	}

	mem_deref(sock->tls);
	mem_deref(sock->ts);
}


static void conn_destructor(void *arg)
{
	struct http_conn *conn = arg;

	list_unlink(&conn->le);
	tmr_cancel(&conn->tmr);
	tmr_cancel(&conn->verify_cert_tmr);
	mem_deref(conn->sc);
	mem_deref(conn->tc);
	mem_deref(conn->mb);
}


static void conn_close(struct http_conn *conn)
{
	list_unlink(&conn->le);
	tmr_cancel(&conn->tmr);
	tmr_cancel(&conn->verify_cert_tmr);
	conn->sc = mem_deref(conn->sc);
	conn->tc = mem_deref(conn->tc);
	conn->sock = NULL;
}


static void timeout_handler(void *arg)
{
	struct http_conn *conn = arg;

	conn_close(conn);
	mem_deref(conn);
}


#ifdef HAVE_TLS1_3_POST_HANDSHAKE_AUTH
struct http_verify_msg_d {
	struct http_conn *conn;
	struct http_msg *msg;
	int err;
	int scode;
	const char *reason;
};


static void verify_msg_destructor(void *arg)
{
	struct http_verify_msg_d *d = arg;
	mem_deref(d->msg);
}


static void verify_cert_done(void *arg)
{
	struct http_verify_msg_d *d = arg;

	if (d->err)
		http_ereply(d->conn, d->scode, d->reason);
	else
		d->conn->sock->reqh(d->conn, d->msg, d->conn->sock->arg);

	mem_deref(arg);
}


static int http_verify_handler(int ok, void *arg)
{
	struct http_verify_msg_d *d = arg;

	if (ok) {
		d->err = 0;
	}
	else {
		d->err = EACCES;
		d->scode = 403;
		d->reason = "Forbidden";
	}

	tmr_start(&d->conn->verify_cert_tmr, 1, verify_cert_done, d);

	return ok;
}


static enum re_https_verify_msg verify_msg(struct http_conn *conn,
	struct http_msg *msg)
{
	enum re_https_verify_msg res;
	struct http_verify_msg_d *d;

	if (!conn->sock)
		return HTTPS_MSG_IGNORE;
	else if (!conn->sock->verifyh)
		return HTTPS_MSG_OK;

	res = conn->sock->verifyh(conn, msg, conn->sock->arg);

	if (res == HTTPS_MSG_REQUEST_CERT) {

		d = mem_zalloc(sizeof(*d), verify_msg_destructor);
		if (!d) {
			res = HTTPS_MSG_IGNORE;
			goto out;
		}

		d->conn = conn;
		d->err = ETIMEDOUT;
		d->scode = 408;
		d->reason = "Request Timeout";
		d->msg = msg;

		tmr_start(&conn->verify_cert_tmr, TIMEOUT_IDLE,
			verify_cert_done, d);

		int err = tls_set_verify_client_handler(http_conn_tls(conn),
			-1, http_verify_handler, d);
		if (err) {
			res = HTTPS_MSG_IGNORE;
			goto out;
		}

		err = tls_verify_client_post_handshake(
				http_conn_tls(conn));
		if (err) {
			res = HTTPS_MSG_IGNORE;
			goto out;
		}
	}

out:
	return res;
}
#endif


static void recv_handler(struct mbuf *mb, void *arg)
{
	struct http_conn *conn = arg;
	int err = 0;

	if (conn->mb) {

		const size_t len = mbuf_get_left(mb), pos = conn->mb->pos;

		if ((mbuf_get_left(conn->mb) + len) >
		    conn->sock->max_body_size) {
			err = EOVERFLOW;
			goto out;
		}

		conn->mb->pos = conn->mb->end;

		err = mbuf_write_mem(conn->mb, mbuf_buf(mb), len);
		if (err)
			goto out;

		conn->mb->pos = pos;
	}
	else {
		conn->mb = mem_ref(mb);
	}

	while (conn->mb) {
		size_t end, pos = conn->mb->pos;
		struct http_msg *msg;

		err = http_msg_decode(&msg, conn->mb, true);
		if (err) {
			if (err == ENODATA) {
				conn->mb->pos = pos;
				err = 0;
				break;
			}

			goto out;
		}

		if (mbuf_get_left(conn->mb) < msg->clen) {
			conn->mb->pos = pos;
			mem_deref(msg);
			break;
		}

		mem_deref(msg->mb);
		msg->mb = mem_ref(msg->_mb);

		mb = conn->mb;

		end     = mb->end;
		mb->end = mb->pos + msg->clen;

		if (end > mb->end) {
			struct mbuf *mbn = mbuf_alloc(end - mb->end);
			if (!mbn) {
				mem_deref(msg);
				err = ENOMEM;
				goto out;
			}

			(void)mbuf_write_mem(mbn, mb->buf + mb->end,
					     end - mb->end);
			mbn->pos = 0;

			mem_deref(conn->mb);
			conn->mb = mbn;
		}
		else {
			conn->mb = mem_deref(conn->mb);
		}

#ifdef HAVE_TLS1_3_POST_HANDSHAKE_AUTH
		if (verify_msg(conn, msg) == HTTPS_MSG_OK) {
			conn->sock->reqh(conn, msg, conn->sock->arg);
			mem_deref(msg);
		}
#else
		conn->sock->reqh(conn, msg, conn->sock->arg);
		mem_deref(msg);
#endif
		if (!conn->tc) {
			err = ENOTCONN;
			goto out;
		}

		tmr_start(&conn->tmr, TIMEOUT_IDLE, timeout_handler, conn);
	}

 out:
	if (err) {
		conn_close(conn);
		mem_deref(conn);
	}
}


static void close_handler(int err, void *arg)
{
	struct http_conn *conn = arg;
	(void)err;

	conn_close(conn);
	mem_deref(conn);
}


static void connect_handler(const struct sa *peer, void *arg)
{
	struct http_sock *sock = arg;
	struct http_conn *conn;
	int err;

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn) {
		err = ENOMEM;
		goto out;
	}

	list_append(&sock->connl, &conn->le, conn);
	conn->peer = *peer;
	conn->sock = sock;

	err = tcp_accept(&conn->tc, sock->ts, NULL, recv_handler,
			 close_handler, conn);
	if (err)
		goto out;

#ifdef USE_TLS
	if (sock->tls) {
		err = tls_start_tcp(&conn->sc, sock->tls, conn->tc, 0);
		if (err)
			goto out;
	}
#endif

	tmr_start(&conn->tmr, TIMEOUT_INIT, timeout_handler, conn);

 out:
	if (err) {
		mem_deref(conn);
		tcp_reject(sock->ts);
	}
}


/**
 * Create an HTTP socket from file descriptor
 *
 * @param sockp Pointer to returned HTTP Socket
 * @param fd    File descriptor
 * @param reqh  Request handler
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int http_listen_fd(struct http_sock **sockp, re_sock_t fd, http_req_h *reqh,
		   void *arg)
{
	struct http_sock *sock;
	int err;

	if (!sockp || fd == RE_BAD_SOCK || !reqh)
		return EINVAL;

	sock = mem_zalloc(sizeof(*sock), sock_destructor);
	if (!sock)
		return ENOMEM;

	err = tcp_sock_alloc_fd(&sock->ts, fd, connect_handler, sock);
	if (err)
		goto out;

	sock->reqh = reqh;
	sock->arg  = arg;
	sock->max_body_size = BUFSIZE_MAX;

out:
	if (err)
		mem_deref(sock);
	else
		*sockp = sock;

	return err;
}


/**
 * Create an HTTP socket
 *
 * @param sockp Pointer to returned HTTP Socket
 * @param laddr Network address to listen on
 * @param reqh  Request handler
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int http_listen(struct http_sock **sockp, const struct sa *laddr,
		http_req_h *reqh, void *arg)
{
	struct http_sock *sock;
	int err;

	if (!sockp || !laddr || !reqh)
		return EINVAL;

	sock = mem_zalloc(sizeof(*sock), sock_destructor);
	if (!sock)
		return ENOMEM;

	err = tcp_listen(&sock->ts, laddr, connect_handler, sock);
	if (err)
		goto out;

	sock->reqh = reqh;
	sock->arg  = arg;
	sock->max_body_size = BUFSIZE_MAX;

 out:
	if (err)
		mem_deref(sock);
	else
		*sockp = sock;

	return err;
}


/**
 * Create an HTTP secure socket
 *
 * @param sockp Pointer to returned HTTP Socket
 * @param laddr Network address to listen on
 * @param cert  File path of TLS certificate
 * @param reqh  Request handler
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int https_listen(struct http_sock **sockp, const struct sa *laddr,
		 const char *cert, http_req_h *reqh, void *arg)
{
	struct http_sock *sock;
	int err;

	if (!sockp || !laddr || !cert || !reqh)
		return EINVAL;

	err = http_listen(&sock, laddr, reqh, arg);
	if (err)
		return err;

#ifdef USE_TLS
	err = tls_alloc(&sock->tls, TLS_METHOD_SSLV23, cert, NULL);
#else
	err = EPROTONOSUPPORT;
#endif
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(sock);
	else
		*sockp = sock;

	return err;
}


/**
 * Set verify http msg handler. (Needs TLS v1.3 post-handshake auth)
 *
 * This handler allows to decide whether e.g. a certificate
 * should be requested from the client or not.
 * E.g. This decision can done based on the http path contained in
 * struct http_msg.
 *
 * @param sock 		HTTP socket
 * @param verifyh 	Verify handler called before the https request
 *                      handler is called to return a http response
 *                      to the client.
 *
 * @return 0 if success, otherwise errorcode
 */
int  https_set_verify_msgh(struct http_sock *sock,
	https_verify_msg_h *verifyh)
{
#ifdef HAVE_TLS1_3_POST_HANDSHAKE_AUTH
	if (!sock || !verifyh)
		return EINVAL;


	sock->verifyh = verifyh;
	return 0;
#else
	(void)sock;
	(void)verifyh;
	return ENOTSUP;
#endif
}


/**
 * Set Request buffer size limit
 *
 * @param sock  HTTP socket
 * @param limit New limit in bytes
 */
void http_set_max_body_size(struct http_sock *sock, size_t limit)
{
	if (!sock)
		return;

	sock->max_body_size = limit;
}


/**
 * Get the TCP socket of an HTTP socket
 *
 * @param sock HTTP socket
 *
 * @return TCP socket
 */
struct tcp_sock *http_sock_tcp(struct http_sock *sock)
{
	return sock ? sock->ts : NULL;
}


/**
 * Get the TLS struct of an HTTP sock
 *
 * @param sock HTTP socket
 *
 * @return TLS struct
 */
struct tls *http_sock_tls(const struct http_sock *sock)
{
	return sock ? sock->tls : NULL;
}


/**
 * Get the peer address of an HTTP connection
 *
 * @param conn HTTP connection
 *
 * @return Peer address
 */
const struct sa *http_conn_peer(const struct http_conn *conn)
{
	return conn ? &conn->peer : NULL;
}


/**
 * Get the TCP connection of an HTTP connection
 *
 * @param conn HTTP connection
 *
 * @return TCP connection
 */
struct tcp_conn *http_conn_tcp(struct http_conn *conn)
{
	return conn ? conn->tc : NULL;
}


/**
 * Get the TLS connection of an HTTP connection
 *
 * @param conn HTTP connection
 *
 * @return TLS connection
 */
struct tls_conn *http_conn_tls(struct http_conn *conn)
{
	return conn ? conn->sc : NULL;
}


/**
 * Reset IDLE Timeout of an HTTP Connection
 *
 * @param conn HTTP connection
 */
void http_conn_reset_timeout(struct http_conn *conn)
{
	tmr_start(&conn->tmr, TIMEOUT_IDLE, timeout_handler, conn);
}


/**
 * Close the HTTP connection
 *
 * @param conn HTTP connection
 */
void http_conn_close(struct http_conn *conn)
{
	if (!conn)
		return;

	conn->sc = mem_deref(conn->sc);
	conn->tc = mem_deref(conn->tc);
}


static int http_vreply(struct http_conn *conn, uint16_t scode,
		       const char *reason, const char *fmt, va_list ap)
{
	struct mbuf *mb;
	int err;

	if (!conn || !scode || !reason)
		return EINVAL;

	if (!conn->tc)
		return ENOTCONN;

	mb = mbuf_alloc(8192);
	if (!mb)
		return ENOMEM;

	err = mbuf_printf(mb, "HTTP/1.1 %u %s\r\n", scode, reason);
	if (fmt)
		err |= mbuf_vprintf(mb, fmt, ap);
	else
		err |= mbuf_write_str(mb, "Content-Length: 0\r\n\r\n");
	if (err)
		goto out;

	mb->pos = 0;

	err = tcp_send(conn->tc, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}


/**
 * Send an HTTP response
 *
 * @param conn   HTTP connection
 * @param scode  Response status code
 * @param reason Response reason phrase
 * @param fmt    Formatted HTTP message
 *
 * @return 0 if success, otherwise errorcode
 */
int http_reply(struct http_conn *conn, uint16_t scode, const char *reason,
	       const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = http_vreply(conn, scode, reason, fmt, ap);
	va_end(ap);

	return err;
}


/**
 * Send an HTTP response with content formatting
 *
 * @param conn   HTTP connection
 * @param scode  Response status code
 * @param reason Response reason phrase
 * @param ctype  Content type
 * @param fmt    Formatted HTTP content
 *
 * @return 0 if success, otherwise errorcode
 */
int http_creply(struct http_conn *conn, uint16_t scode, const char *reason,
		const char *ctype, const char *fmt, ...)
{
	struct mbuf *mb;
	va_list ap;
	int err;

	if (!ctype || !fmt)
		return EINVAL;

	mb = mbuf_alloc(8192);
	if (!mb)
		return ENOMEM;

	va_start(ap, fmt);
	err = mbuf_vprintf(mb, fmt, ap);
	va_end(ap);
	if (err)
		goto out;

	err = http_reply(conn, scode, reason,
			 "Content-Type: %s\r\n"
			 "Content-Length: %zu\r\n"
			 "\r\n"
			 "%b",
			 ctype,
			 mb->end,
			 mb->buf, mb->end);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}


/**
 * Send an HTTP error response
 *
 * @param conn   HTTP connection
 * @param scode  Response status code
 * @param reason Response reason phrase
 *
 * @return 0 if success, otherwise errorcode
 */
int http_ereply(struct http_conn *conn, uint16_t scode, const char *reason)
{
	return http_creply(conn, scode, reason, "text/html",
			   "<!DOCTYPE html>\n"
			   "<html>\n"
			   "<head><title>%u %s</title></head>\n"
			   "<body><h2>%u %s</h2></body>\n"
			   "</html>\n",
			   scode, reason,
			   scode, reason);
}
