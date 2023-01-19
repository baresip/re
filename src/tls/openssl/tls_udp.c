/**
 * @file openssl/tls_udp.c DTLS backend using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_sa.h>
#include <re_srtp.h>
#include <re_udp.h>
#include <re_tmr.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "dtls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	MTU_DEFAULT  = 1400,
	MTU_FALLBACK = 548,
};


/* TLS ContentType defined in RFC 5246 */
enum content_type {
       TYPE_CHANGE_CIPHER_SPEC = 20,
       TYPE_ALERT              = 21,
       TYPE_HANDSHAKE          = 22,
       TYPE_APPLICATION_DATA   = 23
};


struct dtls_sock {
	struct sa peer;
	struct udp_helper *uh;
	struct udp_sock *us;
	struct hash *ht;
	struct mbuf *mb;
	dtls_conn_h *connh;
	void *arg;
	size_t mtu;
	bool single_conn;  /* If enabled, only one DTLS connection */
};


/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	SSL *ssl;             /* inheritance */
	struct tls *tls;      /* inheritance */
	struct tls_conn_d cd; /* inheritance */
	BIO_METHOD *biomet;
	BIO *sbio_out;
	BIO *sbio_in;
	struct tmr tmr;
	struct sa peer;
	struct le he;
	struct dtls_sock *sock;
	dtls_estab_h *estabh;
	dtls_recv_h *recvh;
	dtls_close_h *closeh;
	void *arg;
	bool active;
	bool up;
};


#if DEBUG_LEVEL >= 6
static const char *content_type_str(enum content_type content_type)
{
	switch (content_type) {

	case TYPE_CHANGE_CIPHER_SPEC: return "CHANGE_CIPHER_SPEC";
	case TYPE_ALERT:              return "ALERT";
	case TYPE_HANDSHAKE:          return "HANDSHAKE";
	case TYPE_APPLICATION_DATA:   return "APPLICATION_DATA";
	default: return "???";
	}
}
#endif


static bool first_handler(struct le *le, void *arg)
{
	(void)le;
	(void)arg;

	return true;  /* stop on the first element */
}


static struct le *hash_get_first(const struct hash *ht)
{
	return hash_apply(ht, first_handler, NULL);
}


static int bio_create(BIO *b)
{
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);
	BIO_set_flags(b, 0);

	return 1;
}


static int bio_destroy(BIO *b)
{
	if (!b)
		return 0;

	BIO_set_init(b, 0);
	BIO_set_data(b, NULL);
	BIO_set_flags(b, 0);

	return 1;
}


static int bio_write(BIO *b, const char *buf, int len)
{
	struct tls_conn *tc = BIO_get_data(b);
	struct mbuf *mb;
	enum {SPACE = 4};
	int err;

	mb = mbuf_alloc(SPACE + len);
	if (!mb)
		return -1;

	mb->pos = SPACE;
	(void)mbuf_write_mem(mb, (void *)buf, len);
	mb->pos = SPACE;

	err = udp_send_helper(tc->sock->us, &tc->peer, mb, tc->sock->uh);

	mem_deref(mb);

	return err ? -1 : len;
}


static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	struct tls_conn *tc = BIO_get_data(b);
	(void)num;
	(void)ptr;

	switch (cmd) {

	case BIO_CTRL_FLUSH:
		/* The OpenSSL library needs this */
		return 1;

#if defined (BIO_CTRL_DGRAM_QUERY_MTU)
	case BIO_CTRL_DGRAM_QUERY_MTU:
		return tc ? (long)tc->sock->mtu : MTU_DEFAULT;
#endif

#if defined (BIO_CTRL_DGRAM_GET_FALLBACK_MTU)
	case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
		return MTU_FALLBACK;
#endif
	}

	return 0;
}


static BIO_METHOD *bio_method_udp(void)
{
	BIO_METHOD *method;

	method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "udp_send");
	if (!method) {
		DEBUG_WARNING("alloc: BIO_meth_new() failed\n");
		ERR_clear_error();
		return NULL;
	}

	BIO_meth_set_write(method, bio_write);
	BIO_meth_set_ctrl(method, bio_ctrl);
	BIO_meth_set_create(method, bio_create);
	BIO_meth_set_destroy(method, bio_destroy);

	return method;
}


static void tls_close(struct tls_conn *tc)
{
	int r;

	if (!tc->ssl)
		return;

	r = SSL_shutdown(tc->ssl);
	if (r <= 0)
		ERR_clear_error();

	SSL_free(tc->ssl);
	tc->ssl = NULL;
}


static void conn_destructor(void *arg)
{
	struct tls_conn *tc = arg;

	hash_unlink(&tc->he);
	tmr_cancel(&tc->tmr);
	tls_close(tc);

	if (tc->biomet)
		BIO_meth_free(tc->biomet);

	mem_deref(tc->sock);
}


static void conn_close(struct tls_conn *tc, int err)
{
	tmr_cancel(&tc->tmr);
	tls_close(tc);
	tc->up = false;

	if (tc->closeh)
		tc->closeh(err, tc->arg);
}


static void check_timer(struct tls_conn *tc);


static void timeout(void *arg)
{
	struct tls_conn *tc = arg;

	DEBUG_INFO("timeout\n");

	if (0 <= DTLSv1_handle_timeout(tc->ssl)) {

		check_timer(tc);
	}
	else {
		ERR_clear_error();
		conn_close(tc, ETIMEDOUT);
	}
}


static void check_timer(struct tls_conn *tc)
{
	struct timeval tv = {0, 0};

	if (1 == DTLSv1_get_timeout(tc->ssl, &tv)) {

		tmr_start(&tc->tmr, tv.tv_sec * 1000 + tv.tv_usec / 1000,
			  timeout, tc);
	}
	else {
		tmr_cancel(&tc->tmr);
	}
}


static int tls_connect(struct tls_conn *tc)
{
	int r;

	ERR_clear_error();

	r = SSL_connect(tc->ssl);
	if (r <= 0) {
		const int ssl_err = SSL_get_error(tc->ssl, r);

		tls_flush_error();

		switch (ssl_err) {

		case SSL_ERROR_WANT_READ:
			break;

		default:
			DEBUG_WARNING("connect error: %i\n", ssl_err);
			return EPROTO;
		}
	}

	check_timer(tc);

	return 0;
}


static int tls_accept(struct tls_conn *tc)
{
	int r;

	ERR_clear_error();

	r = SSL_accept(tc->ssl);
	if (r <= 0) {
		const int ssl_err = SSL_get_error(tc->ssl, r);

		tls_flush_error();

		switch (ssl_err) {

		case SSL_ERROR_WANT_READ:
			break;

		default:
			DEBUG_WARNING("accept error: %i\n", ssl_err);
			return EPROTO;
		}
	}

	check_timer(tc);

	return 0;
}


static void conn_recv(struct tls_conn *tc, struct mbuf *mb)
{
	int err, r;

	if (!tc->ssl)
		return;

	/* feed SSL data to the BIO */
	r = BIO_write(tc->sbio_in, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r <= 0) {
		DEBUG_WARNING("receive bio write error: %i\n", r);
		ERR_clear_error();
		conn_close(tc, ENOMEM);
		return;
	}

	if (SSL_state(tc->ssl) != SSL_ST_OK) {

		if (tc->up) {
			conn_close(tc, EPROTO);
			return;
		}

		if (tc->active) {
			err = tls_connect(tc);
		}
		else {
			err = tls_accept(tc);
		}

		if (err) {
			conn_close(tc, err);
			return;
		}

		DEBUG_INFO("%s: state=0x%04x\n",
			   tc->active ? "client" : "server",
			   SSL_state(tc->ssl));

		/* TLS connection is established */
		if (SSL_state(tc->ssl) != SSL_ST_OK)
			return;

		tc->up = true;

		if (tc->estabh) {
			uint32_t nrefs;

			mem_ref(tc);

			tc->estabh(tc->arg);

                        nrefs = mem_nrefs(tc);
                        mem_deref(tc);

                        /* check if connection was deref'd from handler */
                        if (nrefs == 1)
                                return;
		}
	}

	mbuf_set_pos(mb, 0);

	for (;;) {
		int n;

		if (mbuf_get_space(mb) < 4096) {
			err = mbuf_resize(mb, mb->size + 8192);
			if (err) {
				conn_close(tc, err);
				return;
			}
		}

		ERR_clear_error();

		n = SSL_read(tc->ssl, mbuf_buf(mb), (int)mbuf_get_space(mb));
		if (n <= 0) {
			const int ssl_err = SSL_get_error(tc->ssl, n);

			ERR_clear_error();

			switch (ssl_err) {

			case SSL_ERROR_WANT_READ:
				break;

			case SSL_ERROR_ZERO_RETURN:
				conn_close(tc, ECONNRESET);
				return;

			default:
				DEBUG_WARNING("read error: %i\n", ssl_err);
				conn_close(tc, EPROTO);
				return;
			}

			break;
		}

		mb->pos += n;
	}

	mbuf_set_end(mb, mb->pos);
	mbuf_set_pos(mb, 0);

	if (tc->recvh && mbuf_get_left(mb) > 0)
		tc->recvh(mb, tc->arg);

	return;
}


static int conn_alloc(struct tls_conn **ptc, struct tls *tls,
		      struct dtls_sock *sock, const struct sa *peer,
		      dtls_estab_h *estabh, dtls_recv_h *recvh,
		      dtls_close_h *closeh, void *arg)
{
	struct tls_conn *tc;
	int err = 0;

	if (sock->single_conn) {
		if (hash_get_first(sock->ht)) {
			DEBUG_WARNING("single: only one connection allowed\n");
			return EMFILE;
		}
	}

	tc = mem_zalloc(sizeof(*tc), conn_destructor);
	if (!tc)
		return ENOMEM;

	hash_append(sock->ht, sa_hash(peer, SA_ALL), &tc->he, tc);

	tc->sock   = mem_ref(sock);
	tc->peer   = *peer;
	tc->estabh = estabh;
	tc->recvh  = recvh;
	tc->closeh = closeh;
	tc->arg    = arg;
	tc->tls    = tls;

	tc->biomet = bio_method_udp();
	if (!tc->biomet) {
		err = ENOMEM;
		goto out;
	}

	/* Connect the SSL socket */
	tc->ssl = SSL_new(tls_ssl_ctx(tls));
	if (!tc->ssl) {
		DEBUG_WARNING("ssl new failed: %i\n",
			      ERR_GET_REASON(ERR_get_error()));
		ERR_clear_error();
		err = ENOMEM;
		goto out;
	}

	tc->sbio_in = BIO_new(BIO_s_mem());
	if (!tc->sbio_in) {
		ERR_clear_error();
		err = ENOMEM;
		goto out;
	}

	tc->sbio_out = BIO_new(tc->biomet);
	if (!tc->sbio_out) {
		ERR_clear_error();
		BIO_free(tc->sbio_in);
		err = ENOMEM;
		goto out;
	}

	BIO_set_data(tc->sbio_out, tc);

	SSL_set_bio(tc->ssl, tc->sbio_in, tc->sbio_out);

	SSL_set_read_ahead(tc->ssl, 1);

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}


/**
 * DTLS Connect
 *
 * @param ptc    Pointer to allocated DTLS connection
 * @param tls    TLS Context
 * @param sock   DTLS Socket
 * @param peer   Peer address
 * @param estabh Establish handler
 * @param recvh  Receive handler
 * @param closeh Close handler
 * @param arg    Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int dtls_connect(struct tls_conn **ptc, struct tls *tls,
		 struct dtls_sock *sock, const struct sa *peer,
		 dtls_estab_h *estabh, dtls_recv_h *recvh,
		 dtls_close_h *closeh, void *arg)
{
	struct tls_conn *tc;
	int err;

	if (!ptc || !tls || !sock || !peer)
		return EINVAL;

	err = conn_alloc(&tc, tls, sock, peer, estabh, recvh, closeh, arg);
	if (err)
		return err;

	tc->active = true;

	err = tls_connect(tc);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}


/**
 * DTLS Accept
 *
 * @param ptc    Pointer to allocated DTLS connection
 * @param tls    TLS Context
 * @param sock   DTLS Socket
 * @param estabh Establish handler
 * @param recvh  Receive handler
 * @param closeh Close handler
 * @param arg    Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int dtls_accept(struct tls_conn **ptc, struct tls *tls,
		struct dtls_sock *sock,
		dtls_estab_h *estabh, dtls_recv_h *recvh,
		dtls_close_h *closeh, void *arg)
{
	struct tls_conn *tc;
	int err, r;

	if (!ptc || !tls || !sock || !sock->mb)
		return EINVAL;

	err = conn_alloc(&tc, tls, sock, &sock->peer, estabh, recvh, closeh,
			 arg);
	if (err)
		return err;

	tc->active = false;

	r = BIO_write(tc->sbio_in, mbuf_buf(sock->mb),
		      (int)mbuf_get_left(sock->mb));
	if (r <= 0) {
		DEBUG_WARNING("accept bio write error: %i\n", r);
		ERR_clear_error();
		err = ENOMEM;
		goto out;
	}

	err = tls_accept(tc);
	if (err)
		goto out;

	sock->mb = mem_deref(sock->mb);

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}


/**
 * Send data on a DTLS connection
 *
 * @param tc DTLS connection
 * @param mb Buffer to send
 *
 * @return 0 if success, otherwise errorcode
 */
int dtls_send(struct tls_conn *tc, struct mbuf *mb)
{
	int r;

	if (!tc || !mb)
		return EINVAL;

	if (!tc->up || !tc->ssl)
		return ENOTCONN;

	ERR_clear_error();

	r = SSL_write(tc->ssl, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r <= 0) {
		DEBUG_WARNING("write error: %i\n", SSL_get_error(tc->ssl, r));
		ERR_clear_error();
		return EPROTO;
	}

	return 0;
}


/**
 * Set handlers on a DTLS Connection
 *
 * @param tc     DTLS Connection
 * @param estabh DTLS Connection Established handler
 * @param recvh  DTLS Connection Receive data handler
 * @param closeh DTLS Connection Close handler
 * @param arg    Handler argument
 */
void dtls_set_handlers(struct tls_conn *tc, dtls_estab_h *estabh,
		       dtls_recv_h *recvh, dtls_close_h *closeh, void *arg)
{
	if (!tc)
		return;

	tc->estabh = estabh;
	tc->recvh  = recvh;
	tc->closeh = closeh;
	tc->arg    = arg;
}


/**
 * Get the remote peer of a DTLS Connection
 *
 * @param tc DTLS Connection
 *
 * @return Remote peer
 */
const struct sa *dtls_peer(const struct tls_conn *tc)
{
	return tc ? &tc->peer : NULL;
}


/**
 * Set the remote peer of a DTLS Connection
 *
 * @param tc     DTLS Connection
 * @param peer   Peer address
 */
void dtls_set_peer(struct tls_conn *tc, const struct sa *peer)
{
	if (!tc || !peer)
		return;

	hash_unlink(&tc->he);
	hash_append(tc->sock->ht, sa_hash(peer, SA_ALL), &tc->he, tc);

	tc->peer = *peer;
}


static void sock_destructor(void *arg)
{
	struct dtls_sock *sock = arg;

	hash_clear(sock->ht);
	mem_deref(sock->uh);
	mem_deref(sock->us);
	mem_deref(sock->ht);
	mem_deref(sock->mb);
}


static bool cmp_handler(struct le *le, void *arg)
{
	struct tls_conn *tc = le->data;

	return sa_cmp(&tc->peer, arg, SA_ALL);
}


static struct tls_conn *conn_lookup(struct dtls_sock *sock,
				    const struct sa *peer)
{
	if (sock->single_conn) {
		struct le *le = hash_get_first(sock->ht);
		return list_ledata(le);
	}

	return list_ledata(hash_lookup(sock->ht, sa_hash(peer, SA_ALL),
                                       cmp_handler, (void *)peer));
}


static bool recv_handler(struct sa *src, struct mbuf *mb, void *arg)
{
	struct dtls_sock *sock = arg;
	struct tls_conn *tc;
	uint8_t b;

	if (mbuf_get_left(mb) < 1)
		return false;

	b = mb->buf[mb->pos];
	if (b < 20 || b > 63)
		return false;

	DEBUG_INFO("receive '%s' from %J\n", content_type_str(b), src);

	tc = conn_lookup(sock, src);
	if (tc) {
		conn_recv(tc, mb);
		return true;
	}

	if (sock->connh) {

		mem_deref(sock->mb);
		sock->mb   = mem_ref(mb);
		sock->peer = *src;

		sock->connh(src, sock->arg);
	}

	return true;
}


/**
 * Create DTLS Socket
 *
 * @param sockp  Pointer to returned DTLS Socket
 * @param laddr  Local listen address (optional)
 * @param us     External UDP socket (optional)
 * @param htsize Connection hash table size
 * @param layer  UDP protocol layer
 * @param connh  Connect handler
 * @param arg    Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int dtls_listen(struct dtls_sock **sockp, const struct sa *laddr,
		struct udp_sock *us, uint32_t htsize, int layer,
		dtls_conn_h *connh, void *arg)
{
	struct dtls_sock *sock;
	int err;

	if (!sockp)
		return EINVAL;

	sock = mem_zalloc(sizeof(*sock), sock_destructor);
	if (!sock)
		return ENOMEM;

	if (us) {
		sock->us = mem_ref(us);
	}
	else {
		err = udp_listen(&sock->us, laddr, NULL, NULL);
		if (err)
			goto out;
	}

	err = udp_register_helper(&sock->uh, sock->us, layer,
				  NULL, recv_handler, sock);
	if (err)
		goto out;

	err = hash_alloc(&sock->ht, hash_valid_size(htsize));
	if (err)
		goto out;

	sock->mtu   = MTU_DEFAULT;
	sock->connh = connh;
	sock->arg   = arg;

 out:
	if (err)
		mem_deref(sock);
	else
		*sockp = sock;

	return err;
}


/**
 * Get the underlying UDP socket of a DTLS Socket
 *
 * @param sock DTLS Socket
 *
 * @return UDP Socket
 */
struct udp_sock *dtls_udp_sock(struct dtls_sock *sock)
{
	return sock ? sock->us : NULL;
}


/**
 * Set MTU on a DTLS Socket
 *
 * @param sock DTLS Socket
 * @param mtu  MTU value
 */
void dtls_set_mtu(struct dtls_sock *sock, size_t mtu)
{
	if (!sock)
		return;

	sock->mtu = mtu;
}


/**
 * Receive a DTLS packet
 *
 * @param sock DTLS Socket
 * @param src  Source network address
 * @param mb   Mbuffer with DTLS packet
 */
void dtls_recv_packet(struct dtls_sock *sock, const struct sa *src,
		      struct mbuf *mb)
{
	struct sa addr;

	if (!sock || !src || !mb)
		return;

	addr = *src;

	recv_handler(&addr, mb, sock);
}


/**
 * Set single connection mode. If enabled, only one DTLS connection is allowed.
 *
 * @param sock   DTLS Socket
 * @param single True to enable, False to disable
 */
void dtls_set_single(struct dtls_sock *sock, bool single)
{
	if (!sock)
		return;

	sock->single_conn = single;
}
