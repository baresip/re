/**
 * @file openssl/tls_tcp.c TLS/TCP backend using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_main.h>
#include <re_sa.h>
#include <re_srtp.h>
#include <re_tcp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	SSL *ssl;             /* inheritance */
	struct tls *tls;      /* inheritance */
	BIO_METHOD *biomet;
	BIO *sbio_out;
	BIO *sbio_in;
	struct tcp_helper *th;
	struct tcp_conn *tcp;
	bool active;
	bool up;
};


static void destructor(void *arg)
{
	struct tls_conn *tc = arg;

	if (tc->ssl) {
		int r = SSL_shutdown(tc->ssl);
		if (r <= 0)
			ERR_clear_error();

		SSL_free(tc->ssl);
	}

	if (tc->biomet)
		BIO_meth_free(tc->biomet);

	mem_deref(tc->th);
	mem_deref(tc->tcp);
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
	struct mbuf mb;
	int err;

	mb.buf = (void *)buf;
	mb.pos = 0;
	mb.end = mb.size = len;

	err = tcp_send_helper(tc->tcp, &mb, tc->th);
	if (err)
		return -1;

	return len;
}


static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	(void)b;
	(void)num;
	(void)ptr;

	if (cmd == BIO_CTRL_FLUSH) {
		/* The OpenSSL library needs this */
		return 1;
	}

	return 0;
}


static BIO_METHOD *bio_method_tcp(void)
{
	BIO_METHOD *method;

	method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "tcp_send");
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


static int tls_connect(struct tls_conn *tc)
{
	int err = 0, r;

	ERR_clear_error();

	if (tls_get_session_reuse(tc))
		(void) tls_reuse_session(tc);

	r = SSL_connect(tc->ssl);
	if (r <= 0) {
		const int ssl_err = SSL_get_error(tc->ssl, r);

		ERR_clear_error();

		switch (ssl_err) {

		case SSL_ERROR_WANT_READ:
			break;

		default:
			DEBUG_WARNING("connect: error (r=%d, ssl_err=%d)\n",
				      r, ssl_err);
			err = EPROTO;
			break;
		}
	}

	return err;
}


static int tls_accept(struct tls_conn *tc)
{
	int err = 0, r;

	ERR_clear_error();

	r = SSL_accept(tc->ssl);
	if (r <= 0) {
		const int ssl_err = SSL_get_error(tc->ssl, r);

		switch (ssl_err) {

		case SSL_ERROR_WANT_READ:
			break;

		default:
			DEBUG_WARNING("accept error: (r=%d, ssl_err=%d)\n",
				      r, ssl_err);
			tls_flush_error();
			err = EPROTO;
			break;
		}

		ERR_clear_error();
	}

	return err;
}


static bool estab_handler(int *err, bool active, void *arg)
{
	struct tls_conn *tc = arg;

	DEBUG_INFO("tcp established (active=%u)\n", active);

	if (!active)
		return true;

	tc->active = true;
	*err = tls_connect(tc);

	return true;
}


static bool recv_handler(int *err, struct mbuf *mb, bool *estab, void *arg)
{
	struct tls_conn *tc = arg;
	int r;

	/* feed SSL data to the BIO */
	r = BIO_write(tc->sbio_in, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r <= 0) {
		DEBUG_WARNING("recv: BIO_write %d\n", r);
		ERR_clear_error();
		*err = ENOMEM;
		return true;
	}

	if (SSL_state(tc->ssl) != SSL_ST_OK) {

		if (tc->up) {
			*err = EPROTO;
			return true;
		}

		if (tc->active) {
			*err = tls_connect(tc);
		}
		else {
			*err = tls_accept(tc);
		}

		DEBUG_INFO("state=0x%04x\n", SSL_state(tc->ssl));

		/* TLS connection is established */
		if (SSL_state(tc->ssl) != SSL_ST_OK)
			return true;

		*estab = true;
		tc->up = true;
	}

	mbuf_set_pos(mb, 0);

	for (;;) {
		int n;

		if (mbuf_get_space(mb) < 4096) {
			*err = mbuf_resize(mb, mb->size + 8192);
			if (*err)
				return true;
		}

		ERR_clear_error();

		n = SSL_read(tc->ssl, mbuf_buf(mb), (int)mbuf_get_space(mb));
		if (n <= 0) {
			const int ssl_err = SSL_get_error(tc->ssl, n);

			ERR_clear_error();

			switch (ssl_err) {

			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_WANT_READ:
				break;

			default:
				*err = EPROTO;
				return true;
			}

			break;
		}

		mb->pos += n;
	}

	mbuf_set_end(mb, mb->pos);
	mbuf_set_pos(mb, 0);

	return false;
}


static bool send_handler(int *err, struct mbuf *mb, void *arg)
{
	struct tls_conn *tc = arg;
	int r;

	ERR_clear_error();

	r = SSL_write(tc->ssl, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r <= 0) {
		DEBUG_WARNING("SSL_write: %d\n", SSL_get_error(tc->ssl, r));
		ERR_clear_error();
		*err = EPROTO;
	}

	return true;
}


/**
 * Change used certificate+key of an existing SSL object
 *
 * @param tc   TLS connection object
 * @param file Cert+Key file
 *
 * @return int 0 if success, otherwise errorcode
 */
int tls_conn_change_cert(struct tls_conn *tc, const char *file)
{
	int r = 0;

	if (!tc || !file)
		return EINVAL;

#if !defined(LIBRESSL_VERSION_NUMBER)
	SSL_certs_clear(tc->ssl);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	!defined(LIBRESSL_VERSION_NUMBER)
	r = SSL_use_certificate_chain_file(tc->ssl, file);
#else
	r = SSL_use_certificate_file(tc->ssl, file, SSL_FILETYPE_PEM);
#endif
	if (r <= 0) {
		DEBUG_WARNING("change cert: "
			"cant't read certificate file: %s\n", file);
		ERR_clear_error();
		return EINVAL;
	}

	r = SSL_use_PrivateKey_file(tc->ssl, file, SSL_FILETYPE_PEM);
	if (r <= 0) {
		DEBUG_WARNING("change cert: key missmatch in %s\n", file);
		ERR_clear_error();
		return EKEYREJECTED;
	}

	return 0;
}


/**
 * Start TLS on a TCP-connection
 *
 * @param ptc   Pointer to allocated TLS connectioon
 * @param tls   TLS Context
 * @param tcp   TCP Connection
 * @param layer Protocol stack layer
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_start_tcp(struct tls_conn **ptc, struct tls *tls, struct tcp_conn *tcp,
		  int layer)
{
	struct tls_conn *tc;
	int err;

	if (!ptc || !tls || !tcp)
		return EINVAL;

	tc = mem_zalloc(sizeof(*tc), destructor);
	if (!tc)
		return ENOMEM;

	err = tcp_register_helper(&tc->th, tcp, layer, estab_handler,
				  send_handler, recv_handler, tc);
	if (err)
		goto out;

	tc->tcp = mem_ref(tcp);
	tc->tls = tls;

	tc->biomet = bio_method_tcp();
	if (!tc->biomet) {
		err = ENOMEM;
		goto out;
	}

	err = ENOMEM;

	/* Connect the SSL socket */
	tc->ssl = SSL_new(tls_ssl_ctx(tls));
	if (!tc->ssl) {
		DEBUG_WARNING("alloc: SSL_new() failed (ctx=%p)\n",
			tls_ssl_ctx(tls));
		ERR_clear_error();
		goto out;
	}

	tc->sbio_in = BIO_new(BIO_s_mem());
	if (!tc->sbio_in) {
		DEBUG_WARNING("alloc: BIO_new() failed\n");
		ERR_clear_error();
		goto out;
	}


	tc->sbio_out = BIO_new(tc->biomet);
	if (!tc->sbio_out) {
		DEBUG_WARNING("alloc: BIO_new_socket() failed\n");
		ERR_clear_error();
		BIO_free(tc->sbio_in);
		goto out;
	}

	BIO_set_data(tc->sbio_out, tc);

	SSL_set_bio(tc->ssl, tc->sbio_in, tc->sbio_out);

	err = 0;

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}


/**
 * Get tcp connection
 *
 * @param tc   TLS connection
 *
 * @return pointer to tcp connection struct
 */
const struct tcp_conn *tls_get_tcp_conn(const struct tls_conn *tc)
{
	if (!tc)
		return NULL;

	return tc->tcp;
}
