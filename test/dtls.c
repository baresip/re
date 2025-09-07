/**
 * @file dtls.c DTLS Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "dtls_test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct dtls_test {
	bool dtls_srtp;
	struct dtls_sock *sock_cli, *sock_srv;
	struct tls_conn *conn_cli, *conn_srv;
	struct tls *tls;
	int err;

	struct {
		enum srtp_suite suite;
		uint8_t cli_key[12+32];
		uint8_t srv_key[12+32];
	} cli, srv;

	uint8_t fp[32];
	char cn[64];
	unsigned n_srv_estab;
	unsigned n_srv_recv;
	unsigned n_cli_estab;
	unsigned n_cli_recv;
	unsigned n_conn;
};

static const char *common_name = "127.0.0.1";
static const char *payload_str = "hello from a cute DTLS client";


static void abort_test(struct dtls_test *t, int err)
{
	t->err = err;
	re_cancel();
}


static int send_data(struct dtls_test *t, const char *data)
{
	struct mbuf mb;
	int err;

	TEST_ASSERT(t->conn_cli != NULL);

	mb.buf  = (void *)data;
	mb.pos  = 0;
	mb.end  = str_len(data);
	mb.size = str_len(data);

	err = dtls_send(t->conn_cli, &mb);
	TEST_ERR(err);

 out:
	return err;
}


static void srv_estab_handler(void *arg)
{
	struct dtls_test *t = arg;
	int err = 0;

	++t->n_srv_estab;

	if (t->dtls_srtp) {
		err = tls_srtp_keyinfo(t->conn_srv, &t->srv.suite,
				       t->srv.cli_key, sizeof(t->srv.cli_key),
				       t->srv.srv_key, sizeof(t->srv.srv_key));
		TEST_ERR(err);
	}

 out:
	if (err)
		abort_test(t, err);
}


static void srv_recv_handler(struct mbuf *mb, void *arg)
{
	struct dtls_test *t = arg;
	int err;

	++t->n_srv_recv;

	/* echo */
	err = dtls_send(t->conn_srv, mb);
	TEST_ERR(err);

 out:
	if (err)
		abort_test(t, err);
}


static void srv_close_handler(int err, void *arg)
{
	struct dtls_test *t = arg;
	(void)err;

	t->conn_srv = mem_deref(t->conn_srv);
}


static void cli_estab_handler(void *arg)
{
	struct dtls_test *t = arg;
	int err;

	++t->n_cli_estab;

	err = tls_peer_fingerprint(t->conn_cli, TLS_FINGERPRINT_SHA256,
				   t->fp, sizeof(t->fp));
	TEST_ERR(err);

	err = tls_peer_common_name(t->conn_cli, t->cn, sizeof(t->cn));
	TEST_ERR(err);

	if (t->dtls_srtp) {

		err = tls_srtp_keyinfo(t->conn_cli, &t->cli.suite,
				       t->cli.cli_key, sizeof(t->cli.cli_key),
				       t->cli.srv_key, sizeof(t->cli.srv_key));
		TEST_ERR(err);
	}

	err = send_data(t, payload_str);
	TEST_ERR(err);

 out:
	if (err)
		abort_test(t, err);
}


static void cli_recv_handler(struct mbuf *mb, void *arg)
{
	struct dtls_test *t = arg;
	int err = 0;

	++t->n_cli_recv;

	TEST_STRCMP(payload_str, strlen(payload_str),
		    mbuf_buf(mb), mbuf_get_left(mb));

 out:
	abort_test(t, err);
}


static void cli_close_handler(int err, void *arg)
{
	struct dtls_test *t = arg;
	(void)err;

	t->conn_cli = mem_deref(t->conn_cli);
}


static void conn_handler(const struct sa *src, void *arg)
{
	struct dtls_test *t = arg;
	int err;
	(void)src;

	++t->n_conn;

	TEST_ASSERT(t->conn_srv == NULL);

	err = dtls_accept(&t->conn_srv, t->tls, t->sock_srv,
			  srv_estab_handler, srv_recv_handler,
			  srv_close_handler, t);
	if (err) {
		if (err == EPROTO)
			err = ENOMEM;
		TEST_ERR(err);
	}

 out:
	if (err)
		abort_test(t, err);
}


static int test_dtls_srtp_base(enum tls_method method, bool dtls_srtp,
			       const char *srtp_suites)
{
	struct dtls_test test;
	struct udp_sock *us = NULL;
	struct sa cli, srv;
	uint8_t fp[32];
	int err;

	memset(&test, 0, sizeof(test));

	test.dtls_srtp = dtls_srtp;

	err = tls_alloc(&test.tls, method, NULL, NULL);
	TEST_ERR(err);

	err = tls_set_certificate(test.tls, test_certificate_ecdsa,
				  strlen(test_certificate_ecdsa));
	TEST_ERR(err);

	if (dtls_srtp) {
		err = tls_set_srtp(test.tls, srtp_suites);

		/* SRTP not supported */
		if (err == ENOSYS) {
			err = 0;
			goto out;
		}

		TEST_ERR(err);
	}

	err = tls_fingerprint(test.tls, TLS_FINGERPRINT_SHA256,
			      fp, sizeof(fp));
	TEST_EQUALS(0, err);

	(void)sa_set_str(&cli, "127.0.0.1", 0);
	(void)sa_set_str(&srv, "127.0.0.1", 0);

	err = udp_listen(&us, &srv, NULL, NULL);
	TEST_ERR(err);

	err = udp_local_get(us, &srv);
	TEST_ERR(err);

	err = dtls_listen(&test.sock_srv, NULL, us, 4, 0, conn_handler, &test);
	TEST_ERR(err);

	err = dtls_listen(&test.sock_cli, &cli, NULL, 4, 0, NULL, NULL);
	TEST_ERR(err);

	dtls_set_single(test.sock_cli, true);

	/* Set a low MTU to force fragmentation and reassembly */
	dtls_set_mtu(test.sock_srv, 128);

	err = dtls_connect(&test.conn_cli, test.tls, test.sock_cli,
			   &srv, cli_estab_handler,
			   cli_recv_handler, cli_close_handler, &test);
	if (err) {
		if (err == EPROTO)
			err = ENOMEM;
		TEST_ERR(err);
	}

	err = re_main_timeout(800);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		goto out;
	}

	/* verify result after test is complete */
	TEST_EQUALS(1, test.n_srv_estab);
	TEST_EQUALS(1, test.n_srv_recv);
	TEST_EQUALS(1, test.n_cli_estab);
	TEST_EQUALS(1, test.n_cli_recv);
	TEST_EQUALS(1, test.n_conn);

	TEST_MEMCMP(fp, sizeof(fp), test.fp, sizeof(test.fp));
	TEST_STRCMP(common_name, strlen(common_name),
		    test.cn, strlen(test.cn));

	if (dtls_srtp) {

		TEST_EQUALS(test.cli.suite, test.srv.suite);
		TEST_MEMCMP(test.cli.cli_key, sizeof(test.cli.cli_key),
			    test.srv.cli_key, sizeof(test.srv.cli_key));
		TEST_MEMCMP(test.cli.srv_key, sizeof(test.cli.srv_key),
			    test.srv.srv_key, sizeof(test.srv.srv_key));
	}

 out:
	test.conn_cli = mem_deref(test.conn_cli);
	test.conn_srv = mem_deref(test.conn_srv);
	test.sock_cli = mem_deref(test.sock_cli);
	test.sock_srv = mem_deref(test.sock_srv);
	test.tls = mem_deref(test.tls);
	mem_deref(us);

	return err;
}


static bool have_dtls_support(enum tls_method method)
{
	struct tls *tls = NULL;
	int err;

	err = tls_alloc(&tls, method, NULL, NULL);

	mem_deref(tls);

	return err != ENOSYS;
}


int test_dtls(void)
{
	int err = 0;

	/* NOTE: DTLS v1.0 should be available on all
	 *       supported platforms.
	 */
	if (!have_dtls_support(TLS_METHOD_DTLSV1)) {
		(void)re_printf("skip DTLS 1.0 tests\n");
		return ESKIPPED;
	}
	else {
		err = test_dtls_srtp_base(TLS_METHOD_DTLSV1, false, NULL);
		if (err)
			return err;
	}

	return 0;
}


int test_dtls_srtp(void)
{
	int err = 0;

	if (!have_dtls_support(TLS_METHOD_DTLSV1)) {
		(void)re_printf("skip DTLS tests\n");
		return ESKIPPED;
	}

	err = test_dtls_srtp_base(TLS_METHOD_DTLSV1, true,
				  "SRTP_AES128_CM_SHA1_80");
	TEST_ERR(err);

	err = test_dtls_srtp_base(TLS_METHOD_DTLSV1, true,
				  "SRTP_AES128_CM_SHA1_32");
	TEST_ERR(err);

	err = test_dtls_srtp_base(TLS_METHOD_DTLSV1, true,
				  "SRTP_AEAD_AES_128_GCM");
	TEST_ERR(err);

	err = test_dtls_srtp_base(TLS_METHOD_DTLSV1, true,
				  "SRTP_AEAD_AES_256_GCM");
	TEST_ERR(err);

 out:
	return err;
}
