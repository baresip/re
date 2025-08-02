/**
 * @file tls.c  TLS testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <openssl/ssl.h>
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "tlstest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct tls_test {
	struct tls *tls;
	struct tls *tls2;
	struct tls_conn *sc_cli;
	struct tls_conn *sc_srv;
	struct tcp_sock *ts;
	struct tcp_conn *tc_cli;
	struct tcp_conn *tc_srv;
	enum tls_keytype keytype;
	bool estab_cli;
	bool estab_srv;
	bool send_done_cli;
	size_t recv_cli;
	size_t recv_srv;
	int err;
};


static const char *payload = "0123456789";


static void check(struct tls_test *tt, int err)
{
	if (tt->err == 0)
		tt->err = err;

	if (tt->err)
		re_cancel();
}


static void can_send(struct tls_test *tt)
{
	struct mbuf *mb;
	int err = 0;

	if (!tt->estab_cli || !tt->estab_srv || tt->send_done_cli)
		return;

	mb = mbuf_alloc(256);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err = mbuf_write_str(mb, payload);
	if (err)
		goto out;

	mb->pos = 0;
	err = tcp_send(tt->tc_cli, mb);

	if (!err)
		tt->send_done_cli = true;

 out:
	mem_deref(mb);

	check(tt, err);
}


static void client_estab_handler(void *arg)
{
	struct tls_test *tt = arg;
	int err = 0;

	tt->estab_cli = true;
	can_send(tt);

	check(tt, err);
}


static void client_recv_handler(struct mbuf *mb, void *arg)
{
	struct tls_test *tt = arg;
	int err = 0;

	if (!tt->estab_cli) {
		(void)re_fprintf(stderr, "unexpected data received"
				 " on client [%02w]\n",
				 mbuf_buf(mb), mbuf_get_left(mb));
		check(tt, EPROTO);
	}

	++tt->recv_cli;

	TEST_MEMCMP(payload, strlen(payload),
			mbuf_buf(mb), mbuf_get_left(mb));

 out:
	check(tt, err);

	/* We are done */
	re_cancel();
}


static void client_close_handler(int err, void *arg)
{
	struct tls_test *tt = arg;

	if (!tt->estab_cli)
		check(tt, err);
}


static void server_estab_handler(void *arg)
{
	struct tls_test *tt = arg;
	tt->estab_srv = true;
	can_send(tt);
}


static void server_recv_handler(struct mbuf *mb, void *arg)
{
	struct tls_test *tt = arg;
	int err = 0;

	if (!tt->estab_srv) {
		check(tt, EPROTO);
		return;
	}

	++tt->recv_srv;

	TEST_MEMCMP(payload, strlen(payload),
		    mbuf_buf(mb), mbuf_get_left(mb));

	/* echo */
	err = tcp_send(tt->tc_srv, mb);
	if (err) {
		DEBUG_WARNING("server: tcp_send error (%m)\n", err);
	}

 out:
	check(tt, err);
}


static void server_close_handler(int err, void *arg)
{
	struct tls_test *tt = arg;

	if (!tt->estab_cli)
		check(tt, err);
}


static void server_conn_handler(const struct sa *peer, void *arg)
{
	struct tls_test *tt = arg;
	int err;
	(void)peer;

	err = tcp_accept(&tt->tc_srv, tt->ts, server_estab_handler,
			 server_recv_handler, server_close_handler, tt);
	check(tt, err);

	err = tls_start_tcp(&tt->sc_srv, tt->tls, tt->tc_srv, 0);
	check(tt, err);
}


static int test_tls_base(enum tls_keytype keytype, bool add_ca, int exp_verr,
	bool test_sess_reuse, int forced_version)
{
	struct tls_test tt;
	struct sa srv;
	int err, verr;
	unsigned long int i, rounds = 1 + (unsigned long int) test_sess_reuse;

	memset(&tt, 0, sizeof(tt));

	tt.keytype = keytype;

	err = sa_set_str(&srv, "127.0.0.1", 0);
	if (err)
		goto out;

	err = tls_alloc(&tt.tls, TLS_METHOD_SSLV23, NULL, NULL);
	if (err)
		goto out;

	if (forced_version >= 0) {
		TEST_EQUALS(0,
			tls_set_min_proto_version(tt.tls, forced_version));
		TEST_EQUALS(0,
			tls_set_max_proto_version(tt.tls, forced_version));
	}

	switch (keytype) {

	case TLS_KEYTYPE_EC:
		err = tls_set_certificate(tt.tls, test_certificate_ecdsa,
					  strlen(test_certificate_ecdsa));
		if (err)
			goto out;
		break;

	default:
		err = EINVAL;
		goto out;
	}

	if (add_ca) {
		char cafile[256];

		re_snprintf(cafile, sizeof(cafile), "%s/server-ecdsa.pem",
			    test_datapath());

		err = tls_add_ca(tt.tls, cafile);
		if (err)
			goto out;
	}

	err = tcp_listen(&tt.ts, &srv, server_conn_handler, &tt);
	if (err)
		goto out;

	err = tcp_sock_local_get(tt.ts, &srv);
	if (err)
		goto out;

	err = tls_set_session_reuse(tt.tls, test_sess_reuse);
	if (err)
		goto out;

	for (i = 0; i < rounds; i++) {
		tt.send_done_cli = false;
		err = tcp_connect(&tt.tc_cli, &srv, client_estab_handler,
			client_recv_handler, client_close_handler, &tt);
		if (err)
			goto out;

		err = tls_start_tcp(&tt.sc_cli, tt.tls, tt.tc_cli, 0);
		if (err)
			goto out;

		if (exp_verr == 0) {

			err = tls_set_verify_server(tt.sc_cli, "127.0.0.1");
			if (err)
				goto out;
		}

		err = re_main_timeout(800);
		if (err)
			goto out;

		if (tt.err) {
			err = tt.err;
			goto out;
		}

		TEST_EQUALS(true, tt.estab_cli);
		TEST_EQUALS(true, tt.estab_srv);
		TEST_EQUALS(1, tt.recv_cli);
		TEST_EQUALS(1+i, tt.recv_srv);

		verr = tls_peer_verify(tt.sc_cli);
		TEST_EQUALS(exp_verr, verr);

		if (test_sess_reuse) {
			TEST_EQUALS(i == 0 ? false : true,
				tls_session_reused(tt.sc_cli));
		}

		tt.sc_cli = mem_deref(tt.sc_cli);
		tt.sc_srv = mem_deref(tt.sc_srv);
		tt.tc_cli = mem_deref(tt.tc_cli);
		tt.tc_srv = mem_deref(tt.tc_srv);
		tt.estab_cli = false;
		tt.estab_srv = false;
		tt.recv_cli = 0;
	}

 out:
	/* NOTE: close context first */
	mem_deref(tt.tls);

	mem_deref(tt.sc_cli);
	mem_deref(tt.sc_srv);
	mem_deref(tt.tc_cli);
	mem_deref(tt.tc_srv);
	mem_deref(tt.ts);

	return err;
}


int test_tls_session_reuse_tls_v12(void)
{
	return test_tls_base(TLS_KEYTYPE_EC, false, EAUTH, true,
		TLS1_2_VERSION);
}


/* TLS v1.3 session reuse is not yet supported by libre */
int test_tls_session_reuse(void)
{
	return test_tls_base(TLS_KEYTYPE_EC, false, EAUTH, true, -1);
}


int test_tls(void)
{
	return test_tls_base(TLS_KEYTYPE_EC, false, EAUTH, false, -1);
}


int test_tls_ec(void)
{
	int err;

	err = test_tls_base(TLS_KEYTYPE_EC, false, EAUTH, false, -1);
	TEST_ERR(err);

	err = test_tls_base(TLS_KEYTYPE_EC, true, 0, false, -1);
	TEST_ERR(err);

out:
	return err;
}


int test_tls_selfsigned(void)
{
	struct tls *tls = NULL;
	uint8_t fp[32];
	int err;

	err = tls_alloc(&tls, TLS_METHOD_SSLV23, NULL, NULL);
	if (err)
		goto out;

	err = tls_set_selfsigned_ec(tls, "re_ec@test", "unknown");
	TEST_EQUALS(err, ENOTSUP);

	err = tls_set_selfsigned_ec(tls, "re_ec@test", "prime256v1");
	TEST_ERR(err);

	/* verify fingerprint of the self-signed certificate */
	err = tls_fingerprint(tls, TLS_FINGERPRINT_SHA256, fp, sizeof(fp));
	TEST_ERR(err);

 out:
	mem_deref(tls);
	return err;
}


int test_tls_certificate(void)
{
	struct tls *tls = NULL;
	static const uint8_t test_fingerprint[32] =
		"\x50\x5d\x95\x2b\xef\x5b\x6f\x7f"
		"\x2b\x4a\xa8\x1b\xdd\xe1\x99\xfd"
		"\x4e\xb5\xc1\x04\xe7\x67\xa7\x48"
		"\xb1\xf1\x66\x35\x98\xdc\x84\xc6";
	uint8_t fp[32];
	struct mbuf *mb = NULL;
	int err;

	err = tls_alloc(&tls, TLS_METHOD_SSLV23, NULL, NULL);
	if (err)
		goto out;

	mb = mbuf_alloc(20);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err = tls_get_subject(tls, mb);
	TEST_EQUALS(ENOENT, err);

	err = tls_set_certificate(tls, test_certificate_ecdsa,
				  strlen(test_certificate_ecdsa));
	TEST_EQUALS(0, err);

	/* verify fingerprint of the certificate */
	err = tls_fingerprint(tls, TLS_FINGERPRINT_SHA256, fp, sizeof(fp));
	TEST_ERR(err);

	TEST_MEMCMP(test_fingerprint, sizeof(test_fingerprint),
		    fp, sizeof(fp));

	err = tls_get_subject(tls, mb);
	TEST_ERR(err);

 out:
	mem_deref(tls);
	mem_deref(mb);
	return err;
}


int test_tls_false_cafile_path(void)
{
	int err = 0;
	struct tls *tls = NULL;
	const char *cafile_wrong = "/some/path/to/wrong/file.crt";
	const char *capath_wrong = "/some/path/to/nothing";

	err = tls_alloc(&tls, TLS_METHOD_SSLV23, NULL, NULL);
	if (err)
		goto out;

	err = tls_add_cafile_path(tls, NULL, NULL);
	TEST_EQUALS(EINVAL, err);

	err = tls_add_cafile_path(tls, cafile_wrong, NULL);
	TEST_EQUALS(ENOENT, err);

	err = tls_add_cafile_path(tls, NULL, capath_wrong);
	TEST_EQUALS(ENOTDIR, err);

	err = tls_add_cafile_path(tls, cafile_wrong, capath_wrong);
	TEST_EQUALS(ENOTDIR, err);

	err = 0;

  out:
	mem_deref(tls);
	return err;
}


int test_tls_cli_conn_change_cert(void)
{
	struct tls_test tt;
	struct sa srv;
	int err;
	char clientcert[256];
	char clientcert_cn[256];
	char *exp_clientcert_cn = "Mr Retest Client Cert";

	memset(&tt, 0, sizeof(tt));

	tt.keytype = TLS_KEYTYPE_EC;

	err = sa_set_str(&srv, "127.0.0.1", 0);
	if (err)
		goto out;

	err = tls_alloc(&tt.tls, TLS_METHOD_SSLV23, NULL, NULL);
	if (err)
		goto out;

	tls_set_verify_client_trust_all(tt.tls);

	err = tls_set_certificate(tt.tls, test_certificate_ecdsa,
		strlen(test_certificate_ecdsa));
	if (err)
		goto out;

	err = tcp_listen(&tt.ts, &srv, server_conn_handler, &tt);
	if (err)
		goto out;

	err = tcp_sock_local_get(tt.ts, &srv);
	if (err)
		goto out;

	err = tcp_connect(&tt.tc_cli, &srv, client_estab_handler,
			  client_recv_handler, client_close_handler, &tt);
	if (err)
		goto out;

	err = tls_start_tcp(&tt.sc_cli, tt.tls, tt.tc_cli, 0);
	if (err)
		goto out;

	/* actuall test cases*/
	err = tls_conn_change_cert(tt.sc_cli, NULL);
	TEST_EQUALS(EINVAL, err);

	err = tls_conn_change_cert(NULL, clientcert);
	TEST_EQUALS(EINVAL, err);

	memset(clientcert, 0, sizeof(clientcert));
	(void)re_snprintf(clientcert, sizeof(clientcert),
		"%s/not_a_file.pem", test_datapath());

	int ret = tls_conn_change_cert(tt.sc_cli, clientcert);
	ASSERT_TRUE(ret==EINVAL || ret==ENOENT || ret==ENOSYS);

	if (ret == ENOSYS) {
		err = 0;
		goto out;
	}

	memset(clientcert, 0, sizeof(clientcert));
	(void)re_snprintf(clientcert, sizeof(clientcert),
		"%s/client_wrongkey.pem", test_datapath());

	err = tls_conn_change_cert(tt.sc_cli, clientcert);
	TEST_EQUALS(EKEYREJECTED, err);

	memset(clientcert, 0, sizeof(clientcert));
	(void)re_snprintf(clientcert, sizeof(clientcert), "%s/client.pem",
		test_datapath());

	err = tls_conn_change_cert(tt.sc_cli, clientcert);
	if (err)
		goto out;

	err = re_main_timeout(800);
	if (err)
		goto out;

	err = tls_peer_common_name(tt.sc_srv, clientcert_cn,
		sizeof(clientcert_cn));
	if (err) {
		if (!tt.sc_srv) {
			TEST_EQUALS(EINVAL, err);
			err = 0;
			goto out;
		}
	}

	TEST_STRCMP(exp_clientcert_cn, strlen(exp_clientcert_cn),
		clientcert_cn, strlen(clientcert_cn));

	if (tt.err) {
		err = tt.err;
		goto out;
	}

 out:
	/* NOTE: close context first */
	mem_deref(tt.tls);

	mem_deref(tt.sc_cli);
	mem_deref(tt.sc_srv);
	mem_deref(tt.tc_cli);
	mem_deref(tt.tc_srv);
	mem_deref(tt.ts);

	return err;
}


/**
 * SNI Test
 *
 * - UAS opens a TLS connection to UAC by sending a client hello with SNI
 * - UAC chooses a certificate with matching SNI
 * - UAC verifies the chain and common name of the UAS
 * - UAS verifies the chain and common name of the UAC
 *
 * @return 0 if success, otherwise errorcode
 */
int test_tls_sni(void)
{
	struct tls_test tt;
	struct sa srv;
	int err;
	const char *dp = test_datapath();
	char path[256];

	memset(&tt, 0, sizeof(tt));

	err = sa_set_str(&srv, "127.0.0.1", 0);
	TEST_ERR(err);

	/* UAC global not matching cert (test checks that it is not used) */
	re_snprintf(path, sizeof(path), "%s/client.pem", dp);
	err = tls_alloc(&tt.tls, TLS_METHOD_SSLV23, path, NULL);
	TEST_ERR(err);

	/* UAS cert + intermediate CA */
	re_snprintf(path, sizeof(path), "%s/sni/server-interm.pem", dp);
	err = tls_alloc(&tt.tls2, TLS_METHOD_SSLV23, path, NULL);
	TEST_ERR(err);

	/* set root CA at UAC and UAS */
	re_snprintf(path, sizeof(path), "%s/sni/root-ca.pem", dp);
	err  = tls_add_ca(tt.tls, path);
	err |= tls_add_ca(tt.tls2, path);
	TEST_ERR(err);

	/* UAC cert + intermediate CA */
	re_snprintf(path, sizeof(path), "%s/sni/client-interm.pem", dp);
	err = tls_add_certf(tt.tls, path, "retest.server.org");
	TEST_ERR(err);

	/* UAC listens (as TLS server)*/
	err = tcp_listen(&tt.ts, &srv, server_conn_handler, &tt);
	TEST_ERR(err);

	err = tcp_sock_local_get(tt.ts, &srv);
	TEST_ERR(err);

	/* UAS connects to UAC (as TLS client) */
	err = tcp_connect(&tt.tc_cli, &srv, client_estab_handler,
			  client_recv_handler, client_close_handler, &tt);
	TEST_ERR(err);

	err = tls_start_tcp(&tt.sc_cli, tt.tls2, tt.tc_cli, 0);
	TEST_ERR(err);

	err = tls_set_verify_server(tt.sc_cli, "retest.client.org");
	TEST_ERR(err);

	err = re_main_timeout(800);
	TEST_ERR(err);

	if (tt.err) {
		err = tt.err;
		goto out;
	}

	ASSERT_TRUE(tt.estab_cli);
	ASSERT_TRUE(tt.estab_srv);
	ASSERT_EQ(1, tt.recv_cli);
	ASSERT_EQ(1, tt.recv_srv);

	err = tls_peer_verify(tt.sc_cli);
	ASSERT_EQ(0, err);

 out:
	/* NOTE: close context first */
	mem_deref(tt.tls);
	mem_deref(tt.tls2);
	mem_deref(tt.sc_cli);
	mem_deref(tt.sc_srv);
	mem_deref(tt.tc_cli);
	mem_deref(tt.tc_srv);
	mem_deref(tt.ts);

	return err;
}
