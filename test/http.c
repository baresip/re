/**
 * @file http.c HTTP Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_http"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

enum large_body_test {
	REQ_BODY_CHUNK_SIZE = 26 * 42,
	REQ_BODY_SIZE = REQ_BODY_CHUNK_SIZE * 480 - 26,
	REQ_HTTP_REQUESTS = 2
};

enum {
	IP_127_0_0_1 = 0x7f000001,
};

static int test_http_response_no_reasonphrase(void)
{
	struct http_msg *msg = NULL;
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = mbuf_write_str(mb, /*       _---- no space here! */
			     "HTTP/1.1 429\r\n"
			     "Server: nginx\r\n"
			     "Content-Length: 0\r\n"
			     "\r\n");
	if (err)
		goto out;

	mb->pos = 0;

	err = http_msg_decode(&msg, mb, false);
	if (err)
		goto out;

	TEST_STRCMP("1.1", 3, msg->ver.p, msg->ver.l);
	TEST_EQUALS(429, msg->scode);
	TEST_STRCMP("", 0, msg->reason.p, msg->reason.l);

 out:
	mem_deref(msg);
	mem_deref(mb);
	return err;
}


int test_http(void)
{
	static const char req[] =
		"GET /path/file.html HTTP/1.1\r\n"
		"From: plopp@klukk.no\r\n"
		"User-Agent: libre HTTP client/1.0\r\n"
		"Allow: GET, HEAD, PUT\r\n"
		"\r\n"
		"";
	struct mbuf *mb;
	struct http_msg *msg = NULL;
	const struct http_hdr *hdr;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = mbuf_write_str(mb, req);
	if (err)
		goto out;

	mb->pos = 0;
	err = http_msg_decode(&msg, mb, true);
	if (err)
		goto out;

	if (0 != pl_strcmp(&msg->met, "GET"))              goto badmsg;
	if (0 != pl_strcmp(&msg->path, "/path/file.html")) goto badmsg;
	if (0 != pl_strcmp(&msg->ver, "1.1"))              goto badmsg;
	if (pl_isset(&msg->prm))                           goto badmsg;

	hdr = http_msg_hdr(msg, HTTP_HDR_FROM);
	if (!hdr || 0 != pl_strcmp(&hdr->val, "plopp@klukk.no"))
		goto badmsg;
	hdr = http_msg_hdr(msg, HTTP_HDR_USER_AGENT);
	if (!hdr || 0 != pl_strcmp(&hdr->val, "libre HTTP client/1.0"))
		goto badmsg;
	hdr = http_msg_hdr(msg, HTTP_HDR_CONTENT_TYPE);
	if (hdr)
		goto badmsg;
	if (msg->clen != 0)
		goto badmsg;

	if (!http_msg_hdr_has_value(msg, HTTP_HDR_ALLOW, "GET")  ||
	    !http_msg_hdr_has_value(msg, HTTP_HDR_ALLOW, "HEAD") ||
	    !http_msg_hdr_has_value(msg, HTTP_HDR_ALLOW, "PUT"))
		goto badmsg;
	if (3 != http_msg_hdr_count(msg, HTTP_HDR_ALLOW))
		goto badmsg;

	err = test_http_response_no_reasonphrase();
	if (err)
		goto out;

	goto out;

 badmsg:
	(void)re_fprintf(stderr, "%H\n", http_msg_print, msg);
	err = EBADMSG;

 out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


struct test {
	struct mbuf *mb_body;
	size_t clen;
	uint32_t n_request;
	uint32_t n_response;
	size_t i_req_body;
	bool secure;
	bool cert_auth;
	int err;
};


static void abort_test(struct test *t, int err)
{
	t->err = err;
	re_cancel();
}


static enum re_https_verify_msg https_verify_msg_handler(
	struct http_conn *conn, const struct http_msg *msg, void *arg)
{
	(void) conn;
	struct test *t = arg;
	int err = 0;
	enum re_https_verify_msg res = HTTPS_MSG_OK;

	if (!t->cert_auth)
		goto out;

	TEST_STRCMP("/auth/index.html", 11+5, msg->path.p, msg->path.l);

	/* cert authorisation required, request client certificate */
	res = HTTPS_MSG_REQUEST_CERT;
out:
	if (err) {
		res = HTTPS_MSG_IGNORE;
		abort_test(t, err);
	}

	return res;
}


static void http_req_handler(struct http_conn *conn,
			     const struct http_msg *msg, void *arg)
{
	struct test *t = arg;
	struct mbuf *mb_body = mbuf_alloc(1024);
	int err = 0;

	if (!mb_body) {
		err = ENOMEM;
		goto out;
	}

	++t->n_request;

	if (t->secure) {
		TEST_ASSERT(http_conn_tls(conn) != NULL);
	}
	else {
		TEST_ASSERT(http_conn_tls(conn) == NULL);
	}

	/* verify HTTP request */
	TEST_STRCMP("1.1", 3, msg->ver.p, msg->ver.l);
	TEST_STRCMP("GET", 3, msg->met.p, msg->met.l);
	if (t->cert_auth) {
		TEST_STRCMP("/auth/index.html", 11+5, msg->path.p,
			msg->path.l);
	}
	else {
		TEST_STRCMP("/index.html", 11, msg->path.p, msg->path.l);
	}

	TEST_STRCMP("", 0, msg->prm.p, msg->prm.l);
	TEST_EQUALS(t->clen, msg->clen);
	TEST_STRCMP("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", 52,
		mbuf_buf(msg->mb), mbuf_get_left(msg->mb));

	/* Create a chunked response body */
	err = mbuf_write_str(mb_body,
			     "2\r\n"
			     "ab\r\n"

			     "4\r\n"
			     "cdef\r\n"

			     "8\r\n"
			     "ghijklmn\r\n"

			     "c\r\n"
			     "opqrstuvwxyz\r\n"

			     "0\r\n"
			     "\r\n"
			     );
	if (err)
		goto out;

	t->clen = mb_body->end;
	err = http_reply(conn, 200, "OK",
			"Transfer-Encoding: chunked\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %zu\r\n"
			"\r\n"
			"%b",
			mb_body->end,
			mb_body->buf, mb_body->end
			);

 out:
	mem_deref(mb_body);
	if (err)
		abort_test(t, err);
}


static void http_put_req_handler(struct http_conn *conn,
			     const struct http_msg *msg, void *arg)
{
	struct test *t = arg;
	struct mbuf *mb_body = mbuf_alloc(1024);
	int err = 0;
	size_t l = 0;
	size_t cmp_len;

	if (!mb_body) {
		err = ENOMEM;
		goto out;
	}

	++t->n_request;

	if (t->secure) {
		TEST_ASSERT(http_conn_tls(conn) != NULL);
	}
	else {
		TEST_ASSERT(http_conn_tls(conn) == NULL);
	}

	/* verify HTTP request */
	TEST_STRCMP("1.1", 3, msg->ver.p, msg->ver.l);
	TEST_STRCMP("PUT", 3, msg->met.p, msg->met.l);
	TEST_STRCMP("/index.html", 11, msg->path.p, msg->path.l);
	TEST_STRCMP("", 0, msg->prm.p, msg->prm.l);
	TEST_EQUALS(t->clen, msg->clen);

	l = mbuf_get_left(msg->mb);

	while (l > 0) {
		cmp_len = min(l, 26);
		TEST_STRCMP("abcdefghijklmnopqrstuvwxyz", cmp_len,
			mbuf_buf(msg->mb), cmp_len);
		mbuf_advance(msg->mb, cmp_len);
		l -= cmp_len;
	}

	/* Create a chunked response body */
	err = mbuf_write_str(mb_body,
			     "2\r\n"
			     "ab\r\n"

			     "4\r\n"
			     "cdef\r\n"

			     "8\r\n"
			     "ghijklmn\r\n"

			     "c\r\n"
			     "opqrstuvwxyz\r\n"

			     "0\r\n"
			     "\r\n"
			     );
	if (err)
		goto out;

	t->clen = mb_body->end;

	err = http_reply(conn, 200, "OK",
			 "Transfer-Encoding: chunked\r\n"
			 "Content-Type: text/plain\r\n"
			 "Content-Length: %zu\r\n"
			 "\r\n"
			 "%b",
			 mb_body->end,
			 mb_body->buf, mb_body->end
			 );

 out:
	mem_deref(mb_body);
	if (err)
		abort_test(t, err);
}


static void http_resp_handler(int err, const struct http_msg *msg, void *arg)
{
	struct test *t = arg;
	bool chunked;

	if (err) {
		/* translate error code */
		err = ENOMEM;
		goto out;
	}

#if 0
	re_printf("%H\n", http_msg_print, msg);
	re_printf("BODY: %b\n", msg->mb->buf, msg->mb->end);
#endif

	++t->n_response;

	/* verify HTTP response */
	TEST_STRCMP("1.1", 3, msg->ver.p, msg->ver.l);
	TEST_STRCMP("", 0, msg->met.p, msg->met.l);
	TEST_STRCMP("", 0, msg->path.p, msg->path.l);
	TEST_STRCMP("", 0, msg->prm.p, msg->prm.l);
	TEST_EQUALS(200, msg->scode);
	TEST_STRCMP("OK", 2, msg->reason.p, msg->reason.l);
	TEST_EQUALS(t->clen, msg->clen);

	chunked = http_msg_hdr_has_value(msg, HTTP_HDR_TRANSFER_ENCODING,
					 "chunked");
	TEST_ASSERT(chunked);

	TEST_STRCMP("text", 4, msg->ctyp.type.p, msg->ctyp.type.l);
	TEST_STRCMP("plain", 5, msg->ctyp.subtype.p, msg->ctyp.subtype.l);

	re_cancel();

 out:
	if (err)
		abort_test(t, err);
}


static int http_data_handler(const uint8_t *buf, size_t size,
			     const struct http_msg *msg, void *arg)
{
	struct test *t = arg;
	(void)msg;

	if (!t->mb_body)
		t->mb_body = mbuf_alloc(256);
	if (!t->mb_body)
		return 0;

	return mbuf_write_mem(t->mb_body, buf, size);
}


static size_t http_req_body_handler(struct mbuf *mb, void *arg)
{
	struct test *t = arg;

	if (t->i_req_body >= t->clen)
		return 0;

	if (mbuf_write_mem(mb,
			(const uint8_t*) "abcdefghijklmnopqrstuvwxyz",
			strlen("abcdefghijklmnopqrstuvwxyz"))) {
		mbuf_reset(mb);
		return 0;
	}

	t->i_req_body += strlen("abcdefghijklmnopqrstuvwxyz");
	return strlen("abcdefghijklmnopqrstuvwxyz");
}


static size_t http_req_long_body_handler(struct mbuf *mb, void *arg)
{
	struct test *t = arg;
	size_t l = 0;
	size_t wlen;

	/* Create a chunked response body */
	while ( l < REQ_BODY_CHUNK_SIZE && t->i_req_body < t->clen) {
		wlen = min(min(26, REQ_BODY_CHUNK_SIZE - l),
			t->clen - t->i_req_body);
		if (wlen <= 0)
			return l;

		if (mbuf_write_mem(mb,
			(const uint8_t*) "abcdefghijklmnopqrstuvwxyz",
			wlen)) {
			mbuf_reset(mb);
			return 0;
		}
		l += wlen;
		t->i_req_body += (uint32_t)wlen;
	}

	return l;
}


static int test_http_loop_base(bool secure, const char *met, bool http_conn,
	bool dns_srv_query, bool dns_set_conf_test, bool post_handshake)
{
	struct http_sock *sock = NULL;
	struct http_cli *cli = NULL;
	struct http_req *req = NULL;
	struct http_reqconn *conn = NULL;
	struct dnsc *dnsc = NULL;
	struct dns_server *dns_srv = NULL;
	struct sa srv, dns;
	struct test t;
	char url[256];
	char path[256];
	int err = 0;
	unsigned int i;
	bool put = false;
	struct mbuf *mb_body = NULL;
	struct pl pl;
	struct dnsc_conf dconf;
	struct http_conf hconf = {
		30000,
		30000,
		900000,
	};


	if (!strcmp(met, "PUT"))
		put = true;

	memset(&t, 0, sizeof(t));

	t.secure = secure;
	t.cert_auth = secure && post_handshake;

	if (dns_srv_query) {
		/* Setup Mocking DNS Server */
		err = dns_server_alloc(&dns_srv, false);
		TEST_ERR(err);

		err = dns_server_add_a(dns_srv, "test1.example.net",
			IP_127_0_0_1, 1);
		TEST_ERR(err);
	}

	err |= sa_set_str(&srv, "127.0.0.1", 0);
	err |= sa_set_str(&dns, "127.0.0.1", 53);    /* note: unused */
	TEST_ERR(err);

	if (secure) {
		if (t.cert_auth)
			re_snprintf(path, sizeof(path),
				"%s/sni/server-interm.pem", test_datapath());
		else
			re_snprintf(path, sizeof(path), "%s/server-ecdsa.pem",
					test_datapath());

		err = https_listen(&sock, &srv, path,
			put ? http_put_req_handler : http_req_handler, &t);
		if (err)
			goto out;

		if (t.cert_auth)
			err = https_set_verify_msgh(sock,
				https_verify_msg_handler);
	}
	else {
		err = http_listen(&sock, &srv,
			put ? http_put_req_handler : http_req_handler, &t);
	}
	if (err)
		goto out;

	err = tcp_sock_local_get(http_sock_tcp(sock), &srv);
	if (err)
		goto out;

	err = dnsc_alloc(&dnsc, NULL, dns_srv ? &dns_srv->addr : &dns, 1);
	if (err)
		goto out;

	dconf.query_hash_size = 16;
	dconf.tcp_hash_size	 = 2;
	dconf.conn_timeout	 = hconf.conn_timeout;
	dconf.idle_timeout	 = hconf.idle_timeout;
	dconf.cache_ttl_max	 = 1800;
	dconf.getaddrinfo	 = dnsc_getaddrinfo_enabled(dnsc);

	err = http_client_alloc(&cli, dnsc);
	if (err)
		goto out;

	if (secure) {
		struct tls*	 cli_tls;
		http_client_get_tls(cli, &cli_tls);

		if (t.cert_auth) {
			re_snprintf(path, sizeof(path),
				"%s/sni/client-interm.pem", test_datapath());
			err |= http_client_set_cert(cli, path);
			err |= http_client_set_key(cli, path);
			if (err)
				goto out;

			tls_set_posthandshake_auth(cli_tls, 1);

			/* add CAs to http server */
			re_snprintf(path, sizeof(path), "%s/sni/root-ca.pem",
				test_datapath());

			err |=  tls_add_ca(http_sock_tls(sock), path);
			re_snprintf(path, sizeof(path),
				"%s/sni/server-interm.pem", test_datapath());

			err |=  tls_add_ca(http_sock_tls(sock), path);
			if (err)
				goto out;
		}

		if (http_conn && !t.cert_auth)
			err = tls_set_session_reuse(cli_tls, true);

		if (err)
			goto out;
	}

	if (put)
		http_client_set_bufsize_max(cli, REQ_BODY_CHUNK_SIZE + 128);

#ifdef USE_TLS
	/* add root CA to http client */
	if (secure) {
		if (t.cert_auth)
			re_snprintf(path, sizeof(path), "%s/sni/root-ca.pem",
					test_datapath());
		else
			re_snprintf(path, sizeof(path), "%s/server-ecdsa.pem",
					test_datapath());
		err = http_client_add_ca(cli, path);
		if (err)
			goto out;
	}

	if (t.cert_auth) {
		re_snprintf(path, sizeof(path), "%s/sni/client-interm.pem",
				test_datapath());
		err |= http_client_set_cert(cli, path);
		err |= http_client_set_key(cli, path);
		if (err)
			goto out;
	}
#endif

	(void)re_snprintf(url, sizeof(url),
					"http%s://%s:%u/%sindex.html",
					secure ? "s" : "",
					dns_srv_query ?
					"test1.example.net"
					: "127.0.0.1",
					sa_port(&srv),
					t.cert_auth ? "auth/" : "");

	for (i = 1; i <= 10*REQ_HTTP_REQUESTS; i++) {
		t.i_req_body = 0;

		err = http_client_set_config(cli, &hconf);
		if (err)
			goto out;

		if (dns_set_conf_test) {
			err = dnsc_conf_set(dnsc, &dconf);
			if (err)
				goto out;
		}

		t.clen = put ? REQ_BODY_SIZE :
			2 * strlen("abcdefghijklmnopqrstuvwxyz");


		if (http_conn) {
			err = http_reqconn_alloc(&conn, cli,
				http_resp_handler, http_data_handler, &t);
			if (err)
				goto out;

			if (put) {
				err = http_reqconn_set_req_bodyh(conn,
					put ? 	http_req_long_body_handler :
						http_req_body_handler,
					t.clen);
				if (err)
					goto out;

				pl_set_str(&pl, "PUT");
				err = http_reqconn_set_method(conn, &pl);
				if (err)
					goto out;
			}
			else {
				mb_body = mbuf_alloc(t.clen);
				if (!mb_body)
					goto out;

				if (mbuf_write_str(mb_body,
					"abcdefghijklmnopqrstuvwxyz"\
					"abcdefghijklmnopqrstuvwxyz"))
					goto out;

				err = http_reqconn_set_body(conn, mb_body);
				mb_body = mem_deref(mb_body);
				if (err)
					goto out;
			}

			pl_set_str(&pl, url);
			err = http_reqconn_send(conn, &pl);
		}
		else {
			err = http_request(&req, cli, met, url,
				http_resp_handler, http_data_handler,
				put ? 	http_req_long_body_handler :
					http_req_body_handler,
				&t,
				"Content-Length: %zu\r\n%s\r\n%s",
				t.clen,
				t.clen > REQ_BODY_CHUNK_SIZE ?
					"Expect: 100-continue\r\n" : "",
				"abcdefghijklmnopqrstuvwxyz");
		}

		if (err)
			goto out;

		err = re_main_timeout(secure ? 1800 : 900);
		if (err)
			goto out;

		if (t.err) {
			err = t.err;
			goto out;
		}

		/* verify results after HTTP traffic */
		TEST_EQUALS(i, t.n_request);
		TEST_EQUALS(i, t.n_response);

		if (t.mb_body)
			TEST_STRCMP("abcdefghijklmnopqrstuvwxyz", 26,
				t.mb_body->buf, t.mb_body->end);

		t.mb_body = mem_deref(t.mb_body);
		req =  mem_deref(req);
		conn = mem_deref(conn);
	}

 out:
	mem_deref(t.mb_body);
	mem_deref(mb_body);
	mem_deref(req);
	mem_deref(conn);
	mem_deref(cli);
	mem_deref(dnsc);
	mem_deref(sock);
	mem_deref(dns_srv);

	return err;
}


#ifdef USE_TLS
int test_http_client_set_tls(void)
{
	struct sa dns;
	struct dnsc *dnsc = NULL;
	struct http_cli *cli = NULL;
	struct tls *tls = NULL, *tls_test = NULL, *tls_cli = NULL;
	int err;

	TEST_EINVAL(http_client_get_tls, NULL, NULL);
	TEST_EINVAL(http_client_set_tls, NULL, NULL);

	/* Setup */
	err = sa_set_str(&dns, "127.0.0.1", 53);    /* note: unused */
	TEST_ERR(err);

	err = dnsc_alloc(&dnsc, NULL, &dns, 1);
	TEST_ERR(err);

	err = http_client_alloc(&cli, dnsc);
	TEST_ERR(err);

	/* Test original Http Client TLS Context */
	TEST_EINVAL(http_client_get_tls, cli, NULL);
	err = http_client_get_tls(cli, &tls_cli);
	TEST_ERR(err);
	tls_cli = mem_ref(tls_cli);
	TEST_EQUALS(2, mem_nrefs(tls_cli));

	/* Allocate new TLS Context */
	err = tls_alloc(&tls, TLS_METHOD_SSLV23, NULL, NULL);
	TEST_ERR(err);
	TEST_NOT_EQUALS(tls, tls_cli);

	/* Set and verify new TLS Context */
	TEST_EINVAL(http_client_set_tls, cli, NULL);
	err = http_client_set_tls(cli, tls);
	TEST_ERR(err);
	TEST_EQUALS(2, mem_nrefs(tls));
	TEST_EQUALS(1, mem_nrefs(tls_cli));

	err = http_client_get_tls(cli, &tls_test);
	TEST_ERR(err);

	TEST_EQUALS(tls, tls_test);

out:
	if (cli) {
		mem_deref(cli);
		mem_deref(tls_cli);
	}

	if (dnsc)
		mem_deref(dnsc);

	if (tls) {
		TEST_EQUALS(1, mem_nrefs(tls));
		mem_deref(tls);
	}

	return err;
}
#endif


int test_http_loop(void)
{
	return test_http_loop_base(false, "GET", false, false, false, false);
}


#ifdef USE_TLS
int test_https_loop(void)
{
	return test_http_loop_base(true, "GET", false, false, false, false);
}
#endif


int test_http_large_body(void)
{
	return test_http_loop_base(false, "PUT", false, false, false, false);
}


#ifdef USE_TLS
int test_https_large_body(void)
{
	return test_http_loop_base(true, "PUT", false, false, false, false);
}
#endif


int test_http_conn(void)
{
	return test_http_loop_base(false, "GET", true, false, false, false);
}


int test_http_conn_large_body(void)
{
	return test_http_loop_base(false, "PUT", true, false, false, false);
}


int test_dns_http_integration(void)
{
	return test_http_loop_base(false, "GET", true, true, false, false);
}


int test_dns_cache_http_integration(void)
{
	return test_http_loop_base(false, "GET", true, true, true, false);
}

#ifdef USE_TLS
int test_https_conn_post_handshake(void)
{
	return test_http_loop_base(true, "GET", true, false, false, true);
}

#endif
