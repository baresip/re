/**
 * @file httpauth.c HTTP Authentication Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "httpauth"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int pl_equal(const char *name, const struct pl *a, const struct pl *b)
{
	static const struct pl plnil = PL("nil");
	int err;

	if ((a->p && !b->p) || (!a->p && b->p))
		err = EINVAL;
	else
		err = pl_cmp(a, b);

	if (err) {
		DEBUG_WARNING("%s mismatch: '%r' vs '%r'\n",
			      name,
			      a->p ? a : &plnil,
			      b->p ? b : &plnil);
	}

	return err;
}


static bool chall_equal(const struct httpauth_digest_chall *a,
			const struct httpauth_digest_chall *b)
{
	int err = 0;

	err |= pl_equal("realm",     &a->realm,     &b->realm);
	err |= pl_equal("nonce",     &a->nonce,     &b->nonce);
	err |= pl_equal("opaque",    &a->opaque,    &b->opaque);
	err |= pl_equal("stale",     &a->stale,     &b->stale);
	err |= pl_equal("algorithm", &a->algorithm, &b->algorithm);
	err |= pl_equal("qop",       &a->qop,       &b->qop);

	return err == 0;
}


static bool resp_equal(const struct httpauth_digest_resp *a,
		       const struct httpauth_digest_resp *b)
{
	int err = 0;

	err |= pl_equal("realm",     &a->realm,     &b->realm);
	err |= pl_equal("nonce",     &a->nonce,     &b->nonce);
	err |= pl_equal("response",  &a->response,  &b->response);
	err |= pl_equal("username",  &a->username,  &b->username);
	err |= pl_equal("uri",       &a->uri,       &b->uri);
	err |= pl_equal("nc",        &a->nc,        &b->nc);
	err |= pl_equal("cnonce",    &a->cnonce,    &b->cnonce);
	err |= pl_equal("qop",       &a->qop,       &b->qop);

	return err == 0;
}


int test_httpauth_chall(void)
{
	static const struct {
		const char *hval;
		struct httpauth_digest_chall chall;
		int err;
	} testv[] = {
		{
			"Digest realm=\"realm\","
			" nonce=\"4ee102da2fb730e04a26e8da913249b264f391c3\","
			" opaque=\"123\", stale=\"true\""
			" algorithm=\"MD5\""
			,
			{PL("realm"),
			 PL("4ee102da2fb730e04a26e8da913249b264f391c3"),
			 PL("123"),
			 PL("true"),
			 PL("MD5"),
			 PL_INIT,
			 PL_INIT,
			 PL_INIT,
			 PL_INIT},
			0
		},

		{
			"Digest realm=\"creytiv.com\","
			" nonce=\"9c916919cbc6ad7f54a4f64e5b5115074ee109fa\""
			", qop=\"auth\"",
			{PL("creytiv.com"),
			 PL("9c916919cbc6ad7f54a4f64e5b5115074ee109fa"),
			 PL_INIT, PL_INIT, PL_INIT,
			 PL("auth"),
			 PL_INIT, PL_INIT, PL_INIT
			},
			0
		},

		{
			"Basic bogus",
			{PL_INIT, PL_INIT, PL_INIT, PL_INIT, PL_INIT, PL_INIT,
			 PL_INIT, PL_INIT, PL_INIT},
			EBADMSG
		},
	};
	size_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		struct httpauth_digest_chall chall;
		struct pl pl;
		int terr;

		pl_set_str(&pl, testv[i].hval);
		terr = httpauth_digest_challenge_decode(&chall, &pl);
		if (terr != testv[i].err) {
			DEBUG_WARNING("chall: expected error %d, got %d\n",
				      testv[i].err, terr);
			break;
		}

		if (terr)
			continue;

		if (!chall_equal(&testv[i].chall, &chall)) {
			DEBUG_WARNING("chall: test %d failed\n", i);
			err = EBADMSG;
			break;
		}
	}

	return err;
}


int test_httpauth_resp(void)
{
	static const struct {
		const char *hval;
		struct httpauth_digest_resp resp;
		struct pl method;
		uint8_t ha1[MD5_SIZE];
		int err;
	} testv[] = {
		{

			"Digest username=\"aeh\", realm=\"creytiv.com\","
			" nonce=\"9c916919cbc6ad7f54a4f64e5b5115074ee109fa\""
			", uri=\"sip:creytiv.com;transport=udp\","
			" response=\"bb996865add5a86217f39e1f369c29ea\","
			" cnonce=\"66a7a21e46ad8edd\", qop=auth, nc=00000002"
			,
			{PL("creytiv.com"),
			 PL("9c916919cbc6ad7f54a4f64e5b5115074ee109fa"),
			 PL("bb996865add5a86217f39e1f369c29ea"),
			 PL("aeh"),
			 PL("sip:creytiv.com;transport=udp"),
			 PL("00000002"),
			 PL("66a7a21e46ad8edd"),
			 PL("auth"),
			 NULL},
			PL("REGISTER"),
			"\x1c\x0a\x98\x61\x5b\x7b\x37\xc6"
			"\x94\x51\xae\xb6\x4b\x2f\x11\x02",
			0
		},
		{
			"Digest bogus tull",
			{PL_INIT, PL_INIT, PL_INIT, PL_INIT,
			 PL_INIT, PL_INIT, PL_INIT, PL_INIT, NULL},
			PL_INIT,
			"",
			EBADMSG
		},
	};
	size_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		struct httpauth_digest_resp resp;
		struct pl pl;
		int terr;

		pl_set_str(&pl, testv[i].hval);
		terr = httpauth_digest_response_decode(&resp, &pl);
		if (terr != testv[i].err) {
			DEBUG_WARNING("resp: expected error %d, got %d\n",
				      testv[i].err, terr);
			break;
		}

		if (terr)
			continue;

		if (!resp_equal(&testv[i].resp, &resp)) {
			DEBUG_WARNING("resp: test %d failed\n", i);
			err = EBADMSG;
			break;
		}

		err = httpauth_digest_response_auth(&resp, &testv[i].method,
						    testv[i].ha1);
		if (err) {
			if (err != ENOMEM) {
				DEBUG_WARNING("resp: auth failed %m\n", err);
			}
			break;
		}
	}

	return err;
}


int test_httpauth_basic_request(void) {
	static const struct {
		const char *hval;
		struct pl hval_response;
		const char *realm;
		const char *charset;
		const char *user;
		const char *passwd;
		int err;
		int auth_err;
	} testv[] = {
		{
			"Basic realm=\"/my/home\"",
			PL("Basic cmV0ZXN0OnJldGVzdHBhc3N3ZA=="),
			"/my/home", NULL, "retest", "retestpasswd", 0, 0
		},
		{
			"Basic realm=\"/my/home\", charset=\"UTF-8\"",
			PL("Basic cmV0ZXN0OnJldGVzdHBhc3N3ZOKCrA=="),
			"/my/home", "UTF-8", "retest",
			"retestpasswd\xe2\x82\xac",
			0, 0
		},
		{
			"Basic realm=\"/my/home\"",
			PL("Basic d3Jvbmc6Y3JlZGVudGlhbHM=="), "/my/home",
			NULL, "retest", "retestpasswd", 0, EACCES
		},
	};
	unsigned int i;
	int err = 0;

	for (i = 0; i < RE_ARRAY_SIZE(testv); ++i) {
		struct httpauth_basic_req *req = NULL;
		struct mbuf *mb = NULL;
		int terr = 0;
		int tauth_err = 0;

		terr = httpauth_basic_request(&req,
			testv[i].realm, testv[i].charset);
		if (terr == ENOMEM) {
			err = ENOMEM;
			break;
		}
		else if (terr != testv[i].err) {
			DEBUG_WARNING("basic req: expected error %d, got %m\n",
				testv[i].err, terr);
			err = terr;
			break;
		}

		if (str_casecmp(req->realm, testv[i].realm) != 0) {
			DEBUG_WARNING("basic req: expected realm %s, got %s\n",
				testv[i].realm, req->realm);
			err = EBADMSG;
			mem_deref(req);
			break;
		}

		if (testv[i].charset) {
			if (str_casecmp(req->charset, testv[i].charset) != 0) {
				DEBUG_WARNING("basic req: expected charset"
					"%s, got %s\n", testv[i].charset,
					req->charset);
				err = EBADMSG;
				mem_deref(req);
				break;
			}
		}

		mb = mbuf_alloc(512);
		if (!mb) {
			err = ENOMEM;
			mem_deref(req);
			break;
		}

		err = mbuf_printf(mb, "%H", httpauth_basic_request_print, req);
		if (err) {
			mem_deref(mb);
			mem_deref(req);
			break;
		}

		if (memcmp(testv[i].hval, mb->buf,
			str_len(testv[i].hval)) != 0) {
			DEBUG_WARNING("basic req: expected hval %s, got %s\n",
				testv[i].hval, mb->buf);
			err = EBADMSG;
			mem_deref(mb);
			mem_deref(req);
			break;
		}

		mem_deref(mb);
		tauth_err = httpauth_basic_verify(&testv[i].hval_response,
			testv[i].user, testv[i].passwd);
		if (tauth_err != testv[i].auth_err) {
			DEBUG_WARNING("basic req:"
				"authentication expected %d, got %d\n",
				testv[i].auth_err, tauth_err);
			mem_deref(req);
			break;
		}

		mem_deref(req);
	}

	return err;
}


int test_httpauth_digest_request(void)
{
	static const struct {
		const char *hval_fmt;
		const char *realm;
		const char *domain;
		const char *etag;
		const char *opaque;
		const bool stale;
		const char *algorithm;
		const char *qop;
		const char *charset;
		const bool userhash;
		int err;
	} testv [] = {
		{
			"",
			NULL, NULL, "", NULL, false, NULL, "auth", NULL, false,
			EINVAL
		},
		{
			"Digest realm=\"/my/home\", qop=\"\","
			" nonce=\"%s\", algorithm=MD5",
			"/my/home", NULL, "localhost:5060", NULL, false,
			NULL, "", NULL, false,
			0
		},
		{
			"Digest realm=\"/my/home\", qop=\"\","
			" nonce=\"%s\", algorithm=MD5",
			"/my/home", NULL, "localhost:5060", NULL, false,
			NULL, "", NULL, false, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth\","
			" nonce=\"%s\", algorithm=SHA256",
			"/my/home", NULL, "localhost:5060", NULL, false,
			"SHA256", "auth", NULL, false, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth\","
			" nonce=\"%s\", algorithm=SHA256-sess, stale=true",
			"/my/home", NULL, "localhost:5060", NULL, true,
			"SHA256-sess", "auth", NULL, false, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth\","
			" nonce=\"%s\", algorithm=SHA1,"
			" stale=true, userhash=true",
			"/my/home", NULL, "localhost:5060", NULL, true,
			"SHA1", "auth", NULL, true, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth\","
			" nonce=\"%s\", algorithm=SHA1-sess,"
			" domain=\"example.com\", stale=true,"
			" charset=\"UTF-8\", userhash=true",
			"/my/home", "example.com", "localhost:5060", NULL,
			true, "SHA1-sess", "auth", "UTF-8", true, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth\","
			" nonce=\"%s\", algorithm=SHA256,"
			" domain=\"example.com\", stale=true,"
			" charset=\"UTF-8\", userhash=true",
			"/my/home", "example.com", "localhost:5060", NULL,
			true, "SHA256", "auth", "UTF-8", true, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth-int\","
			" nonce=\"%s\", algorithm=MD5-sess,"
			" domain=\"example.com\", stale=true,"
			" charset=\"UTF-8\", userhash=true",
			"/my/home", "example.com", "localhost:5060", NULL,
			true, "MD5-sess", "auth-int", "UTF-8", true, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth-int\","
			" nonce=\"%s\", algorithm=SHA1-sess,"
			" domain=\"example.com\", stale=true,"
			" charset=\"UTF-8\", userhash=true",
			"/my/home", "example.com", "213579023", NULL,
			true, "SHA1-sess", "auth-int", "UTF-8", true, 0
		},
		{
			"Digest realm=\"/my/home\", qop=\"auth-int\","
			" nonce=\"%s\", algorithm=MD5,"
			" domain=\"example.com\", stale=true,"
			" charset=\"UTF-8\", userhash=true",
			"/my/home", "example.com", "129842", NULL,
			true, NULL, "auth-int", "UTF-8", true, 0
		},
	};

	int err = 0;
	for (unsigned int i = 0; i < RE_ARRAY_SIZE(testv); i++) {
		struct httpauth_digest_chall_req *req = NULL;
		struct mbuf *mb_refval = NULL;
		struct mbuf *mb_printed = NULL;

		mb_refval = mbuf_alloc(512);
		mb_printed = mbuf_alloc(512);
		if (!mb_refval || !mb_printed) {
			err = ENOMEM;
			goto for_out;
		}

		err = httpauth_digest_chall_request_full(&req, testv[i].realm,
			testv[i].domain, testv[i].etag, testv[i].opaque,
			testv[i].stale, testv[i].algorithm, testv[i].qop,
			testv[i].charset, testv[i].userhash);
		if (err == ENOMEM) {
			goto for_out;
		}
		else if (err != testv[i].err) {
			DEBUG_WARNING("[%d]"
				" Expected return value %m, got %m\n",
				i, testv[i].err, err);
		}
		else if (err) {
			goto for_continue;
		}

		err = mbuf_printf(mb_refval, testv[i].hval_fmt, req->nonce);
		if (err) {
			DEBUG_WARNING("[%d]"
				" No reference created %m\n", i, err);
			goto for_out;
		}

		err = mbuf_printf(mb_printed, "%H",
			httpauth_digest_chall_req_print, req);
		if (err) {
			DEBUG_WARNING("[%d]"
				" Digest request print error %m\n", i, err);
			goto for_out;
		}

		if (mb_refval->end != mb_printed->end) {
			DEBUG_WARNING("[%d] Expected header len %d, got %d\n",
				i, mb_refval->end, mb_printed->end);
				err = EINVAL;
				goto for_out;
		}

		if (memcmp(mb_refval->buf, mb_printed->buf, mb_refval->end)) {
			DEBUG_WARNING("[%d] Expected header %b, got %b\n", i,
				mb_refval->buf, mb_refval->end,
				mb_printed->buf, mb_printed->end);
			err = EINVAL;
			goto for_out;
		}

for_continue:
		mem_deref(req);
		mem_deref(mb_refval);
		mem_deref(mb_printed);
		continue;

for_out:
		mem_deref(req);
		mem_deref(mb_refval);
		mem_deref(mb_printed);
		break;
	}

	return err;
}
