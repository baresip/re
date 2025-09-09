/**
 * @file uri.c URI Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "testuri"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_uri(void)
{
	const char *uriv[] = {
		"sip:user@host:5060;transport=udp",
		"sip:user@host:5060",
		"sip:host:5060",
		"sip:host",
		"sip:user@81.187.91.2:28481",
		"sip:user@81.187.91.2:28481",
		"sip:81.187.91.2:28481",
		"sips:81.187.91.2:28481",
		"sip:192.168.43.83:443/wss/;transport=wss",

		/* RFC 3261 */
		"sip:alice@atlanta.com",
		"sip:alice@atlanta.com;transport=tcp",
		"sips:alice@atlanta.com?subject=project%20&priority=urgent",
		"sip:+1-212-555-1212@gateway.com;user=phone",
		"sips:1212@gateway.com",
		"sip:alice@192.0.2.4",
		"sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com",
		"sip:alice;day=tuesday@atlanta.com",

		/* IPv6 */
		"sip:[::1];transport=udp",
		"sip:[::1]:1234;transport=udp",
		"sip:user@[::1];transport=udp",
		"sip:user@[::1]:1234;transport=udp",
		"sip:user@[::1]:1234;transport=udp?foo=bar",

		/* draft-ietf-sipping-ipv6-torture-tests-00 */
		"sip:[2001:db8::10]",
		"sip:[2001:db8::10:5070]",
		"sip:[2001:db8::10]:5070",
		"sip:user@[2001:db8::10]",
	};
	struct uri uri;
	struct mbuf mb;
	int err = EINVAL;
	size_t i;

	mbuf_init(&mb);

	for (i=0; i<RE_ARRAY_SIZE(uriv); i++) {
		struct pl pl0, pl;

		/* Decode */
		pl_set_str(&pl0, uriv[i]);
		err = uri_decode(&uri, &pl0);
		if (err) {
			DEBUG_WARNING("uri: uri_decode() failed (%s) (%m)\n",
				      uriv[i], err);
			goto out;
		}

		/* Encode */
		mbuf_reset(&mb);
		err = mbuf_printf(&mb, "%H", uri_encode, &uri);
		if (err) {
			goto out;
		}

		/* Compare */
		pl.p = (const char *)mb.buf;
		pl.l = mb.end;
		err = pl_cmp(&pl, &pl0);
		if (err) {
			DEBUG_WARNING("uri comp: ref=(%s), gen=(%r) (%m)\n",
				      uriv[i], &pl, err);
			goto out;
		}
	}

	const struct pl uri_pass = PL("sip:user:pass@host");

	err = uri_decode(&uri, &uri_pass);
	TEST_ERR(err);

	TEST_STRCMP("user", 4, uri.user.p, uri.user.l);
	TEST_STRCMP("host", 4, uri.host.p, uri.host.l);

 out:
	mbuf_reset(&mb);
	return err;
}


int test_uri_encode(void)
{
	const struct {
		struct uri uri;
		const char *enc;
	} uriv[] = {
		{{PL("sip"),
		  PL("user"),
		  PL("host"), 0,
		  5060,
		  PL(""),
		  PL(";transport=udp"),
		  PL("")},
		 "sip:user@host:5060;transport=udp"
		},
		{{PL("sip"),
		  PL("user"),
		  PL("host"), 0,
		  443,
		  PL("/wss/"),
		  PL(";transport=wss"),
		  PL("")},
		 "sip:user@host:443/wss/;transport=wss"
		},
		{{PL("sip"),
		  PL("user"),
		  PL("::1"), AF_INET6,
		  1234,
		  PL(""),
		  PL(";transport=udp"),
		  PL("")},
		 "sip:user@[::1]:1234;transport=udp"
		}
	};
	struct mbuf mb;
	int err = EINVAL;
	size_t i;

	mbuf_init(&mb);

	for (i=0; i<RE_ARRAY_SIZE(uriv); i++) {
		struct pl pl;

		/* Encode */
		mb.pos = 0;
		mb.end = 0;
		err = mbuf_printf(&mb, "%H", uri_encode, &uriv[i].uri);
		if (err)
			goto out;

		/* Compare */
		pl.p = (const char *)mb.buf;
		pl.l = mb.end;
		err = pl_strcmp(&pl, uriv[i].enc);
		if (err) {
			DEBUG_WARNING("uri enc: ref=(%s), gen=(%r) (%m)\n",
				      uriv[i].enc, &pl, err);
			goto out;
		}
	}

 out:
	mbuf_reset(&mb);
	return err;
}


int test_uri_user(void)
{
	const struct {
		const char *enc;
		const char *dec;
	} uriv[] = {
		{"alice%40atlanta.com", "alice@atlanta.com"},
		{"project%20x", "project x"},
		{"*21%23", "*21#"}
	};
	struct mbuf mbe, mbd;
	int err = EINVAL;
	size_t i;

	mbuf_init(&mbd);
	mbuf_init(&mbe);

	for (i=0; i<RE_ARRAY_SIZE(uriv); i++) {
		struct pl ple, pld, pl;

		/* Decode and compare */
		pl_set_str(&ple, uriv[i].enc);
		mbuf_reset(&mbd);
		err = mbuf_printf(&mbd, "%H", uri_user_unescape, &ple);
		if (err)
			break;

		pl.p = (const char *)mbd.buf;
		pl.l = mbd.end;
		err = pl_strcmp(&pl, uriv[i].dec);
		if (err) {
			DEBUG_WARNING("uri dec comp: ref=(%s), gen=(%r)\n",
				      uriv[i].dec, &pl);
			break;
		}

		/* Encode and compare */
		pl_set_str(&pld, uriv[i].dec);
		mbuf_reset(&mbe);
		err = mbuf_printf(&mbe, "%H", uri_user_escape, &pld);
		if (err)
			break;

		/* Compare */
		pl.p = (const char *)mbe.buf;
		pl.l = mbe.end;
		err = pl_strcmp(&pl, uriv[i].enc);
		if (err) {
			DEBUG_WARNING("uri enc comp: ref=(%s), gen=(%r)\n",
				      uriv[i].enc, &pl);
			break;
		}
	}

	mbuf_reset(&mbe);
	mbuf_reset(&mbd);
	return err;
}


int test_uri_headers(void)
{
	const struct {
		struct pl enc;
		struct pl dec;
	} uriv[] = {
		{PL("alice%40atlanta.com"),
		 PL("alice@atlanta.com")
		},
		{PL("project%20x"),
		 PL("project x")
		},
		{PL("%3Chttp://www.foo.com%3E"),
		 PL("<http://www.foo.com>")
		}
	};
	struct mbuf mbe, mbd;
	int err = EINVAL;
	size_t i;

	mbuf_init(&mbd);
	mbuf_init(&mbe);

	for (i=0; i<RE_ARRAY_SIZE(uriv); i++) {
		struct pl pl;

		/* Decode and compare */
		mbuf_reset(&mbd);
		err = mbuf_printf(&mbd, "%H", uri_header_unescape,
				  &uriv[i].enc);
		if (err)
			break;

		pl.p = (const char *)mbd.buf;
		pl.l = mbd.end;
		err = pl_cmp(&pl, &uriv[i].dec);
		if (err) {
			DEBUG_WARNING("uri dec comp: ref=(%r), gen=(%r)\n",
				      &uriv[i].dec, &pl);
			break;
		}

		/* Encode and compare */
		mbuf_reset(&mbe);
		err = mbuf_printf(&mbe, "%H", uri_header_escape, &uriv[i].dec);
		if (err)
			break;

		/* Compare */
		pl.p = (const char *)mbe.buf;
		pl.l = mbe.end;
		err = pl_cmp(&pl, &uriv[i].enc);
		if (err) {
			DEBUG_WARNING("uri enc comp: ref=(%r), gen=(%r)\n",
				      &uriv[i].enc, &pl);
			break;
		}
	}

	mbuf_reset(&mbe);
	mbuf_reset(&mbd);
	return err;
}


static int uri_param_handler(const struct pl *name, const struct pl *val,
			     void *arg)
{
	uint32_t *n = arg;
	int err;

	switch ((*n)++) {

	case 0:
		err  = pl_strcmp(name, "rport");
		break;

	case 1:
		err  = pl_strcmp(name, "transport");
		err |= pl_strcmp(val, "udp");
		break;

	default:
		return EINVAL;
	}

	return err;
}


static int uri_header_handler(const struct pl *name, const struct pl *val,
			     void *arg)
{
	uint32_t *n = arg;
	int err;

	switch ((*n)++) {

	case 0:
		err  = pl_strcmp(name, "Subject");
		err |= pl_strcmp(val, "Urgent");
		break;

	case 1:
		err  = pl_strcmp(name, "bar");
		err |= pl_strcmp(val, "2");
		break;

	default:
		return EINVAL;
	}

	return err;
}


int test_uri_params_headers(void)
{
	const char *paramv[] = {
		";rport;transport=udp"
	};
	const char *headerv[] = {
		"?Subject=Urgent&bar=2"
	};
	int err;
	uint32_t i;

	err = ENOENT;
	for (i=0; i<RE_ARRAY_SIZE(paramv); i++) {
		static const struct pl transp = PL("transport");
		struct pl pl, val;
		uint32_t n = 0;

		pl_set_str(&pl, paramv[i]);
		err = uri_param_get(&pl, &transp, &val);
		if (err)
			break;
		err = pl_strcmp(&val, "udp");
		if (err)
			break;
		err = uri_params_apply(&pl, uri_param_handler, &n);
		if (err)
			break;
		if (!n)
			err = ENOENT;
	}
	if (err)
		goto out;

	err = ENOENT;
	for (i=0; i<RE_ARRAY_SIZE(headerv); i++) {
		static const struct pl subj = PL("Subject");
		struct pl pl, val;
		uint32_t n = 0;

		pl_set_str(&pl, headerv[i]);

		err = uri_header_get(&pl, &subj, &val);
		if (err)
			break;

		err = pl_strcmp(&val, "Urgent");
		if (err)
			break;

		err = uri_headers_apply(&pl, uri_header_handler, &n);
		if (err)
			break;
		if (!n)
			err = ENOENT;
	}

 out:
	return err;
}


static int devnull_print_handler(const char *p, size_t size, void *arg)
{
	(void)p;
	(void)size;
	(void)arg;
	return 0;
}


int test_uri_escape(void)
{
	struct re_printf pf_devnull = {devnull_print_handler, NULL};
	const struct pl pl1 = PL("%");
	const struct pl pl2 = PL("%0");
	int e, err = 0;

	/* silence warnings */
	dbg_init(DBG_ERR, 0);

	e = uri_user_unescape(&pf_devnull, &pl1);
	TEST_EQUALS(EBADMSG, e);

	e = uri_user_unescape(&pf_devnull, &pl2);
	TEST_EQUALS(EBADMSG, e);

 out:
	dbg_init(DBG_WARNING, 0);

	return err;
}
