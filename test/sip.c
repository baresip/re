/**
 * @file sip.c SIP Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "siptest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int sip_addr_encode(const struct sip_addr *addr, struct mbuf *mb)
{
	bool anglebr = addr->dname.p || addr->uri.params.p;
	int err;

	if (addr->dname.p) {
		err = mbuf_printf(mb, "\"%r\" ", &addr->dname);
		if (err)
			return err;
	}

	if (anglebr) {
		err = mbuf_write_u8(mb, '<');
		if (err)
			return err;
	}

	err = mbuf_printf(mb, "%H", uri_encode, &addr->uri);
	if (err)
		return err;

	if (anglebr) {
		err = mbuf_write_u8(mb, '>');
		if (err)
			return err;
	}

	if (addr->params.p) {
		err = mbuf_write_pl(mb, &addr->params);
		if (err)
			return err;
	}

	return 0;
}


int test_sip_addr(void)
{
	const char *addrv[] = {

		/* With Display name */
		"\"Agmund Bolt\" <sip:agmund@bolt.com:5060;lr;user=phone>",
		"\"Agmund Bolt\" <sip:agmund@bolt.com:5060;user=phone>",
		"\"Agmund Bolt\" <sip:agmund@bolt.com:5060>",
		"\"Agmund Bolt\" <sip:agmund@bolt.com>",
		"\"Agmund Bolt\" <sip:bolt.com:5060>",
		"\"Agmund Bolt\" <sip:bolt.com>",

		"<sip:user@host:5060;transport=udp>",
		"<sip:user@host:5060>",
		"<sip:host:5060>",
		"<sip:host>",
		"<sip:user@81.187.91.2:28481>",
		"<sip:user@81.187.91.2:28481>",
		"<sip:81.187.91.2:28481>",
		"<sips:81.187.91.2:28481>",

		/* RFC 3261 */
		"<sip:alice@atlanta.com>",
		"<sips:alice@atlanta.co"
		  "?subject=project%20x&priority=urgent>",
		"<sips:1212@gateway.com>",
		"<sip:alice@192.0.2.4>",
		"<sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com>",
		"<sip:alice;day=tuesday@atlanta.com>",

		/* With address parameters */
		"\"Agmund Bolt\" <sip:agmund@bolt.com:5060;lr;user=phone>"
		    ";tag=foo123",
		"\"Agmund Bolt\" <sip:agmund@bolt.com:5060;lr;user=phone>"
		   ";tag=foo123;bar=9d7j3",

		/* RFC 5118 - SIP Torture Test Messages for IPv6 */
		"\"Caller\" <sip:caller@[2001:db8::1]>",
		"\"Caller\" <sip:caller@[2001:db8::1]:5080>",

		/* gruu */
		"\"hei\" <sip:alfred1@10.0.0.4:32829;keepalive=crlf>"
		";expires=3845"
		";gruu=\"sip:alfred1@devel.sip.su.se"
		";opaque=t49sgjnwu8;gruu\""
		";+sip.instance="
		"\"<urn:uuid:6B3639EB-77A3-4882-97F7-A357A1F1B4D0>\""
		";reg-id=1",
	};
	struct sip_addr addr;
	struct mbuf mb;
	int err = EINVAL;
	size_t i;

	mbuf_init(&mb);

	for (i=0; i<RE_ARRAY_SIZE(addrv); i++) {
		struct pl pl, pl2;

		pl_set_str(&pl, addrv[i]);

		/* Decode */
		err = sip_addr_decode(&addr, &pl);
		if (err) {
			DEBUG_WARNING("sip_addr: test %u: sip_addr_decode()"
				      " failed (%s) (%m)\n",
				      i, addrv[i], err);
			goto out;
		}

		DEBUG_INFO("addr: dname=(%r) uri=(%r@%r) params=(%r)\n",
			   &addr.dname, &addr.uri.user, &addr.uri.host,
			   &addr.params);

		/* Encode */
		mbuf_reset(&mb);
		err = sip_addr_encode(&addr, &mb);
		if (err) {
			DEBUG_INFO("sip_addr: sip_addr_encode failed (%m)\n",
				   err);
			goto out;
		}

		/* Compare */
		pl2.p = (const char *)mb.buf;
		pl2.l = mb.end;
		err = pl_cmp(&pl2, &pl);
		if (err) {
			DEBUG_WARNING("%u: sip addr cmp: ref='%r' gen='%r'\n",
				      i, &pl, &pl2);
			goto out;
		}
	}

	err = 0;

 out:
	mbuf_reset(&mb);
	return err;
}


int test_sip_via(void)
{
	struct {
		enum sip_transp tp;
		const char *host;
		uint16_t port;
		const char *branch;
	} testv[] = {
		{SIP_TRANSP_UDP, "1.2.3.4",         1234, "z9ghkdkasd"},
		{SIP_TRANSP_TCP, "123.123.123.123", 0,    "b0ajsd01abcdef918"},
		{SIP_TRANSP_TCP, "myhost.com",      0,    "b0ajsd01ab2838475"},
		{SIP_TRANSP_TCP, "fe80::215:58ff:fe2d:90ab", 5060,
		 "b0ajs01cde38475"},
		{SIP_TRANSP_TLS, "fe80::215:58ff:fe2d:90ab", 0, "47daasd5"}
	};
	struct sip_msg *msg = NULL;
	struct mbuf *mb;
	int err = EINVAL;
	size_t i;

	mb = mbuf_alloc(1024);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		bool ipaddr;
		struct sa addr;

		mbuf_rewind(mb);

		/* Encode message */
		err = mbuf_printf(mb,
				  "BYE sip:foo SIP/2.0\r\n"
				  "Via : SIP / 2.0 / %s ",
				  sip_transp_name(testv[i].tp));
		if (err)
			goto out;

		ipaddr = !sa_set_str(&addr, testv[i].host, testv[i].port);

		if (ipaddr && AF_INET6 == sa_af(&addr))
			err = mbuf_printf(mb, "[%s]", testv[i].host);
		else
			err = mbuf_printf(mb, "%s", testv[i].host);
		if (err)
			goto out;

		if (testv[i].port)
			err = mbuf_printf(mb, ":%u", testv[i].port);
		err |= mbuf_printf(mb, ";branch=%s\r\n\r\n",
				   testv[i].branch);
		if (err)
			goto out;

		mbuf_set_pos(mb, 0);

		/* Decode message */

		err = sip_msg_decode(&msg, mb);
		if (err) {
			goto out;
		}

		/* Compare */

		if (msg->via.tp != testv[i].tp) {
			DEBUG_WARNING("%u: via transp: '%s' != '%s'\n",
				      i, sip_transp_name(msg->via.tp),
				      sip_transp_name(testv[i].tp));
			goto out;
		}

		/* Numeric IP address */
		if (ipaddr) {
			if (!sa_cmp(&msg->via.addr, &addr, SA_ALL)) {
				DEBUG_WARNING("%u: via addr: addr=%J\n",
					      i, &msg->via.addr);
				err = EINVAL;
				goto out;
			}
		}
		else {
			err = pl_strcmp(&msg->via.sentby, testv[i].host);
			if (err) {
				DEBUG_WARNING("%u: via uri: sentby='%r'\n",
					      i, &msg->via.sentby);
				goto out;
			}

			if (sa_port(&msg->via.addr) != testv[i].port) {
				DEBUG_WARNING("%u: via: port mismatch (%u)\n",
					      i, sa_port(&msg->via.addr));
				err = EINVAL;
				goto out;
			}
		}

		err = pl_strcmp(&msg->via.branch, testv[i].branch);
		if (err) {
			DEBUG_WARNING("%u: via branch: '%r' != '%s'\n",
				      i, &msg->via.branch, testv[i].branch);
			goto out;
		}

		msg = mem_deref(msg);
	}

	err = 0;
 out:
	mem_deref(mb);
	mem_deref(msg);
	return err;
}


struct apply {
	uint32_t n;
	int err;
};


static bool apply_handler(const struct sip_hdr *hdr, const struct sip_msg *msg,
			  void *arg)
{
	const char *ref = "SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123";
	struct apply *apply = arg;

	(void)msg;
	(void)arg;

	if (hdr->id != SIP_HDR_VIA) {
		apply->err = EINVAL;
		return true;
	}

	apply->err = pl_strcmp(&hdr->val, ref);
	if (apply->err) {
		return true;
	}

	++apply->n;

	return false;
}


int test_sip_apply(void)
{
	struct {
		uint32_t n;
		const char *msg;
	} testv[] = {
		{0,
		 "Tull: tull\r\n"},
		{1,
		 "Via: SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"},
		{1,
		 "Via:   SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"},
		{2,
		 "Via: SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"
		 "Via: SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"
		},
		{2,
		 "Via: SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123,"
		 " SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123\r\n"
		},
		{2,
		 "v: SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123,"
		 " SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123\r\n"
		},
		{2,
		 "v: SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123"
		 ",SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123\r\n"
		},
		{3,
		 "Via: SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"
		 "v: SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123\r\n"
		 "Via: SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"
		},
		{3,
		 "Via: SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"
		 "Tull: tull\r\n"
		 "v: SIP/2.0/UDP 123.45.67.89:12345;branch=z9hG4bK123\r\n"
		 "Via: SIP/2.0/UDP 123.45.67.89:12345"
		 ";branch=z9hG4bK123\r\n"
		},
	};
	struct sip_msg *msg = NULL;
	struct mbuf *mb;
	int err = 0;
	size_t i;

	mb = mbuf_alloc(1024);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		struct apply apply;

		memset(&apply, 0, sizeof(apply));

		mbuf_rewind(mb);
		err = mbuf_printf(mb, "OPTIONS sip:213.175.63.232:56102"
				  ";transport=TCP;dstip=212.13.202.25"
				  ";dstport=5060 SIP/2.0\r\n%s\r\n",
				  testv[i].msg);
		if (err)
			goto out;
		mbuf_set_pos(mb, 0);

		err = sip_msg_decode(&msg, mb);
		if (err) {
			goto out;
		}

		apply.n = 0;
		if (sip_msg_hdr_apply(msg, true, SIP_HDR_VIA,
				      apply_handler, &apply)) {
			err = apply.err;
			goto out;
		}

		if (apply.n != testv[i].n) {
			DEBUG_WARNING("%u: apply: expected"
				      " %u headers, got %u\n",
				      i, testv[i].n, apply.n);
			err = EINVAL;
			goto out;
		}
		if (err) {
			DEBUG_WARNING("%u: apply: header cmp failed (%m)\n",
				      i, err);
			goto out;
		}

		msg = mem_deref(msg);
	}

	err = 0;
 out:
	mem_deref(mb);
	mem_deref(msg);
	return err;
}


int test_sip_param(void)
{
	static const struct {
		const char *str;
		const char *exist;  /* param exist */
		const char *nexist; /* param not exist */
		const char *val;    /* expected value, if any */
	} testv[] = {
		{
			" ; rport ",
			"rport",
			"port",
			NULL,
		},
		{
			" ; branch = 123 ",
			"branch",
			"bra",
			"123",
		},
		{
			" ; expires = 3600 ; reg-id = 1 ",
			"expires",
			"xpires",
			"3600",
		},
		{
			" ; expires = 3600 ; reg-id = 1 ",
			"reg-id",
			"regid",
			"1",
		},
		{
			" ; gruu = \"sip:alfred1@devel.sip.su.se"
			    ";opaque=t49sgjnwu8;gruu\"; foo",
			"gruu",
			"ruu",
			"sip:alfred1@devel.sip.su.se"
			   ";opaque=t49sgjnwu8;gruu",
		},
	};

	int err = EINVAL;
	size_t i;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		struct pl pl, foo;

		pl_set_str(&pl, testv[i].str);

		err = msg_param_exists(&pl, testv[i].exist, &foo);
		if (err) {
			DEBUG_WARNING("%u: expected param not exist (%s)\n", i,
				      testv[i].exist);
			goto out;
		}

		if (0 == msg_param_exists(&pl, testv[i].nexist, &foo)) {
			DEBUG_WARNING("%u: unexpected param (%s)\n", i,
				      testv[i].nexist);
			err = EINVAL;
			goto out;
		}

		if (testv[i].val) {
			struct pl val;

			err = msg_param_decode(&pl, testv[i].exist, &val);
			if (err) {
				DEBUG_WARNING("%u: could not get param (%r)\n",
					      i, &testv[i].exist);
				goto out;
			}

			err = pl_strcmp(&val, testv[i].val);
			if (err) {
				DEBUG_WARNING("%u: cmp: got='%r' exp='%s'\n",
					      i, &val, testv[i].val);
				goto out;
			}
		}
	}

	err = 0;

 out:
	return err;
}


int test_sip_parse(void)
{
	const char str_raw[] =
		"INVITE sip:bob@biloxi.com SIP/2.0\r\n"
		"Via : SIP/2.0/UDP 127.0.0.1:1234;branch=z9hG4bK.2ed0447\r\n"
		"Max-Forwards: 70\r\n"
		"Record-Route: <sip:p2.domain.com;lr>\r\n"
		"t: Bob <sip:bob@biloxi.com>\r\n"
		"f: Alice <sip:alice@atlanta.com>\r\n"
		" ;tag=1928301774\r\n"
		"Call-ID : a84b4c76e66710@pc33.atlanta.com\r\n"
		"CSeq  : 314159 INVITE\r\n"
		"Contact:  <sip:alice@pc33.atlanta.com>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: 142\r\n"
		"\r\n";
	const char hdr_maxf[]   = "70";
	const char hdr_from[]   = "sip:alice@atlanta.com";
	const char hdr_to[]     = "sip:bob@biloxi.com";
	const char hdr_callid[] = "a84b4c76e66710@pc33.atlanta.com";
	struct mbuf *mb;
	struct sip_msg *msg = NULL;
	int err = EINVAL;

	mb = mbuf_alloc(1024);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err = mbuf_write_str(mb, str_raw);
	if (err)
		goto out;

	mbuf_set_pos(mb, 0);
	err = sip_msg_decode(&msg, mb);
	if (err) {
		goto out;
	}

	/* Max-Forwards */
	err = pl_strcmp(&msg->maxfwd, hdr_maxf);
	if (err)
		goto out;

	/* From */
	err = pl_strcmp(&msg->from.auri, hdr_from);
	if (err) {
		DEBUG_WARNING("from header mismatch (%r)\n", &msg->from.auri);
		goto out;
	}

	/* To */
	err = pl_strcmp(&msg->to.auri, hdr_to);
	if (err) {
		DEBUG_WARNING("to header mismatch\n");
		goto out;
	}

	/* Call-ID */
	err = pl_strcmp(&msg->callid, hdr_callid);
	if (err) {
		DEBUG_WARNING("callid header mismatch\n");
		goto out;
	}

	/* CSeq */
	if (314159 != msg->cseq.num) {
		DEBUG_WARNING("cseq number mismatch\n");
		goto out;
	}
	err = pl_strcmp(&msg->cseq.met, "INVITE");
	if (err) {
		DEBUG_WARNING("cseq method mismatch\n");
		goto out;
	}

	/* Content-Type */
	if (!msg_ctype_cmp(&msg->ctyp, "application", "sdp")) {
		DEBUG_WARNING("content type mismatch (%r/%r)\n",
			      &msg->ctyp.type, &msg->ctyp.subtype);
		err = EBADMSG;
		goto out;
	}

	/* Content-Length */
	if (142 != pl_u32(&msg->clen)) {
		DEBUG_WARNING("content length mismatch\n");
		err = EINVAL;
		goto out;
	}

	err = 0;

 out:
	mem_deref(mb);
	mem_deref(msg);
	return err;
}


static bool count_handler(const struct sip_hdr *hdr, const struct sip_msg *msg,
			  void *arg)
{
	(void)hdr;
	(void)msg;
	++(*(uint32_t *)arg);
	return false;
}


static uint32_t xhdr_count(const struct sip_msg *msg, const char *name)
{
	uint32_t n = 0;
	sip_msg_xhdr_apply(msg, true, name, count_handler, &n);
	return n;
}


int test_sip_hdr(void)
{
	const char str[] =
		"REGISTER sip:telio.no SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 85.119.136.184:5080"
		" ;branch=z9hG4bKe282.0c5b6835.0;i=2b505\r\n"
		"Via: SIP/2.0/TCP 172.17.18.219:5060;received=85.0.35.235"
		" ;branch=z9hG4bK6ec163d6cebbbe491e1940b91.1;rport=49505\r\n"
		"Call-ID: 2e60298e76751681@172.17.18.219\r\n"
		"CSeq: 67139 REGISTER\r\n"
		"Contact: <sip:21696001@85.0.35.235:49505;transport=tcp>\r\n"
		"From: <sip:21696001@telio.no>;tag=1ea582725e044bf6\r\n"
		"To: <sip:21696001@telio.no>\r\n"
		"Max-Forwards: 16\r\n"
		"Allow: INVITE,ACK,CANCEL,BYE,UPDATE,INFO,OPTIONS\r\n"
		"User-Agent: TANDBERG/67 (F7.2 PAL)\r\n"
		"Expires: 3600\r\n"
		"Supported: replaces,100rel,timer\r\n"
		"Content-Length: 0\r\n"
		"\r\n";
	struct mbuf *mb;
	struct sip_msg *msg = NULL;
	int err = EINVAL;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err = mbuf_write_str(mb, str);
	if (err)
		goto out;

	mbuf_set_pos(mb, 0);
	err = sip_msg_decode(&msg, mb);
	if (err)
		goto out;

	if (xhdr_count(msg, "Call-ID") != 1) {
		err = EBADMSG;
		goto out;
	}

	if (xhdr_count(msg, "Supported") != 3) {
		err = EBADMSG;
		goto out;
	}

	if (xhdr_count(msg, "Allow") != 7) {
		err = EBADMSG;
		goto out;
	}

	if (xhdr_count(msg, "NonExisting") != 0) {
		err = EBADMSG;
		goto out;
	}


 out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


/** SIP Authenticated Request */
struct sip_req {
	struct sip_request *req;
	struct sip_auth *auth;
	struct sip_dialog *dlg;
	struct sip *sip;
};


static int do_sip_drequestf(struct sa *laddr)
{
	struct sip_req *sr;
	int err;
	char uri[64];
	char touri[64];

	sr = mem_zalloc(sizeof(*sr), NULL);
	if (!sr)
		return ENOMEM;

	re_snprintf(uri, sizeof(uri), "sip:%J;transport=UDP", laddr);
	re_snprintf(touri, sizeof(touri), "sip:test@%J", laddr);

	err = sip_dialog_alloc(&sr->dlg, uri,
			       touri, NULL,
			       touri, NULL, 0);
	TEST_ERR(err);

	err = sip_auth_alloc(&sr->auth, NULL, NULL, false);
	TEST_ERR(err);

	err = sip_alloc(&sr->sip, NULL, 32, 32, 32, "retest", NULL, NULL);
	TEST_ERR(err);

	err  = sip_transp_add(sr->sip, SIP_TRANSP_UDP, laddr);
	TEST_ERR(err);

	err = sip_drequestf(&sr->req, sr->sip, true, "REGISTER", sr->dlg, 0,
			    sr->auth, NULL, NULL, NULL, "");
	TEST_ERR(err);

out:
	mem_deref(sr->dlg);
	mem_deref(sr->auth);
	mem_deref(sr->sip);
	mem_deref(sr);

	return err;
}


int test_sip_drequestf(void)
{
	int err;
	struct sa laddr;

	err = sa_set_str(&laddr, "127.0.0.1", 0);
	TEST_ERR(err);

	err = do_sip_drequestf(&laddr);
	TEST_ERR(err);

out:
	return err;
}


int test_sip_drequestf_network(void)
{
	struct sa laddr;
	int err = 0;

	sa_init(&laddr, AF_INET6);

	if (0 == net_if_getlinklocal(NULL, AF_INET6, &laddr)) {

		err = do_sip_drequestf(&laddr);
		TEST_ERR(err);
	}

out:
	return err;
}


#ifdef USE_TLS
struct sip_transp_tls {
	struct sip *sip;
	struct tls *tls;
	struct uri uri;
	const char *ccert_cn;
};


int test_sip_transp_add_client_cert(void)
{
	struct sip_transp_tls *stt;
	struct sa laddr;
	int err;
	char clientcert[256];
	char cafile[256];

	const char *user    = "abcd";
	const char *scheme  = "sip";
	const char *host    = "localhost";
	const uint16_t port = 5061;

	memset(clientcert, 0, sizeof(clientcert));
	(void)re_snprintf(clientcert, sizeof(clientcert), "%s/client.pem",
		test_datapath());

	stt = mem_zalloc(sizeof(*stt), NULL);
	if (!stt)
		return ENOMEM;

	pl_set_str(&stt->uri.user, user);
	pl_set_str(&stt->uri.scheme, scheme);
	pl_set_str(&stt->uri.host, host);
	stt->uri.port = port;


	err = sa_set_str(&laddr, "127.0.0.1", 0);
	TEST_ERR(err);

	err = tls_alloc(&stt->tls, TLS_METHOD_SSLV23, NULL, NULL);
	TEST_ERR(err);

	(void)re_snprintf(cafile, sizeof(cafile), "%s/server-ecdsa.pem",
		test_datapath());

	err = tls_add_ca(stt->tls, cafile);
	TEST_ERR(err);

	err = sip_alloc(&stt->sip, NULL, 32, 32, 32, "retest", NULL, NULL);
	TEST_ERR(err);

	err = sip_transp_add(stt->sip, SIP_TRANSP_TLS, &laddr, stt->tls);
	TEST_ERR(err);

	/* actuall test cases */
	err = sip_transp_add_ccert(NULL, &stt->uri, clientcert);
	if (err == EINVAL) {
		err = 0;
		goto out;
	}
	TEST_ERR(err);

	err = sip_transp_add_ccert(stt->sip, NULL, clientcert);
	if (err == EINVAL) {
		err = 0;
		goto out;
	}
	TEST_ERR(err);

	err = sip_transp_add_ccert(stt->sip, &stt->uri, NULL);
	if (err == EINVAL) {
		err = 0;
		goto out;
	}
	TEST_ERR(err);

	err = sip_transp_add_ccert(stt->sip, &stt->uri, clientcert);
	TEST_EQUALS(0, err);

 out:
	mem_deref(stt->sip);
	mem_deref(stt->tls);
	mem_deref(stt);

	return err;
}
#endif
