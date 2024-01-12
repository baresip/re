/**
 * @file stun.c STUN Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_stun"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define NATTED (true)


/*
 * Test vectors from RFC 5769
 */

static const uint8_t tid[] =
	"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae";
static const char *username = "evtj:h6vY";
static const struct pl password = PL("VOkJxbRl1RmTxUk/WvJxBt");

static const unsigned char req[] =
     "\x00\x01\x00\x58"
     "\x21\x12\xa4\x42"
     "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
     "\x80\x22\x00\x10"
       "STUN test client"
     "\x00\x24\x00\x04"
       "\x6e\x00\x01\xff"
     "\x80\x29\x00\x08"
       "\x93\x2f\xf9\xb1\x51\x26\x3b\x36"
     "\x00\x06\x00\x09"
       "\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20"
     "\x00\x08\x00\x14"
       "\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5"
       "\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2"
     "\x80\x28\x00\x04"
       "\xe5\x7a\x3b\xcf";

static const unsigned char respv4[] =
     "\x01\x01\x00\x3c"
     "\x21\x12\xa4\x42"
     "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
     "\x80\x22\x00\x0b"
       "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20"
     "\x00\x20\x00\x08"
       "\x00\x01\xa1\x47\xe1\x12\xa6\x43"
     "\x00\x08\x00\x14"
       "\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9"
       "\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7"
     "\x80\x28\x00\x04"
       "\xc0\x7d\x4c\x96";

static const unsigned char respv6[] =
     "\x01\x01\x00\x48"
     "\x21\x12\xa4\x42"
     "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
     "\x80\x22\x00\x0b"
       "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20"
     "\x00\x20\x00\x14"
       "\x00\x02\xa1\x47"
       "\x01\x13\xa9\xfa\xa5\xd3\xf1\x79"
       "\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9"
     "\x00\x08\x00\x14"
       "\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c"
       "\x82\x92\xc2\x75\xbf\xe3\xed\x41"
     "\x80\x28\x00\x04"
       "\xc8\xfb\x0b\x4c";


static const uint32_t ice_prio = 0x6e0001ff;
static const uint64_t ice_contr = 0x932ff9b151263b36ULL;
static const char *client_sw = "STUN test client";
static const char *server_sw = "test vector";


int test_stun_req(void)
{
	struct stun_msg *msg = NULL;
	struct mbuf *mb;
	struct stun_attr *attr;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
			      tid, NULL,
			      (uint8_t *)password.p, password.l, true,
			      0x20, 4,
			      STUN_ATTR_SOFTWARE, client_sw,
			      STUN_ATTR_PRIORITY, &ice_prio,
			      STUN_ATTR_CONTROLLED, &ice_contr,
			      STUN_ATTR_USERNAME, username);
	if (err)
		goto out;

	TEST_MEMCMP(req, sizeof(req)-1, mb->buf, mb->end);

	/* Decode STUN message */
	mb->pos = 0;
	err = stun_msg_decode(&msg, mb, NULL);
	if (err)
		goto out;

	if (STUN_CLASS_REQUEST != stun_msg_class(msg))
		goto bad;

	if (STUN_METHOD_BINDING != stun_msg_method(msg))
		goto out;

	err = stun_msg_chk_mi(msg, (uint8_t *)password.p, password.l);
	if (err)
		goto out;

	err = stun_msg_chk_fingerprint(msg);
	if (err)
		goto out;

	attr = stun_msg_attr(msg, STUN_ATTR_PRIORITY);
	if (!attr || ice_prio != attr->v.priority)
		goto bad;

	attr = stun_msg_attr(msg, STUN_ATTR_CONTROLLED);
	if (!attr || ice_contr != attr->v.controlled)
		goto bad;

	attr = stun_msg_attr(msg, STUN_ATTR_USERNAME);
	if (!attr || strcmp(username, attr->v.username))
		goto bad;

	attr = stun_msg_attr(msg, STUN_ATTR_SOFTWARE);
	if (!attr || strcmp(client_sw, attr->v.software))
		goto bad;

	goto out;

 bad:
	err = EBADMSG;

 out:
	mem_deref(msg);
	mem_deref(mb);
	return err;
}


static int test_resp(const struct pl *resp, const struct sa *addr)
{
	struct stun_msg *msg = NULL;
	struct stun_attr *attr;
	struct mbuf *mb = NULL;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_SUCCESS_RESP,
			      tid, NULL,
			      (uint8_t *)password.p, password.l, true,
			      0x20, 2,
                              STUN_ATTR_SOFTWARE, server_sw,
			      STUN_ATTR_XOR_MAPPED_ADDR, addr);
	if (err)
		goto out;

	if (resp->l != mb->end ||
	    0 != memcmp(mb->buf, resp->p, mb->end)) {
		err = EBADMSG;
		DEBUG_WARNING("compare failed (%J)\n", addr);
		(void)re_printf("msg: [%02w]\n", mb->buf, mb->end);
		(void)re_printf("ref: [%02w]\n", resp->p, resp->l);
		goto out;
	}

	/* Decode STUN message */
	mb->pos = 0;
	err = stun_msg_decode(&msg, mb, NULL);
	if (err)
		goto out;

	if (STUN_CLASS_SUCCESS_RESP != stun_msg_class(msg))
		goto bad;

	if (STUN_METHOD_BINDING != stun_msg_method(msg))
		goto bad;

	err = stun_msg_chk_mi(msg, (uint8_t *)password.p, password.l);
	if (err)
		goto out;

	err = stun_msg_chk_fingerprint(msg);
	if (err)
		goto out;

	attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
	if (!attr || !sa_cmp(&attr->v.xor_mapped_addr, addr, SA_ALL))
		goto bad;

	attr = stun_msg_attr(msg, STUN_ATTR_SOFTWARE);
	if (!attr || strcmp(server_sw, attr->v.software))
		goto bad;

	goto out;

 bad:
	err = EBADMSG;

 out:
	mem_deref(msg);
	mem_deref(mb);
	return err;
}


int test_stun_resp(void)
{
	struct sa maddr;
	struct pl resp;
	int err;

	resp.p = (char *)respv4;
	resp.l = sizeof(respv4) - 1;
	err = sa_set_str(&maddr, "192.0.2.1", 32853);
	if (err)
		return err;
	err = test_resp(&resp, &maddr);
	if (err)
		return err;

	resp.p = (char *)respv6;
	resp.l = sizeof(respv6) - 1;
	err = sa_set_str(&maddr, "2001:db8:1234:5678:11:2233:4455:6677",
			 32853);
	if (err)
		return err;
	err = test_resp(&resp, &maddr);

	return err;
}


static const unsigned char reqltc[] =
     "\x00\x01\x00\x60"
     "\x21\x12\xa4\x42"
     "\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"
     "\x00\x06\x00\x12"
       "\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83"
       "\xe3\x82\xaf\xe3\x82\xb9\x00\x00"
     "\x00\x15\x00\x1c"
       "\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36"
       "\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79"
       "\x36\x34\x73\x41"
     "\x00\x14\x00\x0b"
       "\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00"
     "\x00\x08\x00\x14"
       "\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71"
       "\x2e\x85\xc9\xa2\x8c\xa8\x96\x66";

static const uint8_t tid_ltc[] =
	"\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e";
/* Username:  "<U+30DE><U+30C8><U+30EA><U+30C3><U+30AF><U+30B9>"
   (without quotes) unaffected by SASLprep[RFC4013] processing */
static const char *username_ltc =
	"\xe3\x83\x9e\xe3\x83\x88\xe3\x83"
	"\xaa\xe3\x83\x83\xe3\x82\xaf\xe3"
	"\x82\xb9";
/* Password:  "The<U+00AD>M<U+00AA>tr<U+2168>"" resp "TheMatrIX" (without
   quotes) before resp after SASLprep processing */
static const char *password_ltc = "TheMatrIX";
static const char *nonce_ltc    = "f//499k954d6OL34oL9FSTvy64sA";
static const char *realm_ltc    = "example.org";


int test_stun_reqltc(void)
{
	struct stun_msg *msg = NULL;
	struct stun_attr *attr;
	struct mbuf *mb;
	uint8_t md5_hash[MD5_SIZE];
	int r, err;

	mb = mbuf_alloc(1024);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	/* use long-term credentials */
	err = md5_printf(md5_hash, "%s:%s:%s", username_ltc, realm_ltc,
			 password_ltc);
	if (err)
		goto out;

	err = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
			      tid_ltc, NULL,
			      md5_hash, sizeof(md5_hash),
			      false, 0x00, 3,
			      STUN_ATTR_USERNAME, username_ltc,
			      STUN_ATTR_NONCE, nonce_ltc,
			      STUN_ATTR_REALM, realm_ltc);
	if (err)
		goto out;

	r = memcmp(mb->buf, reqltc, mb->end);
	if ((sizeof(reqltc)-1) != mb->end || 0 != r) {
		err = EBADMSG;
		DEBUG_WARNING("compare failed (r=%d)\n", r);
		(void)re_printf("msg: [%02w]\n", mb->buf, mb->end);
		(void)re_printf("ref: [%02w]\n", reqltc, sizeof(reqltc)-1);
		goto out;
	}

	/* Decode STUN message */
	mb->pos = 0;
	err = stun_msg_decode(&msg, mb, NULL);
	if (err)
		goto out;

	if (STUN_CLASS_REQUEST != stun_msg_class(msg))
		goto bad;

	if (STUN_METHOD_BINDING != stun_msg_method(msg))
		goto bad;

	err = stun_msg_chk_mi(msg, md5_hash, sizeof(md5_hash));
	if (err)
		goto out;

	if (EPROTO != stun_msg_chk_fingerprint(msg))
		goto bad;

	attr = stun_msg_attr(msg, STUN_ATTR_USERNAME);
	if (!attr || strcmp(username_ltc, attr->v.username))
		goto bad;

	attr = stun_msg_attr(msg, STUN_ATTR_NONCE);
	if (!attr || strcmp(nonce_ltc, attr->v.nonce))
		goto bad;

	attr = stun_msg_attr(msg, STUN_ATTR_REALM);
	if (!attr || strcmp(realm_ltc, attr->v.realm))
		goto bad;

	goto out;

 bad:
	err = EBADMSG;

 out:
	mem_deref(msg);
	mem_deref(mb);
	return err;
}


struct test {
	struct stun *stun;
	struct udp_sock *us;
	struct sa mapped_addr;
	size_t n_resp;
	int err;
};


static void stun_resp_handler(int err, uint16_t scode, const char *reason,
			      const struct stun_msg *msg, void *arg)
{
	struct test *test = arg;
	struct stun_attr *attr;
	(void)reason;

	if (err)
		goto out;

	++test->n_resp;

	/* verify STUN response */
	ASSERT_EQ(0, scode);
	TEST_EQUALS(0x0101, stun_msg_type(msg));
	TEST_EQUALS(STUN_CLASS_SUCCESS_RESP, stun_msg_class(msg));
	TEST_EQUALS(STUN_METHOD_BINDING, stun_msg_method(msg));
	TEST_EQUALS(0, stun_msg_chk_fingerprint(msg));

	attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
	TEST_ASSERT(attr != NULL);

	test->mapped_addr = attr->v.sa;

 out:
	if (err)
		test->err = err;

	/* done */
	re_cancel();
}


static void udp_recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct test *test = arg;
	(void)src;

	(void)stun_recv(test->stun, mb);
}


static int test_stun_request(int proto, bool natted)
{
	struct stunserver *srv = NULL;
	struct stun_ctrans *ct = NULL;
	struct nat *nat = NULL;
	struct test test;
	struct sa laddr, public_addr;
	int err;

	memset(&test, 0, sizeof(test));

	err = stunserver_alloc(&srv);
	if (err)
		goto out;

	err = stun_alloc(&test.stun, NULL, NULL, NULL);
	if (err)
		goto out;

	if (proto == IPPROTO_UDP) {
		err = sa_set_str(&laddr, "127.0.0.1", 0);
		TEST_ERR(err);

		err = udp_listen(&test.us, &laddr, udp_recv_handler, &test);
		if (err)
			goto out;
		err = udp_local_get(test.us, &laddr);
		TEST_ERR(err);
	}

	if (natted) {
		err = sa_set_str(&public_addr, "4.5.6.7", 0);
		TEST_ERR(err);

		err = nat_alloc(&nat, NAT_INBOUND_SNAT, srv->us, &public_addr);
		if (err)
			goto out;

		sa_set_port(&public_addr, sa_port(&laddr));
	}
	else if (proto == IPPROTO_UDP) {
		public_addr = laddr;
	}

	err = stun_request(&ct, test.stun, proto, test.us,
			   stunserver_addr(srv, proto), 0,
			   STUN_METHOD_BINDING, NULL, 0, true,
			   stun_resp_handler, &test, 0);
	if (err)
		goto out;

	TEST_ASSERT(ct != NULL);

	err = re_main_timeout(100);
	if (err)
		goto out;

	if (srv->err) {
		err = srv->err;
		goto out;
	}
	if (test.err) {
		err = test.err;
		goto out;
	}

	/* verify results */
	TEST_ASSERT(srv->nrecv >= 1);
	TEST_EQUALS(1, test.n_resp);

	if (proto == IPPROTO_UDP) {
		TEST_SACMP(&public_addr, &test.mapped_addr, SA_ALL);
	}

 out:
	mem_deref(test.stun);
	mem_deref(test.us);
	mem_deref(nat);
	mem_deref(srv);

	return err;
}


static int test_stun_req_attributes(void)
{
	struct stun_msg *msg = NULL;
	struct mbuf *mb;
	struct stun_attr *attr;
	const uint64_t rsv_token = 0x1100c0ffee;
	const uint32_t lifetime = 3600;
	const uint16_t chan = 0x4000;
	const uint8_t req_addr_fam = AF_INET;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
			      tid, NULL, NULL, 0, false,
			      0x00, 4,
			      STUN_ATTR_REQ_ADDR_FAMILY, &req_addr_fam,
			      STUN_ATTR_CHANNEL_NUMBER, &chan,
			      STUN_ATTR_LIFETIME, &lifetime,
			      STUN_ATTR_RSV_TOKEN, &rsv_token);
	if (err)
		goto out;

	/* Decode STUN message */
	mb->pos = 0;
	err = stun_msg_decode(&msg, mb, NULL);
	if (err)
		goto out;

	TEST_EQUALS(STUN_CLASS_REQUEST, stun_msg_class(msg));
	TEST_EQUALS(STUN_METHOD_BINDING, stun_msg_method(msg));

	/* verify integer attributes of different sizes */

	/* 8-bit */
	attr = stun_msg_attr(msg, STUN_ATTR_REQ_ADDR_FAMILY);
	TEST_ASSERT(attr != NULL);
	TEST_EQUALS(req_addr_fam, attr->v.req_addr_family);

	/* 16-bit */
	attr = stun_msg_attr(msg, STUN_ATTR_CHANNEL_NUMBER);
	TEST_ASSERT(attr != NULL);
	TEST_EQUALS(chan, attr->v.channel_number);

	/* 32-bit */
	attr = stun_msg_attr(msg, STUN_ATTR_LIFETIME);
	TEST_ASSERT(attr != NULL);
	TEST_EQUALS(lifetime, attr->v.lifetime);

	/* 64-bit */
	attr = stun_msg_attr(msg, STUN_ATTR_RSV_TOKEN);
	TEST_ASSERT(attr != NULL);
	TEST_EQUALS(rsv_token, attr->v.rsv_token);

 out:
	mem_deref(msg);
	mem_deref(mb);
	return err;
}


/*
 * Send a STUN Binding Request to the mock STUN-Server,
 * and expect a STUN Binding Response.
 */
int test_stun(void)
{
	int err;

	err = test_stun_request(IPPROTO_UDP, false);
	TEST_ERR(err);

	err = test_stun_request(IPPROTO_UDP, NATTED);
	TEST_ERR(err);

	err = test_stun_request(IPPROTO_TCP, false);
	TEST_ERR(err);

	err = test_stun_req_attributes();
	TEST_ERR(err);

out:
	return err;
}
