/**
 * @file sipreg.c SIP Register client regression testcode
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_sipreg"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define LOCAL_PORT        0
#define LOCAL_SECURE_PORT 0


struct test {
	enum sip_transp tp;
	unsigned n_resp;
	uint16_t srcport;
	int err;
};


static void exit_handler(void *arg)
{
	(void)arg;
	re_cancel();
}


static int sipstack_fixture(struct sip **sipp)
{
	struct sa laddr, laddrs;
	struct sip *sip = NULL;
	struct tls *tls = NULL;
#ifdef USE_TLS
	char cafile[256];
#endif
	int err;

	(void)sa_set_str(&laddr, "127.0.0.1", LOCAL_PORT);
	(void)sa_set_str(&laddrs, "127.0.0.1", LOCAL_SECURE_PORT);

	err = sip_alloc(&sip, NULL, 32, 32, 32, "retest", exit_handler, NULL);
	if (err)
		goto out;

	err |= sip_transp_add(sip, SIP_TRANSP_UDP, &laddr);
	err |= sip_transp_add(sip, SIP_TRANSP_TCP, &laddr);
	if (err)
		goto out;

#ifdef USE_TLS
	/* TLS-context for client -- no certificate needed */
	err = tls_alloc(&tls, TLS_METHOD_SSLV23, NULL, NULL);
	if (err)
		goto out;

	re_snprintf(cafile, sizeof(cafile), "%s/server-ecdsa.pem",
		    test_datapath());

	err = tls_add_ca(tls, cafile);
	if (err)
		goto out;

	err |= sip_transp_add(sip, SIP_TRANSP_TLS, &laddrs, tls);
	if (err)
		goto out;
#endif

 out:
	mem_deref(tls);
	if (err)
		mem_deref(sip);
	else
		*sipp = sip;

	return err;
}


static void sip_resp_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;

	if (err) {
		test->err = err;
		re_cancel();
		return;
	}

	++test->n_resp;

	/* verify the SIP response message */
	TEST_ASSERT(msg != NULL);
	TEST_EQUALS(200, msg->scode);
	TEST_STRCMP("REGISTER", 8, msg->cseq.met.p, msg->cseq.met.l);
	TEST_EQUALS(test->tp, msg->tp);
	if (test->srcport)
		TEST_EQUALS(test->srcport, sa_port(&msg->dst));

 out:
	if (err)
		test->err = err;
	re_cancel();
}


static int reg_test(enum sip_transp tp, bool deprecated, uint16_t srcport)
{
	struct test test;
	struct sip_server *srv = NULL;
	struct sipreg *reg = NULL;
	struct sip *sip = NULL;
	char reg_uri[256];
	int err;

	memset(&test, 0, sizeof(test));
	test.tp = tp;
	test.srcport = srcport;

	err = sip_server_alloc(&srv);
	if (err)
		goto out;

	err = sipstack_fixture(&sip);
	if (err)
		goto out;

	err = sip_server_uri(srv, reg_uri, sizeof(reg_uri), tp);
	if (err)
		goto out;

	if (deprecated) {
		err = sipreg_register(&reg, sip, reg_uri,
			      "sip:x@test", NULL,
			      "sip:x@test",
			      3600, "x", NULL, 0, 0, NULL, NULL, false,
			      sip_resp_handler, &test, NULL, NULL);
	}
	else {
		err = sipreg_alloc(&reg, sip, reg_uri,
			      "sip:x@test", NULL,
			      "sip:x@test",
			      3600, "x", NULL, 0, 0, NULL, NULL, false,
			      sip_resp_handler, &test, NULL, NULL);
		if (srcport)
			sipreg_set_srcport(reg, srcport);

		err |= sipreg_send(reg);
	}

	if (err)
		goto out;

	err = re_main_timeout(1000);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	TEST_ASSERT(srv->n_register_req > 0);
	TEST_ASSERT(test.n_resp > 0);

 out:
	mem_deref(reg);

	sip_close(sip, true);
	mem_deref(sip);

	mem_deref(srv);

	return err;
}


int test_sipreg_udp(void)
{
	int err;

	err  = reg_test(SIP_TRANSP_UDP, true, 0);
	err |= reg_test(SIP_TRANSP_UDP, false, 0);
	return err;
}


int test_sipreg_tcp(void)
{
	int err;

	err  = reg_test(SIP_TRANSP_TCP, true, 0);
	err |= reg_test(SIP_TRANSP_TCP, false, 0);
	return err;
}


#ifdef USE_TLS
int test_sipreg_tls(void)
{
	int err;

	err  = reg_test(SIP_TRANSP_TLS, true, 0);
	err |= reg_test(SIP_TRANSP_TLS, false, 0);
	return err;
}
#endif
