/**
 * @file sipsess.c SIP Session regression testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_sipsess"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


typedef void (prack_func)(void *arg);


enum neg_state {
	INITIAL = 0,
	OFFER_RECEIVED,
	ANSWER_RECEIVED,
	EARLY_CONFIRMED
};


enum rel100_state {
	REL100_NONE = 0,
	REL100_SUPPORTED = 1,
	REL100_REQUIRE = 2
};


enum connect_action {
	CONN_PROGRESS = 1,
	CONN_PROGR_ANS = 2,
	CONN_PROGR_UPD = 4,
	CONN_ANSWER = 8,
	CONN_BUSY = 16
};


enum answer_action {
	ANSW_NONE   = 0,
	ANSW_CANCEL = 1,
};


enum offer_action {
	OFFER_NONE   = 0,
	OFFER_ANSW   = 1,
};


struct test {
	struct sip *sip;
	struct sipsess_sock *sock;
	struct sipsess *a;
	struct sipsess *b;
	struct tmr ans_tmr;
	struct tmr ack_tmr;
	bool estab_a;
	bool estab_b;
	bool answr_a;
	bool answr_b;
	bool progr_a;
	bool progr_b;
	bool offer_a;
	bool offer_b;
	bool ack_a;
	bool ack_b;
	enum rel100_mode rel100_a;
	enum rel100_mode rel100_b;
	enum neg_state sdp_state;
	enum rel100_state rel100_state_a;
	enum rel100_state rel100_state_b;
	enum connect_action conn_action;
	enum offer_action offer_action;
	enum answer_action answ_action;
	prack_func *prack_action;
	int progr_ret_code;
	int answ_ret_code;
	int ack_cnt;
	bool upd_a;
	bool upd_b;
	struct mbuf *desc;
	bool blind_transfer;
	uint16_t altaddr_port;
	int err;
};


const char sdp_a[] = "v=0\r\n"
		     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
		     "s=-\r\n"
		     "c=IN IP4 1.2.3.4\r\n"
		     "t=0 0\r\n"
		     "m=audio 49170 RTP/AVP 0 8 97\r\n"
		     "a=rtpmap:0 PCMU/8000\r\n"
		     "a=rtpmap:8 PCMA/8000\r\n"
		     "a=rtpmap:97 iLBC/8000\r\n"
		     "a=sendrecv\r\n"
		     "m=video 51372 RTP/AVP 31 32\r\n"
		     "a=rtpmap:31 H261/90000\r\n"
		     "a=rtpmap:32 MPV/90000\r\n"
		     "a=sendrecv\r\n";
const char sdp_b[] = "v=0\r\n"
		     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
		     "s=-\r\n"
		     "c=IN IP4 5.6.7.8\r\n"
		     "t=0 0\r\n"
		     "m=audio 49174 RTP/AVP 0\r\n"
		     "a=rtpmap:0 PCMU/8000\r\n"
		     "a=sendrecv\r\n"
		     "m=video 49170 RTP/AVP 32\r\n"
		     "a=rtpmap:32 MPV/90000\r\n"
		     "a=sendrecv\r\n";


static void stop_test(void)
{
	re_cancel();
}


static void abort_test(struct test *test, int err)
{
	test->err = err;
	re_cancel();
}


static void exit_handler(void *arg)
{
	(void)arg;
	re_cancel();
}


static void check_ack(void *arg)
{
	struct test *test = arg;
	bool ack_a = sipsess_ack_pending(test->a);
	bool ack_b = sipsess_ack_pending(test->b);

	test->ack_a |= ack_a;
	test->ack_b |= ack_b;

	if (ack_a || ack_b)
		tmr_start(&test->ack_tmr, 1, check_ack, test);
	else
		stop_test();
}


static void wait_for_ack(struct test *test)
{
	test->ack_a = sipsess_ack_pending(test->a);
	test->ack_b = sipsess_ack_pending(test->b);

	if (!test->ack_a && !test->ack_b)
		return;

	tmr_start(&test->ack_tmr, 1, check_ack, test);
}


static void send_answer_b(void *arg)
{
	struct test *test = arg;
	int err;

	err = sipsess_answer(test->b, 200, "Answering", NULL, NULL);
	if (err) {
		abort_test(test, err);
	}
}


static int make_sdp(struct mbuf **mbp, const char *sdp)
{
	struct mbuf *desc;
	int err;

	desc = mbuf_alloc(strlen(sdp) + 1);
	if (!desc)
		return ENOMEM;

	err = mbuf_write_str(desc, sdp);
	TEST_ERR(err);

	mbuf_set_pos(desc, 0);
out:
	if (err)
		mem_deref(desc);
	else
		*mbp = desc;

	return err;
}


static void send_update_a(void *arg)
{
	struct test *test = arg;
	struct mbuf *desc = NULL;
	int err;

	err = make_sdp(&desc, sdp_a);
	TEST_ERR(err);

	err = sipsess_modify(test->a, desc);
	TEST_ERR(err);

out:
	mem_deref(desc);
	if (err)
		abort_test(test, err);

}


static void send_update_b(void *arg)
{
	struct test *test = arg;
	struct mbuf *desc = NULL;
	int err;

	err = make_sdp(&desc, sdp_b);
	TEST_ERR(err);

	err = sipsess_modify(test->b, desc);
	TEST_ERR(err);

out:
	mem_deref(desc);
	if (err)
		abort_test(test, err);

}


static int desc_handler(struct mbuf **descp, const struct sa *src,
				const struct sa *dst, void *arg)
{
	struct test *test = arg;
	(void)src;
	(void)dst;

	test->desc = mbuf_alloc(1);
	if (!test->desc)
		return ENOMEM;

	*descp = test->desc;
	return 0;
}


static int desc_handler_a(struct mbuf **descp, const struct sa *src,
				const struct sa *dst, void *arg)
{
	struct mbuf *desc;
	int err = 0;
	(void)src;
	(void)dst;
	(void)arg;

	err = make_sdp(&desc, sdp_a);
	TEST_ERR(err);

	*descp = desc;

out:
	return err;
}


static int offer_handler_a(struct mbuf **descp, const struct sip_msg *msg,
			   void *arg)
{
	struct test *test = arg;
	(void)descp;
	(void)msg;

	if (test->sdp_state == INITIAL || test->sdp_state == EARLY_CONFIRMED)
		test->sdp_state = OFFER_RECEIVED;

	if (!pl_strcmp(&msg->met, "UPDATE"))
		test->upd_a = true;

	test->offer_a = true;

	return 0;
}


static int offer_handler_b(struct mbuf **descp, const struct sip_msg *msg,
			   void *arg)
{
	struct test *test = arg;
	(void)msg;
	int err = 0;

	if (test->sdp_state == INITIAL || test->sdp_state == EARLY_CONFIRMED)
		test->sdp_state = OFFER_RECEIVED;

	if (!pl_strcmp(&msg->met, "UPDATE"))
		test->upd_b = true;

	test->offer_b = true;

	if (test->offer_action == OFFER_ANSW) {
		err = make_sdp(descp, sdp_b);
		TEST_ERR(err);
	}

out:
	return err;
}


static int answer_handler_a(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	test->answr_a = true;
	if (mbuf_get_left(msg->mb))
		test->sdp_state = ANSWER_RECEIVED;

	if (sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED, "100rel"))
		test->rel100_a |= (enum rel100_mode)REL100_SUPPORTED;

	if (sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE, "100rel"))
		test->rel100_a |= (enum rel100_mode)REL100_REQUIRE;

	if (!pl_strcmp(&msg->cseq.met, "UPDATE")) {
		if (msg->scode < 200 || msg->scode > 299) {
			abort_test(test, msg->scode);
			return msg->scode;
		}

		tmr_start(&test->ans_tmr, 0, send_answer_b, test);
	}

	if (test->answ_action == ANSW_CANCEL)
		wait_for_ack(test);

	return 0;
}


static int answer_handler_b(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	test->answr_b = true;
	if (mbuf_get_left(msg->mb))
		test->sdp_state = ANSWER_RECEIVED;

	if (sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED, "100rel"))
		test->rel100_state_b |= REL100_SUPPORTED;

	if (sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE, "100rel"))
		test->rel100_state_b |= REL100_REQUIRE;

	if (!pl_strcmp(&msg->cseq.met, "UPDATE")) {
		if (msg->scode < 200 || msg->scode > 299) {
			abort_test(test, msg->scode);
			return msg->scode;
		}

		tmr_start(&test->ans_tmr, 0, send_answer_b, test);
	}

	return 0;
}


static void progr_handler_a(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;

	test->progr_a = true;
}


static void prack_handler(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;

	if (test->sdp_state == ANSWER_RECEIVED)
		test->sdp_state = EARLY_CONFIRMED;

	if (test->prack_action)
		tmr_start(&test->ans_tmr, 0, test->prack_action, test);
}


static void estab_handler_a(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;

	test->estab_a = true;
	if (test->estab_b)
		stop_test();
}


static void estab_handler_b(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;

	test->estab_b = true;
	if (test->estab_a)
		stop_test();
}


static void close_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	(void)msg;

	if (!err && test->conn_action == CONN_BUSY)
		err = EBUSY;

	abort_test(test, err ? err : ENOMEM);
}


static void conn_handler(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	struct mbuf *desc = NULL;
	int err;
	char *hdrs = test->rel100_b == REL100_REQUIRED ?
		     "Require: 100rel\r\n" : "";

	if (mbuf_get_left(msg->mb)) {
		test->sdp_state = OFFER_RECEIVED;
		test->offer_b = true;
	}

	if (sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED, "100rel"))
		test->rel100_state_b |= REL100_SUPPORTED;

	if (sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE, "100rel"))
		test->rel100_state_b |= REL100_REQUIRE;

	err = make_sdp(&desc, sdp_b);
	TEST_ERR(err);

	test->desc = desc;

	if (test->conn_action & CONN_PROGRESS
	    || test->conn_action & CONN_PROGR_ANS
	    || test->conn_action & CONN_PROGR_UPD) {
		err = sipsess_accept(&test->b, test->sock, msg, 183,
				"Progress", test->rel100_b, "b",
				"application/sdp", desc, NULL, NULL, false,
				offer_handler_b, answer_handler_b,
				estab_handler_b, NULL, NULL, close_handler,
				test, hdrs);
		if (err != test->progr_ret_code) {
			test->progr_ret_code = err;
			goto out;
		}

		if (err)
			mem_deref(desc);

		err = sipsess_set_prack_handler(test->b, prack_handler);
		if (err)
			abort_test(test, err);
	}

	if (test->conn_action & CONN_PROGR_ANS) {
		err = sipsess_answer(test->b, 200, "Answering", NULL, NULL);
		if (err != test->answ_ret_code) {
			test->answ_ret_code = err;
			goto out;
		}
	}
	else if (test->conn_action & CONN_PROGR_UPD) {
		mem_deref(desc);
		desc = mbuf_alloc(0);
		if (!desc) {
			err = ENOMEM;
			goto out;
		}

		mbuf_set_pos(desc, 0);
		test->desc = desc;

		err = sipsess_modify(test->b, desc);
		TEST_ERR(err);
	}
	else if (test->conn_action & CONN_ANSWER) {
		err = sipsess_accept(&test->b, test->sock, msg, 200, "OK",
				test->rel100_b, "b", "application/sdp",
				desc, NULL, NULL, false, offer_handler_b,
				answer_handler_b, estab_handler_b, NULL, NULL,
				close_handler, test, hdrs);
		if (err != test->answ_ret_code) {
			test->answ_ret_code = err;
			goto out;
		}
	}
	else if (test->conn_action & CONN_BUSY) {
		err = sipsess_accept(&test->b, test->sock, msg, 180,
				"Ringing", test->rel100_b, "b",
				"application/sdp", NULL, NULL, NULL, false,
				offer_handler_b, answer_handler_b,
				estab_handler_b, NULL, NULL, close_handler,
				test, hdrs);
		if (err != test->answ_ret_code) {
			test->answ_ret_code = err;
			goto out;
		}
		err |= sipsess_reject(test->b, 486, "Busy Here", NULL);
		if (err != test->answ_ret_code) {
			test->answ_ret_code = err;
			goto out;
		}
	}

	if (test->conn_action & (CONN_ANSWER | CONN_PROGR_ANS | CONN_BUSY))
		mem_deref(desc);

	return;

out:
	mem_deref(desc);
	abort_test(test, err);
}


static void conn_transfer_handler(const struct sip_msg *msg, void *arg)
{
	struct test *test = arg;
	int err = 0;

	if (test->blind_transfer) {
		conn_handler(msg, arg);
	}
	else {
		err = sip_replyf(test->sip, msg, 302, "Moved Temporarily",
			"Contact: \"alt retest\" "
			"<sip:127.0.0.1:%u>\r\n\r\n", test->altaddr_port);
		if (err) {
			abort_test(test, err);
		}
	}

	return;
}


int test_sipsess(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;
	test.conn_action = CONN_ANSWER;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	if (err)
		goto out;

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	if (err)
		goto out;

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	if (err)
		goto out;

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler, &test);
	if (err)
		goto out;

	err = str_x64dup(&callid, rand_u64());
	if (err)
		goto out;

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test, NULL);
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		goto out;
	}

	/* okay here -- verify */
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.desc);
	ASSERT_TRUE(test.answr_a);
	ASSERT_TRUE(test.offer_b);
	ASSERT_TRUE(!test.offer_a);
	ASSERT_TRUE(!test.answr_b);

	/* test re-invite with wait for ACK */
	test.sdp_state = INITIAL;
	test.answ_action = ANSW_CANCEL;
	test.offer_action = OFFER_ANSW;
	err = make_sdp(&test.desc, sdp_a);
	TEST_ERR(err);
	err = sipsess_modify(test.a, test.desc);
	TEST_ERR(err);
	test.desc = mem_deref(test.desc);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		goto out;
	}

	ASSERT_TRUE(test.ack_b);
	ASSERT_TRUE(!sipsess_ack_pending(test.a));
	ASSERT_TRUE(!sipsess_ack_pending(test.b));
	ASSERT_TRUE(test.sdp_state == ANSWER_RECEIVED);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_reject(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_DISABLED;
	test.rel100_b = REL100_DISABLED;
	test.conn_action = CONN_BUSY;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler, &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test, NULL);
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	/* okay here -- verify */
	ASSERT_TRUE(test.err == EBUSY);
	ASSERT_TRUE(!test.estab_a);
	ASSERT_TRUE(!test.estab_b);
	ASSERT_TRUE(test.desc);
	ASSERT_TRUE(!test.answr_a);
	ASSERT_TRUE(!test.offer_b);

out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_blind_transfer(void)
{
	struct test test;
	struct sa laddr, altaddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;
	test.conn_action = CONN_ANSWER;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_transfer_handler,
		&test);
	TEST_ERR(err);

	(void)sa_set_str(&altaddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &altaddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &altaddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	test.altaddr_port = sa_port(&altaddr);

	err = str_x64dup(&callid, rand_u64());
	if (err)
		goto out;

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test, NULL);
	mem_deref(callid);
	TEST_ERR(err);

	test.blind_transfer = true;

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	ASSERT_TRUE(test.blind_transfer);
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.desc);
	ASSERT_TRUE(test.answr_a);
	ASSERT_TRUE(test.offer_b);
	ASSERT_TRUE(!test.offer_a);
	ASSERT_TRUE(!test.answr_b);

 out:
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}

int test_sipsess_100rel_caller_require(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_REQUIRED;
	test.rel100_b = REL100_ENABLED;
	test.conn_action = CONN_PROGRESS;
	test.prack_action = send_answer_b;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test,
			      "Require: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.desc);
	ASSERT_TRUE(test.offer_b);
	ASSERT_TRUE(!test.answr_b);
	ASSERT_TRUE(test.progr_a);
	ASSERT_TRUE(test.rel100_state_b & REL100_REQUIRE);
	ASSERT_TRUE((test.rel100_state_b & REL100_SUPPORTED) == 0);
	ASSERT_TRUE(test.sdp_state == EARLY_CONFIRMED);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	mem_deref(test.desc);

	return err;
}


int test_sipsess_100rel_supported(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;
	test.conn_action = CONN_PROGRESS;
	test.prack_action = send_answer_b;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test,
			      "Supported: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.desc);
	ASSERT_TRUE(test.answr_a);
	ASSERT_TRUE(!test.offer_a);
	ASSERT_TRUE(test.offer_b);
	ASSERT_TRUE(!test.answr_b);
	ASSERT_TRUE(test.progr_a);
	ASSERT_TRUE(test.rel100_state_b & REL100_SUPPORTED);
	ASSERT_TRUE((test.rel100_state_b & REL100_REQUIRE) == 0);
	ASSERT_TRUE(test.sdp_state == EARLY_CONFIRMED);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	mem_deref(test.desc);

	return err;
}


int test_sipsess_100rel_answer_not_allowed(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;
	test.conn_action = CONN_PROGR_ANS;
	test.answ_ret_code = EAGAIN;
	test.prack_action = send_answer_b;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler, &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test,
			      "Supported: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);
	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	TEST_ERR(test.progr_ret_code);
	ASSERT_TRUE(test.answ_ret_code == EAGAIN);

	/* okay here -- verify */
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.progr_a);
	ASSERT_TRUE(test.rel100_state_b & REL100_SUPPORTED);
	ASSERT_TRUE((test.rel100_state_b & REL100_REQUIRE) == 0);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_100rel_420(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_REQUIRED;
	test.rel100_b = REL100_DISABLED;
	test.conn_action = CONN_PROGRESS;
	test.progr_ret_code = -1;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test,
			      "Require: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);
	ASSERT_TRUE(test.err == EPROTO);

	/* okay here -- verify */
	ASSERT_TRUE(!test.b);
	ASSERT_TRUE(!test.estab_a);
	ASSERT_TRUE(!test.estab_b);
	ASSERT_TRUE(test.desc);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_100rel_421(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_DISABLED;
	test.rel100_b = REL100_REQUIRED;
	test.conn_action = CONN_PROGRESS;
	test.progr_ret_code = -1;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler,
			      offer_handler_a, answer_handler_a, NULL,
			      estab_handler_a, NULL, NULL,
			      close_handler, &test, NULL);
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);
	ASSERT_TRUE(test.err == EPROTO);

	/* okay here -- verify */
	ASSERT_TRUE(!test.b);
	ASSERT_TRUE(!test.estab_a);
	ASSERT_TRUE(!test.estab_b);
	ASSERT_TRUE(test.desc);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	return err;
}


int test_sipsess_update_uac(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	struct mbuf *desc_a = NULL;
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;
	test.conn_action = CONN_PROGRESS;
	test.prack_action = send_update_a;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test,
			      "Supported: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.answr_a);
	ASSERT_TRUE(!test.answr_b);
	ASSERT_TRUE(!test.offer_a);
	ASSERT_TRUE(test.offer_b);
	ASSERT_TRUE(test.progr_a);
	ASSERT_TRUE(test.upd_b);
	ASSERT_TRUE(!test.upd_a);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	mem_deref(desc_a);
	mem_deref(test.desc);

	return err;
}


int test_sipsess_update_uas(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	struct mbuf *desc_a = NULL;
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_ENABLED;
	test.rel100_b = REL100_ENABLED;
	test.conn_action = CONN_PROGRESS;
	test.prack_action = send_update_b;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test,
			      "Supported: 100rel\r\n");
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.answr_a);
	ASSERT_TRUE(test.answr_b);
	ASSERT_TRUE(test.offer_a);
	ASSERT_TRUE(test.offer_b);
	ASSERT_TRUE(test.progr_a);
	ASSERT_TRUE(test.upd_a);
	ASSERT_TRUE(!test.upd_b);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	mem_deref(desc_a);
	mem_deref(test.desc);

	return err;
}


int test_sipsess_update_no_sdp(void)
{
	struct test test;
	struct sa laddr;
	char to_uri[256];
	struct mbuf *desc_a = NULL;
	int err;
	uint16_t port;
	char *callid;

	memset(&test, 0, sizeof(test));

	test.rel100_a = REL100_DISABLED;
	test.rel100_b = REL100_DISABLED;
	test.conn_action = CONN_PROGR_UPD;

	err = sip_alloc(&test.sip, NULL, 32, 32, 32,
			"retest", exit_handler, NULL);
	TEST_ERR(err);

	(void)sa_set_str(&laddr, "127.0.0.1", 0);
	err = sip_transp_add(test.sip, SIP_TRANSP_UDP, &laddr);
	TEST_ERR(err);

	err = sip_transp_laddr(test.sip, &laddr, SIP_TRANSP_UDP, NULL);
	TEST_ERR(err);

	port = sa_port(&laddr);

	err = sipsess_listen(&test.sock, test.sip, 32, conn_handler,
			     &test);
	TEST_ERR(err);

	err = str_x64dup(&callid, rand_u64());
	TEST_ERR(err);

	/* Connect to "b" */
	(void)re_snprintf(to_uri, sizeof(to_uri), "sip:b@127.0.0.1:%u", port);
	err = sipsess_connect(&test.a, test.sock, to_uri, NULL,
			      "sip:a@127.0.0.1", "a", NULL, 0,
			      "application/sdp", NULL, NULL, false,
			      callid, desc_handler_a,
			      offer_handler_a, answer_handler_a,
			      progr_handler_a, estab_handler_a, NULL,
			      NULL, close_handler, &test, NULL);
	mem_deref(callid);
	TEST_ERR(err);

	err = re_main_timeout(200);
	TEST_ERR(err);

	if (test.err) {
		err = test.err;
		TEST_ERR(err);
	}

	/* okay here -- verify */
	ASSERT_TRUE(test.estab_a);
	ASSERT_TRUE(test.estab_b);
	ASSERT_TRUE(test.answr_a);
	ASSERT_TRUE(test.answr_b);
	ASSERT_TRUE(!test.offer_a);
	ASSERT_TRUE(test.offer_b);
	ASSERT_TRUE(test.progr_a);

out:
	tmr_cancel(&test.ans_tmr);
	test.a = mem_deref(test.a);
	test.b = mem_deref(test.b);

	sipsess_close_all(test.sock);
	test.sock = mem_deref(test.sock);

	sip_close(test.sip, false);
	test.sip = mem_deref(test.sip);

	mem_deref(desc_a);
	mem_deref(test.desc);

	return err;
}
