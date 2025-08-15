/**
 * @file combo/dtls_turn.c  DTLS over TURN combination test
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "dtls_turn"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * Combined test of DTLS over TURN, involving two agents.
 *
 *   Agent A:                          Agent B:
 *   -------                           -------
 *
 *
 *     DTLS                             DTLS
 *    Client                           Server
 *      |                                 |
 *      |                                 |
 *      |               .................UDP
 *     TURN           TURN
 *    Client         Server
 *      |              |
 *      |              |
 *     UDP............UDP
 */


enum {
	LAYER_DTLS =  100,
	LAYER_TURN = -100
};


struct agent {

	/* DTLS layer: */
	struct tls *tls;
	struct dtls_sock *dtls_sock;
	struct tls_conn *dtls_conn;
	bool dtls_active;
	unsigned dtls_n_conn;
	unsigned dtls_n_estab;
	unsigned dtls_n_recv;

	/* TURN layer: */
	bool use_turn;
	bool turn_channels;
	struct turnc *turnc;
	struct turnserver *turnsrv;
	unsigned turn_n_alloc_resp;
	unsigned turn_n_perm_resp;
	unsigned turn_n_chan_resp;

	/* common stuff: */
	struct agent *peer;
	struct udp_sock *us;
	struct sa addr;
	unsigned udp_n_recv;
	int err;
};


static int agent_start(struct agent *ag);


static void complete_test(struct agent *ag, int err)
{
	ag->err = err;
	re_cancel();
}


static bool are_established(struct agent *ag)
{
	return ag->dtls_n_estab && ag->peer->dtls_n_estab;
}


static void dtls_estab_handler(void *arg)
{
	struct agent *ag = arg;

	++ag->dtls_n_estab;

	if (are_established(ag)) {
		re_cancel();
	}
}


static void dtls_recv_handler(struct mbuf *mb, void *arg)
{
	struct agent *ag = arg;
	int err;

	++ag->dtls_n_recv;

	if (!ag->dtls_active) {

		/* ECHO SERVER */
		err = dtls_send(ag->dtls_conn, mb);
		if (err) {
			complete_test(ag, err);
		}
	}
}


static void dtls_close_handler(int err, void *arg)
{
	struct agent *ag = arg;
	(void)err;

	ag->dtls_conn = mem_deref(ag->dtls_conn);
}


static void dtls_conn_handler(const struct sa *src, void *arg)
{
	struct agent *ag = arg;
	int err;
	(void)src;

	TEST_ASSERT(!ag->dtls_active);

	++ag->dtls_n_conn;

	TEST_ASSERT(ag->dtls_conn == NULL);

	err = dtls_accept(&ag->dtls_conn, ag->tls, ag->dtls_sock,
			  dtls_estab_handler, dtls_recv_handler,
			  dtls_close_handler, ag);
	if (err)
		goto out;

 out:
	if (err)
		complete_test(ag, err);
}


static void turnc_perm_handler(void *arg)
{
	struct agent *ag = arg;

	++ag->turn_n_perm_resp;

	/* Permission has been granted, we can start DTLS */
	agent_start(ag);
}


static void turnc_chan_handler(void *arg)
{
	struct agent *ag = arg;

	++ag->turn_n_chan_resp;

	/* Channel has been created, we can start DTLS */
	agent_start(ag);
}


static bool is_turn_ready(struct agent *ag)
{
	if (ag->use_turn)
		return ag->turn_n_alloc_resp;
	else
		return true;
}


static bool are_turn_ready(struct agent *ag)
{
	return is_turn_ready(ag) && is_turn_ready(ag->peer);
}


static int agent_permchan(struct agent *ag)
{
	int err;

	/* Channels or Permission is needed for sending data */
	if (ag->turn_channels) {
		err = turnc_add_chan(ag->turnc, &ag->peer->addr,
				     turnc_chan_handler, ag);
	}
	else {
		err = turnc_add_perm(ag->turnc, &ag->peer->addr,
				     turnc_perm_handler, ag);
	}

	return err;
}


static void turnc_handler(int err, uint16_t scode, const char *reason,
			  const struct sa *relay_addr,
			  const struct sa *mapped_addr,
			  const struct stun_msg *msg,
			  void *arg)
{
	struct agent *ag = arg;

	(void)reason;
	(void)mapped_addr;
	(void)msg;

	++ag->turn_n_alloc_resp;

	if (err || scode) {
		complete_test(ag, err ? err : EPROTO);
		return;
	}

	/* Public address must be updated */
	ag->addr = *relay_addr;

	if (are_turn_ready(ag)) {

		agent_permchan(ag);
		agent_permchan(ag->peer);
	}
}


/* in this test we expect no UDP packets */
static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct agent *ag = arg;
	(void)src;
	(void)mb;

	++ag->udp_n_recv;
}


static void destructor(void *arg)
{
	struct agent *ag = arg;

	mem_deref(ag->dtls_conn);
	mem_deref(ag->dtls_sock);
	mem_deref(ag->tls);

	mem_deref(ag->turnc);
	mem_deref(ag->turnsrv);

	mem_deref(ag->us);
}


static int agent_alloc(struct agent **agp, uint16_t lport,
		       bool use_turn, bool turn_channels, bool dtls_active)
{
	struct agent *ag;
	int err;

	ag = mem_zalloc(sizeof(*ag), destructor);
	if (!ag)
		return ENOMEM;

	/* allocate common */
	err = sa_set_str(&ag->addr, "127.0.0.1", lport);
	if (err)
		goto out;

	err = udp_listen(&ag->us, &ag->addr, udp_recv, ag);
	if (err)
		goto out;

	err = udp_local_get(ag->us, &ag->addr);
	if (err)
		goto out;

	/* allocate TURN */
	ag->use_turn = use_turn;
	if (use_turn) {
		ag->turn_channels = turn_channels;

		err = turnserver_alloc(&ag->turnsrv, "127.0.0.1");
		if (err)
			goto out;

		err = turnc_alloc(&ag->turnc, NULL, IPPROTO_UDP, ag->us,
				  LAYER_TURN, &ag->turnsrv->laddr,
				  "username", "password", 600,
				  turnc_handler, ag);
		if (err)
			goto out;
	}

	/* allocate DTLS */
	ag->dtls_active = dtls_active;

	err = tls_alloc(&ag->tls, TLS_METHOD_DTLSV1, NULL, NULL);
	if (err)
		goto out;

	err = tls_set_certificate(ag->tls, test_certificate_ecdsa,
				  strlen(test_certificate_ecdsa));
	if (err)
		goto out;

	err = dtls_listen(&ag->dtls_sock, NULL, ag->us, 4, LAYER_DTLS,
			  dtls_conn_handler, ag);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(ag);
	else if (agp)
		*agp = ag;

	return err;
}


static int agent_start(struct agent *ag)
{
	int err = 0;

	if (ag->dtls_active) {

		TEST_ASSERT(ag->dtls_conn == NULL);

		err = dtls_connect(&ag->dtls_conn, ag->tls, ag->dtls_sock,
				   &ag->peer->addr, dtls_estab_handler,
				   dtls_recv_handler,
				   dtls_close_handler, ag);
		if (err)
			return err;
	}

 out:
	return err;
}


static int agent_verify(struct agent *ag)
{
	int err = 0;

	/* common stuff */
	TEST_EQUALS(0, ag->err);
	TEST_EQUALS(0, ag->udp_n_recv);

	/* TURN */
	if (ag->use_turn) {

		TEST_EQUALS(1, ag->turn_n_alloc_resp);
		TEST_EQUALS(ag->turn_channels ? 0 : 1, ag->turn_n_perm_resp);
		TEST_EQUALS(ag->turn_channels ? 1u : 0, ag->turn_n_chan_resp);

		TEST_ASSERT(ag->turnsrv->n_allocate >= 1);
		if (ag->turn_channels) {
			TEST_ASSERT(ag->turnsrv->n_chanbind >= 1);
			TEST_ASSERT(ag->turnsrv->n_createperm == 0);
			TEST_EQUALS(0, ag->turnsrv->n_send);
			TEST_ASSERT(ag->turnsrv->n_raw >= 2);
		}
		else {
			TEST_ASSERT(ag->turnsrv->n_chanbind == 0);
			TEST_ASSERT(ag->turnsrv->n_createperm >= 1);
			TEST_EQUALS(2, ag->turnsrv->n_send);
			TEST_EQUALS(0, ag->turnsrv->n_raw);
		}
	}

	/* DTLS */
	TEST_ASSERT(ag->dtls_conn != NULL);
	TEST_EQUALS(ag->dtls_active ? 0 : 1, ag->dtls_n_conn);
	TEST_EQUALS(1, ag->dtls_n_estab);
	TEST_EQUALS(0, ag->dtls_n_recv);

 out:
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


int test_dtls_turn(void)
{
	struct agent *a = NULL, *b = NULL;
	int err = 0;

	if (!have_dtls_support(TLS_METHOD_DTLSV1)) {
		re_fprintf(stderr, "skip DTLS/TURN test\n");
		return ESKIPPED;
	}

	err = agent_alloc(&a, 0, true, true, true);
	if (err)
		goto out;
	err = agent_alloc(&b, 0, false, false, false);
	if (err)
		goto out;

	/* connect the 2 agents */
	if (a)
		a->peer = b;
	if (b)
		b->peer = a;

	/* start it! */
	err = re_main_timeout(1000);
	if (err)
		goto out;

	if (a) {
		TEST_EQUALS(0, a->err);
	}
	if (b) {
		TEST_EQUALS(0, b->err);
	}

	/* verify results after test is complete */
	err |= agent_verify(a);
	err |= agent_verify(b);
	if (err)
		goto out;

 out:
	mem_deref(b);
	mem_deref(a);
	return err;
}
