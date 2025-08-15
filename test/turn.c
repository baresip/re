/**
 * @file turn.c  TURN testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_atomic.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_turn"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum rx_state {
	RX_NULL = 0,
	RX_DETACH,
	RX_ATTACH,
	RX_READY,
	RX_CLOSE
};


struct turntest {
	struct turnc *turnc;
	struct turnserver *turnsrv;
	struct udp_sock *us_cli;
	struct udp_sock *us_peer;
	struct tcp_conn *tc;
	struct sa cli;
	struct sa peer;
	struct mbuf *mb;
	struct tmr tmr;
	uint32_t lifetime;
	enum rx_state rx_state;
	thrd_t thr;
	mtx_t *mtx;
	int proto;
	int err;

	size_t n_alloc_resp;
	size_t n_chan_resp;
	size_t n_peer_recv;
};


static const char *test_payload = "guten tag Herr TURN server";


static void destructor(void *arg)
{
	struct turntest *tt = arg;

	/* NOTE: must be derefed before udp socket */
	mem_deref(tt->turnc);

	mem_deref(tt->us_cli);
	mem_deref(tt->us_peer);
	mem_deref(tt->tc);
	mem_deref(tt->mb);
	mem_deref(tt->turnsrv);
	mem_deref(tt->mtx);
}


static bool is_complete(struct turntest *tt)
{
	return tt->n_chan_resp >= 1 && tt->n_peer_recv >= 2;
}


static void complete_test(struct turntest *tt, int err)
{
	tt->err = err;
	re_cancel();
}


/* send a UDP payload via TURN-Server to a UDP-peer */
static int send_payload(struct turntest *tt, size_t offset,
			const struct sa *dst, const char *str)
{
	struct mbuf *mb = mbuf_alloc(offset + str_len(str));
	int err;

	if (!mb)
		return ENOMEM;

	mb->pos = offset;

	err = mbuf_write_str(mb, str);
	if (err)
		goto out;

	mb->pos = offset;

	switch (tt->proto) {

	case IPPROTO_UDP:
		err = udp_send(tt->us_cli, dst, mb);
		break;

	case IPPROTO_TCP:
		err = turnc_send(tt->turnc, dst, mb);
		break;
	}

 out:
	mem_deref(mb);

	return err;
}


static void turnc_chan_handler(void *arg)
{
	struct turntest *tt = arg;
	int err = 0;

	++tt->n_chan_resp;

	err |= send_payload(tt, 4, &tt->peer, test_payload);
	if (err) {
		DEBUG_WARNING("failed to send payload (%m)\n", err);
		complete_test(tt, err);
	}

	if (err)
		complete_test(tt, err);
}


static void turnc_handler(int err, uint16_t scode, const char *reason,
			  const struct sa *relay_addr,
			  const struct sa *mapped_addr,
			  const struct stun_msg *msg,
			  void *arg)
{
	struct turntest *tt = arg;
	(void)reason;
	(void)msg;

	++tt->n_alloc_resp;

	if (err) {
		complete_test(tt, err);
		return;
	}

	if (scode) {
		complete_test(tt, EPROTO);
		return;
	}

	TEST_SACMP(&tt->turnsrv->relay, relay_addr, SA_ALL);
	TEST_SACMP(&tt->cli, mapped_addr, SA_ALL);

	/* Permission is needed for sending data */
	err = turnc_add_perm(tt->turnc, &tt->peer, NULL, NULL);
	if (err)
		goto out;

	/* Headroom for IPv4/IPv6 STUN headers */
	const size_t offset = 48;

	err |= send_payload(tt, offset, &tt->peer, test_payload);
	if (err) {
		DEBUG_WARNING("failed to send payload (%m)\n", err);
		complete_test(tt, err);
	}

	err = turnc_add_chan(tt->turnc, &tt->peer,
			     turnc_chan_handler, tt);
	if (err)
		goto out;

 out:
	if (err)
		complete_test(tt, err);
}


static void peer_udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct turntest *tt = arg;
	int err = 0;
	(void)src;

	++tt->n_peer_recv;

	err = udp_send(tt->us_peer, src, mb);
	TEST_ERR(err);

	TEST_MEMCMP(test_payload, strlen(test_payload),
		    mbuf_buf(mb), mbuf_get_left(mb));

	mtx_lock(tt->mtx);
	if (tt->rx_state > RX_NULL) {
		mtx_unlock(tt->mtx);
		return;
	}
	mtx_unlock(tt->mtx);

 out:
	if (err || is_complete(tt))
		complete_test(tt, err);
}


static void cli_udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct turntest *tt = arg;
	(void)src;

	mtx_lock(tt->mtx);
	if (tt->rx_state == RX_DETACH) {
		udp_thread_detach(tt->us_cli);
		tt->rx_state = RX_ATTACH;
	}
	mtx_unlock(tt->mtx);

	udp_send(tt->us_cli, src, mb);
}


static void data_handler(struct turntest *tt, struct mbuf *mb)
{
	(void)tt;
	(void)mb;
}


static void tcp_estab_handler(void *arg)
{
	struct turntest *tt = arg;
	int err;

	err = tcp_conn_local_get(tt->tc, &tt->cli);
	if (err)
		goto out;

	err = turnc_alloc(&tt->turnc, NULL, IPPROTO_TCP, tt->tc,
			  0, &tt->turnsrv->laddr_tcp,
			  "username", "password", tt->lifetime,
			  turnc_handler, tt);
	if (err)
		goto out;

 out:
	if (err)
		complete_test(tt, err);
}


static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
	struct turntest *tl = arg;
	int err = 0;

	if (tl->mb) {
		size_t pos;

		pos = tl->mb->pos;

		tl->mb->pos = tl->mb->end;

		err = mbuf_write_mem(tl->mb, mbuf_buf(mb),mbuf_get_left(mb));
		if (err)
			goto out;

		tl->mb->pos = pos;
	}
	else {
		tl->mb = mem_ref(mb);
	}

	for (;;) {

		size_t len, pos, end;
		struct sa src;
		uint16_t typ;

		if (mbuf_get_left(tl->mb) < 4)
			break;

		typ = ntohs(mbuf_read_u16(tl->mb));
		len = ntohs(mbuf_read_u16(tl->mb));

		if (typ < 0x4000)
			len += STUN_HEADER_SIZE;
		else if (typ < 0x8000)
			len += 4;
		else {
			err = EBADMSG;
			goto out;
		}

		tl->mb->pos -= 4;

		if (mbuf_get_left(tl->mb) < len)
			break;

		pos = tl->mb->pos;
		end = tl->mb->end;

		tl->mb->end = pos + len;

		err = turnc_recv(tl->turnc, &src, tl->mb);
		if (err)
			goto out;

		if (mbuf_get_left(tl->mb))
			data_handler(tl, tl->mb);

		/* 4 byte alignment */
		while (len & 0x03)
			++len;

		tl->mb->pos = pos + len;
		tl->mb->end = end;

		if (tl->mb->pos >= tl->mb->end) {
			tl->mb = mem_deref(tl->mb);
			break;
		}
	}

 out:
	if (err)
		complete_test(tl, err);
}


static void tcp_close_handler(int err, void *arg)
{
	struct turntest *tt = arg;

	if (err == ECONNRESET) {
		re_printf("translate ECONNRESET -> ENOMEM\n");
		err = ENOMEM;
	}

	if (err)
		complete_test(tt, err);
}


static int turntest_alloc(struct turntest **ttp, int proto, uint32_t lifetime,
			  const char *addr)
{
	struct turntest *tt;
	struct sa laddr;
	int err;

	tt = mem_zalloc(sizeof(*tt), NULL);
	if (!tt)
		return ENOMEM;

	err = mutex_alloc(&tt->mtx);
	if (err)
		goto out;

	mem_destructor(tt, destructor);

	tt->proto    = proto;
	tt->lifetime = lifetime;

	err  = sa_set_str(&laddr, addr, 0);
	if (err)
		goto out;

	if (proto == IPPROTO_UDP) {
		err |= udp_listen(&tt->us_cli, &laddr, cli_udp_recv, tt);
		if (err)
			goto out;

		err = udp_local_get(tt->us_cli, &tt->cli);
		if (err)
			goto out;
	}

	err = udp_listen(&tt->us_peer, &laddr, peer_udp_recv, tt);
	if (err)
		goto out;

	err = udp_local_get(tt->us_peer, &tt->peer);
	if (err)
		goto out;

	err = turnserver_alloc(&tt->turnsrv, addr);
	if (err)
		goto out;

	switch (proto) {

	case IPPROTO_UDP:
		err = turnc_alloc(&tt->turnc, NULL, proto, tt->us_cli,
				  0, &tt->turnsrv->laddr,
				  "username", "password", lifetime,
				  turnc_handler, tt);
		break;

	case IPPROTO_TCP:
		err = tcp_connect(&tt->tc, &tt->turnsrv->laddr_tcp,
				  tcp_estab_handler, tcp_recv_handler,
				  tcp_close_handler, tt);
		break;
	}
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(tt);
	else if (ttp)
		*ttp = tt;

	return err;
}


static int test_turn_param(const char *addr)
{
	struct turntest *tt;
	int err;

	err = turntest_alloc(&tt, IPPROTO_UDP, 600, addr);
	if (err)
		return err;

	err = re_main_timeout(200);
	TEST_ERR(err);

	err = tt->err;
	TEST_ERR(err);

	/* verify results after test is complete */

	TEST_EQUALS(1, tt->n_alloc_resp);
	TEST_EQUALS(1, tt->n_chan_resp);
	TEST_EQUALS(2, tt->n_peer_recv);

	TEST_ASSERT(tt->turnsrv->n_allocate >= 1);
	TEST_ASSERT(tt->turnsrv->n_chanbind >= 1);
	TEST_ASSERT(tt->turnsrv->n_raw >= 1);
	TEST_EQUALS(1, tt->turnsrv->n_send);

 out:
	mem_deref(tt);

	return err;
}


int test_turn(void)
{
	int err = test_turn_param("127.0.0.1");
	TEST_ERR(err);

	if (test_ipv6_supported()) {
		err = test_turn_param("::1");
		TEST_ERR(err);
	}

 out:
	return err;
}


int test_turn_tcp(void)
{
	struct turntest *tt;
	int err;

	err = turntest_alloc(&tt, IPPROTO_TCP, 600, "127.0.0.1");
	if (err)
		return err;

	err = re_main_timeout(200);
	TEST_ERR(err);

	err = tt->err;
	TEST_ERR(err);

	/* verify results after test is complete */

	TEST_EQUALS(1, tt->n_alloc_resp);
	TEST_EQUALS(1, tt->n_chan_resp);
	TEST_EQUALS(2, tt->n_peer_recv);

	TEST_ASSERT(tt->turnsrv->n_allocate >= 1);
	TEST_ASSERT(tt->turnsrv->n_chanbind >= 1);
	TEST_ASSERT(tt->turnsrv->n_raw >= 1);
	TEST_EQUALS(1, tt->turnsrv->n_send);

 out:
	mem_deref(tt);

	return err;
}


static void tmr_handler(void *arg)
{
	struct turntest *tt = arg;

	mtx_lock(tt->mtx);
	if (tt->rx_state == RX_CLOSE)
		re_cancel();

	if (tt->rx_state == RX_ATTACH) {
		udp_thread_attach(tt->us_cli);
		tt->rx_state = RX_READY;
	}
	mtx_unlock(tt->mtx);

	tmr_start(&tt->tmr, 0, tmr_handler, tt);
}


static int turn_thread(void *arg)
{
	struct turntest *tt = arg;
	int err;

	re_thread_init();

	tmr_init(&tt->tmr);
	tmr_start(&tt->tmr, 0, tmr_handler, tt);

	err = re_main(NULL);
	TEST_ERR(err);

	tmr_cancel(&tt->tmr);

out:
	re_thread_close();
	return err;
}


int test_turn_thread(void)
{
	struct turntest *tt;
	int err;

	err = turntest_alloc(&tt, IPPROTO_UDP, 0, "127.0.0.1");
	if (err)
		return err;

	tt->rx_state = RX_DETACH;

	thread_create_name(&tt->thr, "test_turn_thread", turn_thread, tt);

	re_main_timeout(500);

	mtx_lock(tt->mtx);
	tt->rx_state = RX_CLOSE;
	mtx_unlock(tt->mtx);

	thrd_join(tt->thr, &err);
	TEST_ERR(err);

	err = tt->err;
	TEST_ERR(err);

out:
	mem_deref(tt);

	return err;
}
