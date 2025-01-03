/**
 * @file tcp.c  TCP testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "tcptest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 *               .------.                            .------.
 *               |Client|                            |Server|
 *               '------'                            '------'
 *
 *                                                       <------ tcp_listen()
 * tcp_connect() --->
 *                   ------------- TCP [SYN] ----------->
 *                                                       -----> tcp_conn_h
 *
 *                                                       <----- tcp_accept()
 *                   <-------- TCP [SYN, ACK] ----------
 *                   --------- TCP [ACK] -------------->
 * tcp_estab_h   <---
 *
 * tcp_send()    ===>
 *                    ======= TCP [PSH, ACK] ==========>
 *                   <======= TCP [ACK] ===============
 *                                                       =====> tcp_recv_h
 */

struct tcp_test {
	struct tcp_sock *ts;
	struct tcp_conn *tc;
	struct tcp_conn *tc2;
	int err;
};


static const char *ping = "ping from client to server\n";
static const char *pong = "pong from server 2 client\n";


static void destructor(void *arg)
{
	struct tcp_test *tt = arg;

	mem_deref(tt->tc2);
	mem_deref(tt->tc);
	mem_deref(tt->ts);
}


static void abort_test(struct tcp_test *tt, int err)
{
	if (err) {
		tt->err = err;
	}

	re_cancel();
}


static int send_data(struct tcp_conn *tc, const char *data)
{
	struct mbuf mb;
	int err;

	mbuf_init(&mb);

	err = mbuf_write_str(&mb, data);
	if (err)
		goto out;

	mb.pos = 0;
	err = tcp_send(tc, &mb);
	if (err)
		goto out;

 out:
	mbuf_reset(&mb);
	return err;
}


static bool mbuf_compare(const struct mbuf *mb, const char *str)
{
	if (mbuf_get_left(mb) != strlen(str)) {
		DEBUG_WARNING("compare: mbuf=%u str=%u (bytes)\n",
			      mbuf_get_left(mb), strlen(str));
		return false;
	}

	if (0 != memcmp(mbuf_buf(mb), str, strlen(str))) {
		DEBUG_WARNING("compare: mbuf=[%b] str=[%s]\n",
			      mbuf_buf(mb), mbuf_get_left(mb), str);
		return false;
	}

	return true;
}


static void tcp_server_recv_handler(struct mbuf *mb, void *arg)
{
	struct tcp_test *tt = arg;
	int err;

	DEBUG_INFO("Server: TCP Receive data (%u bytes)\n",
		   mbuf_get_left(mb));

	if (!mbuf_compare(mb, ping)) {
		abort_test(tt, EBADMSG);
		return;
	}

	err = send_data(tt->tc2, pong);
	if (err)
		abort_test(tt, err);
}


static void tcp_server_close_handler(int err, void *arg)
{
	struct tcp_test *tt = arg;
	abort_test(tt, err);
}


static void tcp_server_conn_handler(const struct sa *peer, void *arg)
{
	struct tcp_test *tt = arg;
	int err;

	(void)peer;

	DEBUG_INFO("Server: Incoming CONNECT from %J\n", peer);

	err = tcp_accept(&tt->tc2, tt->ts, NULL, tcp_server_recv_handler,
			 tcp_server_close_handler, tt);
	if (err) {
		abort_test(tt, err);
		return;
	}
}


static void tcp_client_estab_handler(void *arg)
{
	struct tcp_test *tt = arg;
	int err;

	DEBUG_INFO("Client: TCP Established\n");

	err = send_data(tt->tc, ping);
	if (err)
		abort_test(tt, err);
}


static void tcp_client_recv_handler(struct mbuf *mb, void *arg)
{
	struct tcp_test *tt = arg;

	DEBUG_INFO("Client: TCP receive: %u bytes\n", mbuf_get_left(mb));

	if (!mbuf_compare(mb, pong)) {
		abort_test(tt, EBADMSG);
		return;
	}

	abort_test(tt, 0);
}


static void tcp_client_close_handler(int err, void *arg)
{
	struct tcp_test *tt = arg;
	DEBUG_NOTICE("Client: TCP Close (%m)\n", err);

	abort_test(tt, err);
}


int test_tcp(void)
{
	struct tcp_test *tt;
	struct sa srv;
	int err;

	tt = mem_zalloc(sizeof(*tt), destructor);
	if (!tt)
		return ENOMEM;

	err = sa_set_str(&srv, "127.0.0.1", 0);
	if (err)
		goto out;

	err = tcp_listen(&tt->ts, &srv, tcp_server_conn_handler, tt);
	if (err)
		goto out;

	err = tcp_local_get(tt->ts, &srv);
	if (err)
		goto out;

	err = tcp_connect(&tt->tc, &srv, tcp_client_estab_handler,
			  tcp_client_recv_handler, tcp_client_close_handler,
			  tt);
	if (err)
		goto out;

	err = re_main_timeout(500);
	if (err)
		goto out;

	if (tt->err)
		err = tt->err;

 out:
	mem_deref(tt);

	return err;
}


#if !defined(WIN32)
static int tcp_tos(const char *addr)
{
	struct tcp_test *tt;
	struct sa srv;
	int err;

	tt = mem_zalloc(sizeof(*tt), destructor);
	if (!tt)
		return ENOMEM;

	err = sa_set_str(&srv, addr, 0);
	TEST_ERR(err);

	err = tcp_listen(&tt->ts, &srv, tcp_server_conn_handler, tt);
	TEST_ERR(err);

	err  = tcp_settos(tt->ts, 184);
	TEST_ERR(err);

	err = tcp_local_get(tt->ts, &srv);
	TEST_ERR(err);

	err = tcp_connect(&tt->tc, &srv, tcp_client_estab_handler,
			  tcp_client_recv_handler, tcp_client_close_handler,
			  tt);
	TEST_ERR(err);

	err = re_main_timeout(500);
	TEST_ERR(err);

	if (tt->err)
		err = tt->err;

 out:
	mem_deref(tt);

	return err;
}


int test_tcp_tos(void)
{
	int err;

	err = tcp_tos("127.0.0.1");
	TEST_ERR(err);

	if (test_ipv6_supported()) {
		err = tcp_tos("::1");
		TEST_ERR(err);
	}

 out:
	return err;
}
#else
/* Outcome of the TOS test on Windows would be dependent on the
 * DisableUserTOSSetting Windows registry setting. */
int test_tcp_tos(void)
{
	return 0;
}
#endif
