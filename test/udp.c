/**
 * @file udp.c  UDP testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "udptest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct udp_test {
	struct udp_sock *usc;
	struct udp_sock *uss;
	struct udp_helper *uh;
	struct sa cli;
	struct sa srv;
	int tindex;
	int err;
};

struct udp_quiesce_test {
	struct udp_sock *us;
	struct udp_helper *helper;
	struct udp_helper *boundary;
	struct mbuf *mb;
	struct sa peer;
	mtx_t mutex;
	cnd_t condition;
	bool send;
	bool entered;
	bool allow_return;
	bool returned;
	bool quiesce_started;
	bool quiesce_done;
	int calls;
	int external_calls;
	int callback_err;
	int quiesce_err;
};

struct udp_cross_quiesce_test {
	struct udp_sock *us_a;
	struct udp_sock *us_b;
	struct udp_helper *helper_a;
	struct udp_helper *helper_b;
	struct mbuf *mb_a;
	struct mbuf *mb_b;
	struct sa peer;
	mtx_t mutex;
	cnd_t condition;
	bool b_entered;
	bool a_entered;
	bool allow_b_return;
	bool b_returned;
	int a_err;
};


static const char *data0 = "data from client to server";


static void destructor(void *arg)
{
	struct udp_test *ut = arg;
	mem_deref(ut->uh);
	mem_deref(ut->usc);
	mem_deref(ut->uss);
}


static int send_data(struct udp_sock *us, const struct sa *peer,
		     const char *data)
{
	struct mbuf *mb = mbuf_alloc(strlen(data) + 1);
	int err;
	if (!mb)
		return ENOMEM;

	(void)mbuf_write_str(mb, data);
	mb->pos = 0;

	err = udp_send(us, peer, mb);

	mem_deref(mb);

	return err;
}


static bool mbuf_compare(const struct mbuf *mb, const char *str)
{
	if (mbuf_get_left(mb) != strlen(str))
		return false;

	if (0 != memcmp(mbuf_buf(mb), str, strlen(str)))
		return false;

	return true;
}


static void udp_recv_client(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct udp_test *ut = arg;

	switch (ut->tindex++) {

	case 0:
		if (!mbuf_compare(mb, data0)) {
			ut->err = EBADMSG;
			break;
		}
		if (!sa_cmp(src, &ut->srv, SA_ALL)) {
			ut->err = EPROTO;
			break;
		}
		break;

	default:
		ut->err = ERANGE;
		break;
	}

	if (ut->tindex >= 1)
		re_cancel();
}


/* Echo server */
static void udp_recv_server(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct udp_test *ut = arg;
	int err;

	err = udp_send(ut->uss, src, mb);
	if (err)
		ut->err = err;

	/* Receive a UDP Datagram on this UDP socket */
	udp_recv_packet(ut->usc, &ut->srv, mb);
}


static bool udp_helper_send(int *err, struct sa *dst,
			    struct mbuf *mb, void *arg)
{
	struct udp_test *ut = arg;
	const size_t pos = mb->pos;

	if (!sa_cmp(dst, &ut->srv, SA_ALL)) {
		*err = EPROTO;
		return false;
	}

	if (!mbuf_compare(mb, data0)) {
		*err = EBADMSG;
		return false;
	}

	/* Append a fake protocol trailer */
	mb->pos = mb->end;
	*err = mbuf_write_str(mb, "ABCD");

	mb->pos = pos;

	return false;
}


static bool udp_helper_recv(struct sa *src, struct mbuf *mb, void *arg)
{
	struct udp_test *ut = arg;

	if (!sa_cmp(src, &ut->srv, SA_ALL))
		ut->err = EPROTO;

	mb->end -= 4;

	if (!mbuf_compare(mb, data0))
		ut->err = EBADMSG;

	return false;
}


static int quiesce_helper_call(struct udp_quiesce_test *qt)
{
	int err = 0;

	mtx_lock(&qt->mutex);
	++qt->calls;
	qt->entered = true;
	cnd_broadcast(&qt->condition);
	while (!qt->allow_return) {
		if (cnd_wait(&qt->condition, &qt->mutex) != thrd_success) {
			err = EPROTO;
			break;
		}
	}
	qt->returned = true;
	cnd_broadcast(&qt->condition);
	mtx_unlock(&qt->mutex);

	return err;
}


static bool quiesce_send_handler(int *err, struct sa *dst,
				 struct mbuf *mb, void *arg)
{
	struct udp_quiesce_test *qt = arg;
	(void)dst;
	(void)mb;

	*err = quiesce_helper_call(qt);
	return false;
}


static bool quiesce_recv_handler(struct sa *src, struct mbuf *mb, void *arg)
{
	struct udp_quiesce_test *qt = arg;
	(void)src;
	(void)mb;

	qt->callback_err = quiesce_helper_call(qt);
	return false;
}


static int quiesce_external_send(const struct sa *dst, struct mbuf *mb,
				  void *arg)
{
	struct udp_quiesce_test *qt = arg;
	(void)dst;
	(void)mb;

	mtx_lock(&qt->mutex);
	++qt->external_calls;
	mtx_unlock(&qt->mutex);
	return 0;
}


static void quiesce_external_recv(const struct sa *src, struct mbuf *mb,
				  void *arg)
{
	struct udp_quiesce_test *qt = arg;
	(void)src;
	(void)mb;

	mtx_lock(&qt->mutex);
	++qt->external_calls;
	mtx_unlock(&qt->mutex);
}


static int quiesce_packet_thread(void *arg)
{
	struct udp_quiesce_test *qt = arg;

	if (qt->send)
		return udp_send_helper(qt->us, &qt->peer, qt->mb,
				       qt->boundary);

	udp_recv_helper(qt->us, &qt->peer, qt->mb, qt->boundary);
	return qt->callback_err;
}


static int quiesce_wait_thread(void *arg)
{
	struct udp_quiesce_test *qt = arg;
	int err;

	mtx_lock(&qt->mutex);
	qt->quiesce_started = true;
	cnd_broadcast(&qt->condition);
	mtx_unlock(&qt->mutex);

	err = udp_helper_quiesce(qt->helper);

	mtx_lock(&qt->mutex);
	if (!err && !qt->returned)
		err = EPROTO;
	qt->quiesce_err = err;
	qt->quiesce_done = true;
	cnd_broadcast(&qt->condition);
	mtx_unlock(&qt->mutex);
	return err;
}


static int test_udp_helper_quiesce_path(bool send)
{
	struct udp_quiesce_test qt = {.send = send};
	thrd_t packet_thread;
	thrd_t wait_thread;
	bool mutex_initialized = false;
	bool condition_initialized = false;
	bool packet_started = false;
	bool wait_started = false;
	int thread_err;
	int err = 0;

	TEST_EQUALS(thrd_success, mtx_init(&qt.mutex, mtx_plain));
	mutex_initialized = true;
	TEST_EQUALS(thrd_success, cnd_init(&qt.condition));
	condition_initialized = true;

	err = sa_set_str(&qt.peer, "127.0.0.1", 5000);
	TEST_ERR(err);
	err = udp_alloc_sockless(&qt.us, quiesce_external_send,
				 quiesce_external_recv, &qt);
	TEST_ERR(err);
	qt.mb = mbuf_alloc(1);
	if (!qt.mb) {
		err = ENOMEM;
		goto out;
	}
	err = mbuf_write_u8(qt.mb, 0);
	TEST_ERR(err);
	qt.mb->pos = 0;

	err = udp_register_helper(&qt.helper, qt.us, 20,
				  quiesce_send_handler,
				  quiesce_recv_handler, &qt);
	TEST_ERR(err);
	err = udp_register_helper(&qt.boundary, qt.us, send ? 30 : 10,
				  NULL, NULL, &qt);
	TEST_ERR(err);

	TEST_EQUALS(thrd_success,
		    thrd_create(&packet_thread, quiesce_packet_thread, &qt));
	packet_started = true;

	mtx_lock(&qt.mutex);
	while (!qt.entered)
		cnd_wait(&qt.condition, &qt.mutex);
	mtx_unlock(&qt.mutex);

	TEST_EQUALS(thrd_success,
		    thrd_create(&wait_thread, quiesce_wait_thread, &qt));
	wait_started = true;

	mtx_lock(&qt.mutex);
	while (!qt.quiesce_started)
		cnd_wait(&qt.condition, &qt.mutex);
	mtx_unlock(&qt.mutex);

	while (udp_helper_find(qt.us, 20) == qt.helper)
		;

	mtx_lock(&qt.mutex);
	if (qt.quiesce_done)
		err = EPROTO;
	qt.allow_return = true;
	cnd_broadcast(&qt.condition);
	mtx_unlock(&qt.mutex);
	TEST_ERR(err);

	TEST_EQUALS(thrd_success, thrd_join(packet_thread, &thread_err));
	packet_started = false;
	TEST_ERR(thread_err);
	TEST_EQUALS(thrd_success, thrd_join(wait_thread, &thread_err));
	wait_started = false;
	TEST_ERR(thread_err);
	TEST_ERR(qt.quiesce_err);
	TEST_EQUALS(1, qt.calls);
	TEST_EQUALS(1, qt.external_calls);
	TEST_ASSERT(qt.returned);
	TEST_ASSERT(qt.quiesce_done);
	TEST_ASSERT(NULL == udp_helper_find(qt.us, 20));

	if (send) {
		err = udp_send_helper(qt.us, &qt.peer, qt.mb, qt.boundary);
		TEST_ERR(err);
		TEST_EQUALS(ENOTCONN,
			    udp_send_helper(qt.us, &qt.peer, qt.mb,
					    qt.helper));
	}
	else {
		udp_recv_helper(qt.us, &qt.peer, qt.mb, qt.boundary);
		TEST_EQUALS(2, qt.external_calls);
		udp_recv_helper(qt.us, &qt.peer, qt.mb, qt.helper);
	}
	TEST_EQUALS(1, qt.calls);
	TEST_EQUALS(2, qt.external_calls);

out:
	if (packet_started) {
		mtx_lock(&qt.mutex);
		qt.allow_return = true;
		cnd_broadcast(&qt.condition);
		mtx_unlock(&qt.mutex);
		thrd_join(packet_thread, NULL);
	}
	if (wait_started)
		thrd_join(wait_thread, NULL);
	if (qt.boundary)
		(void)udp_helper_quiesce(qt.boundary);
	mem_deref(qt.boundary);
	mem_deref(qt.helper);
	mem_deref(qt.mb);
	mem_deref(qt.us);
	if (condition_initialized)
		cnd_destroy(&qt.condition);
	if (mutex_initialized)
		mtx_destroy(&qt.mutex);
	return err;
}


static bool self_quiesce_recv_handler(struct sa *src, struct mbuf *mb,
				      void *arg)
{
	struct udp_quiesce_test *qt = arg;
	(void)src;
	(void)mb;

	++qt->calls;
	qt->callback_err = udp_helper_quiesce(qt->helper);
	return false;
}


static int test_udp_helper_self_quiesce(void)
{
	struct udp_quiesce_test qt = {0};
	int err = 0;

	TEST_EQUALS(thrd_success, mtx_init(&qt.mutex, mtx_plain));
	TEST_EQUALS(thrd_success, cnd_init(&qt.condition));
	err = sa_set_str(&qt.peer, "127.0.0.1", 5000);
	TEST_ERR(err);
	err = udp_alloc_sockless(&qt.us, quiesce_external_send,
				 quiesce_external_recv, &qt);
	TEST_ERR(err);
	qt.mb = mbuf_alloc(1);
	if (!qt.mb) {
		err = ENOMEM;
		goto out;
	}
	err = udp_register_helper(&qt.helper, qt.us, 20, NULL,
				  self_quiesce_recv_handler, &qt);
	TEST_ERR(err);

	/* Self-detection is derived from the reserved callback record itself; it
	 * must not depend on allocating thread-local storage and therefore cannot
	 * turn TLS initialization failure into a wait on this callback. */
	udp_recv_packet(qt.us, &qt.peer, qt.mb);
	TEST_EQUALS(1, qt.calls);
	TEST_EQUALS(EDEADLK, qt.callback_err);
	TEST_EQUALS(qt.helper, udp_helper_find(qt.us, 20));

	err = udp_helper_quiesce(qt.helper);
	TEST_ERR(err);
	udp_recv_packet(qt.us, &qt.peer, qt.mb);
	TEST_EQUALS(1, qt.calls);
	TEST_EQUALS(2, qt.external_calls);

out:
	mem_deref(qt.helper);
	mem_deref(qt.mb);
	mem_deref(qt.us);
	cnd_destroy(&qt.condition);
	mtx_destroy(&qt.mutex);
	return err;
}


static void cross_quiesce_external_recv(const struct sa *src,
					struct mbuf *mb, void *arg)
{
	(void)src;
	(void)mb;
	(void)arg;
}


static int cross_quiesce_external_send(const struct sa *dst,
					struct mbuf *mb, void *arg)
{
	(void)dst;
	(void)mb;
	(void)arg;
	return 0;
}


static bool cross_quiesce_b_handler(struct sa *src, struct mbuf *mb,
				     void *arg)
{
	struct udp_cross_quiesce_test *qt = arg;

	mtx_lock(&qt->mutex);
	qt->b_entered = true;
	cnd_broadcast(&qt->condition);
	while (!qt->allow_b_return)
		cnd_wait(&qt->condition, &qt->mutex);
	qt->b_returned = true;
	cnd_broadcast(&qt->condition);
	mtx_unlock(&qt->mutex);

	(void)src;
	(void)mb;
	return false;
}


static bool cross_quiesce_a_handler(struct sa *src, struct mbuf *mb,
				     void *arg)
{
	struct udp_cross_quiesce_test *qt = arg;
	int err;

	mtx_lock(&qt->mutex);
	qt->a_entered = true;
	cnd_broadcast(&qt->condition);
	mtx_unlock(&qt->mutex);

	err = udp_helper_quiesce(qt->helper_b);

	mtx_lock(&qt->mutex);
	if (!err && !qt->b_returned)
		err = EPROTO;
	qt->a_err = err;
	cnd_broadcast(&qt->condition);
	mtx_unlock(&qt->mutex);

	(void)src;
	(void)mb;
	return false;
}


static int cross_quiesce_a_thread(void *arg)
{
	struct udp_cross_quiesce_test *qt = arg;

	udp_recv_packet(qt->us_a, &qt->peer, qt->mb_a);
	return qt->a_err;
}


static int cross_quiesce_b_thread(void *arg)
{
	struct udp_cross_quiesce_test *qt = arg;

	udp_recv_packet(qt->us_b, &qt->peer, qt->mb_b);
	return 0;
}


static int test_udp_helper_cross_quiesce(void)
{
	struct udp_cross_quiesce_test qt = {0};
	thrd_t thread_a;
	thrd_t thread_b;
	bool mutex_initialized = false;
	bool condition_initialized = false;
	bool a_started = false;
	bool b_started = false;
	int thread_err;
	int err = 0;

	TEST_EQUALS(thrd_success, mtx_init(&qt.mutex, mtx_plain));
	mutex_initialized = true;
	TEST_EQUALS(thrd_success, cnd_init(&qt.condition));
	condition_initialized = true;
	err = sa_set_str(&qt.peer, "127.0.0.1", 5000);
	TEST_ERR(err);
	err = udp_alloc_sockless(&qt.us_a, cross_quiesce_external_send,
				 cross_quiesce_external_recv,
				 &qt);
	TEST_ERR(err);
	err = udp_alloc_sockless(&qt.us_b, cross_quiesce_external_send,
				 cross_quiesce_external_recv,
				 &qt);
	TEST_ERR(err);
	qt.mb_a = mbuf_alloc(1);
	qt.mb_b = mbuf_alloc(1);
	if (!qt.mb_a || !qt.mb_b) {
		err = ENOMEM;
		goto out;
	}
	err = mbuf_write_u8(qt.mb_a, 0);
	err |= mbuf_write_u8(qt.mb_b, 0);
	TEST_ERR(err);
	qt.mb_a->pos = 0;
	qt.mb_b->pos = 0;
	err = udp_register_helper(&qt.helper_a, qt.us_a, 20, NULL,
				  cross_quiesce_a_handler, &qt);
	TEST_ERR(err);
	err = udp_register_helper(&qt.helper_b, qt.us_b, 20, NULL,
				  cross_quiesce_b_handler, &qt);
	TEST_ERR(err);

	TEST_EQUALS(thrd_success,
		    thrd_create(&thread_b, cross_quiesce_b_thread, &qt));
	b_started = true;
	mtx_lock(&qt.mutex);
	while (!qt.b_entered)
		cnd_wait(&qt.condition, &qt.mutex);
	mtx_unlock(&qt.mutex);

	TEST_EQUALS(thrd_success,
		    thrd_create(&thread_a, cross_quiesce_a_thread, &qt));
	a_started = true;
	mtx_lock(&qt.mutex);
	while (!qt.a_entered)
		cnd_wait(&qt.condition, &qt.mutex);
	qt.allow_b_return = true;
	cnd_broadcast(&qt.condition);
	mtx_unlock(&qt.mutex);

	TEST_EQUALS(thrd_success, thrd_join(thread_b, &thread_err));
	b_started = false;
	TEST_ERR(thread_err);
	TEST_EQUALS(thrd_success, thrd_join(thread_a, &thread_err));
	a_started = false;
	TEST_ERR(thread_err);
	TEST_ERR(qt.a_err);
	TEST_ASSERT(qt.b_returned);
	TEST_ASSERT(NULL == udp_helper_find(qt.us_b, 20));

out:
	if (condition_initialized && mutex_initialized) {
		mtx_lock(&qt.mutex);
		qt.allow_b_return = true;
		cnd_broadcast(&qt.condition);
		mtx_unlock(&qt.mutex);
	}
	if (b_started)
		thrd_join(thread_b, NULL);
	if (a_started)
		thrd_join(thread_a, NULL);
	if (qt.helper_a)
		(void)udp_helper_quiesce(qt.helper_a);
	if (qt.helper_b)
		(void)udp_helper_quiesce(qt.helper_b);
	mem_deref(qt.helper_a);
	mem_deref(qt.helper_b);
	mem_deref(qt.mb_a);
	mem_deref(qt.mb_b);
	mem_deref(qt.us_a);
	mem_deref(qt.us_b);
	if (condition_initialized)
		cnd_destroy(&qt.condition);
	if (mutex_initialized)
		mtx_destroy(&qt.mutex);
	return err;
}


static void reentrant_helper_release(struct udp_quiesce_test *qt)
{
	struct udp_helper *helper = qt->helper;

	qt->helper = NULL;
	++qt->calls;
	mem_deref(helper);
}


static bool reentrant_release_send_handler(int *err, struct sa *dst,
					   struct mbuf *mb, void *arg)
{
	struct udp_quiesce_test *qt = arg;
	(void)dst;
	(void)mb;

	reentrant_helper_release(qt);
	*err = 0;
	return false;
}


static bool reentrant_release_recv_handler(struct sa *src, struct mbuf *mb,
					   void *arg)
{
	struct udp_quiesce_test *qt = arg;
	(void)src;
	(void)mb;

	reentrant_helper_release(qt);
	return false;
}


static int test_udp_helper_reentrant_release(bool send)
{
	struct udp_quiesce_test qt = {.send = send};
	bool mutex_initialized = false;
	int err = 0;

	TEST_EQUALS(thrd_success, mtx_init(&qt.mutex, mtx_plain));
	mutex_initialized = true;
	err = sa_set_str(&qt.peer, "127.0.0.1", 5000);
	TEST_ERR(err);
	err = udp_alloc_sockless(&qt.us, quiesce_external_send,
				 quiesce_external_recv, &qt);
	TEST_ERR(err);
	qt.mb = mbuf_alloc(1);
	if (!qt.mb) {
		err = ENOMEM;
		goto out;
	}
	err = udp_register_helper(&qt.helper, qt.us, 20,
				  reentrant_release_send_handler,
				  reentrant_release_recv_handler, &qt);
	TEST_ERR(err);
	err = udp_register_helper(&qt.boundary, qt.us, send ? 30 : 10,
				  NULL, NULL, &qt);
	TEST_ERR(err);

	if (send)
		err = udp_send_helper(qt.us, &qt.peer, qt.mb, qt.boundary);
	else
		udp_recv_helper(qt.us, &qt.peer, qt.mb, qt.boundary);
	TEST_ERR(err);
	TEST_EQUALS(1, qt.calls);
	TEST_EQUALS(1, qt.external_calls);
	TEST_ASSERT(NULL == qt.helper);
	TEST_ASSERT(NULL == udp_helper_find(qt.us, 20));

out:
	if (qt.boundary)
		(void)udp_helper_quiesce(qt.boundary);
	mem_deref(qt.boundary);
	mem_deref(qt.helper);
	mem_deref(qt.mb);
	mem_deref(qt.us);
	if (mutex_initialized)
		mtx_destroy(&qt.mutex);
	return err;
}


static int test_udp_param(const char *addr, const char *mcast)
{
	struct udp_sock *uss2;
	struct udp_test *ut;
	struct sa group;
	int layer = 0;
	int err;

	ut = mem_zalloc(sizeof(*ut), destructor);
	if (!ut)
		return ENOMEM;

	err  = sa_set_str(&ut->cli, addr, 0);
	err |= sa_set_str(&ut->srv, addr, 0);
	if (err)
		goto out;

	err  = udp_listen(&ut->usc, &ut->cli, udp_recv_client, ut);
	err |= udp_listen(&ut->uss, &ut->srv, udp_recv_server, ut);
	if (err)
		goto out;

	if (mcast) {
		sa_set_str(&group, mcast, 0);

		err = udp_multicast_join(ut->usc, &group);
		TEST_ERR(err);
		err = udp_multicast_join(ut->uss, &group);
		TEST_ERR(err);
	}

	udp_rxsz_set(ut->usc, 65536);
	udp_rxsz_set(ut->uss, 65536);

	err = udp_sockbuf_set(ut->usc, 65536);
	TEST_ERR(err);
	err = udp_sockbuf_set(ut->uss, 65536);
	TEST_ERR(err);

	udp_rxbuf_presz_set(ut->uss, 16);

	err  = udp_local_get(ut->usc, &ut->cli);
	err |= udp_local_get(ut->uss, &ut->srv);
	if (err)
		goto out;

	TEST_ASSERT(NULL == udp_helper_find(ut->usc, layer));

	err = udp_register_helper(&ut->uh, ut->usc, layer,
				  udp_helper_send, udp_helper_recv, ut);
	if (err)
		goto out;

	TEST_ASSERT(NULL != udp_helper_find(ut->usc, layer));

	/* expect failure */
	if (!udp_listen(&uss2, &ut->srv, udp_recv_client, ut)) {
		err = EBUSY;
		goto out;
	}

	/* Send from connected client UDP socket */
	err = udp_connect(ut->usc, &ut->srv);
	if (err)
		goto out;

	/* Start test */
	err = send_data(ut->usc, &ut->srv, data0);
	if (err)
		goto out;

	err = re_main_timeout(100);
	if (err)
		goto out;

	if (ut->err)
		err = ut->err;

	if (mcast) {
		udp_multicast_leave(ut->usc, &group);
		udp_multicast_leave(ut->uss, &group);
	}

 out:
	mem_deref(ut);

	return err;
}


int test_udp(void)
{
	int err = test_udp_param("127.0.0.1", NULL);
	TEST_ERR(err);

	err = test_udp_param("127.0.0.1", "224.0.1.194");
	TEST_ERR(err);

	if (test_ipv6_supported()) {
		err = test_udp_param("::1", NULL);
		TEST_ERR(err);
	}

	err = test_udp_helper_quiesce_path(false);
	TEST_ERR(err);
	err = test_udp_helper_quiesce_path(true);
	TEST_ERR(err);
	err = test_udp_helper_self_quiesce();
	TEST_ERR(err);
	err = test_udp_helper_cross_quiesce();
	TEST_ERR(err);
	err = test_udp_helper_reentrant_release(false);
	TEST_ERR(err);
	err = test_udp_helper_reentrant_release(true);
	TEST_ERR(err);

 out:
	return err;
}


#if !defined(WIN32)
static int udp_tos(const char *addr)
{
	struct udp_test *ut;
	int layer = 0;
	int err;

	ut = mem_zalloc(sizeof(*ut), destructor);
	if (!ut)
		return ENOMEM;

	err  = sa_set_str(&ut->cli, addr, 0);
	err |= sa_set_str(&ut->srv, addr, 0);
	TEST_ERR(err);

	err  = udp_listen(&ut->usc, &ut->cli, udp_recv_client, ut);
	err |= udp_listen(&ut->uss, &ut->srv, udp_recv_server, ut);
	TEST_ERR(err);

	err  = udp_settos(ut->usc, 184);
	err |= udp_settos(ut->uss, 120);
	TEST_ERR(err);

	err  = udp_local_get(ut->usc, &ut->cli);
	err |= udp_local_get(ut->uss, &ut->srv);
	TEST_ERR(err);

	err = udp_register_helper(&ut->uh, ut->usc, layer,
				  udp_helper_send, udp_helper_recv, ut);
	TEST_ERR(err);

	/* Send from connected client UDP socket */
	err = udp_connect(ut->usc, &ut->srv);
	TEST_ERR(err);

	/* Start test */
	err = send_data(ut->usc, &ut->srv, data0);
	TEST_ERR(err);

	err = re_main_timeout(100);
	TEST_ERR(err);

	if (ut->err)
		err = ut->err;

 out:
	mem_deref(ut);

	return err;
}


int test_udp_tos(void)
{
	int err;

	err = udp_tos("127.0.0.1");
	TEST_ERR(err);

	if (test_ipv6_supported()) {
		err = udp_tos("::1");
		TEST_ERR(err);
	}

 out:
	return err;
}
#else
/* Outcome of the TOS test on Windows would be dependent on the
 * DisableUserTOSSetting Windows registry setting. */
int test_udp_tos(void)
{
	return 0;
}
#endif
