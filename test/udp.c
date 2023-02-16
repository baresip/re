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


int test_udp(void)
{
	struct udp_sock *uss2;
	struct udp_test *ut;
	int layer = 0;
	int err;

	ut = mem_zalloc(sizeof(*ut), destructor);
	if (!ut)
		return ENOMEM;

	err  = sa_set_str(&ut->cli, "127.0.0.1", 0);
	err |= sa_set_str(&ut->srv, "127.0.0.1", 0);
	if (err)
		goto out;

	err  = udp_listen(&ut->usc, &ut->cli, udp_recv_client, ut);
	err |= udp_listen(&ut->uss, &ut->srv, udp_recv_server, ut);
	if (err)
		goto out;

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

 out:
	mem_deref(ut);

	return err;
}
