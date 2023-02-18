/**
 * @file mock/tcpsrv.c Mock TCP server
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mock/tcpsrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void destructor(void *arg)
{
	struct tcp_server *srv = arg;

	mem_deref(srv->ts);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct tcp_server *srv = arg;
	(void)peer;

	switch (srv->behavior) {

	case BEHAVIOR_REJECT:
		tcp_reject(srv->ts);
		break;

	default:
		DEBUG_WARNING("behavior not implemented\n");
		break;
	}
}


int tcp_server_alloc(struct tcp_server **srvp, enum behavior behavior)
{
	struct tcp_server *srv;
	struct sa laddr;
	int err;

	if (!srvp)
		return EINVAL;

	srv = mem_zalloc(sizeof(*srv), destructor);
	if (!srv)
		return ENOMEM;

	sa_set_str(&laddr, "127.0.0.1", 0);

	srv->behavior = behavior;

	err = tcp_listen(&srv->ts, &laddr, tcp_conn_handler, srv);
	if (err)
		goto out;

	err = tcp_local_get(srv->ts, &srv->laddr);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(srv);
	else
		*srvp = srv;

	return err;
}
