/**
 * @file mock/sipsrv.c Mock SIP server
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mock/sipsrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define LOCAL_PORT        0
#define LOCAL_SECURE_PORT 0


static bool sip_msg_handler(const struct sip_msg *msg, void *arg)
{
	struct sip_server *srv = arg;
	int err;

	if (0 == pl_strcmp(&msg->met, "REGISTER")) {
		mbuf_set_pos(msg->mb, 0);
		if (sip_msg_decode(&srv->sip_msgs[srv->n_register_req],
					msg->mb)) {
			DEBUG_NOTICE("sip message cannot be parsed (%r)\n",
					&msg->met);
			return false;
		}
		++srv->n_register_req;
	}
	else {
		DEBUG_NOTICE("method not handled (%r)\n", &msg->met);
		return false;
	}

	if (srv->terminate)
		err = sip_reply(srv->sip, msg, 503, "Server Error");
	else
		err = sip_reply(srv->sip, msg, 200, "OK");

	if (err) {
		DEBUG_WARNING("could not reply: %m\n", err);
	}

#if 0
	if (srv->terminate)
		re_cancel();
#endif

	return true;
}


static void destructor(void *arg)
{
	struct sip_server *srv = arg;

	srv->terminate = true;

	sip_close(srv->sip, false);
	for (unsigned i=0; i<RE_ARRAY_SIZE(srv->sip_msgs); i++)
	    mem_deref(srv->sip_msgs[i]);
	mem_deref(srv->sip);
}


int sip_server_alloc(struct sip_server **srvp)
{
	struct sip_server *srv;
	struct sa laddr, laddrs;
	struct tls *tls = NULL;
	int err;

	if (!srvp)
		return EINVAL;

	srv = mem_zalloc(sizeof *srv, destructor);
	if (!srv)
		return ENOMEM;

	err  = sa_set_str(&laddr,  "127.0.0.1", LOCAL_PORT);
	err |= sa_set_str(&laddrs, "127.0.0.1", LOCAL_SECURE_PORT);
	if (err)
		goto out;

	err = sip_alloc(&srv->sip, NULL, 16, 16, 16,
			"mock SIP server", NULL, NULL);
	if (err)
		goto out;

	err |= sip_transp_add(srv->sip, SIP_TRANSP_UDP, &laddr);
	err |= sip_transp_add(srv->sip, SIP_TRANSP_TCP, &laddr);
	if (err)
		goto out;

#ifdef USE_TLS
	err = tls_alloc(&tls, TLS_METHOD_SSLV23, NULL, NULL);
	if (err)
		goto out;

	err = tls_set_certificate(tls, test_certificate_ecdsa,
				  strlen(test_certificate_ecdsa));
	if (err)
		goto out;

	err |= sip_transp_add(srv->sip, SIP_TRANSP_TLS, &laddrs, tls);
#endif
	if (err)
		goto out;

	err = sip_listen(&srv->lsnr, srv->sip, true, sip_msg_handler, srv);
	if (err)
		goto out;

 out:
	mem_deref(tls);
	if (err)
		mem_deref(srv);
	else
		*srvp = srv;

	return err;
}


int sip_server_uri(struct sip_server *srv, char *uri, size_t sz,
		   enum sip_transp tp)
{
	struct sa laddr;
	int err;

	if (!srv || !uri || !sz)
		return EINVAL;

	err = sip_transp_laddr(srv->sip, &laddr, tp, NULL);
	if (err)
		return err;

	if (re_snprintf(uri, sz, "sip:%J%s", &laddr, sip_transp_param(tp)) < 0)
		return ENOMEM;

	return 0;
}
