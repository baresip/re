/**
 * @file mock/pf.c Mock packet filter
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mock/pf"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static bool stun_attr_handler(const struct stun_attr *attr, void *arg)
{
	(void)arg;
	(void)re_printf(" %s", stun_attr_name(attr->type));
	return false;
}


static void sniff_stun(struct mbuf *mb)
{
	struct stun_msg *msg;
	size_t pos;
	int err;

	pos = mb->pos;
	err = stun_msg_decode(&msg, mb, NULL);
	if (err) {
		DEBUG_WARNING("could not decode STUN packet (%m)\n", err);
		return;
	}

	stun_msg_attr_apply(msg, stun_attr_handler, 0);
	(void)re_printf("\n");

	mem_deref(msg);

	mb->pos = pos;
}


/* egress */
static bool pf_send_handler(int *err, struct sa *dst,
			    struct mbuf *mb, void *arg)
{
	struct pf *pf = arg;
	(void)err;
	(void)dst;

	(void)re_printf("[%s] send -- ", pf->name);
	sniff_stun(mb);

	return false;
}


/* ingress */
static bool pf_recv_handler(struct sa *src, struct mbuf *mb, void *arg)
{
	struct pf *pf = arg;
	(void)src;

	(void)re_printf("[%s] recv  --", pf->name);
	sniff_stun(mb);

	return false;
}


static void pf_destructor(void *arg)
{
	struct pf *pf = arg;

	mem_deref(pf->uh);
	mem_deref(pf->us);
}


int pf_create(struct pf **pfp, struct udp_sock *us, const char *name)
{
	struct pf *pf;
	int err;

	if (!pfp || !us)
		return EINVAL;

	pf = mem_zalloc(sizeof(*pf), pf_destructor);
	if (!pf)
		return ENOMEM;

	pf->us = mem_ref(us);
	str_ncpy(pf->name, name, sizeof(pf->name));

	err = udp_register_helper(&pf->uh, us,
				  -1000, /* very low layer */
				  pf_send_handler, pf_recv_handler, pf);

	if (err)
		mem_deref(pf);
	else
		*pfp = pf;

	return err;
}
