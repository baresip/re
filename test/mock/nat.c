/**
 * @file mock/nat.c Mock NAT-box
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mock/nat"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	LAYER_NAT = -1000
};


static void nat_binding_add(struct nat *nat, const struct sa *addr)
{
	if (!nat || !addr)
		return;

	if (nat->bindingc >= RE_ARRAY_SIZE(nat->bindingv)) {
		DEBUG_WARNING("NAT-box at max capacity\n");
		return;
	}

	nat->bindingv[nat->bindingc++] = *addr;
}


static struct sa *nat_binding_find_addr(struct nat *nat, const struct sa *addr)
{
	unsigned i;

	if (!nat || !addr)
		return NULL;

	for (i=0; i<nat->bindingc; i++) {

		if (sa_cmp(addr, &nat->bindingv[i], SA_ALL))
			return &nat->bindingv[i];
	}

	return NULL;
}


static struct sa *nat_binding_find(struct nat *nat, uint16_t port)
{
	unsigned i;

	if (!nat || !port)
		return NULL;

	for (i=0; i<nat->bindingc; i++) {

		if (port == sa_port(&nat->bindingv[i]))
			return &nat->bindingv[i];
	}

	return NULL;
}


static bool nat_helper_send(int *err, struct sa *dst,
			    struct mbuf *mb, void *arg)
{
	struct nat *nat = arg;
	struct sa *cli;
	(void)mb;

	cli = nat_binding_find(nat, sa_port(dst));

#if 0
	re_printf("nat: send INGRESS %J -> %J\n", dst, cli);
#endif

	if (cli) {
		*dst = *cli;
		return false;
	}
	else {
		*err = ENOTCONN;
		DEBUG_WARNING("nat: binding to %J not found\n", dst);
		return true;
	}
}


static bool nat_helper_recv(struct sa *src, struct mbuf *mb, void *arg)
{
	struct nat *nat = arg;
	struct sa map;
	(void)mb;

	if (!nat_binding_find(nat, sa_port(src))) {
		nat_binding_add(nat, src);
	}

	map = nat->public_addr;
	sa_set_port(&map, sa_port(src));

#if 0
	re_printf("nat: recv EGRESS %J -> %J\n", src, &map);
#endif

	*src = map;

	return false;
}


static bool firewall_egress(int *err, struct sa *dst,
			    struct mbuf *mb, void *arg)
{
	struct nat *nat = arg;
	(void)err;
	(void)mb;

	/* add egress mapping to external addr */
	if (!nat_binding_find_addr(nat, dst)) {
		nat_binding_add(nat, dst);
	}

	return false;
}


static bool firewall_ingress(struct sa *src,
			     struct mbuf *mb, void *arg)
{
	struct nat *nat = arg;
	(void)mb;

	/* check if external address has a mapping */
	if (!nat_binding_find_addr(nat, src)) {

		DEBUG_NOTICE("firewall: drop 1 packet from %J\n", src);
		return true;
	}

	return false;
}


static void nat_destructor(void *arg)
{
	struct nat *nat = arg;

	mem_deref(nat->uh);
	mem_deref(nat->us);
}


/* inbound NAT */
int nat_alloc(struct nat **natp, enum natbox_type type,
	      struct udp_sock *us, const struct sa *public_addr)
{
	struct nat *nat;
	int err = 0;

	if (!natp || !us)
		return EINVAL;

	if (type == NAT_INBOUND_SNAT && !public_addr)
		return EINVAL;

	if (udp_helper_find(us, LAYER_NAT)) {
		DEBUG_WARNING("udp helper already exist on layer %d\n",
			      LAYER_NAT);
		return EPROTO;
	}

	nat = mem_zalloc(sizeof(*nat), nat_destructor);
	if (!nat)
		return ENOMEM;

	nat->type = type;
	if (public_addr)
		nat->public_addr = *public_addr;
	nat->us = mem_ref(us);

	switch (type) {

	case NAT_INBOUND_SNAT:
		err = udp_register_helper(&nat->uh, us, LAYER_NAT,
					  nat_helper_send,
					  nat_helper_recv, nat);
		break;

	case NAT_FIREWALL:
		err = udp_register_helper(&nat->uh, us, LAYER_NAT,
					  firewall_egress,
					  firewall_ingress, nat);
		break;

	default:
		DEBUG_WARNING("invalid NAT type %d\n", type);
		err = ENOTSUP;
		break;
	}
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(nat);
	else
		*natp = nat;

	return err;
}
