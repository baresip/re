/**
 * @file lcand.c  Local ICE Candidates
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_sys.h>
#include <re_stun.h>
#include <re_udp.h>
#include <re_tcp.h>
#include <re_ice.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "icelcand"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static bool tcpconn_frame_handler(struct trice *icem,
				  struct tcp_conn *tc, struct sa *src,
				  struct mbuf *mb, void *arg)
{
	struct ice_lcand *lcand = arg;
	(void)icem;

	return lcand->recvh(lcand, IPPROTO_TCP, tc,
			    src, mb, lcand->arg);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct ice_lcand *lcand = arg;
	int err;

#if 0
	trice_printf(lcand->icem,
		    "[local=%H] incoming TCP-connect from %J\n",
		    trice_cand_print, lcand, peer);
#endif

	err = trice_conn_alloc(&lcand->icem->connl, lcand->icem,
			     lcand->attr.compid, false,
			     &lcand->attr.addr, peer, lcand->ts, lcand->layer,
			     tcpconn_frame_handler, lcand);
	if (err) {
		DEBUG_WARNING("ice_conn_alloc error (%m)\n", err);
	}
}


static void lcand_destructor(void *arg)
{
	struct ice_lcand *cand = arg;

	list_unlink(&cand->le);

	mem_deref(cand->ts);
	mem_deref(cand->uh);
	mem_deref(cand->us);
}


/** Foundation is a hash of IP address and candidate type */
static int compute_foundation(struct ice_lcand *cand,
			      const struct sa *addr, enum ice_cand_type type)
{
	uint32_t v;

	v  = sa_hash(addr, SA_ADDR);
	v ^= type;

	if (re_snprintf(cand->attr.foundation, sizeof(cand->attr.foundation),
			"%08x", v) < 0)
		return ENOMEM;

	return 0;
}


static bool trice_lcand_recv_handler(struct ice_lcand *lcand,
				  int proto, void *sock, const struct sa *src,
				  struct mbuf *mb, void *arg)
{
	struct trice *icem = arg;

	return trice_stun_process(icem, lcand, proto, sock, src, mb);
}


int trice_add_lcandidate(struct ice_lcand **candp,
			 struct trice *icem, struct list *lst,
			 unsigned compid, char *foundation, int proto,
			 uint32_t prio, const struct sa *addr,
			 const struct sa *base_addr,
			 enum ice_cand_type type,
			 const struct sa *rel_addr,
			 enum ice_tcptype tcptype)
{
	struct ice_lcand *cand;
	int err = 0;

	if (!lst || !compid || !proto || !addr)
		return EINVAL;

	cand = mem_zalloc(sizeof(*cand), lcand_destructor);
	if (!cand)
		return ENOMEM;

	cand->attr.compid = compid;
	if (foundation)
		str_ncpy(cand->attr.foundation, foundation,
			       sizeof(cand->attr.foundation));
	else
		err = compute_foundation(cand, addr, type);
	cand->attr.proto  = proto;
	cand->attr.prio   = prio;
	cand->attr.addr   = *addr;
	cand->attr.type   = type;
	cand->attr.tcptype = tcptype;
	if (rel_addr)
		cand->attr.rel_addr = *rel_addr;
	if (err)
		goto out;

	cand->icem = icem;

	cand->recvh = trice_lcand_recv_handler;
	cand->arg = icem;

	if (base_addr)
		cand->base_addr = *base_addr;

	list_append(lst, &cand->le, cand);

 out:
	if (err)
		mem_deref(cand);
	else if (candp)
		*candp = cand;

	return err;
}


/* this one is only for Send statistics on Local Candidate */
static bool udp_helper_send_handler(int *err, struct sa *dst,
				    struct mbuf *mb, void *arg)
{
	struct ice_lcand *lcand = arg;
	(void)err;
	(void)dst;
	(void)mb;

	lcand->stats.n_tx += 1;

	return false;  /* NOT handled */
}


/*
 * lcand: on which Local Candidate to receive the packet
 *
 * return TRUE if handled
 */
static bool udp_helper_recv_handler(struct sa *src, struct mbuf *mb, void *arg)
{
	struct ice_lcand *lcand = arg;

	lcand->stats.n_rx += 1;

	return lcand->recvh(lcand, IPPROTO_UDP, lcand->us,
			    src, mb, lcand->arg);
}


/* The incoming data should not get here */
static void dummy_udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct ice_lcand *lcand = arg;

	DEBUG_NOTICE("@@@@ NO-ONE cared about this UDP packet? @@@@@"
		     " (%zu bytes from %J to %s.%J)\n",
		     mbuf_get_left(mb), src,
		     ice_cand_type2name(lcand->attr.type),
		     &lcand->attr.addr);
}

static int udp_listen_range(struct udp_sock **usp, const struct sa *ip,
			    uint16_t min_port, uint16_t max_port,
			    udp_recv_h *rh, void *arg)
{
	struct sa laddr;
	int tries = 64;
	int err = 0;

	sa_cpy(&laddr, ip);

	/* try hard */
	while (tries--) {
		struct udp_sock *us;
		uint16_t port;

		port = (min_port + (rand_u16() % (max_port - min_port)));

		sa_set_port(&laddr, port);
		err = udp_listen(&us, &laddr, rh, arg);
		if (err)
			continue;

		/* OK */
		if (usp)
			*usp = us;
		break;
	}

	return err;
}


/*
 * you can call this at any time
 *
 * @param addr HOST:     SA_ADDR portion is used
 *             non-HOST: SA_ADDR + SA_PORT portion is used
 *
 * @param base_addr  Optional
 * @param rel_addr   Optional
 *
 * @param layer  mandatory for HOST and RELAY candidates
 */
int trice_lcand_add(struct ice_lcand **lcandp, struct trice *icem,
		    unsigned compid, int proto,
		    uint32_t prio, const struct sa *addr,
		    const struct sa *base_addr,
		    enum ice_cand_type type, const struct sa *rel_addr,
		    enum ice_tcptype tcptype,
		    void *sock, int layer)
{
	struct ice_lcand *lcand;
	int err = 0;

	if (!icem || !compid || !proto || !addr)
		return EINVAL;

	if (!sa_isset(addr, SA_ADDR)) {
		DEBUG_WARNING("lcand_add: SA_ADDR is not set\n");
		return EINVAL;
	}
	if (type != ICE_CAND_TYPE_HOST) {
		if (!sa_isset(addr, SA_PORT)) {
			DEBUG_WARNING("lcand_add: %s: SA_PORT"
				      " must be set (%J)\n",
				      ice_cand_type2name(type), addr);
			return EINVAL;
		}
	}

	/* lookup candidate, replace if PRIO is higher */

	/* TODO: dont look up TCP-ACTIVE types for now (port is zero) */
	if (proto == IPPROTO_UDP) {

		lcand = trice_lcand_find(icem, -1, compid, proto, addr);
		if (lcand) {
			trice_printf(icem,
				    "add_local[%s.%J] --"
				    " candidate already exists"
				    " (%H)\n",
				    ice_cand_type2name(type), addr,
				    trice_cand_print, lcand);

			if (prio > lcand->attr.prio)
				lcand = mem_deref(lcand);
			else {
				goto out;
			}
		}
	}

	err = trice_add_lcandidate(&lcand, icem, &icem->lcandl, compid, NULL,
				   proto, prio, addr, base_addr,
				   type, rel_addr, tcptype);
	if (err)
		return err;

	if (type == ICE_CAND_TYPE_HOST) {

		switch (proto) {

		case IPPROTO_UDP:
			if (sock) {
				struct sa laddr;

				lcand->us = mem_ref(sock);

				err = udp_local_get(lcand->us,
						    &laddr);
				if (err)
					goto out;

				lcand->attr.addr = *addr;
				sa_set_port(&lcand->attr.addr,
					    sa_port(&laddr));
			}
			else {
				if (icem->ports.min && icem->ports.max) {
					err = udp_listen_range(
						      &lcand->us,
						      addr,
						      icem->ports.min,
						      icem->ports.max,
						      dummy_udp_recv,
						      lcand);
				}
				else {
					err = udp_listen(&lcand->us, addr,
							 dummy_udp_recv,
							 lcand);
				}
				if (err)
					goto out;

				err = udp_local_get(lcand->us,
						    &lcand->attr.addr);
				if (err)
					goto out;
			}

			err = udp_register_helper(&lcand->uh, lcand->us,
						  layer,
						  udp_helper_send_handler,
						  udp_helper_recv_handler,
						  lcand);
			if (err)
				goto out;
			break;

		case IPPROTO_TCP:

			/* TCP-transport has 3 variants:
			   active, passive, so */

			if (lcand->attr.tcptype == ICE_TCP_ACTIVE) {

				/* the port MUST be set to 9 (i.e., Discard) */
				/*sa_set_port(&lcand->attr.addr, 9); */
			}
			else if (lcand->attr.tcptype == ICE_TCP_PASSIVE ||
				 lcand->attr.tcptype == ICE_TCP_SO) {

				err = tcp_listen(&lcand->ts, addr,
						 tcp_conn_handler, lcand);
				if (err)
					goto out;
				err = tcp_local_get(lcand->ts,
						    &lcand->attr.addr);
				if (err)
					goto out;
			}
			else {
				err = EPROTONOSUPPORT;
				goto out;
			}
			break;

		default:
			err = EPROTONOSUPPORT;
			goto out;
		}
	}
	else if (type == ICE_CAND_TYPE_RELAY) {

		switch (proto) {

		case IPPROTO_UDP:

			if (sock) {
				lcand->us = mem_ref(sock);
			}
			else {
				err = udp_listen(&lcand->us, NULL,
						 dummy_udp_recv, lcand);
				if (err)
					goto out;
			}

			err = udp_register_helper(&lcand->uh, lcand->us,
						  layer,
						  udp_helper_send_handler,
						  udp_helper_recv_handler,
						  lcand);
			if (err)
				goto out;

			break;

		default:
			err = EPROTONOSUPPORT;
			goto out;
		}
	}
	else if (type == ICE_CAND_TYPE_SRFLX ||
		 type == ICE_CAND_TYPE_PRFLX) {

		/* Special case for SRFLX UDP candidates, if he has
		 * its own UDP-socket that can be used.
		 */
		if (proto == IPPROTO_UDP && sock) {

			lcand->us = mem_ref(sock);

			err = udp_register_helper(&lcand->uh, lcand->us,
						  layer,
						  udp_helper_send_handler,
						  udp_helper_recv_handler,
						  lcand);
			if (err)
				goto out;
		}
	}

	lcand->layer = layer;

	if (icem->lrole != ICE_ROLE_UNKNOWN) {
		/* pair this local-candidate with all existing
		 * remote-candidates */
		err = trice_candpair_with_local(icem, lcand);
		if (err)
			goto out;

		/* new pair -- refresh the checklist timer */
		trice_checklist_refresh(icem);
	}

 out:
	if (err)
		mem_deref(lcand);
	else if (lcandp)
		*lcandp = lcand;

	return err;
}


struct ice_lcand *trice_lcand_find(struct trice *icem,
				   enum ice_cand_type type,
				   unsigned compid, int proto,
				   const struct sa *addr)
{
	struct list *lst;
	struct le *le;

	if (!icem)
		return NULL;

	if (!proto) {
		DEBUG_WARNING("find_candidate: invalid args\n");
		return NULL;
	}

	lst = &icem->lcandl;

	for (le = list_head(lst); le; le = le->next) {

		struct ice_cand_attr *cand = le->data;

		if (type != (enum ice_cand_type)-1 && type != cand->type)
			continue;

		if (compid && cand->compid != compid)
			continue;

		if (cand->proto != proto)
			continue;

		if (addr && !sa_cmp(&cand->addr, addr, SA_ALL))
			continue;

		return (void *)cand;
	}

	return NULL;
}


struct ice_lcand *trice_lcand_find2(const struct trice *icem,
				    enum ice_cand_type type, int af)
{
	struct le *le;

	if (!icem)
		return NULL;

	for (le = list_head(&icem->lcandl); le; le = le->next) {

		struct ice_cand_attr *cand = le->data;

		if (cand->type != type)
			continue;

		if (af != sa_af(&cand->addr))
			continue;

		return (void *)cand;
	}

	return NULL;
}


int trice_lcands_debug(struct re_printf *pf, const struct list *lst)
{
	struct le *le;
	int err;

	err = re_hprintf(pf, " (%u)\n", list_count(lst));

	for (le = list_head(lst); le && !err; le = le->next) {

		const struct ice_lcand *cand = le->data;

		err |= re_hprintf(pf, "  {%u} [tx=%3zu, rx=%3zu] "
				  "fnd=%-8s prio=%08x ",
				  cand->attr.compid,
				  cand->stats.n_tx,
				  cand->stats.n_rx,
				  cand->attr.foundation,
				  cand->attr.prio);

		if (str_isset(cand->ifname))
			err |= re_hprintf(pf, "%s:", cand->ifname);

		err |= re_hprintf(pf, "%24H", trice_cand_print, cand);

		if (sa_isset(&cand->base_addr, SA_ADDR)) {
			err |= re_hprintf(pf, " (base-addr = %J)",
					  &cand->base_addr);
		}

		if (sa_isset(&cand->attr.rel_addr, SA_ADDR)) {
			err |= re_hprintf(pf, " (rel-addr = %J)",
					  &cand->attr.rel_addr);
		}

		err |= re_hprintf(pf, "\n");
	}

	return err;
}


void *trice_lcand_sock(struct trice *icem, const struct ice_lcand *lcand)
{
	struct ice_lcand *base = NULL;

	if (!icem || !lcand)
		return NULL;

	if (sa_isset(&lcand->base_addr, SA_ALL)) {

		enum ice_cand_type base_type;

		base_type = ice_cand_type_base(lcand->attr.type);

		base = trice_lcand_find(icem,
					base_type,
					lcand->attr.compid,
					lcand->attr.proto,
					&lcand->base_addr);
	}

	/* note: original lcand has presedence, fallback to base-candidate */
	switch (lcand->attr.type) {

	case ICE_CAND_TYPE_HOST:
		return lcand->us;

	case ICE_CAND_TYPE_SRFLX:
	case ICE_CAND_TYPE_PRFLX:
		if (lcand->us)
			return lcand->us;
		else if (base && base->us)
			return base->us;
		else {
			DEBUG_NOTICE("lcand_sock: no SOCK or BASE for "
				     " type '%s'\n",
				     ice_cand_type2name(lcand->attr.type));
			return NULL;
		}

	case ICE_CAND_TYPE_RELAY:
		return lcand->us;

	default:
		return NULL;
	}

	return NULL;
}


void trice_lcand_recv_packet(struct ice_lcand *lcand,
			     const struct sa *src, struct mbuf *mb)
{
	struct sa addr;

	if (!lcand || !src || !mb)
		return;

	addr = *src;

	udp_helper_recv_handler(&addr, mb, lcand);
}
