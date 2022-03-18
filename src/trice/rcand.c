/**
 * @file rcand.c  Remote ICE Candidates
 *
 * Copyright (C) 2010 - 2015 Alfred E. Heggestad
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
#include <re_stun.h>
#include <re_ice.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "rcand"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void rcand_destructor(void *data)
{
	struct ice_rcand *cand = data;

	list_unlink(&cand->le);
}


static int trice_add_rcandidate(struct ice_rcand **candp,
			       struct list *lst,
			       unsigned compid, const char *foundation,
			       int proto,
			       uint32_t prio, const struct sa *addr,
			       enum ice_cand_type type,
			       enum ice_tcptype tcptype)
{
	struct ice_rcand *cand;

	if (!lst || !compid || !foundation || !proto || !addr)
		return EINVAL;

	cand = mem_zalloc(sizeof(*cand), rcand_destructor);
	if (!cand)
		return ENOMEM;

	cand->attr.compid  = compid;
	cand->attr.proto   = proto;
	cand->attr.prio	   = prio;
	cand->attr.addr	   = *addr;
	cand->attr.type	   = type;
	cand->attr.tcptype = tcptype;

	str_ncpy(cand->attr.foundation, foundation,
		 sizeof(cand->attr.foundation));

	list_append(lst, &cand->le, cand);

	*candp = cand;

	return 0;
}


/* you can call this at any time */
int trice_rcand_add(struct ice_rcand **rcandp, struct trice *icem,
		    unsigned compid, const char *foundation,
		    int proto, uint32_t prio,
		    const struct sa *addr, enum ice_cand_type type,
		    enum ice_tcptype tcptype)
{
	struct ice_rcand *rcand;
	int sa_flags = SA_ADDR;
	int err = 0;

	if (!icem || !foundation)
		return EINVAL;

	if (proto == IPPROTO_UDP)
		sa_flags |= SA_PORT;

	if (proto == IPPROTO_TCP &&
	    (tcptype == ICE_TCP_PASSIVE || tcptype == ICE_TCP_SO))
		sa_flags |= SA_PORT;

	if (!sa_isset(addr, sa_flags)) {
		DEBUG_WARNING("add_remote_candidate: invalid address"
			      " (%J) for %s.%s\n",
			      addr, net_proto2name(proto),
			      ice_tcptype_name(tcptype));
		return EINVAL;
	}

	/* avoid duplicates */
	rcand = trice_rcand_find(icem, compid, proto, addr);
	if (rcand) {

		if (rcand->attr.type == ICE_CAND_TYPE_PRFLX &&
		    prio > rcand->attr.prio) {

			rcand->attr.type = type;
			rcand->attr.prio = prio;
		}

		goto out;
	}

	err = trice_add_rcandidate(&rcand, &icem->rcandl,
				 compid, foundation,
				 proto, prio, addr, type, tcptype);
	if (err)
		goto out;

	if (icem->lrole != ICE_ROLE_UNKNOWN) {
		/* pair this remote-candidate with all existing
		 * local-candidates */
		err = trice_candpair_with_remote(icem, rcand);
		if (err)
			goto out;

		/* new pair -- refresh the checklist timer */
		trice_checklist_refresh(icem);
	}

 out:
	if (err)
		mem_deref(rcand);
	else if (rcandp)
		*rcandp = rcand;

	return err;
}


struct ice_rcand *trice_rcand_find(struct trice *icem,
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

	lst = &icem->rcandl;

	for (le = list_head(lst); le; le = le->next) {

		struct ice_cand_attr *cand = le->data;

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


int trice_rcands_debug(struct re_printf *pf, const struct list *lst)
{
	struct le *le;
	int err;

	err = re_hprintf(pf, " (%u)\n", list_count(lst));

	for (le = list_head(lst); le && !err; le = le->next) {

		const struct ice_rcand *rcand = le->data;

		err |= re_hprintf(pf, "  {%u} "
				  "fnd=%-8s prio=%08x %24H",
				  rcand->attr.compid,
				  rcand->attr.foundation,
				  rcand->attr.prio,
				  trice_cand_print, rcand);

		err |= re_hprintf(pf, "\n");
	}

	return err;
}
