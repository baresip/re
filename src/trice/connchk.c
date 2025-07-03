/**
 * @file connchk.c  ICE Connectivity Checks
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
#include <re_stun.h>
#include <re_ice.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "conncheck"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {PRESZ_RELAY = 36};


static void conncheck_destructor(void *arg)
{
	struct ice_conncheck *cc = arg;

	cc->term = true;
	list_unlink(&cc->le);
	mem_deref(cc->ct_conn);
}


static void pair_established(struct trice *icem, struct ice_candpair *pair,
			     const struct stun_msg *msg)
{
	struct ice_tcpconn *conn;

	if (!icem || !pair)
		return;

	if (pair->lcand->attr.proto == IPPROTO_TCP) {

		conn = pair->conn;

		if (!conn) {
			/* todo: Hack to grab TCPCONN */
			conn = trice_conn_find(&icem->connl,
					     pair->lcand->attr.compid,
					     &pair->lcand->attr.addr,
					     &pair->rcand->attr.addr);
		}

		if (conn) {
			pair->tc = mem_deref(pair->tc);
			pair->tc = mem_ref(conn->tc);
		}
		else {
			DEBUG_WARNING("pair_established: TCP-connection "
				      " from %H to %H not found!\n",
				      trice_cand_print, pair->lcand,
				      trice_cand_print, pair->rcand);
		}

	}

	if (!pair->estab) {
		pair->estab = true;

		if (icem->checklist->estabh) {
			icem->checklist->estabh(pair, msg,
						icem->checklist->arg);
		}
	}
}


/*
 * NOTE for TCP-candidates:
 *
 *     Note also that STUN responses received on an active TCP candidate
 *     will typically produce a peer reflexive candidate.
 *
 *
 * NOTE for Trickle ICE and Peer Reflexive Candidates:
 *
 *     With Trickle ICE, it is possible that
 *     server reflexive candidates be discovered as peer reflexive in cases
 *     where incoming connectivity checks are received from these candidates
 *     before the trickle updates that carry them.
 *
 */
static void handle_success(struct trice *icem, struct ice_candpair *pair,
			   const struct sa *mapped_addr,
			   const struct stun_msg *msg,
			   struct ice_conncheck *cc)
{
	unsigned compid;
	int err;

	if (!icem || !pair || !pair->lcand) {
		DEBUG_WARNING("handle_success: invalid params\n");
		return;
	}

	compid = pair->lcand->attr.compid;

	if (icem &&
	    !trice_lcand_find(icem, -1, compid,
			      pair->lcand->attr.proto, mapped_addr)) {

		struct ice_lcand *lcand;
		struct ice_candpair *pair_prflx;
		uint32_t prio;

		prio = ice_cand_calc_prio(ICE_CAND_TYPE_PRFLX, 0, compid);

		err = trice_add_lcandidate(&lcand, icem, &icem->lcandl, compid,
					   "FND", pair->lcand->attr.proto,
					   prio, mapped_addr,
					   &pair->lcand->attr.addr,
					   ICE_CAND_TYPE_PRFLX,
					   &pair->lcand->attr.addr,
					   pair->lcand->attr.tcptype);
		if (err) {
			DEBUG_WARNING("failed to add PRFLX: %m\n", err);
			return;
		}

		if (str_isset(pair->lcand->ifname)) {
			str_ncpy(lcand->ifname, pair->lcand->ifname,
				 sizeof(lcand->ifname));
		}

		trice_printf(icem, "added PRFLX local candidate (%H)"
			     " from base (%H)\n",
			     trice_cand_print, lcand,
			     trice_cand_print, pair->lcand);

		/* newly created Candidate-PAir */
		err = trice_candpair_alloc(&pair_prflx, icem,
					  lcand, pair->rcand);
		if (err) {
			DEBUG_WARNING("prflx alloc: %m\n", err);
			return;
		}

		lcand->us = mem_ref(pair->lcand->us);
		pair_prflx->conn = mem_ref(pair->conn);

		/* mark the original HOST-one as failed */
		trice_candpair_failed(pair, 0, 0);

		trice_candpair_make_valid(icem, pair_prflx);

		pair_established(icem, pair_prflx, msg);
		return;
	}

	pair->state = ICE_CANDPAIR_FROZEN;
	trice_candpair_make_valid(icem, pair);

	/* Updating the Nominated Flag */
	if (icem && ICE_ROLE_CONTROLLING == icem->lrole) {

		if (cc->use_cand)
			pair->nominated = true;
	}

	pair_established(icem, pair, msg);
}


static int print_err(struct re_printf *pf, const int *err)
{
	if (err && *err)
		return re_hprintf(pf, " (%m)", *err);

	return 0;
}


static void stunc_resp_handler(int err, uint16_t scode, const char *reason,
			       const struct stun_msg *msg, void *arg)
{
	struct ice_conncheck *cc = arg;
	struct ice_candpair *pair = cc->pair;
	struct trice *icem = cc->icem;
	struct stun_attr *attr;
	bool success = (err == 0) && (scode == 0);
	(void)reason;

	if (!icem) {
		DEBUG_WARNING("stun response: no icem\n");
	}

	if (cc->term)
		return;

	trice_tracef(icem, success ? 32 : 31,
		     "[%u] Rx %H <--- %H '%u %s'%H\n",
		     pair->lcand->attr.compid,
		     trice_cand_print, pair->lcand,
		     trice_cand_print, pair->rcand,
		     scode, reason, print_err, &err);

	if (err) {
		DEBUG_NOTICE("stun response: [%H --> %H] %m\n",
			     trice_cand_print, pair->lcand,
			     trice_cand_print, pair->rcand,
			     err);

		trice_candpair_failed(pair, err, scode);
		goto out;
	}

	switch (scode) {

	case 0: /* Success case */
		attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
		if (!attr) {
			DEBUG_WARNING("no XOR-MAPPED-ADDR in response\n");
			trice_candpair_failed(pair, EPROTO, 0);
			break;
		}

		handle_success(icem, pair, &attr->v.sa, msg, cc);
		break;

	case 487: /* Role Conflict */
		trice_switch_local_role(icem);
		(void)trice_conncheck_send(icem, pair, cc->use_cand);
		break;

	default:
		trice_candpair_failed(pair, err, scode);
		break;
	}

 out:
	if (err || scode) {
		if (icem && icem->checklist) {
			icem->checklist->failh(err, scode,
					       pair, icem->checklist->arg);
		}
	}

	mem_deref(cc);
	return;
}


int trice_conncheck_stun_request(struct ice_checklist *ic,
			       struct ice_conncheck *cc,
			       struct ice_candpair *cp, void *sock,
			       bool cc_use_cand)
{
	struct ice_lcand *lcand;
	struct trice *icem;
	char username_buf[256];
	uint32_t prio_prflx;
	uint16_t ctrl_attr;
	bool use_cand = false;
	size_t presz = 0;
	int err = 0;

	if (!cp)
		return EINVAL;

	if (!ic)
		return ENOSYS;

	lcand = cp->lcand;
	icem = ic->icem;

	if (!sock) {
		DEBUG_NOTICE("conncheck: no SOCK\n");
		return EINVAL;
	}

	/* The password is equal to the password provided by the peer */
	if (!str_isset(icem->rpwd)) {
		DEBUG_WARNING("conncheck: remote password missing for"
			      " raddr=%J\n", &cp->rcand->attr.addr);
		err = EINVAL;
		goto out;
	}

	if (lcand->attr.proto == IPPROTO_UDP &&
	    lcand->attr.type == ICE_CAND_TYPE_RELAY)
		presz = PRESZ_RELAY;
	else if (lcand->attr.proto == IPPROTO_TCP)
		presz = 2;

	if (re_snprintf(username_buf, sizeof(username_buf),
			"%s:%s", icem->rufrag, icem->lufrag) < 0) {
		DEBUG_WARNING("conncheck: username buffer too small\n");
		err = ENOMEM;
		goto out;
	}

	/* PRIORITY and USE-CANDIDATE */
	prio_prflx = ice_cand_calc_prio(ICE_CAND_TYPE_PRFLX, 0,
					lcand->attr.compid);

	switch (icem->lrole) {

	case ICE_ROLE_CONTROLLING:
		ctrl_attr = STUN_ATTR_CONTROLLING;
		use_cand = cc_use_cand;
		break;

	case ICE_ROLE_CONTROLLED:
		ctrl_attr = STUN_ATTR_CONTROLLED;
		break;

	default:
		DEBUG_WARNING("conncheck: invalid local role\n");
		return EINVAL;
	}

	trice_tracef(icem, 36,
		     "[%u] Tx [presz=%zu] %H ---> %H (%s) %s\n",
		     lcand->attr.compid,
		     presz,
		     trice_cand_print, cp->lcand, trice_cand_print, cp->rcand,
		     trice_candpair_state2name(cp->state),
		     use_cand ? "[USE]" : "");

	/* A connectivity check MUST utilize the STUN short term credential
	   mechanism. */

	err = stun_request(&cc->ct_conn, ic->stun, lcand->attr.proto,
			   sock, &cp->rcand->attr.addr, presz,
			   STUN_METHOD_BINDING,
			   (uint8_t *)icem->rpwd, str_len(icem->rpwd),
			   true, stunc_resp_handler, cc,
			   4,
			   STUN_ATTR_USERNAME, username_buf,
			   STUN_ATTR_PRIORITY, &prio_prflx,
			   ctrl_attr, &icem->tiebrk,
			   STUN_ATTR_USE_CAND,
			   use_cand ? &use_cand : 0);
	if (err) {
		DEBUG_NOTICE("stun_request from %H to %H failed (%m)\n",
			      trice_cand_print, lcand,
			      trice_cand_print, cp->rcand,
			      err);
		goto out;
	}

 out:
	if (err) {
		trice_candpair_failed(cp, err, 0);
	}

	return err;
}


static bool tcpconn_frame_handler(struct trice *icem,
				  struct tcp_conn *tc, struct sa *src,
				  struct mbuf *mb, void *arg)
{
	struct ice_lcand *lcand = arg;

	return trice_stun_process(icem, lcand,
				  IPPROTO_TCP, tc, src, mb);
}


int trice_conncheck_send(struct trice *icem, struct ice_candpair *pair,
			bool use_cand)
{
	struct ice_checklist *ic;
	struct ice_lcand *lcand;
	struct ice_tcpconn *conn;
	struct ice_conncheck *cc = NULL;
	void *sock;
	int err = 0;

	if (!icem || !pair)
		return EINVAL;

	lcand = pair->lcand;
	ic = icem->checklist;
	if (!ic) {
		DEBUG_WARNING("conncheck_send: no checklist\n");
		return EINVAL;
	}

	cc = mem_zalloc(sizeof(*cc), conncheck_destructor);
	if (!cc)
		return ENOMEM;

	cc->icem = icem;
	cc->pair = pair;
	cc->use_cand = use_cand;

	if (pair->state < ICE_CANDPAIR_INPROGRESS)
		trice_candpair_set_state(pair, ICE_CANDPAIR_INPROGRESS);

	switch (pair->lcand->attr.proto) {

	case IPPROTO_UDP:
		sock = trice_lcand_sock(icem, lcand);

		err = trice_conncheck_stun_request(ic, cc, pair,
						 sock, use_cand);
		if (err)
			goto out;
		break;

	case IPPROTO_TCP:
		conn = trice_conn_find(&icem->connl, lcand->attr.compid,
				     &pair->lcand->attr.addr,
				     &pair->rcand->attr.addr);
		if (conn) {
			trice_printf(icem, "TCP-connection"
				    " already exist [%H]\n",
				    trice_conn_debug, conn);

			pair->conn = mem_ref(conn);  /* todo: */

			err = trice_conncheck_stun_request(ic, cc, pair,
							 conn->tc, use_cand);
			if (err)
				goto out;
			break;
		}

		switch (pair->lcand->attr.tcptype) {

		case ICE_TCP_ACTIVE:
		case ICE_TCP_SO:
			err = trice_conn_alloc(&icem->connl, icem,
					     lcand->attr.compid, true,
					     &lcand->attr.addr,
					     &pair->rcand->attr.addr,
					     lcand->ts, lcand->layer,
					     tcpconn_frame_handler, lcand);
			if (err) {
				DEBUG_NOTICE("trice_conn_alloc to"
					      " %J failed (%m)\n",
					      &pair->rcand->attr.addr, err);
				goto out;
			}
			break;

		case ICE_TCP_PASSIVE:
			/* do nothing now. */

			/* we must wait for the other side to create a
			   TCP-connection to us. when this TCP-connection
			   is established, we can then send our
			   Connectivity-check */

			trice_candpair_set_state(pair,
						 ICE_CANDPAIR_INPROGRESS);
			break;
		}
		break;

	default:
		err = EPROTONOSUPPORT;
		goto out;
	}

	list_append(&ic->conncheckl, &cc->le, cc);

 out:
	if (err) {
		mem_deref(cc);
		trice_candpair_failed(pair, err, 0);
	}

	return err;
}


int trice_conncheck_trigged(struct trice *icem, struct ice_candpair *pair,
			   void *sock, bool use_cand)
{
	struct ice_checklist *ic;
	struct ice_conncheck *cc = NULL;
	int err = 0;

	if (!icem || !pair)
		return EINVAL;

	ic = icem->checklist;
	if (!ic) {
		DEBUG_WARNING("conncheck_send: no checklist\n");
		return EINVAL;
	}

	cc = mem_zalloc(sizeof(*cc), conncheck_destructor);
	if (!cc)
		return ENOMEM;

	cc->icem = icem;
	cc->pair = pair;
	cc->use_cand = use_cand;

	if (pair->state < ICE_CANDPAIR_INPROGRESS)
		trice_candpair_set_state(pair, ICE_CANDPAIR_INPROGRESS);

	err = trice_conncheck_stun_request(icem->checklist, cc,
					 pair, sock, use_cand);
	if (err)
		goto out;

	list_append(&ic->conncheckl, &cc->le, cc);

 out:
	if (err) {
		mem_deref(cc);
		trice_candpair_failed(pair, err, 0);
	}

	return err;
}


int trice_conncheck_debug(struct re_printf *pf, const struct ice_conncheck *cc)
{
	if (!cc)
		return 0;

	return re_hprintf(pf, "proto=%s stun=%p use_cand=%d"
			  " state=%s"
			  ,
			  net_proto2name(cc->pair->lcand->attr.proto),
			  cc->ct_conn, cc->use_cand,
			  trice_candpair_state2name(cc->pair->state));
}
