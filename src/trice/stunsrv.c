/**
 * @file stunsrv.c  Basic STUN Server for Connectivity checks
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
#include <re_stun.h>
#include <re_ice.h>
#include <re_udp.h>
#include <re_tcp.h>
#include <re_sys.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "stunsrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static const char *sw = "ice stunsrv v" RE_VERSION " (" ARCH "/" OS ")";


/*
 * NOTE about TCP-candidates:
 *
 *     Note that STUN requests received on a passive TCP candidate
 *     will typically produce a remote peer reflexive candidate.
 */
static int handle_stun_full(struct trice *icem, struct ice_lcand *lcand,
			    void *sock, const struct sa *src,
			    uint32_t prio, bool use_cand)
{
	struct ice_candpair *pair = NULL;
	struct ice_rcand *rcand;
	enum ice_tcptype tcptype_rev;
	int err = 0;

	trice_tracef(icem, 36,
		     "[%u] STUNSRV: Rx Binding Request [%H <--- %J] %s\n",
		     lcand->attr.compid,
		     trice_cand_print, lcand,
		     src,
		     use_cand ? "[USE]" : "");

	tcptype_rev = ice_tcptype_reverse(lcand->attr.tcptype);

	rcand = trice_rcand_find(icem, lcand->attr.compid,
				 lcand->attr.proto, src);
	if (!rcand) {

		err = trice_rcand_add(&rcand, icem,
				      lcand->attr.compid,
				      "444", lcand->attr.proto, prio,
				      src, ICE_CAND_TYPE_PRFLX,
				      tcptype_rev);
		if (err)
			return err;

		trice_printf(icem, "{%u} added PRFLX "
			     "remote candidate (%H)\n",
			     lcand->attr.compid,
			     trice_cand_print, rcand);
	}

	/* already valid, skip */
	pair = trice_candpair_find(&icem->validl, lcand, rcand);
	if (pair)
		goto out;

	/* note: the candidate-pair can exist in either list */
	pair = trice_candpair_find(&icem->checkl, lcand, rcand);
	if (!pair) {
		DEBUG_WARNING("{%u} candidate pair not found:"
			      " source=%J\n",
			      lcand->attr.compid, src);
		goto out;
	}

	/* 7.2.1.5.  Updating the Nominated Flag */
	if (use_cand) {
		if (icem->lrole == ICE_ROLE_CONTROLLED) {

			pair->nominated = true;
		}
	}

 out:
	/*
	  send a triggered request
	 */
	if (pair && use_cand) {

		if (icem->checklist && !pair->trigged) {

			err = trice_conncheck_trigged(icem, pair,
						     sock, use_cand);
			if (err) {
				DEBUG_WARNING("ice_checklist_stun_request"
					      " failed (%m)\n",
					      err);
			}
			pair->trigged = true;
		}
	}

	return 0;
}


static int stunsrv_ereply(struct trice *icem, struct ice_lcand *lcand,
			  void *sock, const struct sa *src,
			  size_t presz, const struct stun_msg *req,
			  uint16_t scode, const char *reason)
{
	DEBUG_WARNING("[%H] replying error to %J (%u %s)\n",
		      trice_cand_print, lcand,
		      src,
		      scode, reason);

	trice_tracef(icem, 31,
		     "[%u] STUNSRV: Tx error [%J <--- %H] (%u %s)\n",
		     lcand->attr.compid,
		     src,
		     trice_cand_print, lcand,
		     scode, reason);

	return stun_ereply(lcand->attr.proto, sock, src, presz, req,
			   scode, reason,
			   (uint8_t *)icem->lpwd, strlen(icem->lpwd), true, 1,
			   STUN_ATTR_SOFTWARE, sw);
}


int trice_stund_recv(struct trice *icem, struct ice_lcand *lcand,
		    void *sock, const struct sa *src,
		    struct stun_msg *req, size_t presz)
{
	struct stun_attr *attr;
	struct pl lu, ru;
	int err;

	/* RFC 5389: Fingerprint errors are silently discarded */
	err = stun_msg_chk_fingerprint(req);
	if (err)
		return err;

	err = stun_msg_chk_mi(req, (uint8_t *)icem->lpwd, strlen(icem->lpwd));
	if (err) {
		DEBUG_WARNING("message-integrity failed (src=%J)\n", src);
		if (err == EBADMSG)
			goto unauth;
		else
			goto badmsg;
	}

	attr = stun_msg_attr(req, STUN_ATTR_USERNAME);
	if (!attr)
		goto badmsg;

	err = re_regex(attr->v.username, strlen(attr->v.username),
		       "[^:]+:[^]+", &lu, &ru);
	if (err) {
		DEBUG_WARNING("could not parse USERNAME attribute (%s)\n",
			      attr->v.username);
		goto unauth;
	}
	if (pl_strcmp(&lu, icem->lufrag)) {
		DEBUG_WARNING("local ufrag err (expected %s, actual %r)\n",
			      icem->lufrag, &lu);
		goto unauth;
	}
	if (str_isset(icem->rufrag) && pl_strcmp(&ru, icem->rufrag)) {
		DEBUG_WARNING("remote ufrag err (expected %s, actual %r)\n",
			      icem->rufrag, &ru);
		goto unauth;
	}

	if (icem->lrole == ICE_ROLE_UNKNOWN) {
		err = trice_reqbuf_append(icem, lcand, sock, src, req, presz);
		if (err) {
			DEBUG_WARNING("unable to buffer STUN request: %m\n",
				      err);
		}
	}

	return trice_stund_recv_role_set(icem, lcand, sock, src, req, presz);

 badmsg:
	return stunsrv_ereply(icem, lcand, sock, src, presz, req,
			      400, "Bad Request");

 unauth:
	return stunsrv_ereply(icem, lcand, sock, src, presz, req,
			      401, "Unauthorized");
}


int trice_stund_recv_role_set(struct trice *icem, struct ice_lcand *lcand,
		    void *sock, const struct sa *src,
		    struct stun_msg *req, size_t presz)
{
	struct stun_attr *attr;
	enum ice_role remote_role = ICE_ROLE_UNKNOWN;
	uint64_t tiebrk = 0;
	uint32_t prio_prflx;
	int err;
	bool use_cand = false;

	attr = stun_msg_attr(req, STUN_ATTR_CONTROLLED);
	if (attr) {
		remote_role = ICE_ROLE_CONTROLLED;
		tiebrk = attr->v.uint64;
	}

	attr = stun_msg_attr(req, STUN_ATTR_CONTROLLING);
	if (attr) {
		remote_role = ICE_ROLE_CONTROLLING;
		tiebrk = attr->v.uint64;
	}

	if (remote_role == ICE_ROLE_UNKNOWN)
		goto badmsg;

	if (remote_role == icem->lrole) {
		DEBUG_NOTICE("role conflict detected (both %s)\n",
			     ice_role2name(remote_role));

		if (icem->tiebrk >= tiebrk)
			trice_switch_local_role(icem);
		else
			goto conflict;
	}

	attr = stun_msg_attr(req, STUN_ATTR_PRIORITY);
	if (attr)
		prio_prflx = attr->v.uint32;
	else
		goto badmsg;

	attr = stun_msg_attr(req, STUN_ATTR_USE_CAND);
	if (attr)
		use_cand = true;

	err = handle_stun_full(icem, lcand, sock, src, prio_prflx, use_cand);

	if (err)
		goto badmsg;

	trice_tracef(icem, 32,
		     "[%u] STUNSRV: Tx success respons [%H ---> %J]\n",
		     lcand->attr.compid,
		     trice_cand_print, lcand, src);

	return stun_reply(lcand->attr.proto, sock, src, presz, req,
			  (uint8_t *)icem->lpwd, strlen(icem->lpwd), true, 2,
			  STUN_ATTR_XOR_MAPPED_ADDR, src,
			  STUN_ATTR_SOFTWARE, sw);


 badmsg:
	return stunsrv_ereply(icem, lcand, sock, src, presz, req,
			      400, "Bad Request");

 conflict:
	return stunsrv_ereply(icem, lcand, sock, src, presz, req,
			      487, "Role Conflict");
}
