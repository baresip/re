/**
 * @file trice.c  ICE Media stream
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_stun.h>
#include <re_ice.h>
#include <re_sys.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "icem"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static const struct trice_conf conf_default = {
	false,
	false,
	false,
	false
};


static void trice_destructor(void *data)
{
	struct trice *icem = data;

	mem_deref(icem->checklist);

	list_flush(&icem->validl);
	list_flush(&icem->checkl);
	list_flush(&icem->lcandl);
	list_flush(&icem->rcandl);
	list_flush(&icem->reqbufl);

	list_flush(&icem->connl);

	mem_deref(icem->rufrag);
	mem_deref(icem->rpwd);
	mem_deref(icem->lufrag);
	mem_deref(icem->lpwd);
}


/**
 * Allocate a new ICE Media object
 *
 * @param icemp       Pointer to allocated ICE Media object
 * @param conf        ICE configuration
 * @param role        Local role
 * @param lufrag      Local username fragment
 * @param lpwd        Local password
 *
 * @return 0 if success, otherwise errorcode
 */
int trice_alloc(struct trice **icemp, const struct trice_conf *conf,
	       enum ice_role role,
	       const char *lufrag, const char *lpwd)
{
	struct trice *icem;
	int err = 0;

	if (!icemp || !lufrag || !lpwd)
		return EINVAL;

	if (str_len(lufrag) < 4 || str_len(lpwd) < 22) {
		DEBUG_WARNING("alloc: lufrag/lpwd is too short\n");
		return EINVAL;
	}

	icem = mem_zalloc(sizeof(*icem), trice_destructor);
	if (!icem)
		return ENOMEM;

	icem->conf = conf ? *conf : conf_default;
	list_init(&icem->reqbufl);
	list_init(&icem->lcandl);
	list_init(&icem->rcandl);
	list_init(&icem->checkl);
	list_init(&icem->validl);

	icem->lrole = role;
	icem->tiebrk = rand_u64();

	err |= str_dup(&icem->lufrag, lufrag);
	err |= str_dup(&icem->lpwd, lpwd);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(icem);
	else
		*icemp = icem;

	return err;
}


/**
 * Set the remote username fragment
 *
 * @param icem    ICE Media object
 * @param rufrag  Remote username fragment
 *
 * @return 0 if success, otherwise errorcode
 */
int trice_set_remote_ufrag(struct trice *icem, const char *rufrag)
{
	if (!icem || !rufrag)
		return EINVAL;

	icem->rufrag = mem_deref(icem->rufrag);
	return str_dup(&icem->rufrag, rufrag);
}


/**
 * Set the remote password
 *
 * @param icem  ICE Media object
 * @param rpwd  Remote password
 *
 * @return 0 if success, otherwise errorcode
 */
int trice_set_remote_pwd(struct trice *icem, const char *rpwd)
{
	if (!icem || !rpwd)
		return EINVAL;

	icem->rpwd = mem_deref(icem->rpwd);

	return str_dup(&icem->rpwd, rpwd);
}


/**
 * Get the ICE Configuration
 *
 * @param icem ICE Media object
 *
 * @return ICE Configuration
 */
struct trice_conf *trice_conf(struct trice *icem)
{
	return icem ? &icem->conf : NULL;
}


/* note: call this ONCE AFTER role has been set */
static void trice_create_candpairs(struct trice *icem)
{
	struct list *lst;
	struct le *le;
	bool refresh_checklist = false;
	int err;

	lst = &icem->lcandl;
	for (le = list_head(lst); le; le = le->next) {
		struct ice_lcand *lcand = le->data;

		/* pair this local-candidate with all existing
		 * remote-candidates */
		err = trice_candpair_with_local(icem, lcand);
		if (err) {
			DEBUG_WARNING("trice_candpair_with_local: %m\n", err);
		}
		else {
			refresh_checklist = true;
		}
	}

	lst = &icem->rcandl;
	for (le = list_head(lst); le; le = le->next) {
		struct ice_rcand *rcand = le->data;

		/* pair this remote-candidate with all existing
		 * local-candidates */
		err = trice_candpair_with_remote(icem, rcand);
		if (err) {
			DEBUG_WARNING("trice_candpair_with_remote: %m\n", err);
		}
		else {
			refresh_checklist = true;
		}
	}

	/* new pair -- refresh the checklist timer */
	if (refresh_checklist)
		trice_checklist_refresh(icem);
}


/* note: call this AFTER role has been set AND candidate pairs
 * have been created */
static void trice_reqbuf_process(struct trice *icem)
{
	struct le *le;

	le = list_head(&icem->reqbufl);
	while (le) {
		struct trice_reqbuf *reqbuf = le->data;
		le = le->next;

		DEBUG_PRINTF("trice_reqbuf_process: Processing buffered "
			     "request\n");

		(void)trice_stund_recv_role_set(icem, reqbuf->lcand,
				reqbuf->sock, &reqbuf->src, reqbuf->req,
				reqbuf->presz);

		mem_deref(reqbuf);
	}
}


/**
 * Set the local role to either CONTROLLING or CONTROLLED.
 * Note: The role can be set multiple times.
 *
 * @param trice ICE Media object
 * @param role  New local role
 *
 * @return 0 if success, otherwise errorcode
 */
int trice_set_role(struct trice *trice, enum ice_role role)
{
	bool refresh;

	if (!trice)
		return EINVAL;

	/* Cannot change the role to unknown */
	if (role == ICE_ROLE_UNKNOWN)
		return EINVAL;

	if (trice->lrole == role)
		return 0;

	/* Cannot switch role manually once it has been set */
	if (trice->lrole == ICE_ROLE_UNKNOWN)
		refresh = false;
	else
		refresh = true;

	trice->lrole = role;

	/* Create candidate pairs and process pending requests */
	if (refresh) {
		trice_candpair_prio_order(&trice->checkl,
					  role == ICE_ROLE_CONTROLLING);
	}
	else {
		trice_create_candpairs(trice);
	}

	trice_reqbuf_process(trice);

	return 0;
}


/**
 * Get the local role
 *
 * @param icem  ICE Media object
 *
 * @return Local role
 */
enum ice_role trice_local_role(const struct trice *icem)
{
	if (!icem)
		return ICE_ROLE_UNKNOWN;

	return icem->lrole;
}


/**
 * Print debug information for the ICE Media
 *
 * @param pf   Print function for debug output
 * @param icem ICE Media object
 *
 * @return 0 if success, otherwise errorcode
 */
int trice_debug(struct re_printf *pf, const struct trice *icem)
{
	struct le *le;
	int err = 0;

	if (!icem)
		return 0;

	err |= re_hprintf(pf, "----- ICE Media <%p> -----\n", icem);

	err |= re_hprintf(pf, " local_role=%s\n",
			  ice_role2name(icem->lrole));
	err |= re_hprintf(pf, " local_ufrag=\"%s\" local_pwd=\"%s\"\n",
			  icem->lufrag, icem->lpwd);

	err |= re_hprintf(pf, " Local Candidates: %H",
			  trice_lcands_debug, &icem->lcandl);
	err |= re_hprintf(pf, " Remote Candidates: %H",
			  trice_rcands_debug, &icem->rcandl);
	err |= re_hprintf(pf, " Check list: ");
	err |= trice_candpairs_debug(pf, icem->conf.ansi, &icem->checkl);

	err |= re_hprintf(pf, " Valid list: ");
	err |= trice_candpairs_debug(pf, icem->conf.ansi, &icem->validl);

	err |= re_hprintf(pf, " Buffered STUN Requests: (%u)\n",
			  list_count(&icem->reqbufl));

	if (icem->checklist)
		err |= trice_checklist_debug(pf, icem->checklist);

	err |= re_hprintf(pf, " TCP Connections: (%u)\n",
			  list_count(&icem->connl));

	for (le = list_head(&icem->connl); le; le = le->next) {
		struct ice_tcpconn *conn = le->data;

		err |= re_hprintf(pf, "      %H\n",
				  trice_conn_debug, conn);
	}

	return err;
}


/**
 * Get the list of Local Candidates (struct cand)
 *
 * @param icem ICE Media object
 *
 * @return List of Local Candidates
 */
struct list *trice_lcandl(const struct trice *icem)
{
	return icem ? (struct list *)&icem->lcandl : NULL;
}


/**
 * Get the list of Remote Candidates (struct cand)
 *
 * @param icem ICE Media object
 *
 * @return List of Remote Candidates
 */
struct list *trice_rcandl(const struct trice *icem)
{
	return icem ? (struct list *)&icem->rcandl : NULL;
}


/**
 * Get the checklist of Candidate Pairs
 *
 * @param icem ICE Media object
 *
 * @return Checklist (struct ice_candpair)
 */
struct list *trice_checkl(const struct trice *icem)
{
	return icem ? (struct list *)&icem->checkl : NULL;
}


/**
 * Get the list of valid Candidate Pairs
 *
 * @param icem ICE Media object
 *
 * @return Validlist (struct ice_candpair)
 */
struct list *trice_validl(const struct trice *icem)
{
	return icem ? (struct list *)&icem->validl : NULL;
}


void trice_printf(struct trice *icem, const char *fmt, ...)
{
	va_list ap;

	if (!icem || !icem->conf.debug)
		return;

	va_start(ap, fmt);
	(void)re_printf("%v", fmt, &ap);
	va_end(ap);
}


void trice_tracef(struct trice *icem, int color, const char *fmt, ...)
{
	va_list ap;

	if (!icem || !icem->conf.trace)
		return;

	if (icem->conf.ansi && color) {
		re_printf("\x1b[%dm", color);
	}

	va_start(ap, fmt);
	(void)re_printf("%v", fmt, &ap);
	va_end(ap);

	if (icem->conf.ansi && color) {
		re_printf("\x1b[;m");
	}
}


void trice_switch_local_role(struct trice *ice)
{
	enum ice_role new_role;

	if (!ice)
		return;

	switch (ice->lrole) {

	case ICE_ROLE_CONTROLLING:
		new_role = ICE_ROLE_CONTROLLED;
		break;

	case ICE_ROLE_CONTROLLED:
		new_role = ICE_ROLE_CONTROLLING;
		break;

	default:
		DEBUG_WARNING("trice_switch_local_role: local role unknown\n");
		return;
	}

	DEBUG_NOTICE("Switch local role from %s to %s\n",
		     ice_role2name(ice->lrole), ice_role2name(new_role));

	ice->lrole = new_role;

	/* recompute pair priorities for all media streams */
	trice_candpair_prio_order(&ice->checkl,
				  ice->lrole == ICE_ROLE_CONTROLLING);
}


/* sock = [ struct udp_sock | struct tcp_conn ] */
bool trice_stun_process(struct trice *icem, struct ice_lcand *lcand,
		       int proto, void *sock, const struct sa *src,
		       struct mbuf *mb)
{
	struct stun_msg *msg = NULL;
	struct stun_unknown_attr ua;
	size_t start = mb->pos;
	(void)proto;

	if (stun_msg_decode(&msg, mb, &ua)) {
		return false;  /* continue recv-processing */
	}

	if (STUN_METHOD_BINDING == stun_msg_method(msg)) {

		switch (stun_msg_class(msg)) {

		case STUN_CLASS_REQUEST:
			(void)trice_stund_recv(icem, lcand, sock,
					      src, msg, start);
			break;

		default:
			if (icem->checklist) {
				(void)stun_ctrans_recv(icem->checklist->stun,
						       msg, &ua);
			}
			else {
				DEBUG_NOTICE("STUN resp from %J dropped"
					     " (no checklist)\n",
					     src);
			}
			break;
		}
	}

	mem_deref(msg);

	return true;
}


static void trice_reqbuf_destructor(void *data)
{
	struct trice_reqbuf *reqbuf = data;

	list_unlink(&reqbuf->le);

	mem_deref(reqbuf->req);
	mem_deref(reqbuf->sock);
	mem_deref(reqbuf->lcand);
}


int trice_reqbuf_append(struct trice *icem, struct ice_lcand *lcand,
		    void *sock, const struct sa *src,
		    struct stun_msg *req, size_t presz)
{
	struct trice_reqbuf *reqbuf;

	if (!icem || !src ||!req)
		return EINVAL;

	reqbuf = mem_zalloc(sizeof(*reqbuf), trice_reqbuf_destructor);
	if (!reqbuf)
		return ENOMEM;

	DEBUG_PRINTF("trice_reqbuf_append: Buffering request\n");
	reqbuf->lcand = mem_ref(lcand);
	reqbuf->sock = mem_ref(sock);
	reqbuf->src = *src;
	reqbuf->req = mem_ref(req);
	reqbuf->presz = presz;

	list_append(&icem->reqbufl, &reqbuf->le, reqbuf);

	return 0;
}


/**
 * Set the port range for local sockets
 *
 * @param trice     ICE Media object
 * @param min_port  Minimum port
 * @param max_port  Maximum port
 *
 * @return 0 if success, otherwise errorcode
 */
int trice_set_port_range(struct trice *trice,
			 uint16_t min_port, uint16_t max_port)
{
	if (!trice)
		return EINVAL;

	if (max_port < min_port)
		return ERANGE;

	trice->ports.min = min_port;
	trice->ports.max = max_port;

	return 0;
}
