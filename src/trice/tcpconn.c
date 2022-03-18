/**
 * @file tcpconn.c  ICE handling of TCP-connections
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
#include <re_tcp.h>
#include <re_udp.h>
#include <re_stun.h>
#include <re_ice.h>
#include <re_shim.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "tcpconn"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/* `mb' contains a complete frame */
static bool shim_frame_handler(struct mbuf *mb, void *arg)
{
	struct ice_tcpconn *conn = arg;

	return conn->frameh(conn->icem, conn->tc, &conn->paddr, mb, conn->arg);
}


static void tcp_estab_handler(void *arg)
{
	struct ice_tcpconn *conn = arg;
	struct trice *icem = conn->icem;
	struct le *le;
	int err;

	conn->estab = true;

	trice_printf(icem, "TCP established (local=%J <---> peer=%J)\n",
		    &conn->laddr, &conn->paddr);

	err = shim_insert(&conn->shim, conn->tc, conn->layer,
			  shim_frame_handler, conn);
	if (err)
		goto out;

	if (!icem->checklist)
		goto out;

	/* check all pending CONNCHECKs for TCP */
	le = icem->checklist->conncheckl.head;
	while (le) {
		struct ice_conncheck *cc = le->data;
		struct ice_candpair *pair = cc->pair;
		le = le->next;

		if (pair->state == ICE_CANDPAIR_INPROGRESS &&
		    pair->lcand->attr.compid == conn->compid &&
		    pair->lcand->attr.proto == IPPROTO_TCP &&
		    sa_cmp(&pair->lcand->attr.addr, &conn->laddr, SA_ADDR) &&
		    sa_cmp(&pair->rcand->attr.addr, &conn->paddr, SA_ALL)) {

			trice_printf(icem,
				    "   estab: sending pending check"
				    " from %j to %J\n",
				    &pair->lcand->attr.addr,
				    &pair->rcand->attr.addr);

			/* todo: */
			pair->conn = mem_ref(conn);

			err = trice_conncheck_stun_request(icem->checklist, cc,
							 pair, conn->tc,
							 cc->use_cand);
			if (err) {
				DEBUG_WARNING("stun_request error (%m)\n",
					      err);
			}
		}
	}

 out:
	if (err) {
		DEBUG_WARNING("estab: errors (%m)\n", err);
	}
}


/* todo: re-connect if estab and active (with a timer) */
static void tcp_close_handler(int err, void *arg)
{
	struct ice_tcpconn *conn = arg;
	struct trice *icem = conn->icem;
	struct le *le;

	trice_printf(conn->icem, "TCP-connection [%J -> %J] closed (%m)\n",
		    &conn->laddr, &conn->paddr, err);

	err = err ? err : ECONNRESET;

	/* note: helper must be closed before tc */
	conn->shim = mem_deref(conn->shim);
	conn->tc = mem_deref(conn->tc);

	/* todo: iterate through conncheckl and cancel all checks
	 * that are using this conn
	 */

	le = conn->icem->checkl.head;
	while (le) {
		struct ice_candpair *pair = le->data;

		le = le->next;

		if (pair->lcand->attr.compid == conn->compid &&
		    pair->lcand->attr.proto == IPPROTO_TCP &&
		    sa_cmp(&pair->rcand->attr.addr, &conn->paddr, SA_ALL)) {

			trice_candpair_failed(pair, err, 0);

			if (icem->checklist) {
				icem->checklist->failh(err, 0,
						       pair,
						       icem->checklist->arg);
			}
		}
	}

	mem_deref(conn);
}


static void conn_destructor(void *arg)
{
	struct ice_tcpconn *conn = arg;

	list_unlink(&conn->le);
	mem_deref(conn->shim);
	mem_deref(conn->tc);
}


/* ts: only for accept */
int trice_conn_alloc(struct list *connl, struct trice *icem, unsigned compid,
		   bool active, const struct sa *laddr, const struct sa *peer,
		   struct tcp_sock *ts, int layer,
		   tcpconn_frame_h *frameh, void *arg)
{
	struct ice_tcpconn *conn;
	int err = 0;

	if (!connl || !icem || !laddr || !peer || !frameh)
		return EINVAL;

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn)
		return ENOMEM;

	conn->icem = icem;
	conn->active = active;
	conn->paddr = *peer;
	conn->compid = compid;
	conn->layer = layer;
	conn->frameh = frameh;
	conn->arg = arg;

	if (active) {

		trice_printf(conn->icem, "<%p> TCP connecting"
			    " [laddr=%J paddr=%J] ..\n",
			    icem, laddr, peer);

		/* This connection is opened from the local candidate of the
		   pair to the remote candidate of the pair.
		 */
		err = tcp_conn_alloc(&conn->tc, peer, tcp_estab_handler,
				     NULL, tcp_close_handler,
				     conn);
		if (err) {
			DEBUG_WARNING("tcp_conn_alloc [peer=%J] (%m)\n",
				      peer, err);
			goto out;
		}

		err = tcp_conn_bind(conn->tc, laddr);
		if (err) {
			DEBUG_WARNING("tcp_conn_bind [laddr=%J paddr=%J]"
				      " (%m)\n",
				      laddr, peer, err);
			goto out;
		}

		err = tcp_conn_connect(conn->tc, peer);
		if (err) {
			/* NOTE: this happens sometimes on OSX when
			 *       setting up two S-O connections
			 */
			if (err == EADDRINUSE) {
				re_printf("EADDRINUSE\n");
			}
			else {
				DEBUG_NOTICE("tcp_conn_connect [peer=%J]"
					      " (%d/%m)\n",
					      peer, err, err);
				goto out;
			}
		}
	}
	else {
		err = tcp_accept(&conn->tc, ts, tcp_estab_handler,
				 NULL, tcp_close_handler, conn);
		if (err) {
			tcp_reject(ts);
			goto out;
		}
	}

	err = tcp_conn_local_get(conn->tc, &conn->laddr);
	if (err)
		goto out;

	list_append(connl, &conn->le, conn);

 out:
	if (err)
		mem_deref(conn);

	return err;
}


/* NOTE: laddr matching is SA_ADDR only */
struct ice_tcpconn *trice_conn_find(struct list *connl, unsigned compid,
				  const struct sa *laddr,
				  const struct sa *peer)
{
	struct le *le;

	for (le = list_head(connl); le; le = le->next) {

		struct ice_tcpconn *conn = le->data;

		if (compid != conn->compid)
			continue;

		/* NOTE: only for established */
		if (!conn->estab)
			continue;

		if (sa_cmp(laddr, &conn->laddr, SA_ADDR) &&
		    sa_cmp(peer, &conn->paddr, SA_ALL))
			return conn;
	}

	return NULL;
}


int trice_conn_debug(struct re_printf *pf, const struct ice_tcpconn *conn)
{
	int err;

	if (!conn)
		return 0;

	err = re_hprintf(pf, "... {%u} [%s|%5s] %J - %J "
			  " (usage = %u) ",
			  conn->compid,
			  conn->active ? "Active" : "Passive",
			  conn->estab ? "ESTAB" : "     ",
			  &conn->laddr, &conn->paddr,
			  mem_nrefs(conn)-1);

	if (conn->shim)
		err |= shim_debug(pf, conn->shim);

	return err;
}
