/**
 * @file bfcp/conn.c BFCP Connection
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_udp.h>
#include <re_tcp.h>
#include <re_tmr.h>
#include <re_bfcp.h>
#include "bfcp.h"


static void destructor(void *arg)
{
	struct bfcp_conn *bc = arg;

	list_flush(&bc->ctransl);
	tmr_cancel(&bc->tmr1);
	tmr_cancel(&bc->tmr2);
	mem_deref(bc->us);
	mem_deref(bc->tc);
	mem_deref(bc->ts);
	mem_deref(bc->mb);
}


static bool strans_cmp(const struct bfcp_strans *st,
		       const struct bfcp_msg *msg)
{
	if (st->tid != msg->tid)
		return false;

	if (st->prim != msg->prim)
		return false;

	if (st->confid != msg->confid)
		return false;

	if (st->userid != msg->userid)
		return false;

	return true;
}


static void udp_recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct bfcp_conn *bc = arg;
	struct bfcp_msg *msg;
	int err;

	err = bfcp_msg_decode(&msg, mb);
	if (err)
		return;

	msg->src = *src;

	if (bfcp_handle_response(bc, msg))
		goto out;

	if (bc->mb && strans_cmp(&bc->st, msg)) {
		(void)bfcp_send(bc, &msg->src, bc->mb);
		goto out;
	}

	if (bc->recvh)
		bc->recvh(msg, bc->arg);

out:
	mem_deref(msg);
}


static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
	struct bfcp_conn *bc = arg;
	struct bfcp_msg *msg;
	int err;

	while (mb->pos < mb->end) {
		err = bfcp_msg_decode(&msg, mb);
		if (err)
			return;

		msg->src = bc->sa_peer;

		if (bfcp_handle_response(bc, msg))
			goto out;

		if (bc->mb && strans_cmp(&bc->st, msg)) {
			(void)bfcp_send(bc, &msg->src, bc->mb);
			goto out;
		}

		if (bc->recvh)
			bc->recvh(msg, bc->arg);

	out:
		mem_deref(msg);
	}
}


static void tcp_estab_handler(void *arg)
{
	struct bfcp_conn *bc = arg;
	if (bc->estabh)
		bc->estabh(bc->arg);
}


static void tcp_close_handler(int err, void *arg)
{
	struct bfcp_conn *bc = arg;

	bc->tc = NULL;

	if (bc->closeh)
		bc->closeh(err, bc->arg);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct bfcp_conn *bc = arg;

	if (bc->connh) {
		bc->connh(peer, bc->arg);
	}
	else {
		int err;
		if (bc->tc) {
			tcp_reject(bc->ts);
			return;
		}

		err = tcp_accept(&bc->tc, bc->ts, tcp_estab_handler,
				 tcp_recv_handler, tcp_close_handler, bc);

		if (err == 0)
			bc->sa_peer = *peer;
	}
}


/**
 * Create BFCP connection. For TCP, creates a listening socket for incoming
 * connections.
 *
 * @param bcp   Pointer to BFCP connection
 * @param tp    BFCP Transport type
 * @param laddr Optional listening address/port
 * @param tls   TLS Context (optional)
 * @param connh Incoming connection handler (optional)
 * @param estabh Connection established handler (optional)
 * @param recvh Receive handler
 * @param closeh Connection closed handler (optional)
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int bfcp_listen(struct bfcp_conn **bcp, enum bfcp_transp tp, struct sa *laddr,
		struct tls *tls, bfcp_conn_h *connh, bfcp_estab_h *estabh,
		bfcp_recv_h *recvh, bfcp_close_h *closeh, void *arg)
{
	struct bfcp_conn *bc;
	int err;
	(void)tls;

	if (!bcp)
		return EINVAL;

	bc = mem_zalloc(sizeof(*bc), destructor);
	if (!bc)
		return ENOMEM;

	bc->tp    = tp;
	bc->connh = connh;
	bc->estabh = estabh;
	bc->recvh = recvh;
	bc->closeh = closeh;
	bc->arg   = arg;

	switch (bc->tp) {

	case BFCP_UDP:
		err = udp_listen(&bc->us, laddr, udp_recv_handler, bc);
		if (err)
			goto out;

		if (laddr) {
			err = udp_local_get(bc->us, laddr);
			if (err)
				goto out;
		}
		break;

	case BFCP_TCP:
		err = tcp_listen(&bc->ts, laddr, tcp_conn_handler, bc);
		if (err)
			goto out;

		if (laddr) {
			err = tcp_local_get(bc->ts, laddr);
			if (err)
				goto out;
		}
		break;

	default:
		err = ENOSYS;
		goto out;
	}

out:
	if (err)
		mem_deref(bc);
	else
		*bcp = bc;

	return err;
}


/**
 * Create BFCP connection. For TCP, creates an outgoing connection.
 *
 * @param bcp   Pointer to BFCP connection
 * @param tp    BFCP Transport type
 * @param laddr Optional local address/port
 * @param peer  Remote address/port
 * @param estabh Connection established handler (optional)
 * @param recvh Receive handler
 * @param closeh Connection closed handler (optional)
 * @param arg   Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int bfcp_connect(struct bfcp_conn **bcp, enum bfcp_transp tp,
		 struct sa *laddr, const struct sa *peer, bfcp_estab_h *estabh,
		 bfcp_recv_h *recvh, bfcp_close_h *closeh, void *arg)
{
	struct bfcp_conn *bc;
	int err;

	if (!bcp)
		return EINVAL;

	bc = mem_zalloc(sizeof(*bc), destructor);
	if (!bc)
		return ENOMEM;

	bc->tp    = tp;
	bc->estabh = estabh;
	bc->recvh = recvh;
	bc->closeh = closeh;
	bc->arg   = arg;

	switch (bc->tp) {

	case BFCP_UDP:
		err = udp_open(&bc->us, laddr ? sa_af(laddr) : AF_UNSPEC);
		if (err)
			goto out;

		udp_handler_set(bc->us, udp_recv_handler, bc);

		if (peer) {
			err = udp_connect(bc->us, peer);
			if (err)
				goto out;

			bc->sa_peer = *peer;
		}

		err = udp_thread_attach(bc->us);
		if (err)
			goto out;

		if (laddr) {
			err = udp_local_get(bc->us, laddr);
			if (err)
				goto out;
		}
		break;

	case BFCP_TCP:
		err = tcp_connect(&bc->tc, peer, tcp_estab_handler,
			   tcp_recv_handler, tcp_close_handler, bc);
		if (err)
			goto out;

		bc->sa_peer = *peer;

		if (laddr) {
			err = tcp_conn_local_get(bc->tc, laddr);
			if (err)
				goto out;
		}
		break;

	default:
		err = ENOSYS;
		goto out;
	}

out:
	if (err)
		mem_deref(bc);
	else
		*bcp = bc;

	return err;
}


/**
 * Accept pending inbound TCP connection for the BFCP connection.
 * Only one TCP connection is supported.
 *
 * @param bc    Pointer to BFCP connection
 *
 * @return 0 if success, otherwise errorcode
 */
int bfcp_accept(struct bfcp_conn *bc)
{
	if (!bc)
		return EINVAL;

	if (bc->tp != BFCP_TCP)
		return ENOSYS;

	if (bc->tc)
		return EALREADY;

	return tcp_accept(&bc->tc, bc->ts, tcp_estab_handler,
		tcp_recv_handler, tcp_close_handler, bc);
}


/**
 * Reject pending inbound TCP connection for the BFCP connection.
 *
 * @param bc    Pointer to BFCP connection
 */
void bfcp_reject(struct bfcp_conn *bc)
{
	if (!bc || bc->tp != BFCP_TCP)
		return;

	tcp_reject(bc->ts);
}


int bfcp_send(struct bfcp_conn *bc, const struct sa *dst, struct mbuf *mb)
{
	if (!bc || !mb)
		return EINVAL;

	switch (bc->tp) {

	case BFCP_UDP:
		if (!dst)
			return EINVAL;
		return udp_send(bc->us, dst, mb);

	case BFCP_TCP:
		return tcp_send(bc->tc, mb);

	default:
		return ENOSYS;
	}
}


/**
 * Returns socket used to send messages over BFCP connection. For TCP,
 * TCP connection socket is returned.
 *
 * @param bc    Pointer to BFCP connection
 *
 * @return Pointer to socket/connection or NULL.
 */
void *bfcp_sock(const struct bfcp_conn *bc)
{
	if (!bc)
		return NULL;

	switch (bc->tp) {

	case BFCP_UDP:
		return bc->us;

	case BFCP_TCP:
		return bc->tc;

	default:
		return NULL;
	}
}
