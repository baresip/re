/**
 * @file sip/transp.c  SIP Transport
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_fmt.h>
#include <re_uri.h>
#include <re_sys.h>
#include <re_tmr.h>
#include <re_udp.h>
#include <re_stun.h>
#include <re_srtp.h>
#include <re_tcp.h>
#include <re_tls.h>
#include <re_msg.h>
#include <re_http.h>
#include <re_websock.h>
#include <re_sip.h>
#include <re_net.h>
#include "sip.h"


#define DEBUG_MODULE "transp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	TCP_ACCEPT_TIMEOUT    = 32,
	TCP_IDLE_TIMEOUT      = 900,
	TCP_KEEPALIVE_TIMEOUT = 10,
	TCP_KEEPALIVE_INTVAL  = 120,
	TCP_BUFSIZE_MAX       = 65536,
};


struct sip_ccert {
	struct le he;
	struct pl file;
};


struct sip_ccert_data {
	uint32_t hsup;
	struct sip_ccert *ccert;
};


struct sip_transport {
	struct le le;
	struct sa laddr;
	struct sip *sip;
	struct hash *ht_ccert;
	struct tls *tls;
	void *sock;
	enum sip_transp tp;
	uint8_t tos;

	struct http_cli *http_cli;
	struct http_sock *http_sock;
};


struct sip_conn {
	struct le he;
	struct list ql;
	struct list kal;
	struct tmr tmr;
	struct tmr tmr_ka;
	struct sa laddr;
	struct sa paddr;
	struct tls_conn *sc;
	struct tcp_conn *tc;
	struct mbuf *mb;
	struct sip *sip;
	uint32_t ka_interval;
	bool established;

	enum sip_transp tp;
	struct websock_conn *websock_conn;
};


struct sip_connqent {
	struct le le;
	struct mbuf *mb;
	struct sip_connqent **qentp;
	sip_transp_h *transph;
	void *arg;
};


static uint8_t crlfcrlf[4] = {0x0d, 0x0a, 0x0d, 0x0a};


static void internal_transport_handler(int err, void *arg)
{
	(void)err;
	(void)arg;
}


static void transp_destructor(void *arg)
{
	struct sip_transport *transp = arg;

	if (transp->tp == SIP_TRANSP_UDP)
		udp_handler_set(transp->sock, NULL, NULL);

	list_unlink(&transp->le);
	hash_flush(transp->ht_ccert);
	mem_deref(transp->ht_ccert);
	mem_deref(transp->sock);
	mem_deref(transp->tls);
	mem_deref(transp->http_cli);
	mem_deref(transp->http_sock);
}


static void conn_destructor(void *arg)
{
	struct sip_conn *conn = arg;

	tmr_cancel(&conn->tmr_ka);
	tmr_cancel(&conn->tmr);
	list_flush(&conn->kal);
	list_flush(&conn->ql);
	hash_unlink(&conn->he);
	mem_deref(conn->sc);
	mem_deref(conn->tc);
	mem_deref(conn->mb);
	mem_deref(conn->websock_conn);
}


static void qent_destructor(void *arg)
{
	struct sip_connqent *qent = arg;

	if (qent->qentp)
		*qent->qentp = NULL;

	list_unlink(&qent->le);
	mem_deref(qent->mb);
}


static const struct sip_transport *transp_find(struct sip *sip,
					       enum sip_transp tp,
					       int af, const struct sa *dst)
{
	struct le *le;
	struct sa dsttmp;
	const struct sip_transport *fb = NULL;

	for (le = sip->transpl.head; le; le = le->next) {

		const struct sip_transport *transp = le->data;
		const struct sa *laddr = &transp->laddr;
		struct sa src;

		if (transp->tp != tp)
			continue;

		if (af != AF_UNSPEC && sa_af(laddr) != af)
			continue;

		if (!sa_isset(dst, SA_ADDR))
			return transp;

		if (sa_is_linklocal(laddr) != sa_is_linklocal(dst))
			continue;

		if (!fb)
			fb = transp;

		sa_cpy(&dsttmp, dst);
		sa_set_scopeid(&dsttmp, sa_scopeid(laddr));

		if (net_dst_source_addr_get(&dsttmp, &src))
			continue;

		if (!sa_cmp(&src, laddr, SA_ADDR))
			continue;

		return transp;
	}

	return fb;
}


static struct le *transp_apply_all(struct sip *sip, enum sip_transp tp, int af,
				   list_apply_h ah, void *arg)
{
	if (!ah)
		return NULL;

	for (struct le *le = sip->transpl.head; le; le = le->next) {

		const struct sip_transport *transp = le->data;
		const struct sa *laddr = &transp->laddr;

		if (transp->tp != tp)
			continue;

		if (af != AF_UNSPEC && sa_af(laddr) != af)
			continue;

		if (ah(le, arg))
			return le;
	}

	return NULL;
}


static struct sip_conn *conn_find(struct sip *sip, const struct sa *paddr,
				  bool secure)
{
	struct le *le;

	le = list_head(hash_list(sip->ht_conn, sa_hash(paddr, SA_ALL)));

	for (; le; le = le->next) {

		struct sip_conn *conn = le->data;

		if (secure && !conn->sc)
			continue;

		if (!secure && conn->sc)
			continue;

		if (!sa_cmp(&conn->paddr, paddr, SA_ALL))
			continue;

		return conn;
	}

	return NULL;
}


static struct sip_conn *ws_conn_find(struct sip *sip, const struct sa *paddr,
				     enum sip_transp tp)
{
	struct le *le;
	(void) tp;

	le = list_head(hash_list(sip->ht_conn, sa_hash(paddr, SA_ALL)));

	for (; le; le = le->next) {

		struct sip_conn *conn = le->data;

		/* if (tp != conn->tp)
		   continue; */

		if (!sa_cmp(&conn->paddr, paddr, SA_ALL))
			continue;

		return conn;
	}

	return NULL;
}


static void conn_close(struct sip_conn *conn, int err)
{
	struct le *le;

	conn->websock_conn = mem_deref(conn->websock_conn);

	conn->sc = mem_deref(conn->sc);
	conn->tc = mem_deref(conn->tc);
	tmr_cancel(&conn->tmr_ka);
	tmr_cancel(&conn->tmr);
	hash_unlink(&conn->he);

	le = list_head(&conn->ql);

	while (le) {

		struct sip_connqent *qent = le->data;
		le = le->next;
		bool qentp_set = qent->qentp ? true : false;

		qent->transph(err, qent->arg);

		if (!qentp_set) {
			list_unlink(&qent->le);
			mem_deref(qent);
		}
	}

	sip_keepalive_signal(&conn->kal, err);
}


static void conn_tmr_handler(void *arg)
{
	struct sip_conn *conn = arg;

	conn_close(conn, ETIMEDOUT);
	mem_deref(conn);
}


static void conn_keepalive_handler(void *arg)
{
	struct sip_conn *conn = arg;
	struct mbuf mb;
	int err;

	mb.buf  = crlfcrlf;
	mb.size = sizeof(crlfcrlf);
	mb.pos  = 0;
	mb.end  = 4;

	err = tcp_send(conn->tc, &mb);
	if (err) {
		conn_close(conn, err);
		mem_deref(conn);
		return;
	}

	tmr_start(&conn->tmr, TCP_KEEPALIVE_TIMEOUT * 1000,
		  conn_tmr_handler, conn);
	tmr_start(&conn->tmr_ka, sip_keepalive_wait(conn->ka_interval),
		  conn_keepalive_handler, conn);
}

static bool have_essential_fields(const struct sip_msg *msg)
{
	if (pl_isset(&(msg->to.auri)) &&
		pl_isset(&(msg->from.auri)) &&
		pl_isset(&(msg->cseq.met)) &&
		pl_isset(&(msg->callid)) &&
		pl_isset(&(msg->via.branch)))
		return true;

	return false;
}

static void sip_recv(struct sip *sip, const struct sip_msg *msg,
		     size_t start)
{
	struct le *le = sip->lsnrl.head;

	if (sip->traceh) {
		sip->traceh(false, msg->tp, &msg->src, &msg->dst,
			    msg->mb->buf + start, msg->mb->end - start,
			    sip->arg);
	}

	if (msg->req) {
		if (!have_essential_fields(msg)){
			(void)sip_reply(sip, msg, 400, "Bad Request");
			return;
		}
	}

	/* check consistency between CSeq method and that of request line */
	if (msg->req && pl_casecmp(&(msg->cseq.met), &(msg->met))){
		(void)sip_reply(sip, msg, 400, "Bad Request");
		return;
	}

	while (le) {
		struct sip_lsnr *lsnr = le->data;

		le = le->next;

		if (msg->req != lsnr->req)
			continue;

		if (lsnr->msgh(msg, lsnr->arg))
			return;
	}

	if (msg->req) {
		(void)re_fprintf(stderr, "unhandled request from %J: %r %r\n",
				 &msg->src, &msg->met, &msg->ruri);

		if (!pl_strcmp(&msg->met, "CANCEL"))
			(void)sip_reply(sip, msg,
					481, "Transaction Does Not Exist");
		else
			(void)sip_reply(sip, msg,
					501, "Not Implemented");
	}
	else {
		(void)re_fprintf(stderr, "unhandled response from %J:"
				 " %u %r (%r)\n", &msg->src,
				 msg->scode, &msg->reason, &msg->cseq.met);
	}
}


static void udp_recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct sip_transport *transp = arg;
	struct stun_unknown_attr ua;
	struct stun_msg *stun_msg;
	struct sip_msg *msg;
	int err;

	if (mb->end <= 4)
		return;

	if (!stun_msg_decode(&stun_msg, mb, &ua)) {

		if (stun_msg_method(stun_msg) == STUN_METHOD_BINDING) {

			switch (stun_msg_class(stun_msg)) {

			case STUN_CLASS_REQUEST:
				(void)stun_reply(IPPROTO_UDP, transp->sock,
						 src, 0, stun_msg,
						 NULL, 0, false, 2,
						 STUN_ATTR_XOR_MAPPED_ADDR,
						 src,
						 STUN_ATTR_SOFTWARE,
						 transp->sip->software);
				break;

			default:
				(void)stun_ctrans_recv(transp->sip->stun,
						       stun_msg, &ua);
				break;
			}
		}

		mem_deref(stun_msg);

		return;
	}

	err = sip_msg_decode(&msg, mb);
	if (err) {
		(void)re_fprintf(stderr, "sip: msg decode err: %m\n", err);
		return;
	}

	msg->sock = mem_ref(transp->sock);
	msg->src = *src;
	msg->dst = transp->laddr;
	msg->tp = SIP_TRANSP_UDP;
	sa_set_scopeid(&msg->src, sa_scopeid(&transp->laddr));

	sip_recv(transp->sip, msg, 0);

	mem_deref(msg);
}


static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
	struct sip_conn *conn = arg;
	size_t pos;
	int err = 0;

	if (conn->mb) {
		pos = conn->mb->pos;

		conn->mb->pos = conn->mb->end;

		err = mbuf_write_mem(conn->mb, mbuf_buf(mb),mbuf_get_left(mb));
		if (err)
			goto out;

		conn->mb->pos = pos;

		if (mbuf_get_left(conn->mb) > TCP_BUFSIZE_MAX) {
			err = EOVERFLOW;
			goto out;
		}
	}
	else {
		conn->mb = mem_ref(mb);
	}

	for (;;) {
		struct sip_msg *msg;
		uint32_t clen;
		size_t end;

		if (mbuf_get_left(conn->mb) < 2)
			break;

		if (!memcmp(mbuf_buf(conn->mb), "\r\n", 2)) {

			tmr_start(&conn->tmr, TCP_IDLE_TIMEOUT * 1000,
				  conn_tmr_handler, conn);

			conn->mb->pos += 2;

			if (mbuf_get_left(conn->mb) >= 2 &&
			    !memcmp(mbuf_buf(conn->mb), "\r\n", 2)) {

				struct mbuf mbr;

				conn->mb->pos += 2;

				mbr.buf  = crlfcrlf;
				mbr.size = sizeof(crlfcrlf);
				mbr.pos  = 0;
				mbr.end  = 2;

				err = tcp_send(conn->tc, &mbr);
				if (err)
					break;
			}

			if (mbuf_get_left(conn->mb))
				continue;

			conn->mb = mem_deref(conn->mb);
			break;
		}

		pos = conn->mb->pos;

		err = sip_msg_decode(&msg, conn->mb);
		if (err) {
			if (err == ENODATA)
				err = 0;
			break;
		}

		if (!msg->clen.p) {
			mem_deref(msg);
			err = EBADMSG;
			break;
		}

		clen = pl_u32(&msg->clen);

		if (mbuf_get_left(conn->mb) < clen) {
			conn->mb->pos = pos;
			mem_deref(msg);
			break;
		}

		tmr_start(&conn->tmr, TCP_IDLE_TIMEOUT * 1000,
			  conn_tmr_handler, conn);

		end = conn->mb->end;

		msg->mb->end = msg->mb->pos + clen;
		msg->sock = mem_ref(conn);
		msg->src = conn->paddr;
		msg->dst = conn->laddr;
		msg->tp = conn->sc ? SIP_TRANSP_TLS : SIP_TRANSP_TCP;

		sip_recv(conn->sip, msg, 0);
		mem_deref(msg);

		if (end <= conn->mb->end) {
			conn->mb = mem_deref(conn->mb);
			break;
		}

		mb = mbuf_alloc(end - conn->mb->end);
		if (!mb) {
			err = ENOMEM;
			goto out;
		}

		(void)mbuf_write_mem(mb, &conn->mb->buf[conn->mb->end],
				     end - conn->mb->end);

		mb->pos = 0;

		mem_deref(conn->mb);
		conn->mb = mb;
	}

 out:
	if (err) {
		conn_close(conn, err);
		mem_deref(conn);
	}
}


static void trace_send(struct sip *sip, enum sip_transp tp,
		       void *sock,
		       const struct sa *dst, struct mbuf *mb)
{
	struct sa src;
	struct sip_conn *conn;

	if (sip->traceh) {

		switch (tp) {

		case SIP_TRANSP_UDP:

			if (udp_local_get(sock, &src))
				sa_init(&src, sa_af(dst));

			break;

		case SIP_TRANSP_TCP:
		case SIP_TRANSP_TLS:
		case SIP_TRANSP_WS:
		case SIP_TRANSP_WSS:
			conn = sock;
			src = conn->laddr;
			break;

		default:
			return;
		}

		sip->traceh(true, tp, &src, dst,
			    mbuf_buf(mb), mbuf_get_left(mb),
			    sip->arg);
	}
}


static void tcp_estab_handler(void *arg)
{
	struct sip_conn *conn = arg;
	struct le *le;
	int err;

#ifdef WIN32
	tcp_conn_local_get(conn->tc, &conn->laddr);
#endif

	conn->established = true;

	le = list_head(&conn->ql);

	while (le) {

		struct sip_connqent *qent = le->data;
		bool qentp_set = qent->qentp ? true : false;
		le = le->next;

		trace_send(conn->sip,
			   conn->sc ? SIP_TRANSP_TLS : SIP_TRANSP_TCP,
			   conn,
			   &conn->paddr, qent->mb);

		err = tcp_send(conn->tc, qent->mb);
		if (err)
			qent->transph(err, qent->arg);

		if (!qentp_set) {
			list_unlink(&qent->le);
			mem_deref(qent);
		}
	}
}


static void tcp_close_handler(int err, void *arg)
{
	struct sip_conn *conn = arg;

	conn_close(conn, err ? err : ECONNRESET);
	mem_deref(conn);
}


static void tcp_connect_handler(const struct sa *paddr, void *arg)
{
	struct sip_transport *transp = arg;
	struct sip_conn *conn;
	int err;

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn) {
		err = ENOMEM;
		goto out;
	}

	hash_append(transp->sip->ht_conn, sa_hash(paddr, SA_ALL),
		    &conn->he, conn);

	conn->paddr = *paddr;
	conn->sip   = transp->sip;

	err = tcp_accept(&conn->tc, transp->sock, tcp_estab_handler,
			 tcp_recv_handler, tcp_close_handler, conn);
	if (err)
		goto out;

	err = tcp_conn_local_get(conn->tc, &conn->laddr);
	if (err)
		goto out;

	(void)tcp_conn_settos(conn->tc, transp->tos);
#ifdef USE_TLS
	if (transp->tls) {
		err = tls_start_tcp(&conn->sc, transp->tls, conn->tc, 0);
		if (err)
			goto out;

		err = tls_verify_client(conn->sc);
		if (err)
			goto out;
	}
#endif

	conn->tp = transp->tls ? SIP_TRANSP_TLS : SIP_TRANSP_TCP;

	tmr_start(&conn->tmr, TCP_ACCEPT_TIMEOUT * 1000,
		  conn_tmr_handler, conn);

 out:
	if (err) {
		tcp_reject(transp->sock);
		mem_deref(conn);
	}
}

#ifdef USE_TLS
static uint32_t get_hash_of_fromhdr(struct mbuf *mb)
{
	struct sip_msg *msg;
	struct mbuf *sup = NULL;
	uint32_t hsup = 0;
	int err = 0;

	err = sip_msg_decode(&msg, mb);
	if (err)
		return 0;

	sup = mbuf_alloc(30);
	if (!sup)
		return ENOMEM;

	err = mbuf_printf(sup, "\"%r\" <%r:%r@%r:%d>", &msg->from.uri.user,
		&msg->from.uri.scheme, &msg->from.uri.user,
		&msg->from.uri.host, msg->from.uri.port);
	if (err)
		goto out;

	mbuf_set_pos(sup, 0);
	hsup = hash_joaat(mbuf_buf(sup), mbuf_get_left(sup));
	mbuf_set_pos(mb, 0);

 out:
	mem_deref(msg);
	mem_deref(sup);

	return hsup;
}
#endif


static int conn_send(struct sip_connqent **qentp, struct sip *sip, bool secure,
		     const struct sa *dst, char *host, struct mbuf *mb,
		     sip_conn_h *connh, sip_transp_h *transph, void *arg)
{
	struct sip_conn *conn, *new_conn = NULL;
	struct sip_conncfg *conncfg;
	struct sip_connqent *qent;
	int err = 0;

#ifndef USE_TLS
	(void) host;
#endif

	conn = conn_find(sip, dst, secure);
	if (conn) {
		if (connh)
			err = connh(&conn->laddr, dst, mb, arg);

		if (!conn->established)
			goto enqueue;

		trace_send(sip,
			   secure ? SIP_TRANSP_TLS : SIP_TRANSP_TCP,
			   conn,
			   dst, mb);

		return tcp_send(conn->tc, mb);
	}

	new_conn = conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn)
		return ENOMEM;

	hash_append(sip->ht_conn, sa_hash(dst, SA_ALL), &conn->he, conn);
	conn->paddr = *dst;
	conn->sip   = sip;
	conn->tp    = secure ? SIP_TRANSP_TLS : SIP_TRANSP_TCP;

	conncfg = sip_conncfg_find(sip, dst);
	if (conncfg && conncfg->srcport) {
		struct sa src;
		sa_init(&src, sa_af(dst));
		sa_set_port(&src, conncfg->srcport);
		err = tcp_connect_bind(&conn->tc, dst,
				       tcp_estab_handler, tcp_recv_handler,
				       tcp_close_handler, &src, conn);
	}
	else {
		err = tcp_connect(&conn->tc, dst,
				  tcp_estab_handler, tcp_recv_handler,
				  tcp_close_handler, conn);
	}

	if (err)
		goto out;

	err = tcp_conn_local_get(conn->tc, &conn->laddr);
	if (err)
		goto out;

	/* Fallback check for any address win32 */
	if (!sa_isset(&conn->laddr, SA_ALL)) {
		uint16_t port = sa_port(&conn->laddr);
		err = sip_transp_laddr(sip, &conn->laddr, conn->tp, dst);
		if (err)
			goto out;

		if (port)
			sa_set_port(&conn->laddr, port);
	}

	if (connh) {
		err = connh(&conn->laddr, dst, mb, arg);
		if (err)
			goto out;
	}

	(void)tcp_conn_settos(conn->tc, sip->tos);
#ifdef USE_TLS
	if (secure) {
		const struct sip_transport *transp;
		struct sip_ccert *ccert;
		uint32_t hash = 0;

		transp = transp_find(sip, SIP_TRANSP_TLS, sa_af(dst), dst);
		if (!transp || !transp->tls) {
			err = EPROTONOSUPPORT;
			goto out;
		}

		err = tls_start_tcp(&conn->sc, transp->tls, conn->tc, 0);
		if (err)
			goto out;

		hash = get_hash_of_fromhdr(mb);
		ccert = list_ledata(
				list_head(hash_list(transp->ht_ccert, hash)));
		if (ccert) {
			char *f;
			err = pl_strdup(&f, &ccert->file);
			if (err)
				goto out;

			err = tls_conn_change_cert(conn->sc, f);
			mem_deref(f);
			if (err)
				goto out;
		}

		err |= tls_set_verify_server(conn->sc, host);
		if (err)
			goto out;
	}
#endif

	tmr_start(&conn->tmr, TCP_IDLE_TIMEOUT * 1000, conn_tmr_handler, conn);

 enqueue:
	qent = mem_zalloc(sizeof(*qent), qent_destructor);
	if (!qent) {
		err = ENOMEM;
		goto out;

	}

	list_append(&conn->ql, &qent->le, qent);
	qent->mb = mem_ref(mb);
	qent->transph = transph ? transph : internal_transport_handler;
	qent->arg = arg;

	if (qentp) {
		qent->qentp = qentp;
		*qentp = qent;
	}

 out:
	if (err)
		mem_deref(new_conn);

	return err;
}


static void websock_estab_handler(void *arg)
{
	struct sip_conn *conn = arg;
	struct le *le;
	int err;

	re_printf("<%p> %s websock established to %J\n",
		  conn, sip_transp_name(conn->tp), &conn->paddr);

	conn->established = true;

	err = tcp_conn_local_get(websock_tcp(conn->websock_conn),
				 &conn->laddr);
	if (err)
		return;

	le = list_head(&conn->ql);

	while (le) {

		struct sip_connqent *qent = le->data;
		bool qentp_set = qent->qentp ? true : false;
		le = le->next;

		trace_send(conn->sip,
			   conn->tp,
			   conn,
			   &conn->paddr, qent->mb);

		re_printf("--> send\n");

		err = websock_send(conn->websock_conn, WEBSOCK_BIN,
				   "%b",
				   mbuf_buf(qent->mb),
				   mbuf_get_left(qent->mb));
		if (err)
			qent->transph(err, qent->arg);

		if (!qentp_set) {
			list_unlink(&qent->le);
			mem_deref(qent);
		}
	}
}


static void websock_recv_handler(const struct websock_hdr *hdr,
				 struct mbuf *mb, void *arg)
{
	struct sip_conn *conn = arg;
	struct sip_msg *msg;
	size_t start;
	int err;
	(void) hdr;

#if 0
	re_printf(
		  "~ ~ ~ ~ ~ websock receive: ~ ~ ~ ~ ~\n"
		  "\x1b[32m"
		  "%b"
		  "\x1b[;m\t\n"
		  "~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n"
		  ,
		  mbuf_buf(mb), mbuf_get_left(mb));
#endif

	if (mb->end <= 4)
		return;

	tmr_start(&conn->tmr, TCP_IDLE_TIMEOUT * 1000, conn_tmr_handler, conn);

	start = mb->pos;

	err = sip_msg_decode(&msg, mb);
	if (err) {
		(void)re_fprintf(stderr, "sip: msg decode err: %m\n", err);
		return;
	}

	msg->sock = mem_ref(conn);
	msg->src = conn->paddr;
	msg->dst = conn->laddr;
	msg->tp = conn->tp;

	sip_recv(conn->sip, msg, start);

	mem_deref(msg);
}


static void websock_close_handler(int err, void *arg)
{
	struct sip_conn *conn = arg;

	re_printf("sip: websock connection closed (%m)\n", err);
	conn_close(conn, err ? err : ECONNRESET);
	mem_deref(conn);
}


static int ws_conn_send(struct sip_connqent **qentp, struct sip *sip,
			bool secure,
			const struct sa *dst, struct mbuf *mb,
			sip_transp_h *transph, void *arg)
{
	struct sip_conn *conn, *new_conn = NULL;
	struct sip_connqent *qent;
	struct sip_transport *transp;
	enum sip_transp tp;
	const char *prefix;
	char ws_uri[256];
	int err = 0;

	if (secure) {
		prefix = "wss";
		tp = SIP_TRANSP_WSS;
	}
	else {
		prefix = "ws";
		tp = SIP_TRANSP_WS;
	}

	conn = ws_conn_find(sip, dst, tp);
	if (conn) {
		if (!conn->established)
			goto enqueue;

		trace_send(sip,
			   secure ? SIP_TRANSP_WSS : SIP_TRANSP_WS,
			   conn,
			   dst, mb);

		return websock_send(conn->websock_conn, WEBSOCK_BIN,
				    "%b",
				    mbuf_buf(mb), mbuf_get_left(mb));
	}

	transp = (struct sip_transport *)transp_find(sip, tp,
						     sa_af(dst), dst);
	if (!transp) {
		err = EPROTONOSUPPORT;
		goto out;
	}

	new_conn = conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn)
		return ENOMEM;

	hash_append(sip->ht_conn, sa_hash(dst, SA_ALL), &conn->he, conn);
	conn->paddr = *dst;
	conn->sip   = sip;
	conn->tp    = tp;

	/* TODO: how to select ports of outbound SIP/WS proxy ?
	 * TODO: http url path "test" is temp, add config
	 */

	/* Use port if specified, otherwise use default HTTP/HTTPS ports */
	if (sa_port(dst)) {
		if (re_snprintf(ws_uri, sizeof(ws_uri),
				"%s://%J/", prefix, dst) < 0) {
			err = ENOMEM;
			goto out;
		}
	}
	else {
		if (re_snprintf(ws_uri, sizeof(ws_uri),
				"%s://%j/", prefix, dst) < 0) {
			err = ENOMEM;
			goto out;
		}
	}

	if (!transp->http_cli) {
		err = http_client_alloc(&transp->http_cli, sip->dnsc);
		if (err) {
			re_fprintf(stderr, "transp: could not create"
				   " http client (%m)\n", err);
			goto out;
		}
#ifdef USE_TLS
		if (transp->tls)
			http_client_set_tls(transp->http_cli, transp->tls);
#endif
	}

	re_printf("websock: connecting to '%s'\n", ws_uri);
	err = websock_connect(&conn->websock_conn, sip->websock,
			      transp->http_cli, ws_uri, 15000,
			      websock_estab_handler, websock_recv_handler,
			      websock_close_handler, conn,
			      "Sec-WebSocket-Protocol: sip\r\n");
	if (err) {
		re_printf("websock_connect: %m\n", err);
		goto out;
	}

	tmr_start(&conn->tmr, TCP_IDLE_TIMEOUT * 1000, conn_tmr_handler, conn);

 enqueue:
	qent = mem_zalloc(sizeof(*qent), qent_destructor);
	if (!qent) {
		err = ENOMEM;
		goto out;

	}

	list_append(&conn->ql, &qent->le, qent);
	qent->mb = mem_ref(mb);
	qent->transph = transph ? transph : internal_transport_handler;
	qent->arg = arg;

	if (qentp) {
		qent->qentp = qentp;
		*qentp = qent;
	}

 out:
	if (err)
		mem_deref(new_conn);

	return err;
}


static int dst_set_scopeid(struct sip *sip, struct sa *dst, enum sip_transp tp)
{
	struct sa laddr;
	int err;

	if (sa_af(dst) != AF_INET6 || !sa_is_linklocal(dst))
		return 0;

	err = sip_transp_laddr(sip, &laddr, tp, dst);
	if (err)
		return err;

	sa_set_scopeid(dst, sa_scopeid(&laddr));
	return 0;
}


int sip_transp_init(struct sip *sip, uint32_t sz)
{
	int err;

	err  = hash_alloc(&sip->ht_conn, sz);
	err |= hash_alloc(&sip->ht_conncfg, sz);
	return err;
}


static void http_req_handler(struct http_conn *hc, const struct http_msg *msg,
			     void *arg)
{
	struct sip_transport *transp = arg;
	struct sip_conn *conn = NULL;
	const struct sa *paddr;
	const struct http_hdr *hdr;
	int err;

	paddr = http_conn_peer(hc);

	re_printf("http request from %J\n", paddr);

	hdr = http_msg_hdr(msg, HTTP_HDR_SEC_WEBSOCKET_PROTOCOL);
	if (!hdr) {
		re_printf("sip: missing Sec-WebSocket-Protocol header\n");
		err = EPROTO;
		goto out;
	}
	if (0 != pl_strcasecmp(&hdr->val, "sip")) {
		re_printf("sip: unknown Sec-WebSocket-Protocol '%r'\n",
			  &hdr->val);
		err = EPROTO;
		goto out;
	}

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn) {
		err = ENOMEM;
		goto out;
	}

	hash_append(transp->sip->ht_conn, sa_hash(paddr, SA_ALL),
		    &conn->he, conn);

	conn->paddr = *paddr;
	conn->sip   = transp->sip;
	conn->tp    = transp->tp;

	err = websock_accept_proto(&conn->websock_conn, "sip",
                             transp->sip->websock, hc, msg, 15000,
                             websock_recv_handler, websock_close_handler,
                             conn);
	if (err)
		goto out;

	err = tcp_conn_local_get(websock_tcp(conn->websock_conn),
				 &conn->laddr);
	if (err)
		goto out;

 out:
	if (err) {
		(void)http_reply(hc, 500, "Server Error", NULL);
		mem_deref(conn);
	}
}


/**
 * Add a SIP transport
 *
 * @param sip    SIP stack instance
 * @param tp     SIP Transport
 * @param listen True to open listening socket (UDP socket always opened)
 * @param laddr  Local network address
 * @param ap     Optional transport parameters such as TLS context
 *
 * @return 0 if success, otherwise errorcode
 */
static int add_transp(struct sip *sip, enum sip_transp tp,
		      bool listen, const struct sa *laddr, va_list ap)
{
	struct sip_transport *transp;
	struct tls *tls;
	int err = 0;

	if (!sip || !laddr || !sa_isset(laddr, SA_ADDR))
		return EINVAL;

	transp = mem_zalloc(sizeof(*transp), transp_destructor);
	if (!transp)
		return ENOMEM;

	if (tp == SIP_TRANSP_TLS) {
		err = hash_alloc(&transp->ht_ccert, 32);
		if (err) {
			mem_deref(transp);
			return err;
		}
	}

	list_append(&sip->transpl, &transp->le, transp);
	transp->sip = sip;
	transp->tp  = tp;

	switch (tp) {

	case SIP_TRANSP_UDP:
		err = udp_listen((struct udp_sock **)&transp->sock, laddr,
				 udp_recv_handler, transp);
		if (err)
			break;

		err = udp_local_get(transp->sock, &transp->laddr);
		break;

	case SIP_TRANSP_TLS:
		tls = va_arg(ap, struct tls *);
		if (!tls) {
			err = EINVAL;
			break;
		}

		transp->tls = mem_ref(tls);

		/*@fallthrough@*/

	case SIP_TRANSP_TCP:

		if (!listen) {
			transp->laddr = *laddr;
			sa_set_port(&transp->laddr, 0);
			return err;
		}

		err = tcp_listen((struct tcp_sock **)&transp->sock, laddr,
				 tcp_connect_handler, transp);
		if (err)
			break;

		err = tcp_sock_local_get(transp->sock, &transp->laddr);
		break;

	default:
		err = EPROTONOSUPPORT;
		break;
	}

	if (err)
		mem_deref(transp);

	return err;
}


/**
 * Add a SIP transport
 *
 * @param sip   SIP stack instance
 * @param tp    SIP Transport
 * @param laddr Local network address
 * @param ...   Optional transport parameters such as TLS context
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_transp_add(struct sip *sip, enum sip_transp tp,
		   const struct sa *laddr, ...)
{
	int err;
	va_list ap;

	va_start(ap, laddr);
	err = add_transp(sip, tp, true, laddr, ap);
	va_end(ap);

	return err;
}


/**
 * Add a SIP transport and open listening socket if requested
 *
 * UDP socket will always be opened even if listen is false.
 *
 * @param sip    SIP stack instance
 * @param tp     SIP Transport
 * @param listen True to open listening socket
 * @param laddr  Local network address
 * @param ...	 Optional transport parameters such as TLS context
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_transp_add_sock(struct sip *sip, enum sip_transp tp,
			bool listen, const struct sa *laddr, ...)
{
	int err;
	va_list ap;

	va_start(ap, laddr);
	err = add_transp(sip, tp, listen, laddr, ap);
	va_end(ap);

	return err;
}


/**
 * Add a SIP websocket transport
 *
 * @param sip    SIP stack instance
 * @param tp     SIP Transport
 * @param laddr  Local network address
 * @param server True if server, otherwise false
 * @param cert   Server Certificate
 * @param tls    Optional TLS context
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_transp_add_websock(struct sip *sip, enum sip_transp tp,
			   const struct sa *laddr,
			   bool server, const char *cert, struct tls *tls)
{
	struct sip_transport *transp;
	bool secure = tp == SIP_TRANSP_WSS;
	int err = 0;

	if (!sip || !laddr || !sa_isset(laddr, SA_ADDR))
		return EINVAL;

	transp = mem_zalloc(sizeof(*transp), transp_destructor);
	if (!transp)
		return ENOMEM;

	list_append(&sip->transpl, &transp->le, transp);
	transp->sip = sip;
	transp->tp  = tp;

	if (tls)
		transp->tls = mem_ref(tls);

	if (server) {

		if (secure) {
			err = https_listen(&transp->http_sock, laddr,
					   cert,
					   http_req_handler, transp);
			if (err) {
				re_fprintf(stderr,
					   "websock: https_listen"
					   " error (%m)\n", err);
				goto out;
			}
		}
		else {
			err = http_listen(&transp->http_sock, laddr,
					  http_req_handler, transp);
			if (err) {
				re_fprintf(stderr, "websock: http_listen"
					   " error (%m)\n", err);
				goto out;
			}
		}

		err = tcp_sock_local_get(http_sock_tcp(transp->http_sock),
					 &transp->laddr);
		if (err)
			goto out;
	}
	else {
		transp->laddr = *laddr;
		sa_set_port(&transp->laddr, 9);
	}

 out:
	if (err)
		mem_deref(transp);

	return err;
}


static bool add_ccert_handler(struct le *le, void *arg)
{
	const struct sip_transport *transp = le->data;
	struct sip_ccert_data *cc = arg;

	if (!cc->ccert->he.list)
		hash_append(transp->ht_ccert, cc->hsup, &cc->ccert->he,
			    cc->ccert);
	else {
		struct sip_ccert *ccert = mem_zalloc(sizeof(*ccert), NULL);
		if (!ccert)
			return false;

		ccert->file = cc->ccert->file;
		hash_append(transp->ht_ccert, cc->hsup, &ccert->he, ccert);
	}

	return false;
}


/**
 * Add a client certificate to the TLS transport object
 * Client certificates are saved as hash-table.
 * Hashtable-Key: "username" <sip:username\@address:port>
 *
 * @param sip Global SIP stack
 * @param uri Account uri information
 * @param cert Certificate + Key file
 *
 * @return int 0 if success, otherwise errorcode
 */
int sip_transp_add_ccert(struct sip *sip, const struct uri *uri,
			 const char *cert)
{
	int err = 0;
	struct sip_ccert *ccert = NULL;
	struct sip_ccert_data cc_data;
	struct mbuf *sup = NULL;

	if (!sip || !uri || !cert)
		return EINVAL;

	sup = mbuf_alloc(30);
	if (!sup)
		return ENOMEM;

	err = mbuf_printf(sup, "\"%r\" <%r:%r@%r:%d>", &uri->user,
		&uri->scheme, &uri->user, &uri->host, uri->port);
	if (err)
		goto out;

	mbuf_set_pos(sup, 0);

	ccert = mem_zalloc(sizeof(*ccert), NULL);
	if (!ccert) {
		err = ENOMEM;
		goto out;
	}
	pl_set_str(&ccert->file, cert);

	cc_data.hsup = hash_joaat(mbuf_buf(sup), mbuf_get_left(sup));
	cc_data.ccert = ccert;

	(void)transp_apply_all(sip, SIP_TRANSP_TLS, AF_INET, add_ccert_handler,
			       &cc_data);
	(void)transp_apply_all(sip, SIP_TRANSP_TLS, AF_INET6,
			       add_ccert_handler, &cc_data);

 out:
	mem_deref(sup);
	return err;
}


/**
 * Flush all transports of a SIP stack instance
 *
 * @param sip SIP stack instance
 */
void sip_transp_flush(struct sip *sip)
{
	if (!sip)
		return;

	hash_flush(sip->ht_conn);
	hash_flush(sip->ht_conncfg);
	list_flush(&sip->transpl);
}


int sip_transp_send(struct sip_connqent **qentp, struct sip *sip, void *sock,
		    enum sip_transp tp, const struct sa *dst, char *host,
		    struct mbuf *mb, sip_conn_h *connh, sip_transp_h *transph,
		    void *arg)
{
	const struct sip_transport *transp;
	struct sip_conn *conn;
	bool secure = false;
	struct sa dsttmp;
	struct sa laddr;
	int err;

	if (!sip || !dst || !mb)
		return EINVAL;

	sa_cpy(&dsttmp, dst);
	err = dst_set_scopeid(sip, &dsttmp, tp);
	if (err)
		return err;

	switch (tp) {

	case SIP_TRANSP_UDP:
		err = sip_transp_laddr(sip, &laddr, tp, dst);
		if (err)
			return err;

		if (connh)
			connh(&laddr, dst, mb, arg);

		if (!sock) {
			transp = transp_find(sip, tp, sa_af(&dsttmp), &dsttmp);
			if (!transp)
				return EPROTONOSUPPORT;

			sock = transp->sock;
		}

		trace_send(sip, tp, sock, &dsttmp, mb);

		err = udp_send(sock, &dsttmp, mb);
		break;

	case SIP_TRANSP_TLS:
		secure = true;
		/*@fallthrough@*/

	case SIP_TRANSP_TCP:
		conn = sock;

		if (conn && conn->tc) {
			if (connh) {
				err = connh(&conn->laddr, dst, mb, arg);
				if (err)
					return err;
			}

			trace_send(sip, tp, conn, &dsttmp, mb);

			err = tcp_send(conn->tc, mb);
		}
		else
			err = conn_send(qentp, sip, secure, &dsttmp, host, mb,
					connh, transph, arg);
		break;

	case SIP_TRANSP_WSS:
		secure = true;
		/*@fallthrough@*/

	case SIP_TRANSP_WS:
		/*TODO: Ideally connh should be called if the websocket was
		 * opened and the source port is known. As a workaround the
		 * listen port is used for Contact and Via headers */
		err = sip_transp_laddr(sip, &laddr, tp, dst);
		if (err)
			return err;

		if (connh)
			connh(&laddr, dst, mb, arg);

		conn = sock;
		if (conn && conn->websock_conn) {

			trace_send(sip, tp, conn, &dsttmp, mb);

			err = websock_send(conn->websock_conn, WEBSOCK_BIN,
					   "%b",
					   mbuf_buf(mb), mbuf_get_left(mb));
			if (err) {
				re_fprintf(stderr, "websock_send failed"
					   " (%m)\n", err);
			}
		}
		else {
			err = ws_conn_send(qentp, sip, secure, &dsttmp, mb,
					   transph, arg);
			if (err) {
				re_fprintf(stderr, "ws_conn_send failed"
					   " (%m)\n", err);
			}
		}
		break;

	default:
		err = EPROTONOSUPPORT;
		break;
	}

	return err;
}


int sip_transp_laddr(struct sip *sip, struct sa *laddr, enum sip_transp tp,
		      const struct sa *dst)
{
	const struct sip_transport *transp;
	struct sip_conncfg *conncfg;

	if (!sip || !laddr)
		return EINVAL;

	transp = transp_find(sip, tp, sa_af(dst), dst);
	if (!transp)
		return EPROTONOSUPPORT;

	*laddr = transp->laddr;
	if (tp != SIP_TRANSP_UDP) {
		conncfg = sip_conncfg_find(sip, dst);
		if (conncfg && conncfg->srcport)
			sa_set_port(laddr, conncfg->srcport);
	}

	return 0;
}


bool sip_transp_supported(struct sip *sip, enum sip_transp tp, int af)
{
	if (!sip)
		return false;

	return transp_find(sip, tp, af, NULL) != NULL;
}


int  sip_transp_set_default(struct sip *sip, enum sip_transp tp)
{
	if (!sip)
		return EINVAL;

	sip->tp_def = tp;
	return 0;
}


/**
 * Check if network address is part of SIP transports
 *
 * @param sip   SIP stack instance
 * @param tp    SIP transport
 * @param laddr Local network address to check
 *
 * @return True if part of SIP transports, otherwise false
 */
bool sip_transp_isladdr(const struct sip *sip, enum sip_transp tp,
			const struct sa *laddr)
{
	struct le *le;

	if (!sip || !laddr)
		return false;

	for (le=sip->transpl.head; le; le=le->next) {

		const struct sip_transport *transp = le->data;

		if (tp != SIP_TRANSP_NONE && transp->tp != tp)
			continue;

		if (!sa_cmp(&transp->laddr, laddr, SA_ALL))
			continue;

		return true;
	}

	return false;
}


/**
 * Get the name of a given SIP Transport
 *
 * @param tp SIP Transport
 *
 * @return Name of the corresponding SIP Transport
 */
const char *sip_transp_name(enum sip_transp tp)
{
	switch (tp) {

	case SIP_TRANSP_UDP: return "UDP";
	case SIP_TRANSP_TCP: return "TCP";
	case SIP_TRANSP_TLS: return "TLS";
	case SIP_TRANSP_WS:  return "WS";
	case SIP_TRANSP_WSS: return "WSS";
	default:             return "???";
	}
}


const char *sip_transp_srvid(enum sip_transp tp)
{
	switch (tp) {

	case SIP_TRANSP_UDP: return "_sip._udp";
	case SIP_TRANSP_TCP: return "_sip._tcp";
	case SIP_TRANSP_TLS: return "_sips._tcp";
	default:             return "???";
	}
}


/**
 * Get the transport parameters for a given SIP Transport
 *
 * @param tp SIP Transport
 *
 * @return Transport parameters of the corresponding SIP Transport
 */
const char *sip_transp_param(enum sip_transp tp)
{
	switch (tp) {

	case SIP_TRANSP_UDP: return "";
	case SIP_TRANSP_TCP: return ";transport=tcp";
	case SIP_TRANSP_TLS: return ";transport=tls";
	case SIP_TRANSP_WS:  return ";transport=ws";
	case SIP_TRANSP_WSS: return ";transport=wss";
	default:             return "";
	}
}


enum sip_transp sip_transp_decode(const struct pl *pl)
{
	enum sip_transp tp = SIP_TRANSP_NONE;
	if (!pl_strcasecmp(pl, "udp"))
		tp = SIP_TRANSP_UDP;
	else if (!pl_strcasecmp(pl, "tcp"))
		tp = SIP_TRANSP_TCP;
	else if (!pl_strcasecmp(pl, "tls"))
		tp = SIP_TRANSP_TLS;
	else if (!pl_strcasecmp(pl, "ws"))
		tp = SIP_TRANSP_WS;
	else if (!pl_strcasecmp(pl, "wss"))
		tp = SIP_TRANSP_WSS;

	return tp;
}


bool sip_transp_reliable(enum sip_transp tp)
{
	switch (tp) {

	case SIP_TRANSP_UDP: return false;
	case SIP_TRANSP_TCP: return true;
	case SIP_TRANSP_TLS: return true;
	case SIP_TRANSP_WS:  return true;
	case SIP_TRANSP_WSS: return true;
	default:             return false;
	}
}


/**
 * Get the default port number for a given SIP Transport
 *
 * @param tp   SIP Transport
 * @param port Port number
 *
 * @return Corresponding port number
 */
uint16_t sip_transp_port(enum sip_transp tp, uint16_t port)
{
	if (port)
		return port;

	switch (tp) {

	case SIP_TRANSP_UDP: return SIP_PORT;
	case SIP_TRANSP_TCP: return SIP_PORT;
	case SIP_TRANSP_TLS: return SIP_PORT_TLS;
	case SIP_TRANSP_WS:  return 80;
	case SIP_TRANSP_WSS: return 443;
	default:             return 0;
	}
}


int  sip_settos(struct sip *sip, uint8_t tos)
{
	struct le *le;
	int err = 0;

	if (!sip)
		return EINVAL;

	sip->tos = tos;

	for (le = sip->transpl.head; le; le = le->next) {

		struct sip_transport *transp = le->data;
		transp->tos = tos;
		switch (transp->tp) {
		case SIP_TRANSP_UDP:
			err = udp_settos(transp->sock, tos);
			break;

		case SIP_TRANSP_TCP:
		case SIP_TRANSP_TLS:
			err = tcp_settos(transp->sock, tos);
			break;
		default:
			break;
		}

		if (err)
			break;
	}

	return err;
}


static void sip_transports_print(struct re_printf *pf, const struct sip* sip)
{
	uint32_t mask = 0;

	for (struct le *le = sip->transpl.head; le; le = le->next) {
		const struct sip_transport *transp = le->data;
		mask |= (1 << transp->tp);
	}

	for (uint8_t i = 0; i < SIP_TRANSPC; ++i) {
		if (mask==0 || (0 != (mask & (1u << i))))
			(void)re_hprintf(pf, "  %s\n", sip_transp_name(i));
	}
}


static bool debug_handler(struct le *le, void *arg)
{
	const struct sip_transport *transp = le->data;
	struct re_printf *pf = arg;

	if (sa_port(&transp->laddr) == 0)
		return false;

	(void)re_hprintf(pf, "  %J (%s)\n",
			 &transp->laddr,
			 sip_transp_name(transp->tp));

	return false;
}


static bool conn_debug_handler(struct le *le, void *arg)
{
	struct sip_conn *conn = le->data;
	struct re_printf *pf = arg;

	(void)re_hprintf(pf, "  [%u] %5s  %J --> %J  (%s)\n",
			 mem_nrefs(conn),
			 sip_transp_name(conn->tp),
			 &conn->laddr, &conn->paddr,
			 conn->established ? "Established" : "..."
			 );

	return false;
}


static bool conncfg_debug_handler(struct le *le, void *arg)
{
	struct sip_conncfg *conncfg = le->data;
	struct re_printf *pf = arg;

	(void)re_hprintf(pf, "  TCP source port  %u\n", conncfg->srcport);

	return false;
}


int sip_transp_debug(struct re_printf *pf, const struct sip *sip)
{
	int err;

	err = re_hprintf(pf, "transports:\n");
	sip_transports_print(pf, sip);

	err |= re_hprintf(pf, "transport sockets:\n");
	list_apply(&sip->transpl, true, debug_handler, pf);

	err |= re_hprintf(pf, "connections:\n");
	hash_apply(sip->ht_conn, conn_debug_handler, pf);

	err |= re_hprintf(pf, "connection configurations:\n");
	hash_apply(sip->ht_conncfg, conncfg_debug_handler, pf);

	return err;
}


/**
 * Get the TCP Connection from a SIP Message
 *
 * @param msg SIP Message
 *
 * @return TCP Connection if reliable transport, otherwise NULL
 */
struct tcp_conn *sip_msg_tcpconn(const struct sip_msg *msg)
{
	if (!msg || !msg->sock)
		return NULL;

	switch (msg->tp) {

	case SIP_TRANSP_TCP:
	case SIP_TRANSP_TLS:
		return ((struct sip_conn *)msg->sock)->tc;

	case SIP_TRANSP_WS:
	case SIP_TRANSP_WSS: {
		struct sip_conn *conn = msg->sock;
		return websock_tcp(conn->websock_conn);
	}

	default:
		return NULL;
	}
}


int  sip_keepalive_tcp(struct sip_keepalive *ka, struct sip_conn *conn,
		       uint32_t interval)
{
	if (!ka || !conn)
		return EINVAL;

	if (!conn->tc || !conn->established)
		return ENOTCONN;

	list_append(&conn->kal, &ka->le, ka);

	if (!tmr_isrunning(&conn->tmr_ka)) {

		interval = MAX(interval ? interval : TCP_KEEPALIVE_INTVAL,
			       TCP_KEEPALIVE_TIMEOUT * 2);

		conn->ka_interval = interval;

		tmr_start(&conn->tmr_ka, sip_keepalive_wait(conn->ka_interval),
			  conn_keepalive_handler, conn);
	}

	return 0;
}


/**
 * Remove all SIP transport instances that are bound to the given local network
 * address
 *
 * @param sip   SIP stack instance
 * @param laddr Local network address
 */
void sip_transp_rmladdr(struct sip *sip, const struct sa *laddr)
{
	struct le *le;
	struct le *len = NULL;

	if (!sip || !laddr)
		return;

	for (le = sip->transpl.head; le; le = len) {
		struct sip_transport *transp = le->data;

		len = le->next;
		if (sa_cmp(&transp->laddr, laddr, SA_ADDR))
			mem_deref(transp);
	}
}


/**
 * Set a SIP connection configuration for a given peer address
 *
 * @param sip      SIP stack instance
 * @param paddr    Peer address
 * @param conncfg  A SIP connection configuration
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_conncfg_set(struct sip *sip, const struct sa *paddr,
		    const struct sip_conncfg *conncfg)
{
	struct sip_conncfg *cfg;

	if (!sip || !sa_isset(paddr, SA_ALL))
		return EINVAL;

	cfg = sip_conncfg_find(sip, paddr);
	if (cfg) {
		cfg->srcport = conncfg->srcport;
		return 0;
	}
	else {
		cfg = mem_zalloc(sizeof(*cfg), NULL);
	}

	if (!cfg)
		return ENOMEM;

	memcpy(cfg, conncfg, sizeof(*cfg));
	memset(&cfg->he, 0, sizeof(cfg->he));
	sa_cpy(&cfg->paddr, paddr);
	hash_append(sip->ht_conncfg, sa_hash(paddr, SA_ALL), &cfg->he, cfg);

	return 0;
}
