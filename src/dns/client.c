/**
 * @file dns/client.c  DNS Client
 *
 * Copyright (C) 2010 Creytiv.com
 * Copyright (C) 2022 Sebastian Reimers
 */
#ifndef WIN32
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_udp.h>
#include <re_tcp.h>
#include <re_sys.h>
#include <re_dns.h>
#include <re_net.h>
#include <re_main.h>


#define DEBUG_MODULE "dnsc"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	NTX_MAX = 4,
	QUERY_HASH_SIZE = 16,
	TCP_HASH_SIZE = 2,
	CONN_TIMEOUT = 10 * 1000,
	IDLE_TIMEOUT = 30 * 1000,
	SRVC_MAX = 32,
	RR_MAX = 32,
	CACHE_TTL_MAX = 1800,
	GETADDRINFO_TTL = 60,
	RRLV_MAX = 3
};


struct tcpconn {
	struct le le;
	struct list ql;
	struct tmr tmr;
	struct sa srv;
	struct tcp_conn *conn;
	struct mbuf *mb;
	bool connected;
	uint16_t flen;
	struct dnsc *dnsc; /* parent */
};


struct dns_query {
	struct le le;
	struct le le_hdl;
	struct le le_tc;
	struct dnshdr hdr;
	struct tmr tmr;
	struct tmr tmr_ttl;
	struct mbuf mb;
	struct list *rrlv[RRLV_MAX];
	char *name;
	const struct sa *srvv;
	const uint32_t *srvc;
	struct tcpconn *tc;
	struct dnsc *dnsc;     /* parent  */
	struct dns_query **qp; /* app ref */
	uint32_t ntx;
	uint16_t id;
	uint16_t type;
	uint16_t dnsclass;
	uint8_t opcode;
	dns_query_h *qh;
	void *arg;
};


struct dnsquery {
	struct dnshdr hdr;
	char *name;
	uint16_t type;
	uint16_t dnsclass;
	struct list *rrlv;
	bool cache;
	struct dnsc *dnsc; /* parent */
};


struct dnsc {
	struct dnsc_conf conf;
	struct tmr hdl_tmr;
	struct list hdl_cache;
	struct hash *ht_query;
	struct hash *ht_query_cache;
	struct hash *ht_tcpconn;
	struct udp_sock *us;
	struct udp_sock *us6;
	struct sa srvv[SRVC_MAX];
	uint32_t srvc;
};


static const struct dnsc_conf default_conf = {
	QUERY_HASH_SIZE,
	TCP_HASH_SIZE,
	CONN_TIMEOUT,
	IDLE_TIMEOUT,
	CACHE_TTL_MAX,
	false
};


static void tcpconn_close(struct tcpconn *tc, int err);
static int  send_tcp(struct dns_query *q);
static void udp_timeout_handler(void *arg);


static bool rr_unlink_handler(struct le *le, void *arg)
{
	struct dnsrr *rr = le->data;
	(void)arg;

	if (mem_nrefs(rr) < 2)
		list_unlink(&rr->le_priv);
	mem_deref(rr);

	return false;
}


static void query_abort(struct dns_query *q)
{
	if (q->tc) {
		list_unlink(&q->le_tc);
		q->tc = mem_deref(q->tc);
	}

	tmr_cancel(&q->tmr);
	hash_unlink(&q->le);
}


static void query_destructor(void *data)
{
	struct dns_query *q = data;

	query_abort(q);
	tmr_cancel(&q->tmr_ttl);
	mbuf_reset(&q->mb);
	mem_deref(q->name);
	list_unlink(&q->le_hdl);

	for (int i = 0; i < RRLV_MAX; i++) {
		(void)list_apply(q->rrlv[i], true, rr_unlink_handler, NULL);
		mem_deref(q->rrlv[i]);
	}
}


static void query_handler(struct dns_query *q, int err, struct list *ansl,
			  struct list *authl, struct list *addl)
{
	/* deref here - before calling handler */
	if (q->qp)
		*q->qp = NULL;

	/* The handler must only be called _once_ */
	if (q->qh) {
		q->qh(err, &q->hdr, ansl, authl, addl, q->arg);
		q->qh = NULL;
	}

	/* in case we have more (than one) q refs */
	query_abort(q);
}


static bool query_close_handler(struct le *le, void *arg)
{
	struct dns_query *q = le->data;
	(void)arg;

	query_handler(q, ECONNABORTED, NULL, NULL, NULL);
	mem_deref(q);

	return false;
}


static bool query_cmp_handler(struct le *le, void *arg)
{
	struct dns_query *q = le->data;
	struct dnsquery *dq = arg;

	if (!dq->cache && q->id != dq->hdr.id)
		return false;

	if (q->opcode != dq->hdr.opcode)
		return false;

	if (q->type != dq->type)
		return false;

	if (q->dnsclass != dq->dnsclass)
		return false;

	if (str_casecmp(q->name, dq->name))
		return false;

	return true;
}


static void ttl_timeout_handler(void *arg)
{
	struct dns_query *q = arg;

	DEBUG_INFO("ttl cache delete (id: %d): %s.\t%s\t%s\n", q->id, q->name,
		   dns_rr_classname(q->dnsclass), dns_rr_typename(q->type));

	mem_deref(q);
}


static int reply_recv(struct dnsc *dnsc, struct mbuf *mb)
{
	struct dns_query *q = NULL;
	uint32_t nv[3];
	struct dnsquery dq;
	int err = 0;
	int64_t ttl;

	if (!dnsc || !mb)
		return EINVAL;

	ttl = dnsc->conf.cache_ttl_max;
	dq.name = NULL;
	dq.cache = false;

	if (dns_hdr_decode(mb, &dq.hdr) || !dq.hdr.qr) {
		err = EBADMSG;
		goto out;
	}

	err = dns_dname_decode(mb, &dq.name, 0);
	if (err)
		goto out;

	if (mbuf_get_left(mb) < 4) {
		err = EBADMSG;
		goto out;
	}

	dq.type     = ntohs(mbuf_read_u16(mb));
	dq.dnsclass = ntohs(mbuf_read_u16(mb));

	q = list_ledata(hash_lookup(dnsc->ht_query, hash_joaat_str_ci(dq.name),
				    query_cmp_handler, &dq));
	if (!q) {
		err = ENOENT;
		goto out;
	}

	/* try next server */
	if (dq.hdr.rcode == DNS_RCODE_SRV_FAIL && q->ntx < *q->srvc) {

		if (!q->tc) /* try next UDP server immediately */
			tmr_start(&q->tmr, 0, udp_timeout_handler, q);

		err = EPROTO;
		goto out;
	}

	nv[0] = dq.hdr.nans;
	nv[1] = dq.hdr.nauth;
	nv[2] = dq.hdr.nadd;

	DEBUG_INFO("--- ANSWER SECTION id: %d ---\n", q->id);
	for (uint32_t i = 0; i < RE_ARRAY_SIZE(nv); i++) {
		uint32_t l = nv[i];

		if (l > RR_MAX) {
			l = RR_MAX;
			DEBUG_WARNING("limit rr records %d\n", l);
		}

		for (uint32_t j = 0; j < l; j++) {

			struct dnsrr *rr = NULL;

			err = dns_rr_decode(mb, &rr, 0);
			if (err) {
				query_handler(q, err, NULL, NULL, NULL);
				mem_deref(q);
				goto out;
			}

			DEBUG_INFO("%H\n", dns_rr_print, rr);

			list_append(q->rrlv[i], &rr->le_priv, rr);
			if (rr->ttl < ttl)
				ttl = rr->ttl;
		}
	}

	if (q->type == DNS_QTYPE_AXFR) {

		struct dnsrr *rrh, *rrt;

		rrh = list_ledata(list_head(q->rrlv[0]));
		rrt = list_ledata(list_tail(q->rrlv[0]));

		/* Wait for last AXFR reply with terminating SOA record */
		if (dq.hdr.rcode == DNS_RCODE_OK && dq.hdr.nans > 0 &&
		    (!rrt || rrt->type != DNS_TYPE_SOA || rrh == rrt)) {
			DEBUG_INFO("waiting for last SOA record in reply\n");
			goto out;
		}
	}

	q->hdr = dq.hdr;
	query_handler(q, 0, q->rrlv[0], q->rrlv[1], q->rrlv[2]);


	if (!dnsc->conf.cache_ttl_max || q->type == DNS_QTYPE_AXFR) {
		mem_deref(q);
		goto out;
	}

	/* Don't cache empty RR answer if authority is also empty. */
	if (!dq.hdr.nans && !dq.hdr.nauth) {
		mem_deref(q);
		goto out;
	}

	/* Cache negative answer with SOA minimum value (RFC 2308) */
	if (!dq.hdr.nans && dq.hdr.nauth) {
		const struct dnsrr *rr = list_ledata(list_head(q->rrlv[1]));

		if (!rr || rr->type != DNS_TYPE_SOA) {
			mem_deref(q);
			goto out;
		}

		if (rr->rdata.soa.ttlmin < dnsc->conf.cache_ttl_max)
			ttl = rr->rdata.soa.ttlmin;
	}

	/* Cache DNS query with TTL timeout */
	hash_append(dnsc->ht_query_cache, hash_joaat_str_ci(q->name), &q->le,
		    q);
	DEBUG_INFO("cache %s. (id: %d) %d secs\n", q->name, q->id, ttl);
	/* Fallback to 100ms for faster unit tests */
	tmr_start(&q->tmr_ttl, ttl > 1 ? ttl * 1000 : 100,
		  ttl_timeout_handler, q);

 out:
	mem_deref(dq.name);

	return err;
}


static void udp_recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	(void)src;
	(void)reply_recv(arg, mb);
}


static void tcp_recv_handler(struct mbuf *mbrx, void *arg)
{
	struct tcpconn *tc = arg;
	struct mbuf *mb = tc->mb;
	int err = 0;
	size_t n;

 next:
	/* frame length */
	if (!tc->flen) {

		n = min(2 - mb->end, mbuf_get_left(mbrx));

		err = mbuf_write_mem(mb, mbuf_buf(mbrx), n);
		if (err)
			goto error;

		mbrx->pos += n;

		if (mb->end < 2)
			return;

		mb->pos = 0;
		tc->flen = ntohs(mbuf_read_u16(mb));
		mb->pos = 0;
		mb->end = 0;
	}

	/* content */
	n = min(tc->flen - mb->end, mbuf_get_left(mbrx));

	err = mbuf_write_mem(mb, mbuf_buf(mbrx), n);
	if (err)
		goto error;

	mbrx->pos += n;

	if (mb->end < tc->flen)
		return;

	mb->pos = 0;

	err = reply_recv(tc->dnsc, mb);
	if (err)
		goto error;

	/* reset tcp buffer */
	tc->flen = 0;
	mb->pos = 0;
	mb->end = 0;

	/* more data ? */
	if (mbuf_get_left(mbrx) > 0) {
		DEBUG_INFO("%u bytes of tcp data left\n", mbuf_get_left(mbrx));
		goto next;
	}

	return;

 error:
	tcpconn_close(tc, err);
}


static void tcpconn_timeout_handler(void *arg)
{
	struct tcpconn *tc = arg;

	DEBUG_NOTICE("tcp (%J) %s timeout \n", &tc->srv,
		     tc->connected ? "idle" : "connect");

	tcpconn_close(tc, ETIMEDOUT);
}


static void tcp_estab_handler(void *arg)
{
	struct tcpconn *tc = arg;
	struct le *le = list_head(&tc->ql);
	int err = 0;

	DEBUG_INFO("connection (%J) established\n", &tc->srv);

	while (le) {
		struct dns_query *q = le->data;

		le = le->next;

		q->mb.pos = 0;
		err = tcp_send(tc->conn, &q->mb);
		if (err)
			break;

		DEBUG_INFO("tcp send %J\n", &tc->srv);
	}

	if (err) {
		tcpconn_close(tc, err);
		return;
	}

	tmr_start(&tc->tmr, tc->dnsc->conf.idle_timeout,
		  tcpconn_timeout_handler, tc);
	tc->connected = true;
}


static void tcp_close_handler(int err, void *arg)
{
	struct tcpconn *tc = arg;

	DEBUG_NOTICE("connection (%J) closed: %m\n", &tc->srv, err);
	tcpconn_close(tc, err);
}


static bool tcpconn_cmp_handler(struct le *le, void *arg)
{
	const struct tcpconn *tc = le->data;

	/* avoid trying this connection if dead */
	if (!tc->conn)
		return false;

	return sa_cmp(&tc->srv, arg, SA_ALL);
}


static bool tcpconn_fail_handler(struct le *le, void *arg)
{
	struct dns_query *q = le->data;
	int err = *((int *)arg);

	list_unlink(&q->le_tc);
	q->tc = mem_deref(q->tc);

	if (q->ntx >= *q->srvc) {
		DEBUG_WARNING("all servers failed, giving up!!\n");
		err = err ? err : ECONNREFUSED;
		goto out;
	}

	/* try next server(s) */
	err = send_tcp(q);
	if (err) {
		DEBUG_WARNING("all servers failed, giving up\n");
		goto out;
	}

 out:
	if (err) {
		query_handler(q, err, NULL, NULL, NULL);
		mem_deref(q);
	}

	return false;
}


static void tcpconn_close(struct tcpconn *tc, int err)
{
	if (!tc)
		return;

	/* avoid trying this connection again (e.g. same address) */
	tc->conn = mem_deref(tc->conn);
	(void)list_apply(&tc->ql, true, tcpconn_fail_handler, &err);
	mem_deref(tc);
}


static void tcpconn_destructor(void *arg)
{
	struct tcpconn *tc = arg;

	hash_unlink(&tc->le);
	tmr_cancel(&tc->tmr);
	mem_deref(tc->conn);
	mem_deref(tc->mb);
}


static int tcpconn_alloc(struct tcpconn **tcpp, struct dnsc *dnsc,
			 const struct sa *srv)
{
	struct tcpconn *tc;
	int err = ENOMEM;

	if (!tcpp || !dnsc || !srv)
		return EINVAL;

	tc = mem_zalloc(sizeof(struct tcpconn), tcpconn_destructor);
	if (!tc)
		goto out;

	hash_append(dnsc->ht_tcpconn, sa_hash(srv, SA_ALL), &tc->le, tc);
	tc->srv = *srv;
	tc->dnsc = dnsc;

	tc->mb = mbuf_alloc(1500);
	if (!tc->mb)
		goto out;

	err = tcp_connect(&tc->conn, srv, tcp_estab_handler,
			  tcp_recv_handler, tcp_close_handler, tc);
	if (err)
		goto out;

	tmr_start(&tc->tmr, tc->dnsc->conf.conn_timeout,
		  tcpconn_timeout_handler, tc);
 out:
	if (err)
		mem_deref(tc);
	else
		*tcpp = tc;

	return err;
}


static int send_tcp(struct dns_query *q)
{
	const struct sa *srv;
	struct tcpconn *tc;
	int err = 0;

	if (!q)
		return EINVAL;

	while (q->ntx < *q->srvc) {

		srv = &q->srvv[q->ntx++];

		DEBUG_NOTICE("trying tcp server#%u: %J\n", q->ntx-1, srv);

		tc = list_ledata(hash_lookup(q->dnsc->ht_tcpconn,
					     sa_hash(srv, SA_ALL),
					     tcpconn_cmp_handler,
					     (void *)srv));
		if (!tc) {
			err = tcpconn_alloc(&tc, q->dnsc, srv);
			if (err)
				continue;
		}

		if (tc->connected) {
			q->mb.pos = 0;
			err = tcp_send(tc->conn, &q->mb);
			if (err) {
				tcpconn_close(tc, err);
				continue;
			}

			tmr_start(&tc->tmr, tc->dnsc->conf.idle_timeout,
				  tcpconn_timeout_handler, tc);
			DEBUG_NOTICE("tcp send %J\n", srv);
		}

		list_append(&tc->ql, &q->le_tc, q);
		q->tc = mem_ref(tc);
		break;
	}

	return err;
}


static void tcp_timeout_handler(void *arg)
{
	struct dns_query *q = arg;

	query_handler(q, ETIMEDOUT, NULL, NULL, NULL);
	mem_deref(q);
}


static int send_udp(struct dns_query *q)
{
	const struct sa *srv;
	int err = ETIMEDOUT;
	uint32_t i;

	if (!q)
		return EINVAL;

	for (i=0; i<*q->srvc; i++) {

		struct udp_sock *us;

		srv = &q->srvv[q->ntx++%*q->srvc];

		DEBUG_INFO("trying udp server#%u: %J\n", i, srv);

		switch (sa_af(srv)) {

		case AF_INET:
			us = q->dnsc->us;
			break;

		case AF_INET6:
			us = q->dnsc->us6;
			break;

		default:
			continue;
		}

		q->mb.pos = 0;
		err = udp_send(us, srv, &q->mb);
		if (!err)
			break;
	}

	return err;
}


static void udp_timeout_handler(void *arg)
{
	struct dns_query *q = arg;
	int err = ETIMEDOUT;

	if (q->ntx >= NTX_MAX * *q->srvc)
		goto out;

	err = send_udp(q);
	if (err)
		goto out;

	int timeout = 500 << MIN(2, (q->ntx - 1) / *q->srvc);

	DEBUG_INFO("waiting udp timeout: %dms\n", timeout);
	tmr_start(&q->tmr, timeout, udp_timeout_handler, q);

 out:
	if (err) {
		query_handler(q, err, NULL, NULL, NULL);
		mem_deref(q);
	}
}


static void hdl_tmr_cache(void *arg)
{
	struct list *l = arg;
	struct le *le;

	LIST_FOREACH(l, le) {
		struct dns_query *q = le->data;
#if DEBUG_LEVEL > 5
		struct le *re_rr;
		DEBUG_INFO("--- ANSWER SECTION (CACHED) id: %d ---\n",
			   q->id);
		LIST_FOREACH(q->rrlv[0], re_rr) {
			struct dnsrr *rr = re_rr->data;
			DEBUG_INFO("%H\n", dns_rr_print, rr);
		}
#endif
		query_handler(q, 0, q->rrlv[0], q->rrlv[1], q->rrlv[2]);
	}
	list_flush(l);
}


static bool query_cache_handler(struct dns_query *q)
{
	struct dnsquery dq;
	const struct dns_query *qc = NULL;
	struct le *le;

	dq.hdr	    = q->hdr;
	dq.type	    = q->type;
	dq.dnsclass = q->dnsclass;
	dq.name	    = q->name;
	dq.cache    = true;

	qc = list_ledata(hash_lookup(q->dnsc->ht_query_cache,
				     hash_joaat_str_ci(q->name),
				     query_cmp_handler, &dq));
	if (!qc)
		return false;


	for (int i = 0; i < RRLV_MAX; i++) {
		LIST_FOREACH(qc->rrlv[i], le)
		{
			struct dnsrr *rr = le->data;
			mem_ref(rr);
		}
		q->rrlv[i] = mem_ref(qc->rrlv[i]);
	}

	hash_unlink(&q->le);
	list_append(&q->dnsc->hdl_cache, &q->le_hdl, q);

	tmr_start(&q->dnsc->hdl_tmr, 0, hdl_tmr_cache, &q->dnsc->hdl_cache);

	return true;
}


static bool getaddr_dup(struct le *le, void *arg)
{
	struct dnsrr *r1 = list_ledata(le);
	struct dnsrr *r2 = arg;

	if (r1->type == DNS_TYPE_A && r2->type == DNS_TYPE_A) {
		if (r1->rdata.a.addr == r2->rdata.a.addr)
			return true;
	}

	if (r1->type == DNS_TYPE_AAAA && r2->type == DNS_TYPE_AAAA) {
		if (r1->rdata.aaaa.addr == r2->rdata.aaaa.addr)
			return true;
	}

	return false;
}


static int async_getaddrinfo(void *arg)
{
	struct dnsquery *dq = arg;
	int err;
	struct addrinfo *res0 = NULL;
	struct addrinfo *res;
	struct addrinfo hints;
	struct sa sa;

	memset(&hints, 0, sizeof(hints));

	if (dq->type == DNS_TYPE_A)
		hints.ai_family = AF_INET;
	if (dq->type == DNS_TYPE_AAAA)
		hints.ai_family = AF_INET6;
	hints.ai_flags = AI_ADDRCONFIG;

	err = getaddrinfo(dq->name, NULL, &hints, &res0);
	if (err)
		return EADDRNOTAVAIL;

	for (res = res0; res; res = res->ai_next) {
		struct dnsrr *rr = dns_rr_alloc();
		struct le *le;

		if (!rr) {
			err = ENOMEM;
			goto out;
		}

		str_dup(&rr->name, dq->name);

		rr->dnsclass = DNS_CLASS_IN;
		rr->ttl	     = GETADDRINFO_TTL;

		err = sa_set_sa(&sa, res->ai_addr);
		if (err) {
			mem_deref(rr);
			continue;
		}

		if (sa_af(&sa) == AF_INET) {
			rr->type	 = DNS_TYPE_A;
			rr->rdlen	 = 4;
			rr->rdata.a.addr = sa_in(&sa);
		}

		if (sa_af(&sa) == AF_INET6) {
			rr->type  = DNS_TYPE_AAAA;
			rr->rdlen = 16;
			sa_in6(&sa, rr->rdata.aaaa.addr);
		}

		le = list_apply(dq->rrlv, false, getaddr_dup, rr);
		if (le) {
			mem_deref(rr);
			continue;
		}

		list_append(dq->rrlv, &rr->le_priv, rr);
	}

out:
	if (err)
		list_flush(dq->rrlv);

	freeaddrinfo(res0);

	return err;
}


static void getaddrinfo_h(int err, void *arg)
{
	struct dnsquery *dq = arg;
	struct dns_query *q;

	q = list_ledata(hash_lookup(dq->dnsc->ht_query,
				    hash_joaat_str_ci(dq->name),
				    query_cmp_handler, dq));
	if (!q) {
		DEBUG_WARNING("getaddrinfo_h: no query found\n");
		list_flush(dq->rrlv);
		mem_deref(dq->rrlv);
		goto out;
	}

	mem_deref(q->rrlv[0]);
	q->rrlv[0] = dq->rrlv;

	const bool cache = q->dnsc->conf.cache_ttl_max > 0;

	DEBUG_INFO("--- ANSWER SECTION (getaddrinfo) id: %d %s ---\n", q->id,
		   cache ? "(caching)" : "");

	if (err) {
		DEBUG_INFO("getaddrinfo_h: err %m\n", err);
	}
	else {
		struct le *le;
		LIST_FOREACH(q->rrlv[0], le)
		{
			DEBUG_INFO("%H%s\n", dns_rr_print, le->data);
		}
	}

	query_handler(q, err, q->rrlv[0], q->rrlv[1], q->rrlv[2]);

	if (err || !cache) {
		mem_deref(q);
		goto out;
	}

	hash_append(q->dnsc->ht_query_cache, hash_joaat_str_ci(q->name),
		    &q->le, q);
	tmr_start(&q->tmr_ttl, GETADDRINFO_TTL * 1000, ttl_timeout_handler, q);

out:
	mem_deref(dq);
}


static void dq_deref(void *arg)
{
	struct dnsquery *dq = arg;

	mem_deref(dq->dnsc);
	mem_deref(dq->name);
}


static int query_getaddrinfo(struct dns_query *q)
{
	int err;

	struct dnsquery *dq = mem_zalloc(sizeof(struct dnsquery), dq_deref);
	if (!dq)
		return ENOMEM;

	err = str_dup(&dq->name, q->name);
	if (err)
		goto out;

	dq->type       = q->type;
	dq->hdr.id     = q->id;
	dq->hdr.opcode = q->opcode;
	dq->dnsclass   = q->dnsclass;
	dq->dnsc       = mem_ref(q->dnsc);

	dq->rrlv = mem_alloc(sizeof(struct list), NULL);
	if (!dq->rrlv) {
		err = ENOMEM;
		goto out;
	}

	list_init(dq->rrlv);

	err = re_thread_async(async_getaddrinfo, getaddrinfo_h, dq);
	if (err)
		DEBUG_WARNING("re_thread_async: %m\n", err);

out:
	if (err)
		mem_deref(dq);

	return err;
}


static int query(struct dns_query **qp, struct dnsc *dnsc, uint8_t opcode,
		 const char *name, uint16_t type, uint16_t dnsclass,
		 const struct dnsrr *ans_rr, int proto,
		 const struct sa *srvv, const uint32_t *srvc,
		 bool aa, bool rd, dns_query_h *qh, void *arg)
{
	struct dns_query *q = NULL;
	struct dnshdr hdr;
	int err = 0;
	bool use_getaddrinfo = false;
	bool srv_available = srvv && srvc && *srvc != 0;

	if (!dnsc || !name)
		return EINVAL;

	use_getaddrinfo = dnsc->conf.getaddrinfo &&
		(type == DNS_TYPE_A || type == DNS_TYPE_AAAA);

	if (!srv_available && !use_getaddrinfo)
		return ENOTSUP;

	if (DNS_QTYPE_AXFR == type)
		proto = IPPROTO_TCP;

	q = mem_zalloc(sizeof(*q), query_destructor);
	if (!q)
		goto nmerr;

	hash_append(dnsc->ht_query, hash_joaat_str_ci(name), &q->le, q);
	tmr_init(&q->tmr);
	tmr_init(&q->tmr_ttl);
	mbuf_init(&q->mb);

	err = str_dup(&q->name, name);
	if (err)
		goto error;

	q->srvv = srvv;
	q->srvc = srvc;
	q->id   = rand_u16();
	q->type = type;
	q->opcode = opcode;
	q->dnsclass = dnsclass;
	q->dnsc = dnsc;

	memset(&hdr, 0, sizeof(hdr));

	hdr.id = q->id;
	hdr.opcode = q->opcode;
	hdr.aa = aa;
	hdr.rd = rd;
	hdr.nq = 1;
	hdr.nans = ans_rr ? 1 : 0;

	q->qh  = qh;
	q->arg = arg;
	q->hdr = hdr;

	DEBUG_INFO("--- QUESTION SECTION id: %d ---\n", q->id);
	DEBUG_INFO("%s.\t%s\t%s\n", q->name, dns_rr_classname(q->dnsclass),
		   dns_rr_typename(q->type));

	if (query_cache_handler(q))
		goto out;

	for (int i = 0; i < RRLV_MAX; i++) {
		q->rrlv[i] = mem_alloc(sizeof(struct list), NULL);
		if (!q->rrlv[i])
			goto nmerr;
		list_init(q->rrlv[i]);
	}

	if (use_getaddrinfo) {
		err = query_getaddrinfo(q);
		if (err)
			goto error;

		goto out;
	}

	if (proto == IPPROTO_TCP)
		q->mb.pos += 2;

	err = dns_hdr_encode(&q->mb, &hdr);
	if (err)
		goto error;

	err = dns_dname_encode(&q->mb, name, NULL, 0, false);
	if (err)
		goto error;

	err |= mbuf_write_u16(&q->mb, htons(type));
	err |= mbuf_write_u16(&q->mb, htons(dnsclass));
	if (err)
		goto error;

	if (ans_rr) {
		err = dns_rr_encode(&q->mb, ans_rr, 0, NULL, 0);
		if (err)
			goto error;
	}

	switch (proto) {

	case IPPROTO_TCP:
		q->mb.pos = 0;
		(void)mbuf_write_u16(&q->mb, htons((uint16_t)q->mb.end - 2));

		err = send_tcp(q);
		if (err)
			goto error;

		tmr_start(&q->tmr, 60 * 1000, tcp_timeout_handler, q);
		break;

	case IPPROTO_UDP:
		err = send_udp(q);
		if (err)
			goto error;

		tmr_start(&q->tmr, 500, udp_timeout_handler, q);
		break;

	default:
		err = EPROTONOSUPPORT;
		goto error;
	}

out:
	if (qp) {
		q->qp = qp;
		*qp = q;
	}

	return 0;

 nmerr:
	err = ENOMEM;
 error:
	mem_deref(q);

	return err;
}


/**
 * Query a DNS name
 *
 * @param qp       Pointer to allocated DNS query
 * @param dnsc     DNS Client
 * @param name     DNS name
 * @param type     DNS Resource Record type
 * @param dnsclass DNS Class
 * @param rd       Recursion Desired (RD) flag
 * @param qh       Query handler
 * @param arg      Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int dnsc_query(struct dns_query **qp, struct dnsc *dnsc, const char *name,
	       uint16_t type, uint16_t dnsclass,
	       bool rd, dns_query_h *qh, void *arg)
{
	if (!dnsc)
		return EINVAL;

	return query(qp, dnsc, DNS_OPCODE_QUERY, name, type, dnsclass, NULL,
		     IPPROTO_UDP, dnsc->srvv, &dnsc->srvc, false, rd, qh, arg);
}


/**
 * Query a DNS name SRV record
 *
 * @param qp       Pointer to allocated DNS query
 * @param dnsc     DNS Client
 * @param name     DNS name
 * @param type     DNS Resource Record type
 * @param dnsclass DNS Class
 * @param proto    Protocol
 * @param srvv     DNS Nameservers
 * @param srvc     Number of DNS nameservers
 * @param rd       Recursion Desired (RD) flag
 * @param qh       Query handler
 * @param arg      Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int dnsc_query_srv(struct dns_query **qp, struct dnsc *dnsc, const char *name,
		   uint16_t type, uint16_t dnsclass, int proto,
		   const struct sa *srvv, const uint32_t *srvc,
		   bool rd, dns_query_h *qh, void *arg)
{
	return query(qp, dnsc, DNS_OPCODE_QUERY, name, type, dnsclass,
		     NULL, proto, srvv, srvc, false, rd, qh, arg);
}


/**
 * Send a DNS query with NOTIFY opcode
 *
 * @param qp       Pointer to allocated DNS query
 * @param dnsc     DNS Client
 * @param name     DNS name
 * @param type     DNS Resource Record type
 * @param dnsclass DNS Class
 * @param ans_rr   Answer Resource Record
 * @param proto    Protocol
 * @param srvv     DNS Nameservers
 * @param srvc     Number of DNS nameservers
 * @param qh       Query handler
 * @param arg      Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int dnsc_notify(struct dns_query **qp, struct dnsc *dnsc, const char *name,
		uint16_t type, uint16_t dnsclass, const struct dnsrr *ans_rr,
		int proto, const struct sa *srvv, const uint32_t *srvc,
		dns_query_h *qh, void *arg)
{
	return query(qp, dnsc, DNS_OPCODE_NOTIFY, name, type, dnsclass,
		     ans_rr, proto, srvv, srvc, true, false, qh, arg);
}


static void dnsc_destructor(void *data)
{
	struct dnsc *dnsc = data;

	list_flush(&dnsc->hdl_cache);

	(void)hash_apply(dnsc->ht_query, query_close_handler, NULL);
	hash_flush(dnsc->ht_tcpconn);
	hash_flush(dnsc->ht_query_cache);
	tmr_cancel(&dnsc->hdl_tmr);

	mem_deref(dnsc->ht_tcpconn);
	mem_deref(dnsc->ht_query);
	mem_deref(dnsc->ht_query_cache);
	mem_deref(dnsc->us6);
	mem_deref(dnsc->us);
}


/**
 * Allocate a DNS Client
 *
 * @param dcpp Pointer to allocated DNS Client
 * @param conf Optional DNS configuration, NULL for default
 * @param srvv DNS servers
 * @param srvc Number of DNS Servers
 *
 * @return 0 if success, otherwise errorcode
 */
int dnsc_alloc(struct dnsc **dcpp, const struct dnsc_conf *conf,
	       const struct sa *srvv, uint32_t srvc)
{
	struct dnsc *dnsc;
	struct sa laddr;
	struct sa laddr6;
	int err;

	if (!dcpp)
		return EINVAL;

	dnsc = mem_zalloc(sizeof(*dnsc), dnsc_destructor);
	if (!dnsc)
		return ENOMEM;

	if (conf)
		dnsc->conf = *conf;
	else
		dnsc->conf = default_conf;

	err = dnsc_srv_set(dnsc, srvv, srvc);
	if (err)
		goto out;

	sa_set_str(&laddr, "0.0.0.0", 0);
	err  = udp_listen(&dnsc->us, &laddr, udp_recv_handler, dnsc);

	sa_set_str(&laddr6, "::", 0);
	err &= udp_listen(&dnsc->us6, &laddr6, udp_recv_handler, dnsc);

	if (err)
		goto out;

	err = hash_alloc(&dnsc->ht_query, dnsc->conf.query_hash_size);
	if (err)
		goto out;

	err = hash_alloc(&dnsc->ht_query_cache, dnsc->conf.query_hash_size);
	if (err)
		goto out;

	err = hash_alloc(&dnsc->ht_tcpconn, dnsc->conf.tcp_hash_size);
	if (err)
		goto out;

	tmr_init(&dnsc->hdl_tmr);
	list_init(&dnsc->hdl_cache);

 out:
	if (err)
		mem_deref(dnsc);
	else
		*dcpp = dnsc;

	return err;
}


void  dnsc_conf_set_timeout(struct dnsc *dnsc, uint32_t connect, uint32_t idle)
{
	if (!dnsc)
		return;

	dnsc->conf.conn_timeout = connect;
	dnsc->conf.idle_timeout = idle;
}


int dnsc_conf_set(struct dnsc *dnsc, const struct dnsc_conf *conf)
{
	int err;
	if (!dnsc)
		return EINVAL;

	if (conf)
		dnsc->conf = *conf;
	else
		dnsc->conf = default_conf;

	list_flush(&dnsc->hdl_cache);

	hash_flush(dnsc->ht_tcpconn);
	hash_flush(dnsc->ht_query_cache);

	dnsc->ht_query = mem_deref(dnsc->ht_query);
	dnsc->ht_query_cache = mem_deref(dnsc->ht_query_cache);
	dnsc->ht_tcpconn = mem_deref(dnsc->ht_tcpconn);

	err = hash_alloc(&dnsc->ht_query, dnsc->conf.query_hash_size);
	if (err)
		return err;

	err = hash_alloc(&dnsc->ht_query_cache, dnsc->conf.query_hash_size);
	if (err)
		return err;

	err = hash_alloc(&dnsc->ht_tcpconn, dnsc->conf.tcp_hash_size);
	return err;
}


/**
 * Set the DNS Servers on a DNS Client
 *
 * @param dnsc DNS Client
 * @param srvv DNS Nameservers
 * @param srvc Number of nameservers
 *
 * @return 0 if success, otherwise errorcode
 */
int dnsc_srv_set(struct dnsc *dnsc, const struct sa *srvv, uint32_t srvc)
{
	uint32_t i;

	if (!dnsc)
		return EINVAL;

	dnsc->srvc = min((uint32_t)RE_ARRAY_SIZE(dnsc->srvv), srvc);

	if (srvv) {
		for (i=0; i<dnsc->srvc; i++)
			dnsc->srvv[i] = srvv[i];
	}

	return 0;
}


/**
 * Flush DNS cache
 *
 * @param dnsc DNS Client
 */
void dnsc_cache_flush(struct dnsc *dnsc)
{
	if (!dnsc)
		return;

	hash_flush(dnsc->ht_query_cache);
}


/**
 * Set max. Cache TTL
 *
 * @param dnsc  DNS Client
 * @param max   Value in [s] and 0 to disable caching
 */
void dnsc_cache_max(struct dnsc *dnsc, uint32_t max)
{
	if (!dnsc)
		return;

	dnsc->conf.cache_ttl_max = max;

	if (!max)
		dnsc_cache_flush(dnsc);
}


/**
 * Enable/Disable getaddrinfo usage
 *
 * @param dnsc   DNS Client
 * @param active true for enabled, otherwise disabled (default)
 */
void dnsc_getaddrinfo(struct dnsc *dnsc, bool active)
{
	if (!dnsc)
		return;

	dnsc->conf.getaddrinfo = active;
}


/**
 * Return if getaddrinfo usage is enabled
 *
 * @param dnsc  DNS Client
 *
 * @return true if getaddrinfo is used, false otherwise
 */
bool dnsc_getaddrinfo_enabled(struct dnsc *dnsc)
{
	if (!dnsc)
		return false;

	return dnsc->conf.getaddrinfo;
}


/**
 * Return if getaddrinfo usage is enabled and exclusive,
 * i.e. there are no DNS servers known explicitly
 *
 * @param dnsc  DNS Client
 *
 * @return true if DNS servers are available, false otherwise
 */
bool dnsc_getaddrinfo_only(const struct dnsc *dnsc)
{
	if (!dnsc)
		return false;

	return dnsc->conf.getaddrinfo && dnsc->srvc == 0;
}
