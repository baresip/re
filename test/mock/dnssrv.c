/**
 * @file mock/dnssrv.c Mock DNS server
 *
 * Copyright (C) 2010 - 2016 Alfred E. Heggestad
 */
#include <string.h>
#include <re.h>
#include "../test.h"


#define DEBUG_MODULE "mock/dnssrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define LOCAL_PORT 0


static void dns_server_match(struct dns_server *srv, struct list *rrl,
			     const char *name, uint16_t type)
{
	struct dnsrr *rr0 = NULL;
	struct le *le;

	le = srv->rrl.head;
	while (le) {

		struct dnsrr *rr = le->data;
		le		 = le->next;

		if (type == rr->type && 0 == str_casecmp(name, rr->name)) {

			if (!rr0)
				rr0 = rr;
			list_append(rrl, &rr->le_priv, rr);
		}
	}
}


static void decode_dns_query(struct dns_server *srv, const struct sa *src,
			     struct mbuf *mb, int proto)
{
	struct list rrl = LIST_INIT;
	struct dnshdr hdr;
	struct le *le;
	char *qname = NULL;
	size_t start, end;
	uint16_t type, dnsclass;
	int err = 0;

	start = mb->pos;
	end   = mb->end;

	if (dns_hdr_decode(mb, &hdr) || hdr.qr || hdr.nq != 1) {
		DEBUG_WARNING("unable to decode query header\n");
		return;
	}

	err = dns_dname_decode(mb, &qname, start);
	if (err) {
		DEBUG_WARNING("unable to decode query name\n");
		goto out;
	}

	if (mbuf_get_left(mb) < 4) {
		DEBUG_WARNING("unable to decode query type/class\n");
		goto out;
	}

	type	 = ntohs(mbuf_read_u16(mb));
	dnsclass = ntohs(mbuf_read_u16(mb));

	DEBUG_INFO("dnssrv: type=%s query-name='%s'\n", dns_rr_typename(type),
		   qname);

	if (dnsclass == DNS_CLASS_IN) {
		dns_server_match(srv, &rrl, qname, type);
	}

	hdr.qr	  = true;
	hdr.tc	  = false;
	hdr.rcode = DNS_RCODE_OK;
	hdr.nq	  = 1;
	hdr.nans  = list_count(&rrl);

	mb->pos = start;

	err = dns_hdr_encode(mb, &hdr);
	if (err)
		goto out;

	mb->pos = end;

	DEBUG_INFO("dnssrv: @@ found %u answers for %s\n", list_count(&rrl),
		   qname);

	for (le = rrl.head; le; le = le->next) {
		struct dnsrr *rr = le->data;

		err = dns_rr_encode(mb, rr, 0, NULL, start);
		if (err)
			goto out;
	}

	mb->pos = start;

	switch (proto) {

	case IPPROTO_UDP:
		(void)udp_send(srv->us, src, mb);
		break;

	case IPPROTO_TCP: {
		size_t length = mb->end - start;
		struct mbuf *mb_tcp = mbuf_alloc(sizeof(uint16_t) + length);
		if (!mb_tcp)
			goto out;

		mbuf_write_u16(mb_tcp, htons((uint16_t)length));
		mbuf_write_mem(mb_tcp, mbuf_buf(mb), length);
		mbuf_set_pos(mb_tcp, 0);

		tcp_send(srv->tc, mb_tcp);

		mem_deref(mb_tcp);
	}
		break;
	}

out:
	list_clear(&rrl);
	mem_deref(qname);
}


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct dns_server *srv = arg;

	decode_dns_query(srv, src, mb, IPPROTO_UDP);
}


static void destructor(void *arg)
{
	struct dns_server *srv = arg;

	list_flush(&srv->rrl);
	mem_deref(srv->us);
	mem_deref(srv->tc);
	mem_deref(srv->ts);
	mem_deref(srv->mb);
}


static void tcp_recv_handler(struct mbuf *mbrx, void *arg)
{
	struct dns_server *srv = arg;
	struct mbuf *mb = srv->mb;
	int err = 0;
	size_t n;

 next:
	/* frame length */
	if (!srv->flen) {

		n = min(2 - mb->end, mbuf_get_left(mbrx));

		err = mbuf_write_mem(mb, mbuf_buf(mbrx), n);
		if (err)
			goto error;

		mbrx->pos += n;

		if (mb->end < 2)
			return;

		mb->pos = 0;
		srv->flen = ntohs(mbuf_read_u16(mb));
		mb->pos = 0;
		mb->end = 0;
	}

	n = min(srv->flen - mb->end, mbuf_get_left(mbrx));

	err = mbuf_write_mem(mb, mbuf_buf(mbrx), n);
	if (err)
		goto error;

	mbrx->pos += n;

	if (mb->end < srv->flen)
		return;

	mb->pos = 0;

	decode_dns_query(srv, NULL, mb, IPPROTO_TCP);

	srv->flen = 0;
	mb->pos = 0;
	mb->end = 0;

	if (mbuf_get_left(mbrx) > 0) {
		DEBUG_INFO("%zu bytes of tcp data left\n",
			   mbuf_get_left(mbrx));
		goto next;
	}

	return;

 error:
	srv->tc = mem_deref(srv->tc);
}


static void tcp_close_handler(int err, void *arg)
{
	struct dns_server *srv = arg;
	(void)err;

	srv->tc = mem_deref(srv->tc);
	srv->mb = mem_deref(srv->mb);
	srv->flen = 0;
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct dns_server *srv = arg;
	int err = 0;
	(void)peer;

	/* max 1 TCP connection */
	TEST_ASSERT(srv->tc == NULL);

	srv->mb = mbuf_alloc(1500);
	if (!srv->mb) {
		err = ENOMEM;
		goto out;
	}

	err = tcp_accept(&srv->tc, srv->ts, NULL, tcp_recv_handler,
			 tcp_close_handler, srv);
	if (err)
		goto out;

 out:
	if (err) {
		tcp_reject(srv->ts);
		srv->mb = mem_deref(srv->mb);
		srv->flen = 0;
	}
}


void dns_server_flush(struct dns_server *srv)
{
	list_flush(&srv->rrl);
}


int dns_server_alloc(struct dns_server **srvp, const char *laddr)
{
	struct dns_server *srv;
	struct sa laddr_tcp;
	int err;

	if (!srvp)
		return EINVAL;

	sa_set_str(&laddr_tcp, laddr, 0);

	srv = mem_zalloc(sizeof(*srv), destructor);
	if (!srv)
		return ENOMEM;

	err = sa_set_str(&srv->addr, laddr, LOCAL_PORT);
	if (err)
		goto out;

	err = udp_listen(&srv->us, &srv->addr, udp_recv, srv);
	if (err)
		goto out;

	err = udp_local_get(srv->us, &srv->addr);
	if (err)
		goto out;

	err = tcp_listen(&srv->ts, &laddr_tcp, tcp_conn_handler, srv);
	if (err)
		goto out;

	err = tcp_local_get(srv->ts, &srv->addr_tcp);
	if (err)
		goto out;

out:
	if (err)
		mem_deref(srv);
	else
		*srvp = srv;

	return err;
}


int dns_server_add_a(struct dns_server *srv, const char *name, uint32_t addr,
		     int64_t ttl)
{
	struct dnsrr *rr;
	int err;

	if (!srv || !name)
		return EINVAL;

	rr = dns_rr_alloc();
	if (!rr)
		return ENOMEM;

	err = str_dup(&rr->name, name);
	if (err)
		goto out;

	rr->type     = DNS_TYPE_A;
	rr->dnsclass = DNS_CLASS_IN;
	rr->ttl	     = ttl;
	rr->rdlen    = 0;

	rr->rdata.a.addr = addr;

	list_append(&srv->rrl, &rr->le, rr);

out:
	if (err)
		mem_deref(rr);

	return err;
}


int dns_server_add_aaaa(struct dns_server *srv, const char *name,
			const uint8_t *addr)
{
	struct dnsrr *rr;
	int err;

	if (!srv || !name)
		return EINVAL;

	rr = dns_rr_alloc();
	if (!rr)
		return ENOMEM;

	err = str_dup(&rr->name, name);
	if (err)
		goto out;

	rr->type     = DNS_TYPE_AAAA;
	rr->dnsclass = DNS_CLASS_IN;
	rr->ttl	     = 3600;
	rr->rdlen    = 0;

	memcpy(rr->rdata.aaaa.addr, addr, 16);

	list_append(&srv->rrl, &rr->le, rr);

out:
	if (err)
		mem_deref(rr);

	return err;
}


int dns_server_add_srv(struct dns_server *srv, const char *name, uint16_t pri,
		       uint16_t weight, uint16_t port, const char *target)
{
	struct dnsrr *rr;
	int err;

	if (!srv || !name || !port || !target)
		return EINVAL;

	rr = dns_rr_alloc();
	if (!rr)
		return ENOMEM;

	err = str_dup(&rr->name, name);
	if (err)
		goto out;

	rr->type     = DNS_TYPE_SRV;
	rr->dnsclass = DNS_CLASS_IN;
	rr->ttl	     = 3600;
	rr->rdlen    = 0;

	rr->rdata.srv.pri    = pri;
	rr->rdata.srv.weight = weight;
	rr->rdata.srv.port   = port;
	str_dup(&rr->rdata.srv.target, target);

	list_append(&srv->rrl, &rr->le, rr);

out:
	if (err)
		mem_deref(rr);

	return err;
}
