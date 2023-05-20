/**
 * @file pcp/request.c  PCP request
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sys.h>
#include <re_sa.h>
#include <re_tmr.h>
#include <re_udp.h>
#include <re_pcp.h>
#include "pcp.h"


/*
 * Defines a PCP client request
 *
 * the application must keep a reference to this object and the
 * object must be deleted by the application. the response handler
 * might be called multiple times.
 */
struct pcp_request {
	struct pcp_conf conf;
	struct sa srv;
	struct udp_sock *us;
	struct mbuf *mb;
	struct tmr tmr;
	struct tmr tmr_dur;
	struct tmr tmr_refresh;
	enum pcp_opcode opcode;
	union pcp_payload payload;
	uint32_t lifetime;
	bool granted;
	unsigned txc;
	double RT;
	pcp_resp_h *resph;
	void *arg;
};


/*
 * RT:   Retransmission timeout
 * IRT:  Initial retransmission time, SHOULD be 3 seconds
 * MRC:  Maximum retransmission count, SHOULD be 0 (no maximum)
 * MRT:  Maximum retransmission time, SHOULD be 1024 seconds
 * MRD:  Maximum retransmission duration, SHOULD be 0 (no maximum)
 * RAND: Randomization factor
 */
static const struct pcp_conf default_conf = {
	3,
	0,
	1024,
	0
};


static int start_sending(struct pcp_request *req);


/* random number between -0.1 and +0.1 */
static inline double RAND(void)
{
	return (1.0 * rand_u16() / 32768 - 1.0) / 10.0;
}

static double RT_init(const struct pcp_conf *conf)
{
	return (1.0 + RAND()) * conf->irt;
}

static double RT_next(const struct pcp_conf *conf, double RTprev)
{
	return (1.0 + RAND()) * min (2 * RTprev, conf->mrt);
}


static void destructor(void *arg)
{
	struct pcp_request *req = arg;

	/* Destroy the mapping if it was granted */
	if (req->granted && req->lifetime && req->mb) {

		/* set the lifetime to zero */
		req->mb->pos = 4;
		mbuf_write_u32(req->mb, 0);

		req->mb->pos = 0;
		(void)udp_send(req->us, &req->srv, req->mb);
	}

	tmr_cancel(&req->tmr);
	tmr_cancel(&req->tmr_dur);
	tmr_cancel(&req->tmr_refresh);
	mem_deref(req->us);
	mem_deref(req->mb);
}


static void completed(struct pcp_request *req, int err, struct pcp_msg *msg)
{
	pcp_resp_h *resph = req->resph;
	void *arg = req->arg;

	tmr_cancel(&req->tmr);
	tmr_cancel(&req->tmr_dur);

	/* if the request failed, we only called the
	   response handler once and never again */
	if (err || !msg || msg->hdr.result != PCP_SUCCESS ) {
		req->resph = NULL;
	}

	if (resph)
		resph(err, msg, arg);
}


static void refresh_timeout(void *arg)
{
	struct pcp_request *req = arg;

	/* todo: update request with new EXT-ADDR from server */
	(void)start_sending(req);
}


static void timeout(void *arg)
{
	struct pcp_request *req = arg;
	int err;

	req->txc++;

	if (req->conf.mrc > 0 && req->txc > req->conf.mrc) {
		completed(req, ETIMEDOUT, NULL);
		return;
	}

	req->mb->pos = 0;
	err = udp_send(req->us, &req->srv, req->mb);
	if (err) {
		completed(req, err, NULL);
		return;
	}

	req->RT = RT_next(&req->conf, req->RT);
	tmr_start(&req->tmr, (uint64_t)req->RT * 1000, timeout, req);
}


static void timeout_duration(void *arg)
{
	struct pcp_request *req = arg;

	completed(req, ETIMEDOUT, NULL);
}


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct pcp_request *req = arg;
	struct pcp_msg *msg;
	int err;

	if (!sa_cmp(src, &req->srv, SA_ALL))
		return;

	err = pcp_msg_decode(&msg, mb);
	if (err)
		return;

	if (!msg->hdr.resp) {
		(void)re_fprintf(stderr, "pcp: ignoring PCP request\n");
		goto out;
	}

	if (msg->hdr.opcode != req->opcode)
		goto out;

	/* compare opcode-specific data */

	switch (msg->hdr.opcode) {

	case PCP_MAP:
	case PCP_PEER:
		if (0 != memcmp(msg->pld.map.nonce, req->payload.map.nonce,
				PCP_NONCE_SZ)) {
			(void)re_fprintf(stderr, "ignoring unknown nonce\n");
			goto out;
		}
		req->payload.map.ext_addr = msg->pld.map.ext_addr;
		break;

	default:
		break;
	}

	req->lifetime = msg->hdr.lifetime;
	req->granted = (msg->hdr.result == PCP_SUCCESS);

	/* todo:
	 *
	 * Once a PCP client has successfully received a response from a PCP
	 * server on that interface, it resets RT to a value randomly selected
	 * in the range 1/2 to 5/8 of the mapping lifetime, as described in
	 * Section 11.2.1, "Renewing a Mapping", and sends subsequent PCP
	 * requests for that mapping to that same server.
	 */
	if (req->granted && req->lifetime) {

		uint32_t v = req->lifetime * 3/4;

		tmr_start(&req->tmr_refresh, v * 1000, refresh_timeout, req);
	}

	completed(req, 0, msg);

 out:
	mem_deref(msg);
}


static int start_sending(struct pcp_request *req)
{
	int err;

	req->txc = 1;

	req->mb->pos = 0;
	err = udp_send(req->us, &req->srv, req->mb);
	if (err)
		return err;

	req->RT = RT_init(&req->conf);
	tmr_start(&req->tmr, (uint64_t)req->RT * 1000, timeout, req);

	if (req->conf.mrd) {
		tmr_start(&req->tmr_dur, req->conf.mrd * 1000,
			  timeout_duration, req);
	}

	return 0;
}


static int pcp_vrequest(struct pcp_request **reqp, const struct pcp_conf *conf,
			const struct sa *srv, enum pcp_opcode opcode,
			uint32_t lifetime, const void *payload,
			pcp_resp_h *resph, void *arg,
			uint32_t optionc, va_list ap)
{
	const union pcp_payload *up = payload;
	struct pcp_request *req;
	struct sa laddr;
	int err;

	if (!reqp || !srv)
		return EINVAL;

	sa_init(&laddr, sa_af(srv));

	req = mem_zalloc(sizeof(*req), destructor);
	if (!req)
		return ENOMEM;

	req->conf   = conf ? *conf : default_conf;
	req->opcode = opcode;
	req->srv    = *srv;
	req->resph  = resph;
	req->arg    = arg;

	req->lifetime = lifetime;

	if (up)
		req->payload = *up;

	err = udp_listen(&req->us, &laddr, udp_recv, req);
	if (err)
		goto out;

	/*
	 * see RFC 6887 section 16.4
	 */
	err = udp_connect(req->us, srv);
	if (err)
		goto out;
	err = udp_local_get(req->us, &laddr);
	if (err)
		goto out;

	req->mb = mbuf_alloc(128);
	if (!req->mb) {
		err = ENOMEM;
		goto out;
	}

	err = pcp_msg_req_vencode(req->mb, opcode, lifetime,
				  &laddr, up, optionc, ap);
	if (err)
		goto out;

	err = start_sending(req);

 out:
	if (err)
		mem_deref(req);
	else
		*reqp = req;

	return err;
}


int pcp_request(struct pcp_request **reqp, const struct pcp_conf *conf,
		const struct sa *srv, enum pcp_opcode opcode,
		uint32_t lifetime, const void *payload,
		pcp_resp_h *resph, void *arg, uint32_t optionc, ...)
{
	va_list ap;
	int err;

	va_start(ap, optionc);
	err = pcp_vrequest(reqp, conf, srv, opcode, lifetime, payload,
			   resph, arg, optionc, ap);
	va_end(ap);

	return err;
}


void pcp_force_refresh(struct pcp_request *req)
{
	if (!req)
		return;

	tmr_cancel(&req->tmr);
	tmr_cancel(&req->tmr_dur);

	tmr_start(&req->tmr_refresh, rand_u16() % 2000, refresh_timeout, req);
}
