/**
 * @file prack.c  SIP Session PRACK (RFC 3262)
 *
 * Copyright (C) 2022 commend.com - m.fridrich@commend.com
 */
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_fmt.h>
#include <re_uri.h>
#include <re_tmr.h>
#include <re_msg.h>
#include <re_sip.h>
#include <re_sipsess.h>
#include "sipsess.h"


struct sipsess_prack {
	uint32_t cseq;
	uint32_t rseq;
	char *met;
	struct sipsess_request *req;
};


static int prack_request(struct sipsess_prack *prack);


static void destructor(void *arg)
{
	struct sipsess_prack *prack = arg;

	mem_deref(prack->met);
	mem_deref(prack->req);
}


static void tmr_handler(void *arg)
{
	struct sipsess_prack *prack = arg;
	int err;

	if (!prack)
		return;

	err = prack_request(prack);
	if (err)
		mem_deref(prack);
}


static void prack_resp_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct sipsess_prack *prack = arg;
	struct sipsess_request *req = prack->req;
	const struct sip_hdr *hdr;

	if (!msg || err || sip_request_loops(&req->ls, msg->scode))
		goto out;

	if (msg->scode < 200) {
		return;
	}
	else if (msg->scode < 300) {
		(void)sip_dialog_update(req->sess->dlg, msg);

		if (mbuf_get_left(msg->mb)) {
			if (req->sess->neg_state == SDP_NEG_LOCAL_OFFER) {
				req->sess->neg_state = SDP_NEG_DONE;
				(void)req->sess->answerh(msg, req->sess->arg);
			}

			req->sess->desc = mem_deref(req->sess->desc);
		}
	}
	else {
		if (req->sess->terminated)
			goto out;

		switch (msg->scode) {

		case 401:
		case 407:
			err = sip_auth_authenticate(req->sess->auth, msg);
			if (err) {
				err = (err == EAUTH) ? 0 : err;
				break;
			}

			err = prack_request(prack);
			if (err)
				break;

			return;
		case 408:
		case 491:
			tmr_start(&req->tmr, req->sess->owner ? 3000 : 1000,
				  tmr_handler, req);
			return;
		case 500:
			hdr = sip_msg_hdr(msg, SIP_HDR_RETRY_AFTER);
			if (!hdr)
				break;

			tmr_start(&req->tmr, pl_u32(&hdr->val) * 1000,
				  tmr_handler, req);
			return;
		}
	}

out:
	if (!req->sess->terminated) {
		if (err == ETIMEDOUT)
			sipsess_terminate(req->sess, err, NULL);
	}

	mem_deref(prack);
}


static int prack_request(struct sipsess_prack *prack)
{
	struct sipsess_request *req = prack->req;
	char rack_header[256];
	int err;

	if (!req || req->tmr.th)
		return EINVAL;

	err = re_snprintf(rack_header, sizeof(rack_header), "%d %d %s",
			  prack->rseq, prack->cseq, prack->met);
	if (err == -1)
		return err;

	return sip_drequestf(&req->req, req->sess->sip, true, "PRACK",
			     req->sess->dlg, 0, req->sess->auth, NULL,
			     prack_resp_handler, prack,
			     "RAck: %s\n"
			     "%s%s%s"
			     "Content-Length: %zu\r\n"
			     "\r\n"
			     "%b",
			     rack_header,
			     req->body ? "Content-Type: " : "",
			     req->body ? req->sess->ctype : "",
			     req->body ? "\r\n" : "",
			     req->body ? mbuf_get_left(req->body) : (size_t)0,
			     req->body ? mbuf_buf(req->body) : NULL,
			     req->body ? mbuf_get_left(req->body) : (size_t)0);
}


/**
 * Send PRACK request (RFC 3262)
 *
 * @param sess      SIP Session
 * @param cseq      CSeq number to be written in RAck header
 * @param rseq      RSeq number to be written in RAck header
 * @param met       Method to be written in RAck header
 * @param desc      Content description (e.g. SDP)
 *
 * @return 0 if success, otherwise errorcode
 */
int sipsess_prack(struct sipsess *sess, uint32_t cseq, uint32_t rseq,
		  const struct pl *met, struct mbuf *desc)
{
	struct sipsess_prack *prack;
	int err;

	if (!sess || sess->terminated)
		return EINVAL;

	prack = mem_zalloc(sizeof(*prack), destructor);
	if (!prack)
		return ENOMEM;

	err = sipsess_request_alloc(&prack->req, sess, sess->ctype, desc,
				    NULL, prack);
	if (err)
		goto out;

	prack->cseq = cseq;
	prack->rseq = rseq;
	err = pl_strdup(&prack->met, met);
	if (err)
		goto out;

	err = prack_request(prack);

out:
	if (err)
		mem_deref(prack);

	return err;
}
