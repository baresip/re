/**
 * @file update.c  SIP Session UPDATE (RFC 3311)
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


static int update_request(struct sipsess_request *req);


static void tmr_handler(void *arg)
{
	struct sipsess_request *req = arg;
	int err;

	err = update_request(req);
	if (err)
		mem_deref(req);
}


static void update_resp_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct sipsess_request *req = arg;
	const struct sip_hdr *hdr;

	if (!msg || err || sip_request_loops(&req->ls, msg->scode))
		goto out;

	if (msg->scode < 200) {
		return;
	}
	else if (msg->scode < 300) {
		(void)sip_dialog_update(req->sess->dlg, msg);

		if (req->sess->neg_state == SDP_NEG_LOCAL_OFFER) {
			(void)req->sess->answerh(msg, req->sess->arg);
			req->sess->neg_state = SDP_NEG_DONE;
		}
	}
	else {
		if (req->sess->terminated)
			goto out;

		req->sess->neg_state = SDP_NEG_DONE;

		switch (msg->scode) {

		case 401:
		case 407:
			err = sip_auth_authenticate(req->sess->auth, msg);
			if (err) {
				err = (err == EAUTH) ? 0 : err;
				break;
			}

			err = update_request(req);
			if (err)
				break;

			return;

		case 408:
		case 481:
			sipsess_terminate(req->sess, 0, msg);
			break;
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
		else
			req->resph(err, msg, req->arg);
	}

	mem_deref(req);
}


static int send_handler(enum sip_transp tp, struct sa *src,
			const struct sa *dst, struct mbuf *mb,
			struct mbuf **contp, void *arg)
{
	struct sip_contact contact;
	struct sipsess_request *req = arg;
	(void)dst;
	(void)contp;

	sip_contact_set(&contact, req->sess->cuser, src, tp);

	return mbuf_printf(mb, "%H", sip_contact_print, &contact);
}


static int update_request(struct sipsess_request *req)
{
	int err;

	if (!req || req->tmr.th)
		return -1;

	err = sip_drequestf(&req->req, req->sess->sip, true, "UPDATE",
			    req->sess->dlg, 0, req->sess->auth, send_handler,
			    update_resp_handler, req,
			    "%s%s%s"
			    "Content-Length: %zu\r\n"
			    "\r\n"
			    "%b",
			    req->body ? "Content-Type: " : "",
			    req->body ? req->ctype : "",
			    req->body ? "\r\n" : "",
			    req->body ? mbuf_get_left(req->body) :(size_t)0,
			    req->body ? mbuf_buf(req->body) : NULL,
			    req->body ? mbuf_get_left(req->body):(size_t)0);

	if (!err && req->sess->desc)
		req->sess->neg_state = SDP_NEG_LOCAL_OFFER;

	return err;
}


/**
 * Send UPDATE request (RFC 3311)
 *
 * @param sess      SIP Session
 *
 * @return 0 if success, otherwise errorcode
 */
int sipsess_update(struct sipsess *sess)
{
	struct sipsess_request *req;
	int err;

	if (!sess || sess->terminated || !sess->ctype || !sess->desc)
		return EINVAL;

	err = sipsess_request_alloc(&req, sess, sess->ctype, sess->desc, NULL,
				    NULL);
	if (err)
		return err;

	err = update_request(req);
	if (err) {
		mem_deref(req);
		return err;
	}

	sess->modify_pending = false;

	return err;
}
