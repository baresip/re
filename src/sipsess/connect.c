/**
 * @file connect.c  SIP Session Connect
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
#include <re_tmr.h>
#include <re_msg.h>
#include <re_sip.h>
#include <re_sipsess.h>
#include "sipsess.h"


static int invite(struct sipsess *sess);


static int send_handler(enum sip_transp tp, struct sa *src,
			const struct sa *dst, struct mbuf *mb,
			struct mbuf **contp, void *arg)
{
	struct sip_contact contact;
	struct sipsess *sess = arg;
	struct mbuf *desc = NULL;
	struct mbuf *cont = NULL;
	int err;

	if (sess->desch) {
		err = sess->desch(&desc, src, dst, sess->arg);
		if (err)
			return err;
	}

	sip_contact_set(&contact, sess->cuser, src, tp);
	err = mbuf_printf(mb, "%H", sip_contact_print, &contact);
	if (err)
		goto out;

	cont = mbuf_alloc(1024);
	if (!cont) {
		err = ENOMEM;
		goto out;
	}

	err |= mbuf_printf(cont,
			"%s%s%s"
			"Content-Length: %zu\r\n"
			"\r\n"
			"%b",
			desc ? "Content-Type: " : "",
			desc ? sess->ctype : "",
			desc ? "\r\n" : "",
			mbuf_get_left(desc),
			mbuf_buf(desc),
			mbuf_get_left(desc));
	cont->pos = 0;

	if (err)
		mem_deref(cont);
	else
		*contp = cont;

out:
	if (desc)
		sess->neg_state = SDP_NEG_LOCAL_OFFER;

	mem_deref(desc);
	return err;
}


static void invite_resp_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct sipsess *sess = arg;
	struct mbuf *desc = NULL;
	bool sdp;
	const struct sip_hdr *contact;
	struct sip_addr addr;
	char *uri;

	if (!sess)
		return;

	if (!msg || err || sip_request_loops(&sess->ls, msg->scode))
		goto out;

	if (!sip_dialog_cmp_half(sess->dlg, msg)
		|| sip_dialog_lseqinv(sess->dlg) != msg->cseq.num)
		goto out;

	sdp = mbuf_get_left(msg->mb) > 0;

	if (msg->scode < 200) {
		if (msg->scode == 100)
			return;

		contact = sip_msg_hdr(msg, SIP_HDR_CONTACT);
		if (pl_isset(&msg->to.tag) && contact) {
			err = sip_dialog_established(sess->dlg) ?
					sip_dialog_update(sess->dlg, msg) :
					sip_dialog_create(sess->dlg, msg);
			if (err)
				goto out;
		}

		if (sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE, "100rel")
				&& sess->rel100_supported) {

			if (sess->rel_seq && msg->rel_seq != (sess->rel_seq+1))
				return;

			sess->rel_seq = msg->rel_seq;
			if (sess->neg_state == SDP_NEG_NONE && !sdp)
				goto out;

			sess->progrh(msg, sess->arg);

			if (sdp) {
				if (sess->neg_state == SDP_NEG_LOCAL_OFFER) {
					sess->neg_state = SDP_NEG_DONE;
					err = sess->answerh(msg, sess->arg);
				}
				else if (sess->neg_state == SDP_NEG_NONE) {
					sess->neg_state = SDP_NEG_REMOTE_OFFER;
					err = sess->offerh(&desc, msg,
							   sess->arg);
				}
			}

			err |= sipsess_prack(sess, msg->cseq.num, msg->rel_seq,
					     &msg->cseq.met, desc);
			if (err)
				goto out;

			if (sess->neg_state == SDP_NEG_REMOTE_OFFER
			    && mbuf_get_left(desc))
				sess->neg_state = SDP_NEG_DONE;

			mem_deref(desc);
			sess->desc = mem_deref(sess->desc);
			return;
		}

		sess->progrh(msg, sess->arg);

		if (sdp && sess->neg_state == SDP_NEG_LOCAL_OFFER) {
			err = sess->answerh(msg, sess->arg);
			if (err)
				goto out;
		}
		return;
	}
	else if (msg->scode < 300) {

		sess->established = true;

		sess->hdrs = mem_deref(sess->hdrs);

		err = sip_dialog_established(sess->dlg) ?
				sip_dialog_update(sess->dlg, msg) :
				sip_dialog_create(sess->dlg, msg);

		if (sdp && !err) {
			if (sess->neg_state == SDP_NEG_LOCAL_OFFER) {
				sess->neg_state = SDP_NEG_DONE;
				err = sess->answerh(msg, sess->arg);
			}
			else if (sess->neg_state == SDP_NEG_NONE) {
				sess->neg_state = SDP_NEG_REMOTE_OFFER;
				err = sess->offerh(&desc, msg, sess->arg);
			}
		}

		err |= sipsess_ack(sess->sock, sess->dlg, msg->cseq.num,
				  sess->auth, sess->ctype, desc);
		if (err)
			goto out;

		if (sess->neg_state == SDP_NEG_NONE && !sdp)
			goto out;

		if (sess->neg_state == SDP_NEG_REMOTE_OFFER
		    && mbuf_get_left(desc))
			sess->neg_state = SDP_NEG_DONE;

		mem_deref(desc);

		if (err || sess->terminated)
			goto out;

		if (sess->modify_pending)
			(void)sipsess_reinvite(sess, true);
		else
			sess->desc = mem_deref(sess->desc);

		sess->estabh(msg, sess->arg);
		return;
	}
	else if (msg->scode < 400) {

		if (sess->terminated)
			goto out;

		if (sess->redirecth) {

			contact = sip_msg_hdr(msg, SIP_HDR_CONTACT);
			if (!contact) {
				err = EBADMSG;
				goto out;
			}
			if (sip_addr_decode(&addr, &contact->val)) {
				err = EBADMSG;
				goto out;
			}
			err = pl_strdup(&uri, &addr.auri);
			if (err)
				goto out;

			sess->redirecth(msg, uri, sess->arg);

			mem_deref(uri);
		}
		else {
			/* Redirect to first Contact */

			err = sip_dialog_update(sess->dlg, msg);
			if (err)
				goto out;

			err = invite(sess);
			if (err)
				goto out;

			return;
		}
	}
	else {
		if (sess->terminated)
			goto out;

		switch (msg->scode) {

		case 401:
		case 407:
			err = sip_auth_authenticate(sess->auth, msg);
			if (err) {
				err = (err == EAUTH) ? 0 : err;
				break;
			}

			err = invite(sess);
			if (err)
				break;

			return;
		}
	}

 out:
	if (!sess->terminated)
		sipsess_terminate(sess, err, msg);
	else
		mem_deref(sess);

}


static int invite(struct sipsess *sess)
{
	sess->modify_pending = false;

	return sip_drequestf(&sess->req, sess->sip, true, "INVITE",
			     sess->dlg, 0, sess->auth,
			     send_handler, invite_resp_handler, sess,
			     "%b",
			     sess->hdrs ? mbuf_buf(sess->hdrs) : NULL,
			     sess->hdrs ? mbuf_get_left(sess->hdrs) :(size_t)0
			     );
}


/**
 * Connect to a remote SIP useragent
 *
 * @param sessp     Pointer to allocated SIP Session
 * @param sock      SIP Session socket
 * @param to_uri    To SIP uri
 * @param from_name From display name
 * @param from_uri  From SIP uri
 * @param cuser     Contact username or URI
 * @param routev    Outbound route vector
 * @param routec    Outbound route vector count
 * @param ctype     Session content-type
 * @param authh     SIP Authentication handler
 * @param aarg      Authentication handler argument
 * @param aref      True to mem_ref() aarg
 * @param callid    Call Identifier
 * @param desch     Content description handler
 * @param offerh    Session offer handler
 * @param answerh   Session answer handler
 * @param progrh    Session progress handler
 * @param estabh    Session established handler
 * @param infoh     Session info handler
 * @param referh    Session refer handler
 * @param closeh    Session close handler
 * @param arg       Handler argument
 * @param fmt       Formatted strings with extra SIP Headers
 *
 * @return 0 if success, otherwise errorcode
 */
int sipsess_connect(struct sipsess **sessp, struct sipsess_sock *sock,
		    const char *to_uri, const char *from_name,
		    const char *from_uri, const char *cuser,
		    const char *routev[], uint32_t routec,
		    const char *ctype,
		    sip_auth_h *authh, void *aarg, bool aref,
		    const char *callid,
		    sipsess_desc_h *desch,
		    sipsess_offer_h *offerh, sipsess_answer_h *answerh,
		    sipsess_progr_h *progrh, sipsess_estab_h *estabh,
		    sipsess_info_h *infoh, sipsess_refer_h *referh,
		    sipsess_close_h *closeh, void *arg, const char *fmt, ...)
{
	struct sipsess *sess;
	struct pl hdrs;
	int err;

	if (!sessp || !sock || !to_uri || !from_uri || !cuser || !ctype)
		return EINVAL;

	err = sipsess_alloc(&sess, sock, cuser, ctype, NULL, authh, aarg, aref,
			    desch,
			    offerh, answerh, progrh, estabh, infoh, referh,
			    closeh, arg);
	if (err)
		return err;

	/* Custom SIP headers */
	if (fmt) {
		va_list ap;

		sess->hdrs = mbuf_alloc(256);
		if (!sess->hdrs) {
			err = ENOMEM;
			goto out;
		}

		va_start(ap, fmt);
		err = mbuf_vprintf(sess->hdrs, fmt, ap);
		sess->hdrs->pos = 0;
		va_end(ap);

		if (err)
			goto out;

		pl_set_mbuf(&hdrs, sess->hdrs);
	}

	sess->owner = true;
	sess->rel100_supported = fmt && !re_regex(hdrs.p, hdrs.l, "100rel");

	err = sip_dialog_alloc(&sess->dlg, to_uri, to_uri, from_name,
			       from_uri, routev, routec);
	if (err)
		goto out;

	if (str_isset(callid))
		err = sip_dialog_set_callid(sess->dlg, callid);

	if (err)
		goto out;

	hash_append(sock->ht_sess,
		    hash_joaat_str(sip_dialog_callid(sess->dlg)),
		    &sess->he, sess);

	err = invite(sess);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(sess);
	else
		*sessp = sess;

	return err;
}
