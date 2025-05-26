/**
 * @file sipsess/reply.c  SIP Session Reply
 *
 * Copyright (C) 2010 Creytiv.com
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
#include <re_sys.h>
#include "sipsess.h"


struct sipsess_reply {
	struct le le;
	struct tmr tmr;
	struct tmr tmrg;
	const struct sip_msg *msg;
	struct mbuf *mb;
	struct sipsess *sess;
	bool awaiting_prack;
	uint16_t scode;
	uint32_t seq;
	uint32_t rel_seq;
	uint32_t txc;
};


static void destructor(void *arg)
{
	struct sipsess_reply *reply = arg;

	list_unlink(&reply->le);
	tmr_cancel(&reply->tmr);
	tmr_cancel(&reply->tmrg);
	mem_deref((void *)reply->msg);
	mem_deref(reply->mb);
}


static void tmr_handler(void *arg)
{
	struct sipsess_reply *reply = arg;
	struct sipsess *sess = reply->sess;

	/* we want to send bye */

	if (!sess->terminated) {
		if (reply->scode < 200 && !sess->established) {
			(void)sip_reply(sess->sip, reply->msg, 504,
					"Timeout");
		}
		else {
			sess->established = true;
			mem_deref(reply);
			sipsess_terminate(sess, ETIMEDOUT, NULL);
			return;
		}
	}
	else {
		mem_deref(reply);
		mem_deref(sess);
		return;
	}

	mem_deref(reply);
}


static void retransmit_handler(void *arg)
{
	struct sipsess_reply *reply = arg;
	uint32_t delay;

	(void)sip_send(reply->sess->sip, reply->msg->sock, reply->msg->tp,
		       &reply->msg->src, reply->mb);

	reply->txc++;

	delay = !reply->rel_seq ?
		MIN(SIP_T1 << reply->txc, SIP_T2) : SIP_T1 << reply->txc;

	tmr_start(&reply->tmrg, delay, retransmit_handler, reply);
}


static bool cancel_1xx_timers(struct le *le, void *arg)
{
	struct sipsess_reply *reply = le->data;
	(void)arg;

	if (reply->scode > 100 && reply->scode < 200) {
		tmr_cancel(&reply->tmr);
		tmr_cancel(&reply->tmrg);
	}

	return false;
}


int sipsess_reply_2xx(struct sipsess *sess, const struct sip_msg *msg,
		      uint16_t scode, const char *reason, struct mbuf *desc,
		      const char *fmt, va_list *ap)
{
	struct sipsess_reply *reply = NULL;
	struct sip_contact contact;
	int err = ENOMEM;
	bool sdp = mbuf_get_left(msg->mb) > 0;
	bool non_invite = !pl_strcmp(&msg->met, "PRACK")
			  || !pl_strcmp(&msg->met, "UPDATE");

	if (!non_invite) {
		if (sess->neg_state == SDP_NEG_NONE && !mbuf_get_left(desc))
			return EINVAL;
		else if (sess->neg_state == SDP_NEG_DONE)
			desc = NULL;

		if (sess->prack_waiting_cnt > 0)
			return EAGAIN;

		reply = mem_zalloc(sizeof(*reply), destructor);
		if (!reply)
			goto out;

		list_append(&sess->replyl, &reply->le, reply);

		reply->seq  = msg->cseq.num;
		reply->msg  = mem_ref((void *)msg);
		reply->scode = scode;
		reply->sess = sess;
	}

	if (non_invite && sess->neg_state != SDP_NEG_REMOTE_OFFER)
		desc = NULL;

	sip_contact_set(&contact, sess->cuser, &msg->dst, msg->tp);
	err = sip_treplyf(non_invite ? NULL : &sess->st,
			  reply ? &reply->mb : NULL, sess->sip,
			  msg, true, scode, reason,
			  "%H"
			  "%v"
			  "%s%s%s"
			  "Content-Length: %zu\r\n"
			  "\r\n"
			  "%b",
			  sip_contact_print, &contact,
			  fmt, ap,
			  desc ? "Content-Type: " : "",
			  desc ? sess->ctype : "",
			  desc ? "\r\n" : "",
			  desc ? mbuf_get_left(desc) : (size_t)0,
			  desc ? mbuf_buf(desc) : NULL,
			  desc ? mbuf_get_left(desc) : (size_t)0);

	if (err)
		goto out;

	if (!non_invite)
		(void)list_ledata(list_apply(&sess->replyl, false,
				  cancel_1xx_timers, NULL));

	if (mbuf_get_left(desc)) {
		if (sdp)
			sess->neg_state = SDP_NEG_DONE;
		else if (!non_invite)
			sess->neg_state = SDP_NEG_LOCAL_OFFER;
	}

	if (reply) {
		tmr_start(&reply->tmr, 64 * SIP_T1, tmr_handler, reply);
		tmr_start(&reply->tmrg, SIP_T1, retransmit_handler, reply);
	}

 out:
	if (err) {
		if (!non_invite)
			sess->st = mem_deref(sess->st);

		mem_deref(reply);
	}

	return err;
}


int sipsess_reply_1xx(struct sipsess *sess, const struct sip_msg *msg,
		      uint16_t scode, const char *reason,
		      enum rel100_mode rel100, struct mbuf *desc,
		      const char *fmt, va_list *ap)
{
	struct sipsess_reply *reply;
	struct sip_contact contact;
	char rseq_header[64];
	bool reliably;
	enum rel100_mode rel100_peer = REL100_DISABLED;
	struct pl require_header = pl_null;
	int err = ENOMEM;

	if (sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE, "100rel"))
		rel100_peer = REL100_REQUIRED;
	else if (sip_msg_hdr_has_value(msg, SIP_HDR_SUPPORTED, "100rel"))
		rel100_peer = REL100_ENABLED;

	if (rel100 == REL100_REQUIRED && !rel100_peer) {
		(void)sip_treplyf(&sess->st, NULL, sess->sip, msg, false,
				  421, "Extension required",
				  "Require: 100rel\r\n"
				  "Content-Length: 0\r\n\r\n");
		return EPROTO;
	}
	else if (rel100_peer == REL100_REQUIRED && !rel100) {
		(void)sip_treplyf(&sess->st, NULL, sess->sip, msg, false, 420,
				  "Bad Extension", "Unsupported: 100rel\r\n"
				  "Content-Length: 0\r\n\r\n");
		return EPROTO;
	}

	reliably = rel100 && rel100_peer && scode != 100;

	if (reliably && sess->prack_waiting_cnt)
		return EAGAIN;

	if (sess->neg_state == SDP_NEG_NONE) {
		if (reliably && !mbuf_get_left(desc))
			return EINVAL;
		else if (!reliably)
			desc = NULL;
	}
	else if (sess->neg_state == SDP_NEG_DONE
		 || sess->neg_state == SDP_NEG_LOCAL_OFFER) {
		desc = NULL;
	}

	if (rel100 != REL100_REQUIRED && reliably) {
		pl_set_str(&require_header, "Require: 100rel\r\n");
	}

	reply = mem_zalloc(sizeof(*reply), destructor);
	if (!reply)
		goto out;

	list_append(&sess->replyl, &reply->le, reply);
	reply->seq  = msg->cseq.num;
	reply->msg  = mem_ref((void *)msg);
	reply->sess = sess;
	reply->scode = scode;

	sip_contact_set(&contact, sess->cuser, &msg->dst, msg->tp);
	if (reliably) {
		sess->rel_seq = sess->rel_seq ? sess->rel_seq+1 : rand_u16();
		reply->rel_seq = sess->rel_seq;
		re_snprintf(rseq_header, sizeof(rseq_header),
					"%d", reply->rel_seq);
	}

	err = sip_treplyf(&sess->st, &reply->mb, sess->sip,
			  msg, true, scode, reason,
			  "%H"
			  "%v"
			  "%s%s%s%s%s%s%s"
			  "Content-Length: %zu\r\n"
			  "\r\n"
			  "%b",
			  sip_contact_print, &contact,
			  fmt, ap,
			  require_header.p ? require_header.p : "",
			  reliably ? "RSeq: " : "",
			  reliably ? rseq_header : "",
			  reliably ? "\r\n" : "",
			  desc ? "Content-Type: " : "",
			  desc ? sess->ctype : "",
			  desc ? "\r\n" : "",
			  desc ? mbuf_get_left(desc) : (size_t)0,
			  desc ? mbuf_buf(desc) : NULL,
			  desc ? mbuf_get_left(desc) : (size_t)0);

	if (err)
		goto out;

	if (reliably) {
		tmr_start(&reply->tmr, 64 * SIP_T1, tmr_handler, reply);
		tmr_start(&reply->tmrg, SIP_T1, retransmit_handler, reply);

		reply->awaiting_prack = true;
		++sess->prack_waiting_cnt;
		if (desc) {
			sess->neg_state = mbuf_get_left(msg->mb) ?
				SDP_NEG_DONE : SDP_NEG_LOCAL_OFFER;
		}
	}
	else {
		if (desc && sess->neg_state == SDP_NEG_REMOTE_OFFER)
			sess->neg_state = SDP_NEG_PREVIEW_ANSWER;

		mem_deref(reply);
	}

 out:
	if (err) {
		sess->st = mem_deref(sess->st);
		mem_deref(reply);
	}

	return err;
}


static bool cmp_handler_prack(struct le *le, void *arg)
{
	struct sipsess_reply *reply = le->data;
	const struct sip_msg *msg = arg;

	return msg->rack.cseq == reply->seq &&
			msg->rack.rel_seq == reply->rel_seq &&
			!pl_cmp(&msg->rack.met, &reply->msg->met);
}


static bool cmp_handler(struct le *le, void *arg)
{
	struct sipsess_reply *reply = le->data;
	const struct sip_msg *msg = arg;

	return msg->cseq.num == reply->seq;
}


int sipsess_reply_prack(struct sipsess *sess, const struct sip_msg *msg,
			bool *awaiting_prack)
{
	struct sipsess_reply *reply;

	reply = list_ledata(list_apply(&sess->replyl, false, cmp_handler_prack,
				       (void *)msg));
	if (!reply)
		return ENOENT;

	*awaiting_prack = reply->awaiting_prack;

	mem_deref(reply);

	return 0;
}


int sipsess_reply_ack(struct sipsess *sess, const struct sip_msg *msg)
{
	struct sipsess_reply *reply;

	reply = list_ledata(list_apply(&sess->replyl, false, cmp_handler,
				       (void *)msg));
	if (!reply)
		return ENOENT;

	mem_deref(reply);

	return 0;
}
