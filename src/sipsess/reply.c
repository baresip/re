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
	bool awaiting_answer;
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

	mem_deref(reply);

	/* wait for all pending ACKs */
	if (sess->replyl.head)
		return;

	/* we want to send bye */
	sess->established = true;

	if (!sess->terminated)
		sipsess_terminate(sess, ETIMEDOUT, NULL);
	else
		mem_deref(sess);
}


static void retransmit_handler(void *arg)
{
	struct sipsess_reply *reply = arg;

	(void)sip_send(reply->sess->sip, reply->msg->sock, reply->msg->tp,
		       &reply->msg->src, reply->mb);

	reply->txc++;
	tmr_start(&reply->tmrg, MIN(SIP_T1<<reply->txc, SIP_T2),
		  retransmit_handler, reply);
}


int sipsess_reply_2xx(struct sipsess *sess, const struct sip_msg *msg,
		      uint16_t scode, const char *reason, struct mbuf *desc,
		      const char *fmt, va_list *ap)
{
	struct sipsess_reply *reply;
	struct sip_contact contact;
	int err = ENOMEM;

	reply = mem_zalloc(sizeof(*reply), destructor);
	if (!reply)
		goto out;

	list_append(&sess->replyl, &reply->le, reply);
	reply->seq  = msg->cseq.num;
	reply->msg  = mem_ref((void *)msg);
	reply->sess = sess;

	sip_contact_set(&contact, sess->cuser, &msg->dst, msg->tp);

	err = sip_treplyf(&sess->st, &reply->mb, sess->sip,
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

	if (pl_strcmp(&msg->met, "PRACK")) {
		tmr_start(&reply->tmr, 64 * SIP_T1, tmr_handler, reply);
		tmr_start(&reply->tmrg, SIP_T1, retransmit_handler, reply);
	}
	else {
		mem_deref(reply);
	}

	if (!mbuf_get_left(msg->mb) && desc) {
		reply->awaiting_answer = true;
		sess->awaiting_answer = true;
	}

 out:
	if (err) {
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
	bool rel100_peer_sup;
	bool rel100_peer_req;
	bool send_reliably;
	struct pl require_header;
	int err = ENOMEM;

	rel100_peer_sup = sip_msg_hdr_has_value(msg,
						SIP_HDR_SUPPORTED, "100rel");
	rel100_peer_req = sip_msg_hdr_has_value(msg,
						SIP_HDR_REQUIRE, "100rel");

	if (rel100 == REL100_REQUIRED
	    && !(rel100_peer_sup || rel100_peer_req)) {
		(void)sip_treplyf(&sess->st, NULL, sess->sip, msg, false,
				  421, "Extension required",
				  "Require: 100rel\r\n"
				  "Content-Length: 0\r\n\r\n");
		return -1;
	}
	else if (rel100_peer_req && !rel100) {
		(void)sip_treplyf(&sess->st, NULL, sess->sip, msg, false, 420,
				  "Bad Extension", "Unsupported: 100rel\r\n"
				  "Content-Length: 0\r\n\r\n");
		return -1;
	}
	if (rel100 != REL100_REQUIRED && rel100_peer_req) {
		pl_set_str(&require_header, "Require: 100rel\r\n");
	}
	else {
		require_header.p = NULL;
	}

	send_reliably = rel100 == REL100_REQUIRED || rel100_peer_req;

	reply = mem_zalloc(sizeof(*reply), destructor);
	if (!reply)
		goto out;

	list_append(&sess->replyl, &reply->le, reply);
	reply->seq  = msg->cseq.num;
	reply->msg  = mem_ref((void *)msg);
	reply->sess = sess;

	sip_contact_set(&contact, sess->cuser, &msg->dst, msg->tp);

	if (send_reliably) {
		reply->rel_seq = rand_u16();
		re_snprintf(rseq_header, sizeof(rseq_header), "%d",
			    reply->rel_seq);
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
			  send_reliably ? "RSeq: " : "",
			  send_reliably ? rseq_header : "",
			  send_reliably ? "\n" : "",
			  desc ? "Content-Type: " : "",
			  desc ? sess->ctype : "",
			  desc ? "\r\n" : "",
			  desc ? mbuf_get_left(desc) : (size_t)0,
			  desc ? mbuf_buf(desc) : NULL,
			  desc ? mbuf_get_left(desc) : (size_t)0);

	if (err)
		goto out;

	if (send_reliably) {
		tmr_start(&reply->tmr, 64 * SIP_T1, tmr_handler, reply);
		tmr_start(&reply->tmrg, SIP_T1, retransmit_handler, reply);
	}
	else {
		mem_deref(reply);
	}

	if (!mbuf_get_left(msg->mb) && desc) {
		reply->awaiting_answer = true;
		sess->awaiting_answer = true;
	}

 out:
	if (err) {
		sess->st = mem_deref(sess->st);
		mem_deref(reply);
	}

	return err;
}


static bool cmp_handler(struct le *le, void *arg)
{
	struct sipsess_reply *reply = le->data;
	const struct sip_msg *msg = arg;

	if (!pl_strcmp(&msg->met, "PRACK")) {
		return msg->rack.cseq == reply->seq &&
				msg->rack.rel_seq == reply->rel_seq &&
				!pl_cmp(&msg->rack.met, &reply->msg->met);
	}
	return msg->cseq.num == reply->seq;
}


int sipsess_reply_ack(struct sipsess *sess, const struct sip_msg *msg,
		      bool *awaiting_answer)
{
	struct sipsess_reply *reply;

	reply = list_ledata(list_apply(&sess->replyl, false, cmp_handler,
				       (void *)msg));
	if (!reply)
		return ENOENT;

	*awaiting_answer = reply->awaiting_answer;

	mem_deref(reply);

	return 0;
}

int sipsess_reply_prack(struct sipsess *sess, const struct sip_msg *msg,
		      bool *awaiting_answer)
{
	struct sipsess_reply *reply;

	reply = list_ledata(list_apply(&sess->replyl, false, cmp_handler,
				       (void *)msg));
	if (!reply)
		return ENOENT;

	*awaiting_answer = reply->awaiting_answer;
	(void)sipsess_reply_2xx(sess, msg, 200, "OK", NULL,
					NULL, NULL);

	mem_deref(reply);

	return 0;
}
