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
	struct le he;
	struct tmr tmr;
	struct sa dst;
	struct sip_request *req;
	struct sip_dialog *dlg;
	struct sipsess_sock *sock;
	struct mbuf *mb;
	enum sip_transp tp;
	uint32_t cseq;
};


static void destructor(void *arg)
{
	struct sipsess_prack *prack = arg;

	hash_unlink(&prack->he);
	tmr_cancel(&prack->tmr);
	mem_deref(prack->req);
	mem_deref(prack->dlg);
	mem_deref(prack->sock);
	mem_deref(prack->mb);
}


static void tmr_handler(void *arg)
{
	struct sipsess_prack *prack = arg;

	mem_deref(prack);
}


static int send_handler(enum sip_transp tp, struct sa *src,
			const struct sa *dst, struct mbuf *mb,
			struct mbuf **contp, void *arg)
{
	struct sipsess_prack *prack = arg;
	(void)src;
	(void)contp;

	mem_deref(prack->mb);
	prack->mb = mem_ref(mb);
	prack->dst = *dst;
	prack->tp  = tp;

	tmr_start(&prack->tmr, 64 * SIP_T1, tmr_handler, prack);
	return 0;
}


static void resp_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct sipsess *sess;
	struct sipsess_prack *prack = arg;
	if (err || !msg)
		goto out;

	sess = sipsess_find(prack->sock, msg);
	if (!sess)
		goto out;
	if (sess->prackh)
		sess->prackh(msg, sess->arg);

out:
	mem_deref(prack);
}


/**
 * Send PRACK message (RFC 3262)
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
	char rack_header[256];
	char method[64];
	int err;

	prack = mem_zalloc(sizeof(*prack), destructor);
	if (!prack)
		return ENOMEM;

	hash_append(sess->sock->ht_prack,
		    hash_joaat_str(sip_dialog_callid(sess->dlg)),
		    &prack->he, prack);

	prack->dlg  = mem_ref(sess->dlg);
	prack->sock  = mem_ref(sess->sock);
	prack->cseq = cseq;

	(void)pl_strcpy(met, method, sizeof(method));
	re_snprintf(rack_header, sizeof(rack_header), "%d %d %s", rseq, cseq,
		    method);

	err = sip_drequestf(&prack->req, sess->sock->sip, true, "PRACK",
			    sess->dlg, cseq, sess->auth, send_handler,
			    resp_handler, prack,
			    "RAck: %s\n"
			    "%s%s%s"
			    "Content-Length: %zu\r\n"
			    "\r\n"
			    "%b",
			    rack_header,
			    desc ? "Content-Type: " : "",
			    desc ? sess->ctype : "",
			    desc ? "\r\n" : "",
			    desc ? mbuf_get_left(desc) : (size_t)0,
			    desc ? mbuf_buf(desc) : NULL,
			    desc ? mbuf_get_left(desc) : (size_t)0);

	if (err)
		mem_deref(prack);

	return err;
}
