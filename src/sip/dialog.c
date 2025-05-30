/**
 * @file dialog.c  SIP Dialog
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
#include <re_msg.h>
#include <re_sip.h>
#include "sip.h"


enum {
	ROUTE_OFFSET = 7,
};

struct sip_dialog {
	struct uri route;
	struct mbuf *mb;
	char *callid;
	char *ltag;
	char *rtag;
	char *uri;
	uint32_t hash;
	uint32_t lseq;
	uint32_t rseq;
	uint32_t lseqinv;
	size_t cpos;
	size_t rpos;
	enum sip_transp tp;
	uint32_t srcport;
};


struct route_enc {
	struct mbuf *mb;
	size_t end;
};


static void destructor(void *arg)
{
	struct sip_dialog *dlg = arg;

	mem_deref(dlg->callid);
	mem_deref(dlg->ltag);
	mem_deref(dlg->rtag);
	mem_deref(dlg->uri);
	mem_deref(dlg->mb);
}


/**
 * Allocate a SIP Dialog
 *
 * @param dlgp      Pointer to allocated SIP Dialog
 * @param uri       Target URI
 * @param to_uri    To URI
 * @param from_name From displayname (optional)
 * @param from_uri  From URI
 * @param routev    Route vector
 * @param routec    Route count
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_dialog_alloc(struct sip_dialog **dlgp,
		     const char *uri, const char *to_uri,
		     const char *from_name, const char *from_uri,
		     const char *routev[], uint32_t routec)
{
	const uint64_t ltag = rand_u64();
	struct sip_dialog *dlg;
	struct sip_addr addr;
	size_t rend = 0;
	struct pl pl;
	uint32_t i;
	int err;

	if (!dlgp || !uri || !to_uri || !from_uri)
		return EINVAL;

	dlg = mem_zalloc(sizeof(*dlg), destructor);
	if (!dlg)
		return ENOMEM;

	dlg->hash = hash_fast_str(from_uri);
	dlg->lseq = rand_u16();
	dlg->tp   = SIP_TRANSP_NONE;

	err = str_dup(&dlg->uri, uri);
	if (err)
		goto out;

	err = str_x64dup(&dlg->callid, rand_u64());
	if (err)
		goto out;

	err = str_x64dup(&dlg->ltag, ltag);
	if (err)
		goto out;

	dlg->mb = mbuf_alloc(512);
	if (!dlg->mb) {
		err = ENOMEM;
		goto out;
	}

	for (i=0; i<routec; i++) {
		err |= mbuf_printf(dlg->mb, "Route: <%s;lr>\r\n", routev[i]);
		if (i == 0)
			rend = dlg->mb->pos - 2;
	}
	dlg->rpos = dlg->mb->pos;
	err |= mbuf_printf(dlg->mb, "To: <%s>\r\n", to_uri);
	dlg->cpos = dlg->mb->pos;
	err |= mbuf_printf(dlg->mb, "From: %s%s%s<%s>;tag=%016llx\r\n",
			   from_name ? "\"" : "", from_name,
			   from_name ? "\" " : "",
			   from_uri, ltag);
	if (err)
		goto out;

	dlg->mb->pos = 0;

	if (rend) {
		pl.p = (const char *)mbuf_buf(dlg->mb) + ROUTE_OFFSET;
		pl.l = rend - ROUTE_OFFSET;
		err = sip_addr_decode(&addr, &pl);
		dlg->route = addr.uri;
	}
	else {
		pl_set_str(&pl, dlg->uri);
		err = uri_decode(&dlg->route, &pl);
	}

 out:
	if (err)
		mem_deref(dlg);
	else
		*dlgp = dlg;

	return err;
}


static bool record_route_handler(const struct sip_hdr *hdr,
				 const struct sip_msg *msg,
				 void *arg)
{
	struct route_enc *renc = arg;
	(void)msg;

	if (mbuf_printf(renc->mb, "Route: %r\r\n", &hdr->val))
		return true;

	if (!renc->end)
	        renc->end = renc->mb->pos - 2;

	return false;
}


/**
 * Accept and create a SIP Dialog from an incoming SIP Message
 *
 * @param dlgp Pointer to allocated SIP Dialog
 * @param msg  SIP Message
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_dialog_accept(struct sip_dialog **dlgp, const struct sip_msg *msg)
{
	const struct sip_hdr *contact;
	struct sip_dialog *dlg;
	struct route_enc renc;
	struct sip_addr addr;
	struct pl pl;
	int err;

	if (!dlgp || !msg || !msg->req)
		return EINVAL;

	contact = sip_msg_hdr(msg, SIP_HDR_CONTACT);

	if (!contact || !msg->callid.p)
		return EBADMSG;

	if (sip_addr_decode(&addr, &contact->val))
		return EBADMSG;

	dlg = mem_zalloc(sizeof(*dlg), destructor);
	if (!dlg)
		return ENOMEM;

	dlg->hash = rand_u32();
	dlg->lseq = rand_u16();
	dlg->rseq = msg->cseq.num;
	dlg->tp   = msg->tp;

	err = pl_strdup(&dlg->uri, &addr.auri);
	if (err)
		goto out;

	err = pl_strdup(&dlg->callid, &msg->callid);
	if (err)
		goto out;

	err = str_x64dup(&dlg->ltag, msg->tag);
	if (err)
		goto out;

	err = pl_strdup(&dlg->rtag, &msg->from.tag);
	if (err)
		goto out;

	dlg->mb = mbuf_alloc(512);
	if (!dlg->mb) {
		err = ENOMEM;
		goto out;
	}

	renc.mb  = dlg->mb;
	renc.end = 0;

	err |= sip_msg_hdr_apply(msg, true, SIP_HDR_RECORD_ROUTE,
				 record_route_handler, &renc) ? ENOMEM : 0;
	dlg->rpos = dlg->mb->pos;
	err |= mbuf_printf(dlg->mb, "To: %r\r\n", &msg->from.val);
	dlg->cpos = dlg->mb->pos;
	err |= mbuf_printf(dlg->mb, "From: %r;tag=%016llx\r\n", &msg->to.val,
			   msg->tag);
	if (err)
		goto out;

	dlg->mb->pos = 0;

	if (renc.end) {
		pl.p = (const char *)mbuf_buf(dlg->mb) + ROUTE_OFFSET;
		pl.l = renc.end - ROUTE_OFFSET;
		err = sip_addr_decode(&addr, &pl);
		dlg->route = addr.uri;
	}
	else {
		pl_set_str(&pl, dlg->uri);
		err = uri_decode(&dlg->route, &pl);
	}

 out:
	if (err)
		mem_deref(dlg);
	else
		*dlgp = dlg;

	return err;
}


/**
 * Initialize a SIP Dialog from an incoming SIP Message
 *
 * @param dlg SIP Dialog to initialize
 * @param msg SIP Message
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_dialog_create(struct sip_dialog *dlg, const struct sip_msg *msg)
{
	char *uri = NULL, *rtag = NULL;
	const struct sip_hdr *contact;
	struct route_enc renc;
	struct sip_addr addr;
	struct pl pl;
	int err;

	if (!dlg || dlg->rtag || !dlg->cpos || !msg)
		return EINVAL;

	contact = sip_msg_hdr(msg, SIP_HDR_CONTACT);

	if (!contact)
		return EBADMSG;

	if (sip_addr_decode(&addr, &contact->val))
		return EBADMSG;

	renc.mb = mbuf_alloc(512);
	if (!renc.mb)
		return ENOMEM;

	err = pl_strdup(&uri, &addr.auri);
	if (err)
		goto out;

	err = pl_strdup(&rtag, msg->req ? &msg->from.tag : &msg->to.tag);
	if (err)
		goto out;

	renc.end = 0;

	err |= sip_msg_hdr_apply(msg, msg->req, SIP_HDR_RECORD_ROUTE,
				 record_route_handler, &renc) ? ENOMEM : 0;
	dlg->rpos = renc.mb->pos;
	err |= mbuf_printf(renc.mb, "To: %r\r\n",
			   msg->req ? &msg->from.val : &msg->to.val);

	dlg->mb->pos = dlg->cpos;
	dlg->cpos = renc.mb->pos;
	err |= mbuf_write_mem(renc.mb, mbuf_buf(dlg->mb),
			      mbuf_get_left(dlg->mb));
	dlg->mb->pos = 0;

	if (err)
		goto out;

	renc.mb->pos = 0;

	if (renc.end) {
		pl.p = (const char *)mbuf_buf(renc.mb) + ROUTE_OFFSET;
		pl.l = renc.end - ROUTE_OFFSET;
		err = sip_addr_decode(&addr, &pl);
		if (err)
			goto out;

		dlg->route = addr.uri;
	}
	else {
		struct uri tmp;

		pl_set_str(&pl, uri);
		err = uri_decode(&tmp, &pl);
		if (err)
			goto out;

		dlg->route = tmp;
	}

	mem_deref(dlg->mb);
	mem_deref(dlg->uri);

	dlg->mb   = mem_ref(renc.mb);
	dlg->rtag = mem_ref(rtag);
	dlg->uri  = mem_ref(uri);
	dlg->rseq = msg->req ? msg->cseq.num : 0;
	dlg->tp   = msg->tp;

 out:
	mem_deref(renc.mb);
	mem_deref(rtag);
	mem_deref(uri);

	return err;
}


/**
 * Fork a SIP Dialog from an incoming SIP Message
 *
 * @param dlgp Pointer to allocated SIP Dialog
 * @param odlg Original SIP Dialog
 * @param msg  SIP Message
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_dialog_fork(struct sip_dialog **dlgp, struct sip_dialog *odlg,
		    const struct sip_msg *msg)
{
	const struct sip_hdr *contact;
	struct sip_dialog *dlg;
	struct route_enc renc;
	struct sip_addr addr;
	struct pl pl;
	int err;

	if (!dlgp || !odlg || !odlg->cpos || !msg)
		return EINVAL;

	contact = sip_msg_hdr(msg, SIP_HDR_CONTACT);

	if (!contact || !msg->callid.p)
		return EBADMSG;

	if (sip_addr_decode(&addr, &contact->val))
		return EBADMSG;

	dlg = mem_zalloc(sizeof(*dlg), destructor);
	if (!dlg)
		return ENOMEM;

	dlg->callid  = mem_ref(odlg->callid);
	dlg->ltag    = mem_ref(odlg->ltag);
	dlg->hash    = odlg->hash;
	dlg->lseq    = odlg->lseq;
	dlg->lseqinv = odlg->lseqinv;
	dlg->rseq    = msg->req ? msg->cseq.num : 0;
	dlg->tp      = msg->tp;

	err = pl_strdup(&dlg->uri, &addr.auri);
	if (err)
		goto out;

	err = pl_strdup(&dlg->rtag, msg->req ? &msg->from.tag : &msg->to.tag);
	if (err)
		goto out;

	dlg->mb = mbuf_alloc(512);
	if (!dlg->mb) {
		err = ENOMEM;
		goto out;
	}

	renc.mb  = dlg->mb;
	renc.end = 0;

	err |= sip_msg_hdr_apply(msg, msg->req, SIP_HDR_RECORD_ROUTE,
				 record_route_handler, &renc) ? ENOMEM : 0;
	err |= mbuf_printf(dlg->mb, "To: %r\r\n",
			   msg->req ? &msg->from.val : &msg->to.val);

	odlg->mb->pos = odlg->cpos;
	err |= mbuf_write_mem(dlg->mb, mbuf_buf(odlg->mb),
			      mbuf_get_left(odlg->mb));
	odlg->mb->pos = 0;

	if (err)
		goto out;

	dlg->mb->pos = 0;

	if (renc.end) {
		pl.p = (const char *)mbuf_buf(dlg->mb) + ROUTE_OFFSET;
		pl.l = renc.end - ROUTE_OFFSET;
		err = sip_addr_decode(&addr, &pl);
		dlg->route = addr.uri;
	}
	else {
		pl_set_str(&pl, dlg->uri);
		err = uri_decode(&dlg->route, &pl);
	}

 out:
	if (err)
		mem_deref(dlg);
	else
		*dlgp = dlg;

	return err;
}


/**
 * Update an existing SIP Dialog from a SIP Message
 *
 * @param dlg SIP Dialog to update
 * @param msg SIP Message
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_dialog_update(struct sip_dialog *dlg, const struct sip_msg *msg)
{
	const struct sip_hdr *contact;
	struct sip_addr addr;
	struct mbuf *mb;
	struct pl pl;
	size_t cpos;
	char *uri;
	int err;

	if (!dlg || !msg)
		return EINVAL;

	contact = sip_msg_hdr(msg, SIP_HDR_CONTACT);
	if (!contact)
		return EBADMSG;

	if (sip_addr_decode(&addr, &contact->val))
		return EBADMSG;

	err = pl_strdup(&uri, &addr.auri);
	if (err)
		return err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = mbuf_write_mem(mb, mbuf_buf(dlg->mb), dlg->rpos);
	err |= mbuf_printf(mb, "To: %r\r\n",
		   msg->req ? &msg->from.val : &msg->to.val);
	cpos = mb->pos;
	err |= mbuf_write_mem(mb, mbuf_buf(dlg->mb) + dlg->cpos,
			      mbuf_get_left(dlg->mb) - dlg->cpos);

	if (err)
		goto out;

	dlg->cpos = cpos;
	mb->pos = 0;

	mem_deref(dlg->rtag);
	err = pl_strdup(&dlg->rtag, msg->req ? &msg->from.tag : &msg->to.tag);
	if (err)
		return err;

	mem_deref(dlg->mb);
	dlg->mb = mem_ref(mb);

	if (dlg->route.scheme.p == dlg->uri) {

		struct uri tmp;

		pl_set_str(&pl, uri);
		err = uri_decode(&tmp, &pl);
		if (err)
			goto out;

		dlg->route = tmp;
	}
	else {
		pl.p = (const char *)mbuf_buf(dlg->mb) + ROUTE_OFFSET;
		pl.l = dlg->rpos - ROUTE_OFFSET;
		err = sip_addr_decode(&addr, &pl);
		dlg->route = addr.uri;
	}

	mem_deref(dlg->uri);
	dlg->uri = mem_ref(uri);
 out:
	mem_deref(mb);
	mem_deref(uri);

	return err;
}


/**
 * Check if a remote sequence number is valid
 *
 * @param dlg SIP Dialog
 * @param msg SIP Message
 *
 * @return True if valid, False if invalid
 */
bool sip_dialog_rseq_valid(struct sip_dialog *dlg, const struct sip_msg *msg)
{
	if (!dlg || !msg || !msg->req)
		return false;

	if (msg->cseq.num < dlg->rseq)
		return false;

	dlg->rseq = msg->cseq.num;

	return true;
}


int sip_dialog_encode(struct mbuf *mb, struct sip_dialog *dlg, uint32_t cseq,
		      const char *met)
{
	int err = 0;

	if (!mb || !dlg || !met)
		return EINVAL;

	if (!strcmp(met, "INVITE"))
		dlg->lseqinv = dlg->lseq;

	err |= mbuf_write_mem(mb, mbuf_buf(dlg->mb), mbuf_get_left(dlg->mb));
	err |= mbuf_printf(mb, "Call-ID: %s\r\n", dlg->callid);
	err |= mbuf_printf(mb, "CSeq: %u %s\r\n", strcmp(met, "ACK") ?
			   dlg->lseq++ : cseq, met);

	return err;
}


const char *sip_dialog_uri(const struct sip_dialog *dlg)
{
	return dlg ? dlg->uri : NULL;
}


const char *sip_dialog_ltag(const struct sip_dialog *dlg)
{
	return dlg ? dlg->ltag : NULL;
}


const char *sip_dialog_rtag(const struct sip_dialog *dlg)
{
	return dlg ? dlg->rtag : NULL;
}


const struct uri *sip_dialog_route(const struct sip_dialog *dlg)
{
	return dlg ? &dlg->route : NULL;
}


uint32_t sip_dialog_hash(const struct sip_dialog *dlg)
{
	return dlg ? dlg->hash : 0;
}


/**
 * Get the Call-ID from a SIP Dialog
 *
 * @param dlg SIP Dialog
 *
 * @return Call-ID string
 */
const char *sip_dialog_callid(const struct sip_dialog *dlg)
{
	return dlg ? dlg->callid : NULL;
}


int sip_dialog_set_callid(struct sip_dialog *dlg, const char *callid)
{
	dlg->callid = mem_deref(dlg->callid);
	return str_dup(&dlg->callid, callid);
}


/**
 * Set TCP source port for a SIP Dialog
 *
 * @param dlg  SIP Dialog
 * @param srcport The TCP source port to be used
 */
void sip_dialog_set_srcport(struct sip_dialog *dlg, uint16_t srcport)
{
	if (!dlg)
		return;

	dlg->srcport = srcport;
}


/**
 * Get TCP source port for a SIP Dialog
 *
 * @param dlg  SIP Dialog
 *
 * @return TCP source port
 */
uint16_t sip_dialog_srcport(struct sip_dialog *dlg)
{
	if (!dlg)
		return 0;

	return dlg->srcport;
}


/**
 * Get the local sequence number from a SIP Dialog
 *
 * @param dlg SIP Dialog
 *
 * @return Local sequence number
 */
uint32_t sip_dialog_lseq(const struct sip_dialog *dlg)
{
	return dlg ? dlg->lseq : 0;
}


/**
 * Get the local sequence number of the last sent INVITE
 *
 * @param dlg SIP Dialog
 *
 * @return Local sequence number
 */
uint32_t sip_dialog_lseqinv(const struct sip_dialog *dlg)
{
	return dlg ? dlg->lseqinv : 0;
}


/**
 * Check if a SIP Dialog is established
 *
 * @param dlg SIP Dialog
 *
 * @return True if established, False if not
 */
bool sip_dialog_established(const struct sip_dialog *dlg)
{
	return dlg && dlg->rtag;
}


enum sip_transp sip_dialog_tp(const struct sip_dialog *dlg)
{
	return dlg ? dlg->tp : SIP_TRANSP_NONE;
}


/**
 * Compare a SIP Dialog against a SIP Message
 *
 * @param dlg SIP Dialog
 * @param msg SIP Message
 *
 * @return True if match, False if no match
 */
bool sip_dialog_cmp(const struct sip_dialog *dlg, const struct sip_msg *msg)
{
	if (!dlg || !msg)
		return false;

	if (pl_strcmp(&msg->callid, dlg->callid))
		return false;

	if (pl_strcmp(msg->req ? &msg->to.tag : &msg->from.tag, dlg->ltag))
		return false;

	if (pl_strcmp(msg->req ? &msg->from.tag : &msg->to.tag, dlg->rtag))
		return false;

	return true;
}


/**
 * Compare a half SIP Dialog against a SIP Message
 *
 * @param dlg SIP Dialog
 * @param msg SIP Message
 *
 * @return True if match, False if no match
 */
bool sip_dialog_cmp_half(const struct sip_dialog *dlg,
			 const struct sip_msg *msg)
{
	if (!dlg || !msg)
		return false;

	if (pl_strcmp(&msg->callid, dlg->callid))
		return false;

	if (pl_strcmp(msg->req ? &msg->to.tag : &msg->from.tag, dlg->ltag))
		return false;

	return true;
}
