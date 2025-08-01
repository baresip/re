/**
 * @file reg.c  SIP Registration
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
#include <re_msg.h>
#include <re_sip.h>
#include <re_sipreg.h>


enum {
	DEFAULT_EXPIRES = 3600,
};


/** Defines a SIP Registration client */
struct sipreg {
	struct sip_loopstate ls;
	struct sa laddr;
	struct tmr tmr;
	struct sip *sip;
	struct sip_keepalive *ka;
	struct sip_request *req;
	struct sip_dialog *dlg;
	struct sip_auth *auth;
	struct mbuf *hdrs;
	char *cuser;
	char *cparams;
	sip_resp_h *resph;
	void *arg;
	uint32_t expires;
	uint32_t pexpires;
	uint32_t failc;
	uint32_t rwait;
	uint32_t wait;
	uint32_t fbregint;
	enum sip_transp tp;
	bool registered;
	bool terminated;
	char *params;
	int regid;
	uint16_t srcport;
};


static int request(struct sipreg *reg, bool reset_ls);


static void dummy_handler(int err, const struct sip_msg *msg, void *arg)
{
	(void)err;
	(void)msg;
	(void)arg;
}


static void destructor(void *arg)
{
	struct sipreg *reg = arg;

	tmr_cancel(&reg->tmr);

	if (!reg->terminated) {

		reg->resph = dummy_handler;
		reg->terminated = true;

		if (reg->req) {
			mem_ref(reg);
			return;
		}

		if (reg->registered && !request(reg, true)) {
			mem_ref(reg);
			return;
		}
	}

	mem_deref(reg->ka);
	mem_deref(reg->dlg);
	mem_deref(reg->auth);
	mem_deref(reg->cuser);
	mem_deref(reg->sip);
	mem_deref(reg->hdrs);
	mem_deref(reg->params);
	mem_deref(reg->cparams);
}


static uint32_t failwait(uint32_t failc)
{
	return min(1800, (30 * (1<<min(failc, 6)))) * (500 + rand_u16() % 501);
}


static void tmr_handler(void *arg)
{
	struct sipreg *reg = arg;
	int err;

	err = request(reg, true);
	if (err) {
		tmr_start(&reg->tmr, failwait(++reg->failc), tmr_handler, reg);
		reg->resph(err, NULL, reg->arg);
	}
}


static void keepalive_handler(int err, void *arg)
{
	struct sipreg *reg = arg;

	/* failure will be handled in response handler */
	if (reg->req || reg->terminated)
		return;

	tmr_start(&reg->tmr, failwait(++reg->failc), tmr_handler, reg);
	reg->resph(err, NULL, reg->arg);
}


static void start_outbound(struct sipreg *reg, const struct sip_msg *msg)
{
	const struct sip_hdr *flowtimer;

	if (!sip_msg_hdr_has_value(msg, SIP_HDR_REQUIRE, "outbound"))
		return;

	flowtimer = sip_msg_hdr(msg, SIP_HDR_FLOW_TIMER);

	(void)sip_keepalive_start(&reg->ka, reg->sip, msg,
				  flowtimer ? pl_u32(&flowtimer->val) : 0,
				  keepalive_handler, reg);
}


static bool contact_handler(const struct sip_hdr *hdr,
			    const struct sip_msg *msg, void *arg)
{
	struct sipreg *reg = arg;
	struct sip_addr c;
	struct pl transp = PL("transport");
	struct pl pval;
	struct sa host;
	enum sip_transp tp;
	int err;

	if (sip_addr_decode(&c, &hdr->val))
		return false;

	if (pl_strcmp(&c.uri.user, reg->cuser))
	    return false;

	err = sa_set(&host, &c.uri.host, c.uri.port);
	if (err)
		return false;

	if (!sa_cmp(&host, &reg->laddr, SA_ADDR))
		return false;

	err = uri_param_get(&c.auri, &transp, &pval);
	if (err)
		pl_set_str(&pval, "udp");

	tp = sip_transp_decode(&pval);
	if (tp != reg->tp)
		return false;

	if (!msg_param_decode(&c.params, "expires", &pval)) {
		reg->wait = pl_u32(&pval);
	}
	else if (pl_isset(&msg->expires))
		reg->wait = pl_u32(&msg->expires);
	else
		reg->wait = DEFAULT_EXPIRES;

	return true;
}


static void response_handler(int err, const struct sip_msg *msg, void *arg)
{
	const struct sip_hdr *minexp;
	struct sipreg *reg = arg;
	uint16_t last_scode = reg->ls.last_scode;

	reg->wait = failwait(reg->failc + 1);
	if (err || !msg || sip_request_loops(&reg->ls, msg->scode)) {
		reg->failc++;
		goto out;
	}

	if (msg->scode < 200) {
		return;
	}
	else if (msg->scode < 300) {
		reg->wait = reg->expires;
		sip_msg_hdr_apply(msg, true, SIP_HDR_CONTACT, contact_handler,
				  reg);
		reg->registered = reg->wait > 0;
		reg->pexpires = reg->wait;
		reg->wait *= reg->rwait * (1000 / 100);
		reg->failc = 0;

		if (reg->regid > 0 && !reg->terminated && !reg->ka)
			start_outbound(reg, msg);
		goto out;
	}

	if (reg->terminated && !reg->registered)
		goto out;

	switch (msg->scode) {

	case 401:
	case 407:
		if (reg->ls.failc > 1 && last_scode == msg->scode) {
			reg->failc++;
			goto out;
		}

		sip_auth_reset(reg->auth);
		err = sip_auth_authenticate(reg->auth, msg);
		if (err) {
			err = (err == EAUTH) ? 0 : err;
			break;
		}

		err = request(reg, false);
		if (err)
			break;

		return;

	case 403:
		sip_auth_reset(reg->auth);
		break;

	case 423:
		minexp = sip_msg_hdr(msg, SIP_HDR_MIN_EXPIRES);
		if (!minexp || !pl_u32(&minexp->val) || !reg->expires)
			break;

		reg->expires = pl_u32(&minexp->val);

		err = request(reg, false);
		if (err)
			break;

		return;
	}

	++reg->failc;

 out:
	if (!reg->expires) {
		if (msg && msg->scode >= 400 && msg->scode < 500)
			reg->fbregint = 0;

		if (reg->terminated) {
			mem_deref(reg);
			return;
		}

		if (reg->fbregint)
			tmr_start(&reg->tmr, reg->fbregint * 1000,
					  tmr_handler, reg);
		else
			tmr_cancel(&reg->tmr);

		reg->resph(err, msg, reg->arg);

	}
	else if (reg->terminated) {
		if (!reg->registered || request(reg, true))
			mem_deref(reg);
	}
	else {
		tmr_start(&reg->tmr, reg->wait, tmr_handler, reg);
		reg->resph(err, msg, reg->arg);
	}
}


static int send_handler(enum sip_transp tp, struct sa *src,
			const struct sa *dst, struct mbuf *mb,
			struct mbuf **contp, void *arg)
{
	struct sipreg *reg = arg;
	int err;

	(void)contp;
	(void)dst;

	reg->tp = tp;
	if (reg->srcport && tp != SIP_TRANSP_UDP)
		sa_set_port(src, reg->srcport);

	reg->laddr = *src;
	err = mbuf_printf(mb, "Contact: <sip:%s@%J%s%s%s>;expires=%u%s%s",
			  reg->cuser, &reg->laddr, sip_transp_param(reg->tp),
			  reg->cparams ? ";" : "",
			  reg->cparams ? reg->cparams : "",
			  reg->expires,
			  reg->params ? ";" : "",
			  reg->params ? reg->params : "");

	if (reg->regid > 0)
		err |= mbuf_printf(mb, ";reg-id=%d", reg->regid);

	err |= mbuf_printf(mb, "\r\n");
	return err;
}


static int request(struct sipreg *reg, bool reset_ls)
{
	if (reg->terminated)
		reg->expires = 0;

	if (reset_ls) {
		sip_loopstate_reset(&reg->ls);
	}

	return sip_drequestf(&reg->req, reg->sip, true, "REGISTER", reg->dlg,
			     0, reg->auth, send_handler, response_handler, reg,
			     "%s"
			     "%b"
			     "Content-Length: 0\r\n"
			     "\r\n",
			     reg->regid > 0
			     ? "Supported: gruu, outbound, path\r\n" : "",
			     reg->hdrs ? mbuf_buf(reg->hdrs) : NULL,
			     reg->hdrs ? mbuf_get_left(reg->hdrs) : (size_t)0);
}


static int vsipreg_alloc(struct sipreg **regp, struct sip *sip,
		    const char *reg_uri,
		    const char *to_uri, const char *from_name,
		    const char *from_uri, uint32_t expires,
		    const char *cuser, const char *routev[], uint32_t routec,
		    int regid, sip_auth_h *authh, void *aarg, bool aref,
		    sip_resp_h *resph, void *arg,
		    const char *params, const char *fmt, va_list ap)
{
	struct sipreg *reg;
	int err;

	if (!regp || !sip || !reg_uri || !to_uri || !from_uri || !cuser)
		return EINVAL;

	reg = mem_zalloc(sizeof(*reg), destructor);
	if (!reg)
		return ENOMEM;

	err = sip_dialog_alloc(&reg->dlg, reg_uri, to_uri, from_name, from_uri,
			       routev, routec);
	if (err)
		goto out;

	err = sip_auth_alloc(&reg->auth, authh, aarg, aref);
	if (err)
		goto out;

	err = str_dup(&reg->cuser, cuser);
	if (params)
		err |= str_dup(&reg->params, params);
	if (err)
		goto out;

	/* Custom SIP headers */
	if (fmt) {
		reg->hdrs = mbuf_alloc(256);
		if (!reg->hdrs) {
			err = ENOMEM;
			goto out;
		}

		err = mbuf_vprintf(reg->hdrs, fmt, ap);
		reg->hdrs->pos = 0;
		if (err)
			goto out;
	}

	reg->sip     = mem_ref(sip);
	reg->expires = expires;
	reg->rwait   = 90;
	reg->resph   = resph ? resph : dummy_handler;
	reg->arg     = arg;
	reg->regid   = regid;

 out:
	if (err)
		mem_deref(reg);
	else
		*regp = reg;

	return err;
}


int sipreg_send(struct sipreg *reg)
{
	if (!reg)
		return EINVAL;

	return request(reg, true);
}


/**
 * Unregisters SIP Registration client
 *
 * @param reg   SIP Registration client
 */
void sipreg_unregister(struct sipreg *reg)
{
	if (!reg)
		return;

	reg->expires = 0;

	(void)sipreg_send(reg);
}


/**
 * Allocate a SIP Registration client
 *
 * @param regp     Pointer to allocated SIP Registration client
 * @param sip      SIP Stack instance
 * @param reg_uri  SIP Request URI
 * @param to_uri   SIP To-header URI
 * @param from_name  SIP From-header display name (optional)
 * @param from_uri SIP From-header URI
 * @param expires  Registration expiry time in [seconds]
 * @param cuser    Contact username
 * @param routev   Optional route vector
 * @param routec   Number of routes
 * @param regid    Register identification
 * @param authh    Authentication handler
 * @param aarg     Authentication handler argument
 * @param aref     True to ref argument
 * @param resph    Response handler
 * @param arg      Response handler argument
 * @param params   Optional Contact-header parameters
 * @param fmt      Formatted strings with extra SIP Headers
 *
 * @return 0 if success, otherwise errorcode
 */
int sipreg_alloc(struct sipreg **regp, struct sip *sip, const char *reg_uri,
		    const char *to_uri, const char *from_name,
		    const char *from_uri, uint32_t expires,
		    const char *cuser, const char *routev[], uint32_t routec,
		    int regid, sip_auth_h *authh, void *aarg, bool aref,
		    sip_resp_h *resph, void *arg,
		    const char *params, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = vsipreg_alloc(regp, sip, reg_uri, to_uri, from_name,
			    from_uri, expires, cuser, routev, routec,
			    regid, authh, aarg, aref, resph, arg,
			    params, fmt, ap);
	va_end(ap);

	return err;
}


/**
 * Set the relative registration interval in percent from proxy expiry time. A
 * value from 5-95% is accepted.
 *
 * @param reg   SIP Registration client
 * @param rwait The relative registration interval in [%].
 *
 * @return 0 if success, otherwise errorcode
 */
int sipreg_set_rwait(struct sipreg *reg, uint32_t rwait)
{
	if (!reg || rwait < 5 || rwait > 95)
		return EINVAL;

	reg->rwait = rwait;
	return 0;
}


/**
 * Get the local socket address for a SIP Registration client
 *
 * @param reg SIP Registration client
 *
 * @return Local socket address
 */
const struct sa *sipreg_laddr(const struct sipreg *reg)
{
	return reg ? &reg->laddr : NULL;
}


/**
 * Get the proxy expires value of a SIP registration client
 *
 * @param reg SIP registration client
 *
 * @return the proxy expires value
 */
uint32_t sipreg_proxy_expires(const struct sipreg *reg)
{
	return reg ? reg->pexpires : 0;
}


bool sipreg_registered(const struct sipreg *reg)
{
	return reg ? reg->registered : false;
}


bool sipreg_failed(const struct sipreg *reg)
{
	return reg ? reg->failc > 0 : false;
}


void sipreg_incfailc(struct sipreg *reg)
{
	if (!reg)
		return;

	reg->failc++;
}


int sipreg_set_fbregint(struct sipreg *reg, uint32_t fbregint)
{
	if (!reg)
		return EINVAL;

	reg->fbregint = fbregint;
	return 0;
}


/**
 * Set TCP source port number for the SIP registration client
 *
 * @param reg      SIP registration client
 * @param srcport  TCP source port number
 */
void sipreg_set_srcport(struct sipreg *reg, uint16_t srcport)
{
	if (!reg || !reg->dlg)
		return;

	reg->srcport = srcport;

	sip_dialog_set_srcport(reg->dlg, srcport);
}


/**
 * Set contact URI optional parameters
 *
 * @param reg      SIP registration client
 * @param cparams  Contact URI optional parameters
 *
 * @return 0 if success, otherwise errorcode
 */
int sipreg_set_contact_params(struct sipreg *reg, const char *cparams)
{
	if (!reg)
		return EINVAL;

	return str_dup(&reg->cparams, cparams);
}
