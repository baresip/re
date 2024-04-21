/**
 * @file sip/auth.c  SIP Authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <time.h>
#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_uri.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_sys.h>
#include <re_md5.h>
#include <re_sha.h>
#include <re_httpauth.h>
#include <re_udp.h>
#include <re_msg.h>
#include <re_sip.h>
#include "sip.h"

#define DEBUG_MODULE "sip_auth"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

enum {
	NONCE_EXPIRES  = 300,
	NONCE_MIN_SIZE = 33,
};

struct sip_auth {
	struct list realml;
	sip_auth_h *authh;
	void *arg;
	bool ref;
	int err;
};


struct realm {
	struct le le;
	char *realm;
	char *nonce;
	char *qop;
	char *opaque;
	char *user;
	char *pass;
	char *algorithm;
	uint32_t nc;
	enum sip_hdrid hdr;
};


static int dummy_handler(char **user, char **pass, const char *rlm, void *arg)
{
	(void)user;
	(void)pass;
	(void)rlm;
	(void)arg;

	return EAUTH;
}


static void realm_destructor(void *arg)
{
	struct realm *realm = arg;

	list_unlink(&realm->le);
	mem_deref(realm->realm);
	mem_deref(realm->nonce);
	mem_deref(realm->qop);
	mem_deref(realm->opaque);
	mem_deref(realm->user);
	mem_deref(realm->pass);
	mem_deref(realm->algorithm);
}


static void auth_destructor(void *arg)
{
	struct sip_auth *auth = arg;

	if (auth->ref)
		mem_deref(auth->arg);

	list_flush(&auth->realml);
}


static int mkdigest(struct mbuf **digestp, const struct realm *realm,
		    const char *met, const char *uri, uint64_t cnonce)
{
	struct mbuf *digest;
	uint8_t *ha1 = NULL, *ha2 = NULL;
	digest_printf_h *digest_printf;
	int err;

	bool use_sha256 = str_casecmp(realm->algorithm, "sha-256") == 0;
	size_t h_size	= use_sha256 ? SHA256_DIGEST_SIZE : MD5_SIZE;

	digest = mbuf_alloc(h_size);
	if (!digest)
		return ENOMEM;

	mbuf_set_end(digest, h_size);

	ha1 = mem_zalloc(h_size, NULL);
	if (!ha1) {
		err = ENOMEM;
		goto out;
	}

	ha2 = mem_zalloc(h_size, NULL);
	if (!ha2) {
		err = ENOMEM;
		goto out;
	}

	if (use_sha256)
		digest_printf = &sha256_printf;
	else
		digest_printf = &md5_printf;

	err = digest_printf(ha1, "%s:%s:%s", realm->user, realm->realm,
			    realm->pass);
	if (err)
		goto out;

	err = digest_printf(ha2, "%s:%s", met, uri);
	if (err)
		goto out;

	if (realm->qop)
		err = digest_printf(
			mbuf_buf(digest), "%w:%s:%08x:%016llx:auth:%w", ha1,
			h_size, realm->nonce, realm->nc, cnonce, ha2, h_size);
	else
		err = digest_printf(mbuf_buf(digest), "%w:%s:%w", ha1, h_size,
				    realm->nonce, ha2, h_size);
out:
	mem_deref(ha1);
	mem_deref(ha2);

	if (err)
		mem_deref(digest);
	else
		*digestp = digest;

	return err;
}


static bool cmp_handler(struct le *le, void *arg)
{
	struct realm *realm = le->data;
	struct pl *chrealm = arg;

	/* handle multiple authenticate headers with equal realm value */
	if (realm->nc == 1)
		return false;

	return 0 == pl_strcasecmp(chrealm, realm->realm);
}


static bool auth_handler(const struct sip_hdr *hdr, const struct sip_msg *msg,
			 void *arg)
{
	struct httpauth_digest_chall ch;
	struct sip_auth *auth = arg;
	struct realm *realm   = NULL;
	int err;
	(void)msg;

	if (httpauth_digest_challenge_decode(&ch, &hdr->val)) {
		err = EBADMSG;
		goto out;
	}

	if (!pl_isset(&ch.algorithm))
		pl_set_str(&ch.algorithm, "MD5");

	if (pl_strcasecmp(&ch.algorithm, "md5") &&
	    pl_strcasecmp(&ch.algorithm, "sha-256")) {
		err = ENOSYS;
		goto out;
	}

	realm = list_ledata(list_apply(&auth->realml, true, cmp_handler,
				       &ch.realm));
	if (!realm) {
		realm = mem_zalloc(sizeof(*realm), realm_destructor);
		if (!realm) {
			err = ENOMEM;
			goto out;
		}

		list_append(&auth->realml, &realm->le, realm);

		err = pl_strdup(&realm->realm, &ch.realm);
		if (err)
			goto out;

		err = pl_strdup(&realm->algorithm, &ch.algorithm);
		if (err)
			goto out;

		err = auth->authh(&realm->user, &realm->pass,
				  realm->realm, auth->arg);
		if (err)
			goto out;
	}
	else {
		if (!pl_isset(&ch.stale) || pl_strcasecmp(&ch.stale, "true")) {
			err = EAUTH;
			goto out;
		}

		realm->nonce	 = mem_deref(realm->nonce);
		realm->qop	 = mem_deref(realm->qop);
		realm->opaque	 = mem_deref(realm->opaque);
		realm->algorithm = mem_deref(realm->algorithm);
	}

	realm->hdr = hdr->id;
	realm->nc  = 1;

	err = pl_strdup(&realm->nonce, &ch.nonce);

	if (pl_isset(&ch.qop))
		err |= pl_strdup(&realm->qop, &ch.qop);

	if (pl_isset(&ch.opaque))
		err |= pl_strdup(&realm->opaque, &ch.opaque);

out:
	if (err) {
		mem_deref(realm);
		auth->err = err;
		return true;
	}

	return false;
}


/**
 * Update a SIP authentication state from a SIP message
 *
 * @param auth SIP Authentication state
 * @param msg  SIP Message
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_auth_authenticate(struct sip_auth *auth, const struct sip_msg *msg)
{
	if (!auth || !msg)
		return EINVAL;

	if (sip_msg_hdr_apply(msg, true, SIP_HDR_WWW_AUTHENTICATE,
			      auth_handler, auth))
		return auth->err;

	if (sip_msg_hdr_apply(msg, true, SIP_HDR_PROXY_AUTHENTICATE,
			      auth_handler, auth))
		return auth->err;

	return 0;
}


int sip_auth_encode(struct mbuf *mb, struct sip_auth *auth, const char *met,
		    const char *uri)
{
	struct le *le;
	int err = 0;

	if (!mb || !auth || !met || !uri)
		return EINVAL;

	for (le = auth->realml.head; le; le = le->next) {

		const uint64_t cnonce = rand_u64();
		struct realm *realm = le->data;
		struct mbuf *digest = NULL;

		err = mkdigest(&digest, realm, met, uri, cnonce);
		if (err)
			break;

		switch (realm->hdr) {

		case SIP_HDR_WWW_AUTHENTICATE:
			err = mbuf_write_str(mb, "Authorization: ");
			break;

		case SIP_HDR_PROXY_AUTHENTICATE:
			err = mbuf_write_str(mb, "Proxy-Authorization: ");
			break;

		default:
			continue;
		}

		err |= mbuf_printf(mb, "Digest username=\"%s\"", realm->user);
		err |= mbuf_printf(mb, ", realm=\"%s\"", realm->realm);
		err |= mbuf_printf(mb, ", nonce=\"%s\"", realm->nonce);
		err |= mbuf_printf(mb, ", uri=\"%s\"", uri);
		err |= mbuf_printf(mb, ", response=\"%w\"", digest->buf,
				   digest->end);
		digest = mem_deref(digest);

		if (realm->opaque)
			err |= mbuf_printf(mb, ", opaque=\"%s\"",
					   realm->opaque);

		if (realm->qop) {
			err |= mbuf_printf(mb, ", cnonce=\"%016llx\"", cnonce);
			err |= mbuf_write_str(mb, ", qop=auth");
			err |= mbuf_printf(mb, ", nc=%08x", realm->nc);
		}

		++realm->nc;

		err |= mbuf_printf(mb, ", algorithm=%s", realm->algorithm);
		err |= mbuf_write_str(mb, "\r\n");
		if (err)
			break;
	}

	return err;
}


/**
 * Allocate a SIP authentication state
 *
 * @param authp Pointer to allocated SIP authentication state
 * @param authh Authentication handler
 * @param arg   Handler argument
 * @param ref   True to mem_ref() argument
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_auth_alloc(struct sip_auth **authp, sip_auth_h *authh,
		   void *arg, bool ref)
{
	struct sip_auth *auth;

	if (!authp)
		return EINVAL;

	auth = mem_zalloc(sizeof(*auth), auth_destructor);
	if (!auth)
		return ENOMEM;

	auth->authh = authh ? authh : dummy_handler;
	auth->arg   = ref ? mem_ref(arg) : arg;
	auth->ref   = ref;

	*authp = auth;

	return 0;
}


/**
 * Reset a SIP authentication state
 *
 * @param auth SIP Authentication state
 */
void sip_auth_reset(struct sip_auth *auth)
{
	if (!auth)
		return;

	list_flush(&auth->realml);
}


static int gen_nonce(char **noncep, time_t ts, const struct sa *src,
		     const char *realm)
{
	uint8_t key[MD5_SIZE];
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(40);
	if (!mb)
		return ENOMEM;

	err = mbuf_printf(mb,"%lu%j%s", (long unsigned)ts, src, realm);
	if (err)
		goto out;

	md5(mb->buf, mb->end, key);
	mbuf_rewind(mb);
	err = mbuf_printf(mb,"%w%016lx", key, sizeof(key), (long unsigned)ts);
	if (err)
		goto out;

	mbuf_set_pos(mb, 0);
	err = mbuf_strdup(mb, noncep, mbuf_get_left(mb));

out:
	mem_deref(mb);
	return err;
}


static int check_nonce(const struct pl *nonce, const struct sa *src,
		       const char *realm)
{
	struct pl pl;
	time_t ts;
	char *comp = NULL;
	bool eq;
	int err;

	if (!nonce || !nonce->p || nonce->l < NONCE_MIN_SIZE)
		return EINVAL;

	pl = *nonce;
	pl.p = pl.p + (pl.l - 16);
	pl.l = 16;
	ts = (time_t) pl_x64(&pl);

	if (time(NULL) - ts > NONCE_EXPIRES)
		return ETIMEDOUT;

	err = gen_nonce(&comp, ts, src, realm);
	if (err)
		return err;

	eq = !pl_strcmp(nonce, comp);
	mem_deref(comp);
	return eq ? 0 : EAUTH;
}


int sip_uas_auth_print(struct re_printf *pf,
		       const struct sip_uas_auth *auth)
{
	return re_hprintf(pf, "WWW-Authenticate: "
			      "Digest realm=\"%s\", nonce=\"%s\", "
			      "algorithm=MD5, "
			      "qop=\"auth\"%s"
			      "\r\n",
			      auth->realm, auth->nonce,
			      auth->stale ? ", stale=true" : "");
}


static void sip_uas_destructor(void *arg)
{
	struct sip_uas_auth *auth = arg;

	mem_deref(auth->nonce);
}


int sip_uas_auth_gen(struct sip_uas_auth **authp, const struct sip_msg *msg,
		     const char *realm)
{
	struct sip_uas_auth *auth;
	int err;

	if (!authp || !msg)
		return EINVAL;

	auth = mem_zalloc(sizeof(*auth), sip_uas_destructor);
	if (!auth)
		return ENOMEM;

	auth->realm = realm;
	err  = gen_nonce(&auth->nonce, time(NULL), &msg->src, realm);

	if (err)
		mem_deref(auth);
	else
		*authp = auth;

	return err;
}


int sip_uas_auth_check(struct sip_uas_auth *auth, const struct sip_msg *msg,
		       sip_uas_auth_h *authh, void *arg)
{
	struct httpauth_digest_resp resp;
	const struct sip_hdr *hdr;
	uint8_t ha1[MD5_SIZE];
	int err;

	if (!msg || !auth || !authh)
		return EINVAL;

	hdr = sip_msg_hdr_apply(msg, true, SIP_HDR_AUTHORIZATION, NULL, NULL);
	if (!hdr)
		return EAUTH;

	if (httpauth_digest_response_decode(&resp, &hdr->val))
		return EINVAL;

	if (pl_strcasecmp(&resp.realm, auth->realm))
		return EINVAL;

	err = check_nonce(&resp.nonce, &msg->src, auth->realm);
	if (err == ETIMEDOUT || err == EAUTH) {
		auth->stale = true;
		return EAUTH;
	}
	else if (err) {
		return err;
	}

	if (authh(ha1, &resp.username, auth->realm, arg))
		return EINVAL;

	if (httpauth_digest_response_auth(&resp, &msg->met, ha1))
		return EACCES;

	return 0;
}
