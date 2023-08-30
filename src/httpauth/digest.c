/**
 * @file digest.c  HTTP Digest authentication (RFC 2617) - obsolete
 *                 HTTP Digest authentication (RFC 7616) - wip
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <time.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_mem.h>
#include <re_md5.h>
#include <re_sha.h>
#include <re_sys.h>
#include <re_httpauth.h>


typedef void (digest_decode_h)(const struct pl *name, const struct pl *val,
			       void *arg);


static const struct pl param_algorithm = PL("algorithm");
static const struct pl param_cnonce    = PL("cnonce");
static const struct pl param_nc        = PL("nc");
static const struct pl param_nonce     = PL("nonce");
static const struct pl param_opaque    = PL("opaque");
static const struct pl param_qop       = PL("qop");
static const struct pl param_realm     = PL("realm");
static const struct pl param_response  = PL("response");
static const struct pl param_uri       = PL("uri");
static const struct pl param_username  = PL("username");
static const struct pl param_stale     = PL("stale");


static void challenge_decode(const struct pl *name, const struct pl *val,
			     void *arg)
{
	struct httpauth_digest_chall *chall = arg;

	if (!pl_casecmp(name, &param_realm))
		chall->realm = *val;
	else if (!pl_casecmp(name, &param_nonce))
		chall->nonce = *val;
	else if (!pl_casecmp(name, &param_opaque))
		chall->opaque= *val;
	else if (!pl_casecmp(name, &param_stale))
		chall->stale = *val;
	else if (!pl_casecmp(name, &param_algorithm))
		chall->algorithm = *val;
	else if (!pl_casecmp(name, &param_qop))
		chall->qop = *val;
}


static void response_decode(const struct pl *name, const struct pl *val,
			    void *arg)
{
	struct httpauth_digest_resp *resp = arg;

	if (!pl_casecmp(name, &param_realm))
		resp->realm = *val;
	else if (!pl_casecmp(name, &param_nonce))
		resp->nonce = *val;
	else if (!pl_casecmp(name, &param_response))
		resp->response = *val;
	else if (!pl_casecmp(name, &param_username))
		resp->username = *val;
	else if (!pl_casecmp(name, &param_uri))
		resp->uri = *val;
	else if (!pl_casecmp(name, &param_nc))
		resp->nc = *val;
	else if (!pl_casecmp(name, &param_cnonce))
		resp->cnonce = *val;
	else if (!pl_casecmp(name, &param_qop))
		resp->qop = *val;
}


static int digest_decode(const struct pl *hval, digest_decode_h *dech,
			 void *arg)
{
	struct pl r = *hval, start, end, name, val;

	if (re_regex(r.p, r.l, "[ \t\r\n]*Digest[ \t\r\n]+", &start, &end) ||
	    start.p != r.p)
		return EBADMSG;

	pl_advance(&r, end.p - r.p);

	while (!re_regex(r.p, r.l,
			 "[ \t\r\n,]+[a-z]+[ \t\r\n]*=[ \t\r\n]*[~ \t\r\n,]*",
			 NULL, &name, NULL, NULL, &val)) {

		pl_advance(&r, val.p + val.l - r.p);

		dech(&name, &val, arg);
	}

	return 0;
}


static void response_destructor(void *data)
{
	struct httpauth_digest_resp *resp = data;

	mem_deref(resp->mb);
}


/**
 * Decode a Digest challenge
 *
 * @param chall Digest challenge object to decode into
 * @param hval  Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_digest_challenge_decode(struct httpauth_digest_chall *chall,
				     const struct pl *hval)
{
	int err;

	if (!chall || !hval)
		return EINVAL;

	memset(chall, 0, sizeof(*chall));

	err = digest_decode(hval, challenge_decode, chall);
	if (err)
		return err;

	if (!chall->realm.p || !chall->nonce.p)
		return EBADMSG;

	return 0;
}


/**
 * Decode a Digest response
 *
 * @param resp Digest response object to decode into
 * @param hval Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_digest_response_decode(struct httpauth_digest_resp *resp,
				    const struct pl *hval)
{
	int err;

	if (!resp || !hval)
		return EINVAL;

	memset(resp, 0, sizeof(*resp));

	err = digest_decode(hval, response_decode, resp);
	if (err)
		return err;

	if (!resp->realm.p    ||
	    !resp->nonce.p    ||
	    !resp->response.p ||
	    !resp->username.p ||
	    !resp->uri.p)
		return EBADMSG;

	return 0;
}


/**
 * Authenticate a digest response
 *
 * @param resp   Digest response
 * @param method Request method
 * @param ha1    HA1 value from MD5(username:realm:password)
 *
 * @return 0 if successfully authenticated, otherwise errorcode
 */
int httpauth_digest_response_auth(const struct httpauth_digest_resp *resp,
				  const struct pl *method, const uint8_t *ha1)
{
	uint8_t ha2[MD5_SIZE], digest[MD5_SIZE], response[MD5_SIZE];
	const char *p;
	uint32_t i;
	int err;

	if (!resp || !method || !ha1)
		return EINVAL;

	if (resp->response.l != 32)
		return EAUTH;

	err = md5_printf(ha2, "%r:%r", method, &resp->uri);
	if (err)
		return err;

	if (pl_isset(&resp->qop))
		err = md5_printf(digest, "%w:%r:%r:%r:%r:%w",
				 ha1, (size_t)MD5_SIZE,
				 &resp->nonce,
				 &resp->nc,
				 &resp->cnonce,
				 &resp->qop,
				 ha2, sizeof(ha2));
	else
		err = md5_printf(digest, "%w:%r:%w",
				 ha1, (size_t)MD5_SIZE,
				 &resp->nonce,
				 ha2, sizeof(ha2));
	if (err)
		return err;

	for (i=0, p=resp->response.p; i<sizeof(response); i++) {
		response[i]  = ch_hex(*p++) << 4;
		response[i] += ch_hex(*p++);
	}

	if (memcmp(digest, response, MD5_SIZE))
		return EAUTH;

	return 0;
}


static uint32_t nc = 1;

int httpauth_digest_make_response(struct httpauth_digest_resp **presp,
		const struct httpauth_digest_chall *chall,
		const char *path, const char *method, const char *user,
		const char *pwd, struct mbuf *body)
{
	struct httpauth_digest_resp *resp;
	size_t p1, p2;
	uint8_t ha1[MD5_SIZE], ha2[MD5_SIZE], response[MD5_SIZE];
	uint32_t cnonce;
	struct mbuf *mb = NULL;
	int err;

	if (!presp || !chall || !method || !user || !path || !pwd)
		return EINVAL;

	resp = mem_zalloc(sizeof(*resp), response_destructor);
	if (!resp) {
		return ENOMEM;
	}

	mb = mbuf_alloc(256);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	resp->realm = chall->realm;
	resp->nonce = chall->nonce;
	pl_set_str(&resp->username, user);
	pl_set_str(&resp->uri, path);
	resp->qop = chall->qop;

	err = mbuf_printf(mb, "%x", nc);
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	/* Client nonce should change, so we use random value. */
	cnonce = rand_u32();
	p1 = mb->pos;
	err = mbuf_printf(mb, "%x", cnonce);
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	/* compute response */
	/* HA1 = MD5(username:realm:password) */
	p2 = mb->pos;
	err = mbuf_printf(mb, "%r:%r:%s", &resp->username, &resp->realm,
			pwd);
	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), ha1);
	mbuf_skip_to_end(mb);
	if (0 == pl_strcmp(&chall->algorithm, "MD5-sess")) {
		/* HA1 = MD5(HA1:nonce:cnonce) */
		p2 = mb->pos;
		err = mbuf_printf(mb, "%w:%r:%x", ha1, sizeof(ha1),
				&resp->nonce, cnonce);
		if (err)
			goto out;

		mbuf_set_pos(mb, p2);
		md5(mbuf_buf(mb), mbuf_get_left(mb), ha1);
		mbuf_skip_to_end(mb);
	}

	/* HA2 */
	p2 = mb->pos;
	if (0 == pl_strcmp(&resp->qop, "auth-int") && mbuf_get_left(body)) {
		/* HA2 = MD5(method:digestURI:MD5(entityBody)) */
		err = mbuf_write_mem(mb, mbuf_buf(body), mbuf_get_left(body));
		if (err)
			goto out;

		mbuf_set_pos(mb, p2);
		md5(mbuf_buf(mb), mbuf_get_left(mb), ha2);
		mbuf_skip_to_end(mb);
		p2 = mb->pos;
		err = mbuf_printf(mb, "%s:%r:%w", method, &resp->uri,
				ha2, sizeof(ha2));
	}
	else {
		/* HA2 = MD5(method:digestURI) */
		err = mbuf_printf(mb, "%s:%r", method, &resp->uri);

	}

	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), ha2);
	mbuf_skip_to_end(mb);

	/* response */
	p2 = mb->pos;
	if (0 == pl_strcmp(&resp->qop, "auth-int") ||
			0 == pl_strcmp(&resp->qop, "auth")) {
	/* response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2) */
		err = mbuf_printf(mb, "%w:%r:%x:%x:%r:%w",
				ha1, sizeof(ha1), &resp->nonce, nc, cnonce,
				&resp->qop, ha2, sizeof(ha2));
	}
	else {
	/* response = MD5(HA1:nonce:HA2) */
		err = mbuf_printf(mb, "%w:%r:%w", ha1, sizeof(ha1),
				&resp->nonce, ha2, sizeof(ha2));
	}

	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), response);
	mbuf_skip_to_end(mb);

	p2 = mb->pos;
	err = mbuf_printf(mb, "%w", response, sizeof(response));
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	++nc;
	mbuf_set_pos(mb, 0);
	pl_set_str(&resp->nc, (const char*) mbuf_buf(mb));
	mbuf_set_pos(mb, p1);
	pl_set_str(&resp->cnonce, (const char*) mbuf_buf(mb));
	mbuf_set_pos(mb, p2);
	pl_set_str(&resp->response, (const char*) mbuf_buf(mb));
out:
	resp->mb = mb;
	if (err)
		mem_deref(resp);
	else
		*presp = resp;

	return err;
}


int httpauth_digest_response_encode(const struct httpauth_digest_resp *resp,
				  struct mbuf *mb)
{
	int err;
	size_t s;

	if (!resp || !mb)
		return EINVAL;

	/* length of string literals */
	s = 93;
	if (pl_isset(&resp->qop))
		s += 26;

	/* length of values */
	s += resp->username.l + resp->realm.l + resp->nonce.l + resp->uri.l;
	s += resp->response.l;
	if (pl_isset(&resp->qop))
		s += resp->qop.l + resp->nc.l + resp->cnonce.l;

	if (s > mb->size) {
		err = mbuf_resize(mb, s);
		if (err)
			return err;
	}

	err = mbuf_write_str(mb, "Authorization: ");
	err |= mbuf_printf(mb, "Digest username=\"%r\"", &resp->username);
	err |= mbuf_printf(mb, ", realm=\"%r\"", &resp->realm);
	err |= mbuf_printf(mb, ", nonce=\"%r\"", &resp->nonce);
	err |= mbuf_printf(mb, ", uri=\"%r\"", &resp->uri);
	err |= mbuf_printf(mb, ", response=\"%r\"", &resp->response);

	if (pl_isset(&resp->qop)) {
		err |= mbuf_printf(mb, ", qop=%r", &resp->qop);
		err |= mbuf_printf(mb, ", nc=%r", &resp->nc);
		err |= mbuf_printf(mb, ", cnonce=\"%r\"", &resp->cnonce);
	}

	mbuf_set_pos(mb, 0);
	return err;
}


static void httpauth_digest_chall_req_destructor(void *arg)
{
	struct httpauth_digest_chall_req *req = arg;

	mem_deref(req->realm);
	mem_deref(req->domain);
	mem_deref(req->nonce);
	mem_deref(req->opaque);
	mem_deref(req->algorithm);
	mem_deref(req->qop);
	mem_deref(req->charset);
}


static int generate_nonce(char **pnonce, const time_t ts,
	const char *etag, const char *secret)
{
	struct mbuf *mb = NULL;
	char *nonce = NULL;
	uint8_t hash [SHA256_DIGEST_LENGTH];
	int err = 0;

	mb = mbuf_alloc(32);
	if (!mb)
		return ENOMEM;

	if (str_isset(secret))
		err = mbuf_printf(mb, "%Lu:%s:%s", (uint64_t)ts, etag, secret);
	else
		err = mbuf_printf(mb, "%Lu:%s", (uint64_t)ts, etag);

	if (err)
		goto out;

	sha256(mb->buf, mb->end, hash);
	mbuf_rewind(mb);

	err = mbuf_printf(mb, "%w%016Lx", hash, sizeof(hash), (uint64_t)ts);
	if (err)
		goto out;

	mbuf_set_pos(mb, 0);
	err = mbuf_strdup(mb, &nonce, mbuf_get_left(mb));

out:
	if (err)
		mem_deref(nonce);
	else
		*pnonce = nonce;

	mem_deref(mb);

	return err;
}


/**
 * Prints / encodes an HTTP digest request challenge
 *
 * @param pf  Re_printf object
 * @param req Request to print
 *
 * @return 0 if success, otherwise errorcode
 */
int httpauth_digest_chall_req_print(struct re_printf *pf,
	const struct httpauth_digest_chall_req *req)
{
	int err = 0;

	if (!req)
		return EINVAL;

	/* historical reason quoted strings:   */
	/*   realm, domain, nonce, opaque, qop */
	/* historical reason unquoted strings: */
	/*   stale, algorithm                  */
	err = re_hprintf(pf, "Digest realm=\"%s\", "
		"qop=\"%s\", nonce=\"%s\", algorithm=%s",
		req->realm, req->qop, req->nonce, req->algorithm);

	if (str_isset(req->opaque))
		err |= re_hprintf(pf, ", opaque=\"%s\"", req->opaque);
	if (str_isset(req->domain))
		err |= re_hprintf(pf, ", domain=\"%s\"", req->domain);
	if (req->stale)
		err |= re_hprintf(pf, ", stale=true");
	if (str_isset(req->charset))
		err |= re_hprintf(pf, ", charset=\"%s\"", req->charset);
	if (req->userhash)
		err |= re_hprintf(pf, ", userhash=true");

	return err;
}


/**
 * Create a digest authentication request
 *
 * @param preq  Httpauth_digest_chall_req object ptr
 * @param realm Realm
 * @param etag  Changing data for nonce creation
 *              (HTTP ETag header / SIP msg src address)
 * @param qop   Quality of protection
 *
 * @return 0 if success, otherwise errorcode
 */
int httpauth_digest_chall_request(struct httpauth_digest_chall_req **preq,
	const char *realm, const char *etag, const char *qop)
{
	return httpauth_digest_chall_request_full(preq, realm, NULL, etag,
		NULL, false, NULL, qop, NULL, false);
}


/**
 * Create a full configurable digest authentication request
 *
 * @param preq      Httpauth_digest_chall_req object ptr
 * @param realm     Realm
 * @param domain    Domain (not used in SIP)
 * @param etag      Changing data for nonce creation
 *                  (HTTP ETag header / SIP msg src address)
 * @param opaque    Opaque
 * @param stale     Stale
 * @param algo      Supported algorithm (MD5, SHA1, SHA256 and sess versions)
 * @param qop       Quality of protection
 * @param charset   Character set used (not used in SIP)
 * @param userhash  Userhash support (not used in SIP)
 *
 * @return 0 if success, otherwise errorcode
 */
int httpauth_digest_chall_request_full(struct httpauth_digest_chall_req **preq,
	const char *realm, const char *domain, const char *etag,
	const char *opaque, const bool stale, const char *algo,
	const char *qop, const char *charset, const bool userhash)
{
	struct httpauth_digest_chall_req *req = NULL;
	int err = 0;

	if (!preq || !realm || !etag || !qop)
		return EINVAL;

	req = mem_zalloc(sizeof(*req), httpauth_digest_chall_req_destructor);
	if (!req)
		return ENOMEM;

	req->stale    = stale;
	req->userhash = userhash;
	err  = str_dup(&req->realm, realm);
	err |= str_dup(&req->qop, qop);

	if (str_isset(algo))
		err |= str_dup(&req->algorithm, algo);
	else
		err |= str_dup(&req->algorithm, "MD5");

	if (str_isset(domain))
		err |= str_dup(&req->domain, domain);
	if (str_isset(opaque))
		err |= str_dup(&req->opaque, opaque);
	if (str_isset(charset) && str_casecmp(charset, "UTF-8") == 0)
		err |= str_dup(&req->charset, charset);

	if (err)
		goto out;

	err = generate_nonce(&req->nonce, time(NULL), etag, NULL);

out:
	if (err)
		mem_deref(req);
	else
		*preq = req;

	return err;
}
