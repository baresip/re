/**
 * @file basic.c HTTP Basic authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_mbuf.h>
#include <re_base64.h>
#include <re_mem.h>
#include <re_fmt.h>
#include <re_httpauth.h>


#define DEBUG_MODULE "httpauth_basic"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void httpauth_basic_destr(void *arg)
{
	struct httpauth_basic *basic = arg;

	mem_deref(basic->mb);
}


struct httpauth_basic *httpauth_basic_alloc(void)
{
	struct httpauth_basic *basic = mem_zalloc(sizeof(*basic),
			httpauth_basic_destr);

	if (!basic)
		DEBUG_WARNING("could not allocate httpauth_basic\n");

	return basic;
}


/**
 * Decode a Basic response
 *
 * @param basic Basic response object
 * @param hval Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_basic_decode(struct httpauth_basic *basic,
				    const struct pl *hval)
{
	if (!basic || !hval)
		return EINVAL;

	if (re_regex(hval->p, hval->l,
			"[ \t\r\n]*Basic[ \t\r\n]+realm[ \t\r\n]*=[ \t\r\n]*"
				"[~ \t\r\n,]*",
			NULL, NULL, NULL, NULL, &basic->realm) ||
			!pl_isset(&basic->realm))
		return EBADMSG;

	return 0;
}


int httpauth_basic_make_response(struct httpauth_basic *basic,
		const char *user, const char *pwd)
{
	uint8_t *in;
	char *out;
	size_t si, so;
	size_t poso;
	int err;

	if (!basic || !user || !pwd)
		return EINVAL;

	si = strlen(user) + strlen(pwd) + 1;
	so = 4 * (si + 2) / 3;
	basic->mb = mbuf_alloc(si + so + 1);
	if (!basic->mb)
		return ENOMEM;

	err = mbuf_printf(basic->mb, "%s:%s", user, pwd);
	poso = basic->mb->pos;

	err |= mbuf_fill(basic->mb, 0, so + 1);
	if (err)
		goto fault;

	mbuf_set_pos(basic->mb, 0);
	in = mbuf_buf(basic->mb);
	mbuf_set_pos(basic->mb, poso);
	out = (char*) mbuf_buf(basic->mb);
	err = base64_encode(in, si, out, &so);
	if (err)
		goto fault;

	pl_set_str(&basic->auth, out);

	return 0;

fault:
	mem_deref(basic->mb);
	return err;
}

int httpauth_basic_encode(const struct httpauth_basic *basic, struct mbuf *mb)
{
	int err;

	if (!basic || !mb || !pl_isset(&basic->auth))
		return EINVAL;

	err = mbuf_resize(mb, basic->auth.l + 21);
	if (err)
		return err;

	err = mbuf_write_str(mb, "Authorization: Basic ");
	err |= mbuf_write_pl(mb, &basic->auth);
	if (err)
		return err;

	mbuf_set_pos(mb, 0);
	return 0;
}

/* HTTPAUTH BASIC REQUESTS*/

static void httpauth_basic_request_destructor(void *arg)
{
	struct httpauth_basic_req *req = arg;

	mem_deref(req->realm);
	mem_deref(req->charset);
}


int httpauth_basic_request_print(struct re_printf *pf,
	const struct httpauth_basic_req *req)
{
	int err = 0;

	if (!pf || !req)
		return EINVAL;

	err = re_hprintf(pf, "Basic realm=\"%s\"", req->realm);
	if (str_isset(req->charset))
		err |= re_hprintf(pf, ", charset=\"%s\"", req->charset);

	return err;
}


/**
 * Verify received credentials
 *
 * @param hval   http authentication header value containing the credentials
 * @param user   user name (may be an UTF-8 string)
 * @param passwd user password (may be an UTF-8 string)
 *
 * @return 0 if successfully verified, otherwise errorcode
 */
int httpauth_basic_verify(const struct pl *hval, const char *user,
	const char *passwd)
{
	struct pl b64c = PL_INIT;
	struct mbuf *mb = NULL;
	char *c = NULL;
	size_t clen = 0;
	int err = 0;

	if (!hval || !user || !passwd)
		return EINVAL;

	mb = mbuf_alloc(str_len(user) + str_len(passwd) + 1);
	if (!mb)
		return ENOMEM;

	if (re_regex(hval->p, hval->l, "[ \t\r\n]*Basic[ \t\r\n]+[~ \t\r\n]*",
		NULL, NULL, &b64c) || !pl_isset(&b64c)) {
		err = EBADMSG;
		goto out;
	}

	clen = b64c.l;
	c = mem_zalloc(clen, NULL);
	if (!c) {
		err = ENOMEM;
		goto out;
	}

	err = base64_decode(b64c.p, b64c.l, (uint8_t *) c, &clen);
	if (err)
		goto out;

	err = mbuf_printf(mb, "%s:%s", user, passwd);
	if (err)
		goto out;

	if (mem_seccmp(mb->buf, (uint8_t *)c, clen) != 0)
		err = EACCES;

out:
	if (c)
		mem_secclean(c, clen);

	if (mb)
		mem_secclean(mb->buf, mb->size);

	mem_deref(c);
	mem_deref(mb);

	return err;
}


/**
 * Create a Basic Authentication Request
 *
 * @param preq    httpauth_basic_req object ptr
 * @param realm   realm
 * @param charset optional charset
 *
 * @return 0 if successful, otherwise errorcode
 */
int httpauth_basic_request(struct httpauth_basic_req **preq,
	const char *realm, const char *charset)
{
	struct httpauth_basic_req *req = NULL;
	int err = 0;

	if (!preq || !realm)
		return EINVAL;

	req = mem_zalloc(sizeof(*req), httpauth_basic_request_destructor);
	if (!req)
		return ENOMEM;

	err = str_dup(&req->realm, realm);
	if (str_isset(charset) && str_casecmp(charset, "UTF-8") == 0)
		err |= str_dup(&req->charset, charset);

	if (err)
		mem_deref(req);
	else
		*preq = req;

	return err;
}
