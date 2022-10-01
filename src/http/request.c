/**
 * @file http/request.c HTTP request connection
 *
 * Supports:
 * - GET, POST and PUT requests
 * - basic, digest and token authentication (e.g. bearer)
 * - TLS
 *
 * Copyright (C) 2020 Commend.com
 */

#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_fmt.h>
#include <re_tmr.h>
#include <re_srtp.h>
#include <re_tcp.h>
#include <re_tls.h>
#include <re_dns.h>
#include <re_msg.h>
#include <re_http.h>
#include <re_httpauth.h>
#include "http.h"

#define DEBUG_MODULE "reqconn"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#ifndef VERSION
#define VERSION "???"
#endif


enum {
	MAX_RETRIES = 3,
};

struct http_reqconn {
	struct le le;

	struct http_cli *client;        /**< HTTP client                     */

	struct sa peer;          /**< Peer address                           */
	struct http_req *req;    /**< Current HTTP request                   */

	char *uri;               /**< Request URI                            */
	char *met;               /**< Request Method                         */
	char *path;              /**< Request path/resource                  */
	char *ctype;             /**< Content-type                           */
	uint32_t timeout;        /**< Timeout for DNS and HTTP               */
	char *user;              /**< Auth user                              */
	char *pass;              /**< Auth password                          */
	struct mbuf *body;       /**< HTTP body for POST/PUT request         */
	char *token;             /**< Auth token (e.g. bearer token)         */
	char *tokentype;         /**< Auth token type                        */
	struct mbuf *custhdr;    /**< Custom HTTP headers                    */

	int retries;             /**< Auth retry counter                     */
	http_resp_h *resph;      /**< HTTP response handler                  */
	http_data_h *datah;      /**< HTTP data handler for downloads        */
	void *arg;               /**< User data pointer for resph and datah  */

	http_bodyh *bodyh;       /**< Handler for the request body           */
	uint64_t bodyl;          /**< Size of body if request handler used   */

#ifdef USE_TLS
	char *tlshn;             /**< TLS host name                          */
#endif
};


static void destructor(void *arg)
{
	struct http_reqconn *conn = arg;

	mem_deref(conn->req);
	mem_deref(conn->uri);
	mem_deref(conn->met);
	mem_deref(conn->path);
	mem_deref(conn->ctype);
	mem_deref(conn->user);
	mem_deref(conn->pass);
	mem_deref(conn->body);
	mem_deref(conn->token);
	mem_deref(conn->tokentype);
	mem_deref(conn->custhdr);
#ifdef USE_TLS
	mem_deref(conn->tlshn);
#endif
}


static int make_digest_mb(struct mbuf *mb,
		struct httpauth_digest_chall *digest,
		struct http_reqconn *conn)
{
	struct httpauth_digest_resp *resp = NULL;
	int err;

	err = httpauth_digest_make_response(&resp, digest, conn->path,
			conn->met, conn->user, conn->pass, conn->body);
	if (err)
		return err;

	err = httpauth_digest_response_encode(resp, mb);
	mem_deref(resp);
	return err;
}


static int make_token_mb(struct mbuf *mb, const struct http_reqconn *conn)
{
	int err;
	const char auth[] = "Authorization: ";
	const char defaulttype[] = "Bearer";

	if (!conn || !mb)
		return EINVAL;

	if (!str_isset(conn->token) || !mb)
		return EINVAL;

	err = mbuf_resize(mb, strlen(conn->token) + sizeof(auth) +
		strlen(conn->tokentype ? conn->tokentype : defaulttype) + 1);
	if (err)
		return err;

	err  = mbuf_write_str(mb, auth);

	if (conn->tokentype)
		err |= mbuf_write_str(mb, conn->tokentype);
	else
		err |= mbuf_write_str(mb, defaulttype);

	err |= mbuf_write_str(mb, " ");
	err |= mbuf_write_str(mb, conn->token);
	mbuf_set_pos(mb, 0);
	return err;
}


static int make_basic_mb(struct mbuf *mb, struct http_reqconn *conn)
{
	int err;
	struct httpauth_basic *basic;

	if (!conn || !mb)
		return EINVAL;

	basic = httpauth_basic_alloc();
	if (!basic)
		return ENOMEM;

	err = httpauth_basic_make_response(basic, conn->user, conn->pass);
	if (err)
		goto out;

	err = httpauth_basic_encode(basic, mb);

out:
	mem_deref(basic);
	return err;
}


static int send_req(struct http_reqconn *conn, const struct pl *auth);


static void resp_handler(int err, const struct http_msg *msg, void *arg)
{
	struct http_reqconn *conn = arg;
	const struct http_hdr *hdr;
	struct httpauth_digest_chall digest;
	struct httpauth_basic *basic = NULL;
	struct pl auth;
	struct mbuf *abuf = NULL;

	if (!conn)
		return;

	if (!msg) {
		DEBUG_INFO("no http_msg (%m)\n", err);
		goto disconnect;
	}
	else {
		DEBUG_INFO("scode=%u (%m)\n", msg->scode, err);
	}

	if (err || (msg->scode != 401 && msg->scode != 403))
		goto disconnect;

	hdr = http_msg_hdr(msg, HTTP_HDR_WWW_AUTHENTICATE);
	if (!hdr)
		goto disconnect;

	conn->retries++;
	if (conn->retries > MAX_RETRIES) {
		err = EAUTH;
		DEBUG_INFO("not authorized\n");
		goto disconnect;
	}

	if (httpauth_digest_challenge_decode(&digest, &hdr->val)) {
		/* It's not digest. Now try basic. */
		basic = httpauth_basic_alloc();
		if (!basic) {
			err = ENOMEM;
			goto disconnect;
		}

		if (httpauth_basic_decode(basic, &hdr->val)) {
			err = EBADMSG;
			goto disconnect;
		}
	}

	abuf = mbuf_alloc(1);
	if (!abuf) {
		err = ENOMEM;
		goto disconnect;
	}

	if (pl_isset(&digest.nonce))
		err = make_digest_mb(abuf, &digest, conn);
	else if (basic && pl_isset(&basic->realm))
		err = make_basic_mb(abuf, conn);
	else
		err = EBADMSG;

	if (err) {
		DEBUG_WARNING("Authentication failed (%m)\n", err);
		goto disconnect;
	}

	pl_set_mbuf(&auth, abuf);
	err = send_req(conn, &auth);
	if (err)
		goto disconnect;

	goto out;

 disconnect:
	if (conn && conn->resph)
		conn->resph(err, msg, conn->arg);

 out:
	mem_deref(abuf);
	mem_deref(basic);
	mem_deref(conn);
}


static int data_handler(const uint8_t *buf, size_t size,
		const struct http_msg *msg, void *arg)
{
	struct http_reqconn *conn = arg;

	if (!conn)
		return EINVAL;

	if (!conn->datah)
		return 0;

	return conn->datah(buf, size, msg, conn->arg);
}


static size_t req_body_handler(struct mbuf *mb, void *arg)
{
	struct http_reqconn *conn = arg;
	size_t len = 0;

	if (!mb)
		return 0;

	if (conn->bodyh) {
		len = conn->bodyh(mb, conn->arg);
	}
	else if (conn->body) {
		len = min(mbuf_get_left(conn->body),
			http_client_get_bufsize_max(conn->client));
		if (!len)
			return len;

		mbuf_write_mem(mb, mbuf_buf(conn->body), len);
		mbuf_advance(conn->body, len);
	}

	return len;
}


static int send_req(struct http_reqconn *conn, const struct pl *auth)
{
	int err;
	struct mbuf *ctbuf = NULL;
	struct mbuf *clbuf = NULL;
	struct pl ct = PL_INIT;
	struct pl cl = PL_INIT;
	struct pl custh = PL_INIT;
#if (DEBUG_LEVEL >= 7)
	struct pl dbg;
#endif

	if (!conn)
		return EINVAL;

	if (conn->body || conn->bodyh) {
		clbuf = mbuf_alloc(22);
		if (!clbuf)
			return ENOMEM;

		if (conn->bodyh)
			mbuf_printf(clbuf, "Content-Length: %llu\r\n",
				    conn->bodyl);
		else
			mbuf_printf(clbuf, "Content-Length: %lu\r\n",
				    mbuf_get_left(conn->body));

		mbuf_set_pos(clbuf, 0);
		pl_set_mbuf(&cl, clbuf);
	}

	if (conn->ctype) {
		ctbuf = mbuf_alloc(17 + strlen(conn->ctype));
		mbuf_printf(ctbuf, "Content-Type: %s\r\n", conn->ctype);
		mbuf_set_pos(ctbuf, 0);
		pl_set_mbuf(&ct, ctbuf);
	}

	DEBUG_INFO("send %s uri=%s path=%s len=%lu %s auth.\n",
			conn->met, conn->uri, conn->path,
			mbuf_get_left(conn->body),
			auth ? "with" : "without");

	if (auth) {
		DEBUG_INFO("auth=|%r|\n", auth);
	}

#if (DEBUG_LEVEL >= 7)
	if (conn->body) {
		pl_set_mbuf(&dbg, conn->body);
		DEBUG_PRINTF("postdata:\n%r\n", &dbg);
	}
#endif

	if (conn->custhdr)
		pl_set_mbuf(&custh, conn->custhdr);

	err = http_request(&conn->req, conn->client,
			conn->met, conn->uri,
			resp_handler, conn->datah ? data_handler : NULL,
			(conn->bodyh || conn->body) ? req_body_handler : NULL,
			conn,
			"%r%s"
			"User-Agent: re " VERSION "\r\n"
			"%r"
			"%r"
			"%r"
			"\r\n",
			auth, auth ? "\r\n" : "",
			&ct,
			&custh,
			&cl);

	mem_deref(clbuf);
	mem_deref(ctbuf);
	if (err) {
		DEBUG_WARNING("Could not send %s request. (%m)\n", conn->met);
		return err;
	}

	/* keep internal reference for resp_handler */
	mem_ref(conn);
	return 0;
}


static int send_auth_token(struct http_reqconn *conn)
{
	struct pl auth;
	int err = 0;
	struct mbuf *mb = mbuf_alloc(1);

	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	err = make_token_mb(mb, conn);
	if (err)
		goto out;

	pl_set_mbuf(&auth, mb);
	err = send_req(conn, &auth);

out:
	mem_deref(mb);
	return err;
}


/**
 * Allocates a new http_reqconn instance. Has to be freed after usage with
 * mem_deref().
 *
 * @param pconn   A pointer for returning the new http_reqconn.
 * @param client  The HTTP client. Multiple parallel HTTP request with the same
 *                HTTP client are possible.
 * @param resph   The optional response handler.
 * @param datah   The optional data handler. This is useful for downloading
 *                large files.
 * @param arg     A pointer that will be passed to resph and datah.
 *
 * @return 0 if success, otherwise errorcode
 */
int http_reqconn_alloc(struct http_reqconn **pconn,
		struct http_cli *client,
		http_resp_h *resph, http_data_h *datah, void* arg)
{
	struct http_reqconn *conn = NULL;
	int err;
	struct pl pl = PL("GET");

	if (!pconn || !client)
		return EINVAL;

	conn = mem_zalloc(sizeof(*conn), destructor);
	if (!conn)
		return ENOMEM;

	conn->client = client;
	conn->resph = resph;
	conn->datah = datah;
	conn->arg = arg;

	err = http_reqconn_set_method(conn, &pl);
	if (err)
		conn = mem_deref(conn);

	*pconn = conn;
	return err;
}


int http_reqconn_set_auth(struct http_reqconn *conn, const struct pl *user,
		const struct pl *pass)
{
	int err = 0;

	if (!conn)
		return EINVAL;

	conn->user = mem_deref(conn->user);
	conn->pass = mem_deref(conn->pass);
	if (pl_isset(user))
		err |= pl_strdup(&conn->user, user);

	if (pl_isset(pass))
		err |= pl_strdup(&conn->pass, pass);

	return err;
}


int http_reqconn_set_bearer(struct http_reqconn *conn, const struct pl *bearer)
{
	conn->tokentype = mem_deref(conn->tokentype);
	return http_reqconn_set_authtoken(conn, bearer);
}


int http_reqconn_set_authtoken(struct http_reqconn *conn,
	const struct pl *token)
{
	if (!conn)
		return EINVAL;

	conn->token = mem_deref(conn->token);
	if (!pl_isset(token))
		return 0;

	return pl_strdup(&conn->token, token);
}


int http_reqconn_set_tokentype(struct http_reqconn *conn,
	const struct pl *tokentype)
{
	if (!conn)
		return EINVAL;

	conn->tokentype = mem_deref(conn->tokentype);
	if (!pl_isset(tokentype))
		return 0;

	return pl_strdup(&conn->tokentype, tokentype);
}


int http_reqconn_set_method(struct http_reqconn *conn, const struct pl *met)
{
	if (!conn)
		return EINVAL;

	conn->met = mem_deref(conn->met);
	return pl_strdup(&conn->met, met);
}


int http_reqconn_set_body(struct http_reqconn *conn, struct mbuf *body)
{
	if (!conn || !body)
		return EINVAL;

	conn->body = mbuf_alloc_ref(body);

	if (!conn->body)
		return ENOMEM;

	mbuf_set_pos(conn->body, 0);
	conn->bodyl = mbuf_get_left(conn->body);

	return 0;
}


int http_reqconn_set_ctype(struct http_reqconn *conn, const struct pl *ctype)
{
	if (!conn)
		return EINVAL;

	conn->ctype = mem_deref(conn->ctype);
	if (!pl_isset(ctype))
		return 0;

	return pl_strdup(&conn->ctype, ctype);
}


int http_reqconn_add_header(struct http_reqconn *conn, const struct pl *header)
{
	int err;
	if (!conn)
		return EINVAL;

	if (!pl_isset(header))
		return 0;

	if (!conn->custhdr)
		conn->custhdr = mbuf_alloc(8);

	if (!conn->custhdr)
		return ENOMEM;

	err = mbuf_write_pl(conn->custhdr, header);
	err |= mbuf_write_str(conn->custhdr, "\r\n");
	if (err)
		conn->custhdr = mem_deref(conn->custhdr);

	return err;
}


int http_reqconn_clr_header(struct http_reqconn *conn)
{
	if (!conn)
		return EINVAL;

	conn->custhdr = mem_deref(conn->custhdr);
	return 0;
}


#ifdef USE_TLS
int http_reqconn_set_tls_hostname(struct http_reqconn *conn,
		const struct pl *hostname)
{
	if (!conn)
		return EINVAL;

	conn->tlshn = mem_deref(conn->tlshn);
	if (!pl_isset(hostname))
		return 0;

	return pl_strdup(&conn->tlshn, hostname);
}
#endif


int http_reqconn_send(struct http_reqconn *conn, const struct pl *uri)
{
	int err;
	struct http_uri hu;
	char *host = NULL;
#ifdef USE_TLS
	struct pl tlshn;
#endif

	if (!conn || !pl_isset(uri))
		return EINVAL;

	err = http_uri_decode(&hu, uri);
	if (err) {
		DEBUG_WARNING("http uri %r decode error (%m)\n", uri, err);
		return EINVAL;
	}

	conn->uri = mem_deref(conn->uri);
	conn->path = mem_deref(conn->path);
	err |= pl_strdup(&conn->uri, uri);
	err |= pl_strdup(&conn->path, &hu.path);
	err |= pl_strdup(&host, &hu.host);
	if (err)
		return err;

#ifdef USE_TLS
	if (conn->tlshn) {
		pl_set_str(&tlshn, conn->tlshn);
		err = http_client_set_tls_hostname(conn->client, &tlshn);
	}

	if (err) {
		DEBUG_WARNING("Could not set TLS hostname.\n");
		mem_deref(host);
		return err;
	}
#endif

	mem_deref(host);
	if (conn->custhdr)
		mbuf_set_pos(conn->custhdr, 0);

	conn->retries = 0;
	if (conn->token)
		err = send_auth_token(conn);
	else
		err = send_req(conn, NULL);

	return err;
}


int http_reqconn_set_req_bodyh(struct http_reqconn *conn,
			       http_bodyh cb, uint64_t len)
{
	int err = 0;

	if (!conn)
		return EINVAL;

	conn->bodyh = cb;
	conn->bodyl = len;

	return err;
}
