/**
 * @file re_uri.h  Interface to URI module
 *
 * Copyright (C) 2010 Creytiv.com
 */


/** Defines a URI - Uniform Resource Identifier */
struct uri {
	struct pl scheme;    /**< URI scheme e.g. "sip:" "sips:"    */
	struct pl user;      /**< Username                          */
	struct pl host;      /**< Hostname or IP-address            */
	int af;              /**< Address family of host IP-address */
	uint16_t port;       /**< Port number                       */
	struct pl path;      /**< Optional URI-path                 */
	struct pl params;    /**< Optional URI-parameters           */
	struct pl headers;   /**< Optional URI-headers              */
};

typedef int (uri_apply_h)(const struct pl *name, const struct pl *val,
			  void *arg);

struct re_printf;
int  uri_encode(struct re_printf *pf, const struct uri *uri);
int  uri_decode(struct uri *uri, const struct pl *pl);
int  uri_decode_hostport(const struct pl *hostport, struct pl *host,
			 struct pl *port);
int  uri_param_get(const struct pl *pl, const struct pl *pname,
		   struct pl *pvalue);
int  uri_params_apply(const struct pl *pl, uri_apply_h *ah, void *arg);
int  uri_header_get(const struct pl *pl, const struct pl *hname,
		    struct pl *hvalue);
int  uri_headers_apply(const struct pl *pl, uri_apply_h *ah, void *arg);


/* Special URI escaping/unescaping */
int uri_user_escape(struct re_printf *pf, const struct pl *pl);
int uri_user_unescape(struct re_printf *pf, const struct pl *pl);
int uri_param_escape(struct re_printf *pf, const struct pl *pl);
int uri_param_unescape(struct re_printf *pf, const struct pl *pl);
int uri_header_escape(struct re_printf *pf, const struct pl *pl);
int uri_header_unescape(struct re_printf *pf, const struct pl *pl);
int uri_escape_user(struct re_printf *pf, const char *user);
int uri_escape(struct re_printf *pf, const char *uri);
int uri_escape_pl(struct re_printf *pf, const struct pl *pl);
int uri_unescape_pl(struct re_printf *pf, const struct pl *pl);
