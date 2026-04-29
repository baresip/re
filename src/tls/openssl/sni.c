/**
 * @file openssl/sni.c Server Name Indication API
 *
 * Copyright (C) 2022 Commend.com - c.spielberger@commend.com
 */
#include <openssl/tls1.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls/sni"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

struct tls_conn;


static bool x509_match_common_name(X509 *x509, const char *sni)
{
	const X509_NAME *nm = X509_get_subject_name(x509);

	int lastpos = -1;
	for (;;) {
		lastpos = X509_NAME_get_index_by_NID(nm, NID_commonName,
						     lastpos);
		if (lastpos == -1)
			break;

		const X509_NAME_ENTRY *e = X509_NAME_get_entry(nm, lastpos);
		const ASN1_STRING *astr	 = X509_NAME_ENTRY_get_data(e);
		if (!astr)
			continue;

		struct pl cn = {(char *)ASN1_STRING_get0_data(astr),
				ASN1_STRING_length(astr)};

		if (!pl_strcasecmp(&cn, sni))
			return true;
	}

	return false;
}


static bool x509_match_alt_name(X509 *x509, const char *sni)
{
	GENERAL_NAMES *gs = NULL;
	ASN1_STRING *astr = NULL;
	ASN1_OCTET_STRING *octet = NULL;
	bool match = false;

	gs = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (!gs)
		return false;

	for (int i = 0; i < sk_GENERAL_NAME_num(gs); i++) {
		GENERAL_NAME *g = sk_GENERAL_NAME_value(gs, i);

		if (g->type == GEN_DNS) {
			astr = ASN1_IA5STRING_new();
			if (!astr)
				goto out;

			if (!ASN1_STRING_set(astr, sni, -1))
				goto out;

			if (!ASN1_STRING_cmp(astr, g->d.dNSName)) {
				match = true;
				break;
			}
		}
		else if (g->type == GEN_IPADD) {
			octet = a2i_IPADDRESS(sni);
			if (!octet)
				break;
			if (!ASN1_OCTET_STRING_cmp(octet, g->d.iPAddress)) {
				match = true;
				break;
			}
			ASN1_OCTET_STRING_free(octet);
		}
	}

out:
	GENERAL_NAMES_free(gs);
	ASN1_IA5STRING_free(astr);
	ASN1_OCTET_STRING_free(octet);
	return match;
}


/**
 * Finds a TLS certificate that matches a given Server Name Indication (SNI)
 *
 * @param tls TLS Context
 * @param sni Server Name Indication
 *
 * @return TLS certificate or NULL if not found
 */
struct tls_cert *tls_cert_for_sni(const struct tls *tls, const char *sni)
{
	struct tls_cert *tls_cert = NULL;
	struct le *le;
	const struct list *certs = tls_certs(tls);

	if (!list_head(certs))
		return NULL;

	if (!str_isset(sni))
		return list_head(certs)->data;

	LIST_FOREACH(certs, le) {
		X509 *x509;

		tls_cert = le->data;
		x509 = tls_cert_x509(tls_cert);
		if (!x509) {
			tls_cert = NULL;
			continue;
		}

		if (x509_match_common_name(x509, sni))
			break;

		if (x509_match_alt_name(x509, sni))
			break;

		tls_cert = NULL;
	}

	ERR_clear_error();
	return tls_cert;
}


static int ssl_servername_handler(SSL *ssl, int *al, void *arg)
{
	struct tls *tls	= arg;
	struct tls_cert *uc = NULL;
	const char *sni;

	if (!SSL_is_server(ssl))
		return SSL_TLSEXT_ERR_OK;

	sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!str_isset(sni))
		return SSL_TLSEXT_ERR_OK;

	/* find and apply matching certificate */
	uc = tls_cert_for_sni(tls, sni);
	if (!uc) {
		*al = SSL_AD_UNRECOGNIZED_NAME;
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	DEBUG_INFO("found cert for sni %s\n", sni);
	if (SSL_set_SSL_CTX(ssl, tls_cert_ctx(uc)) == NULL) {
		*al = SSL_AD_INTERNAL_ERROR;
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	return SSL_TLSEXT_ERR_OK;
}


/**
 * Enables SNI handling on the given TLS context for incoming TLS connections
 *
 * @param tls TLS Context
 */
void tls_enable_sni(struct tls *tls)
{
	SSL_CTX_set_tlsext_servername_callback(tls_ssl_ctx(tls),
					       ssl_servername_handler);
	SSL_CTX_set_tlsext_servername_arg(tls_ssl_ctx(tls), tls);
}
