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


static int x509_match_alt_name(X509 *x509, const char *sni, bool *match)
{
	GENERAL_NAMES *gs = NULL;
	ASN1_STRING *astr = NULL;
	ASN1_OCTET_STRING *octet = NULL;
	int err = 0;

	*match = false;
	gs = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (!gs)
		return 0;

	for (int i = 0; i < sk_GENERAL_NAME_num(gs); i++) {
		GENERAL_NAME *g = sk_GENERAL_NAME_value(gs, i);

		if (g->type == GEN_DNS) {
			astr = ASN1_IA5STRING_new();
			if (!astr) {
				err = ENOMEM;
				goto out;
			}

			if (!ASN1_STRING_set(astr, sni, -1)) {
				err = ENOMEM;
				goto out;
			}

			if (!ASN1_STRING_cmp(astr, g->d.dNSName)) {
				*match = true;
				break;
			}
		}
		else if (g->type == GEN_IPADD) {
			octet = a2i_IPADDRESS(sni);
			if (!ASN1_OCTET_STRING_cmp(octet, g->d.iPAddress)) {
				*match = true;
				break;
			}
		}
	}

out:
	ASN1_IA5STRING_free(astr);
	ASN1_OCTET_STRING_free(octet);
	return err;
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
		char cn[TLSEXT_MAXLEN_host_name] = "";
		X509 *x509;
		X509_NAME *nm;
		bool match = false;
		int err;

		tls_cert = le->data;
		x509 = tls_cert_x509(tls_cert);
		if (!x509) {
			tls_cert = NULL;
			continue;
		}

		nm = X509_get_subject_name(x509);
		int n = X509_NAME_get_text_by_NID(nm, NID_commonName,
						  cn, (int) sizeof(cn));
		if (n > 0 && !str_cmp(sni, cn))
			break;

		err = x509_match_alt_name(x509, sni, &match);
		if (err) {
			tls_cert = NULL;
			break;
		}

		if (match)
			break;
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
