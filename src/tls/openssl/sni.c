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
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"
#include "sni.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#include <re_list.h>
#include <re_hash.h>


struct tls_conn;


static int x509_match_alt_name(X509 *x509, const struct pl *sni, bool *match)
{
	GENERAL_NAMES *gs = NULL;
	char *snistr;
	ASN1_STRING *astr = NULL;
	ASN1_OCTET_STRING *octet = NULL;
	int i;
	int err = 0;

	*match = false;
	gs = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (!gs)
		return 0;

	err = pl_strdup(&snistr, sni);
	if (err)
		return err;

	astr = ASN1_IA5STRING_new();
	if (!astr) {
		err = ENOMEM;
		goto out;
	}

	if (!ASN1_STRING_set(astr, snistr, -1)) {
		err = ENOMEM;
		goto out;
	}

	octet = a2i_IPADDRESS(snistr);
	for (i = 0; i < sk_GENERAL_NAME_num(gs); i++) {
		GENERAL_NAME *g = sk_GENERAL_NAME_value(gs, i);

		if (g->type == GEN_DNS) {
			if (!ASN1_STRING_cmp(astr, g->d.dNSName)) {
				*match = true;
				break;
			}
		}
		else if (g->type == GEN_IPADD) {
			if (!ASN1_OCTET_STRING_cmp(octet, g->d.iPAddress)) {
				*match = true;
				break;
			}
		}
	}

out:
	mem_deref(snistr);
	ASN1_IA5STRING_free(astr);
	ASN1_OCTET_STRING_free(octet);
	return err;
}


struct tls_cert *tls_cert_for_sni(const struct tls *tls, const struct pl *sni)
{
	struct tls_cert *tls_cert = NULL;
	struct le *le;
	int sz;
	char *cn;
	const struct list *certs = tls_certs(tls);

	if (!certs)
		return NULL;

	if (!pl_isset(sni))
		return list_head(certs)->data;

	if (sni->l >= TLSEXT_MAXLEN_host_name)
		return NULL;

	sz = (int) sni->l + 1;
	cn = mem_zalloc(sz, NULL);
	LIST_FOREACH(certs, le) {
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
		X509_NAME_get_text_by_NID(nm, NID_commonName, cn, sz);
		if (!pl_strcmp(sni, cn))
			break;

		err = x509_match_alt_name(x509, sni, &match);
		if (err) {
			tls_cert = NULL;
			break;
		}

		if (match)
			break;
	}

	mem_deref(cn);
	return tls_cert;
}


static int ssl_use_cert(SSL *ssl, struct tls_cert *uc)
{
	int err;
	long r;

#if !defined(LIBRESSL_VERSION_NUMBER)
	SSL_certs_clear(ssl);
#endif
	r = SSL_clear_chain_certs(ssl);
	if (r != 1)
		return EINVAL;

	r = SSL_use_cert_and_key(ssl, tls_cert_x509(uc), tls_cert_pkey(uc),
				 tls_cert_chain(uc), 1);
	if (r != 1)
		return EINVAL;

	err = ssl_set_verify_client(ssl, tls_cert_host(uc));
	return err;
}


int ssl_servername_handler(SSL *ssl, int *al, void *arg)
{
	struct tls *tls = arg;
	struct pl pl;
	struct tls_cert *uc = NULL;
	const char *sni;
	(void)al;

	sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!str_isset(sni))
		goto out;

	pl_set_str(&pl, sni);

	/* find and apply matching certificate */
	uc = tls_cert_for_sni(tls, &pl);
	if (!uc)
		goto out;

	(void)ssl_use_cert(ssl, uc);

out:
	return SSL_TLSEXT_ERR_OK;
}
