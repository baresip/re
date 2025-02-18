/**
 * @file openssl/ocsp.c Online Certificate Status Protocol API
 *
 * Copyright (C) 2025 Commend.com - m.fridrich@commend.com
 */
#if defined(WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_sa.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"

#define DEBUG_MODULE "tls/ocsp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static OCSP_RESPONSE *get_ocsp_response(SSL *ssl, long *resp_len)
{
	int rsp_status;
	OCSP_RESPONSE *rsp;
	const unsigned char *ocsp_resp;
	*resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_resp);

	if (*resp_len <= 0 || !ocsp_resp)
		return NULL;

	rsp = d2i_OCSP_RESPONSE(NULL, &ocsp_resp, *resp_len);
	if (!rsp)
		return NULL;

	rsp_status = OCSP_response_status(rsp);
	if (rsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		OCSP_RESPONSE_free(rsp);
		return NULL;
	}

	return rsp;
}


static int get_certificates(SSL *ssl, X509 **cert, X509 **issuer)
{
	X509_NAME *iname;
	STACK_OF(X509) *peer_chain;

#if OPENSSL_VERSION_MAJOR >= 3
	*cert = SSL_get1_peer_certificate(ssl);
#else
	*cert = SSL_get_peer_certificate(ssl);
#endif
	if (!*cert)
		return EINVAL;

	peer_chain = SSL_get_peer_cert_chain(ssl);
	if (!peer_chain) {
		X509_free(*cert);
		*cert = NULL;
		return EINVAL;
	}

	iname = X509_get_issuer_name(*cert);
	for (int i = 0; i < sk_X509_num(peer_chain); i++) {
		X509 *c = sk_X509_value(peer_chain, i);
		if (X509_NAME_cmp(X509_get_subject_name(c), iname) == 0) {
			*issuer = X509_dup(c);
			return 0;
		}
	}

	X509_free(*cert);
	*cert = NULL;
	return EINVAL;
}


/* Verifies that the CERTSTATUS is GOOD and that the validity period is ok. */
static int verify_cert_status(OCSP_BASICRESP *br, X509 *cert, X509 *issuer)
{
	int reason;
	int cert_status;
	int ret = EPROTO;
	ASN1_GENERALIZEDTIME *revtime = NULL;
	ASN1_GENERALIZEDTIME *thisupd = NULL;
	ASN1_GENERALIZEDTIME *nextupd = NULL;

	OCSP_CERTID *certid = OCSP_cert_to_id(NULL, cert, issuer);
	if (!certid)
		return EINVAL;

	if (!OCSP_resp_find_status(br, certid, &cert_status, &reason, &revtime,
	                           &thisupd, &nextupd))
		goto cleanup;

	if (cert_status != V_OCSP_CERTSTATUS_GOOD)
		goto cleanup;

	/* Check validity period with 5-minute allowance */
	if (!OCSP_check_validity(thisupd, nextupd, 300, -1))
		goto cleanup;

	ret = 0;

cleanup:
	OCSP_CERTID_free(certid);
	return ret;
}


/* Returns 0 if OSCP status is okay. Non-zero otherwise. */
int verify_ocsp_status(SSL *ssl, enum tls_ocsp_stapling stapling_mode)
{
	long resp_len;
	int basic_verify;
	X509_STORE *store;
	STACK_OF(X509) *peer_chain;
	int err = EPROTO;
	X509 *cert = NULL;
	X509 *issuer = NULL;
	OCSP_RESPONSE *rsp = NULL;
	OCSP_BASICRESP *br = NULL;
	SSL_CTX *ctx = ssl ? SSL_get_SSL_CTX(ssl) : NULL;

	if (!stapling_mode)
		return 0;

	if (!ssl || !ctx)
		return EINVAL;

	rsp = get_ocsp_response(ssl, &resp_len);
	if (!rsp)
		return stapling_mode == TLS_OCSP_STAPLE_REQUIRED ? EPROTO : 0;

	br = OCSP_response_get1_basic(rsp);
	if (!br)
		goto cleanup;

	if (get_certificates(ssl, &cert, &issuer) != 0)
		goto cleanup;

	if (verify_cert_status(br, cert, issuer) != 0)
		goto cleanup;

	store = SSL_CTX_get_cert_store(ctx);
	peer_chain = SSL_get_peer_cert_chain(ssl);
	if (!peer_chain || !store)
		goto cleanup;

	basic_verify = OCSP_basic_verify(br, peer_chain, store, 0);
	if (!basic_verify)
		goto cleanup;

	err = 0;

cleanup:
	X509_free(cert);
	X509_free(issuer);
	OCSP_BASICRESP_free(br);
	OCSP_RESPONSE_free(rsp);

	return err;
}
