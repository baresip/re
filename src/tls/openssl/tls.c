/**
 * @file openssl/tls.c TLS backend using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_main.h>
#include <re_sa.h>
#include <re_srtp.h>
#include <re_sys.h>
#include <re_tcp.h>
#include <re_tls.h>
#include <re_thread.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#include <re_list.h>
#include <re_hash.h>


struct session_reuse {
	bool enabled;
	struct hash *ht_sessions;
};

struct tls {
	SSL_CTX *ctx;
	X509 *cert;
	char *pass;          /**< password for private key             */
	bool verify_server;  /**< Enable SIP TLS server verification   */
	bool verify_client;  /**< Enable SIP TLS client verification   */
	struct session_reuse reuse;
	struct list certs;   /**< Certificates for SNI selection       */
};

/**
 * A TLS certificate with private key, certificate chain and a host name that
 * is passed to OpenSSL for the host name check
 *
 */
struct tls_cert {
	struct le le;
	SSL_CTX *ctx;
	char *host;
};


#if defined(TRACE_SSL)
/**
 * Global flag if key material must be appended to file
 */
static bool fresh_keylog_file = true;


/**
 * SSL Key logger callback function
 *
 * @param ssl  OpenSSL SSL object
 * @param line Key material in NSS format
 */
static void tls_keylogger_cb(const SSL *ssl,
	const char *line)
{
	FILE *f = NULL;

	(void) ssl;

	if (fresh_keylog_file) {
		f = fopen(TRACE_SSL, "w");
		fresh_keylog_file = false;
	}
	else {
		f = fopen(TRACE_SSL, "a");
	}

	if (!f)
		return;

	(void)re_fprintf(f, "%s\n", line);

	if (f)
		(void)fclose(f);

}
#endif


/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	SSL *ssl;
	struct tls *tls;
	struct tls_conn_d cd;
};


static void destructor(void *data)
{
	struct tls *tls = data;

	if (tls->ctx) {
		SSL_CTX_sess_set_new_cb(tls->ctx, NULL);
		SSL_CTX_sess_set_remove_cb(tls->ctx, NULL);
		SSL_CTX_free(tls->ctx);
	}

	if (tls->cert)
		X509_free(tls->cert);

	hash_flush(tls->reuse.ht_sessions);
	mem_deref(tls->reuse.ht_sessions);
	mem_deref(tls->pass);
	list_flush(&tls->certs);
}


/*The password code is not thread safe*/
static int password_cb(char *buf, int size, int rwflag, void *userdata)
{
	struct tls *tls = userdata;

	(void)rwflag;

	DEBUG_NOTICE("password callback\n");

	if (size < (int)strlen(tls->pass)+1)
		return 0;

	strncpy(buf, tls->pass, size);

	return (int)strlen(tls->pass);
}


/**
 * OpenSSL verify handler for debugging purposes. Prints only warnings in the
 * default build
 *
 * @param ok  Verification result of OpenSSL
 * @param ctx OpenSSL X509 store context set by OpenSSL
 *
 * @return passes parameter ok unchanged
 */
static int tls_verify_handler(int ok, X509_STORE_CTX *ctx)
{
	int err, depth;

	err = X509_STORE_CTX_get_error(ctx);

#if (DEBUG_LEVEL >= 6)
	char    buf[128];
	X509   *err_cert;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 128);
	DEBUG_INFO("%s: subject_name = %s\n", __func__, buf);

	X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 128);
	DEBUG_INFO("%s: issuer_name  = %s\n", __func__, buf);
#endif

	if (err) {
		depth = X509_STORE_CTX_get_error_depth(ctx);
		DEBUG_WARNING("%s: err          = %d\n", __func__, err);
		DEBUG_WARNING("%s: error_string = %s\n", __func__,
				X509_verify_cert_error_string(err));
		DEBUG_WARNING("%s: depth        = %d\n", __func__, depth);
	}

#if (DEBUG_LEVEL >= 6)
	DEBUG_INFO("tls verify ok = %d\n", ok);
#endif

	return ok;
}


static int tls_verify_idx = -1;
static once_flag oflag = ONCE_FLAG_INIT;

static void tls_init_verify_idx(void)
{
	if (tls_verify_idx > -1)
		return;

	tls_verify_idx = SSL_get_ex_new_index(0, "tls verify ud",
		NULL, NULL, NULL);
}


static int tls_ctx_alloc(SSL_CTX **ctxp, enum tls_method method,
			 const char *certf, const char *pwd, struct tls *tls)
{
	int err = 0;
	int r;
	SSL_CTX *ctx;
	int min_proto = 0;

	switch (method) {

	case TLS_METHOD_TLS:
	case TLS_METHOD_SSLV23:
		ctx	  = SSL_CTX_new(TLS_method());
		min_proto = TLS1_2_VERSION;
		break;

	case TLS_METHOD_DTLS:
	case TLS_METHOD_DTLSV1:
	case TLS_METHOD_DTLSV1_2:
		ctx = SSL_CTX_new(DTLS_method());
		break;

	default:
		DEBUG_WARNING("tls method %d not supported\n", method);
		return ENOSYS;
	}

	if (!ctx) {
		ERR_clear_error();
		return ENOMEM;
	}

	SSL_CTX_set_min_proto_version(ctx, min_proto);

	if (!certf)
		goto out;

	/* Load our keys and certificates */
	if (pwd && tls) {
		err = str_dup(&tls->pass, pwd);
		if (err)
			goto out;

		SSL_CTX_set_default_passwd_cb(ctx, password_cb);
		SSL_CTX_set_default_passwd_cb_userdata(ctx, tls);
	}

	r = SSL_CTX_use_certificate_chain_file(ctx, certf);
	if (r <= 0) {
		DEBUG_WARNING("Can't read certificate file: %s (%d)\n", certf,
			      r);
		ERR_clear_error();
		err = EINVAL;
		goto out;
	}

	r = SSL_CTX_use_PrivateKey_file(ctx, certf, SSL_FILETYPE_PEM);
	if (r <= 0) {
		DEBUG_WARNING("Can't read key file: %s (%d)\n", certf, r);
		ERR_clear_error();
		err = EINVAL;
		goto out;
	}

out:
	if (err)
		SSL_CTX_free(ctx);
	else
		*ctxp = ctx;

	return err;
}


/**
 * Allocate a new TLS context
 *
 * @param tlsp    Pointer to allocated TLS context
 * @param method  TLS method
 * @param keyfile Optional private key file
 * @param pwd     Optional password
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_alloc(struct tls **tlsp, enum tls_method method, const char *keyfile,
	      const char *pwd)
{
	struct tls *tls;
	int err;

	if (!tlsp)
		return EINVAL;

	tls = mem_zalloc(sizeof(*tls), destructor);
	if (!tls)
		return ENOMEM;

	err = tls_ctx_alloc(&tls->ctx, method, keyfile, pwd, tls);
	if (err)
		goto out;

	tls->verify_server = true;

#if defined(TRACE_SSL)
	SSL_CTX_set_keylog_callback(tls->ctx, tls_keylogger_cb);
#endif

	err = hash_alloc(&tls->reuse.ht_sessions, 256);
	if (err)
		goto out;

	call_once(&oflag, tls_init_verify_idx);

	err = 0;
 out:
	if (err)
		mem_deref(tls);
	else
		*tlsp = tls;

	return err;
}


/**
 * Set default locations for trusted CA certificates
 *
 * @param tls    TLS Context
 * @param cafile PEM file with CA certificates
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_add_ca(struct tls *tls, const char *cafile)
{
	return tls_add_cafile_path(tls, cafile, NULL);
}


/**
 * Set default file and path for trusted CA certificates
 *
 * @param tls    TLS Context
 * @param cafile PEM file with CA certificate(s)
 * @param capath Path containing CA certificates files
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_add_cafile_path(struct tls *tls, const char *cafile,
	const char *capath)
{
	if (!tls || (!cafile && !capath) || !tls->ctx)
		return EINVAL;

	if (capath && !fs_isdir(capath)) {
		return ENOTDIR;
	}

	/* Load the CAs we trust */
	if (!(SSL_CTX_load_verify_locations(tls->ctx, cafile, capath))) {

		ERR_clear_error();
		return ENOENT;
	}

	return 0;
}


/**
 * Add trusted CA certificates given as string
 *
 * @param tls    TLS Context
 * @param capem  Trusted CA as null-terminated string given in PEM format
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_add_capem(const struct tls *tls, const char *capem)
{
	X509_STORE *store;
	X509 *x509;
	BIO *bio;
	int ok;
	int err = 0;

	if (!tls || !capem || !tls->ctx)
		return EINVAL;

	store = SSL_CTX_get_cert_store(tls->ctx);
	if (!store)
		return EINVAL;

	bio  = BIO_new_mem_buf((char *)capem, (int)strlen(capem));
	if (!bio)
		return EINVAL;

	x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (!x509) {
		err = EINVAL;
		DEBUG_WARNING("Could not read certificate capem\n");
		goto out;
	}

	ok = X509_STORE_add_cert(store, x509);
	if (!ok) {
		err = EINVAL;
		DEBUG_WARNING("Could not add certificate capem\n");
	}

out:
	X509_free(x509);
	BIO_free(bio);

	return err;
}


/**
 * Add trusted CRL certificates given as string
 *
 * @param tls  TLS Context
 * @param pem  Trusted CRL as null-terminated string given in PEM format
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_add_crlpem(const struct tls *tls, const char *pem)
{
	X509_STORE *store;
	X509_CRL *crl;
	BIO *bio;
	int ok;
	int err = 0;

	if (!tls || !pem || !tls->ctx)
		return EINVAL;

	store = SSL_CTX_get_cert_store(tls->ctx);
	if (!store)
		return EINVAL;

	bio  = BIO_new_mem_buf(pem, (int)strlen(pem));
	if (!bio)
		return EINVAL;

	crl = PEM_read_bio_X509_CRL(bio, NULL, 0, NULL);
	if (!crl) {
		err = EINVAL;
		DEBUG_WARNING("Could not read certificate crlpem\n");
		goto out;
	}

	ok = X509_STORE_add_crl(store, crl);
	if (!ok) {
		err = EINVAL;
		DEBUG_WARNING("Could not add certificate crlpem\n");
	}

out:
	X509_CRL_free(crl);
	BIO_free(bio);

	return err;
}


/**
 * Set SSL verification of the certificate purpose
 *
 * @param tls     TLS Context
 * @param purpose Certificate purpose as string
 *
 * @return int    0 if success, errorcode otherwise
 */
int tls_set_verify_purpose(struct tls *tls, const char *purpose)
{
	int err;
	int i;
	const X509_PURPOSE *xptmp;

	if (!tls || !purpose)
		return EINVAL;

	i = X509_PURPOSE_get_by_sname(purpose);
	if (i < 0)
		return EINVAL;

	/* purpose index -> purpose object */
	/* purpose object -> purpose value */
	xptmp = X509_PURPOSE_get0(i);
	i = X509_PURPOSE_get_id(xptmp);
	err = SSL_CTX_set_purpose(tls->ctx, i);

	return err == 1 ? 0 : EINVAL;
}


static int tls_generate_cert(X509 **pcert, const char *cn)
{
	X509 *cert = NULL;
	X509_NAME *subj = NULL;
	int e = 0;

	if (!pcert || !cn)
		goto err;

	cert = X509_new();
	if (!cert)
		goto err;

	if (!X509_set_version(cert, 2))
		goto err;

	if (!ASN1_INTEGER_set(X509_get_serialNumber(cert), rand_u32()))
		goto err;

	subj = X509_NAME_new();
	if (!subj)
		goto err;

	if (!X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
					(unsigned char *)cn,
					(int)strlen(cn), -1, 0))
		goto err;

	if (!X509_set_issuer_name(cert, subj) ||
	    !X509_set_subject_name(cert, subj))
		goto err;

	if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600*24*365) ||
	    !X509_gmtime_adj(X509_getm_notAfter(cert),   3600*24*365*10))
		goto err;

	goto out;

 err:
	e = 1;

 out:
	if (e)
		X509_free(cert);
	else
		*pcert = cert;

	X509_NAME_free(subj);
	return e;
}


/**
 * Create a selfsigned X509 certificate using EC
 *
 * @param tls      TLS Contect
 * @param cn       Common Name
 * @param curve_n  Known EC curve name
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_selfsigned_ec(struct tls *tls, const char *cn, const char *curve_n)
{
#ifndef OPENSSL_VERSION_MAJOR
	EC_KEY *eckey = NULL;
	int eccgrp;
#endif
	EVP_PKEY *key = NULL;
	X509 *cert = NULL;
	int r, err = ENOMEM;

	if (!tls || !cn)
		return EINVAL;

#if OPENSSL_VERSION_MAJOR >= 3
	key = EVP_EC_gen(curve_n);
	if (!key) {
		err = ENOTSUP;
		goto out;
	}
#else
	eccgrp = OBJ_txt2nid(curve_n);
	if (eccgrp == NID_undef)
		return ENOTSUP;


	eckey = EC_KEY_new_by_curve_name(eccgrp);
	if (!eckey)
		goto out;

	if (!EC_KEY_generate_key(eckey))
		goto out;

	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	key = EVP_PKEY_new();
	if (!key)
		goto out;

	if (!EVP_PKEY_set1_EC_KEY(key, eckey))
		goto out;
#endif /* OPENSSL_VERSION_MAJOR */

	if (tls_generate_cert(&cert, cn))
		goto out;

	if (!X509_set_pubkey(cert, key))
		goto out;

	if (!X509_sign(cert, key, EVP_sha256()))
		goto out;

	r = SSL_CTX_use_certificate(tls->ctx, cert);
	if (r != 1)
		goto out;

	r = SSL_CTX_use_PrivateKey(tls->ctx, key);
	if (r != 1)
		goto out;

	if (tls->cert)
		X509_free(tls->cert);

	tls->cert = cert;
	cert = NULL;

	err = 0;

 out:
#ifndef OPENSSL_VERSION_MAJOR
	if (eckey)
		EC_KEY_free(eckey);
#endif
	if (key)
		EVP_PKEY_free(key);
	if (cert)
		X509_free(cert);


	return err;
}


/**
 * Set the certificate and private key on a TLS context
 *
 * @param tls      TLS Context
 * @param cert     Certificate
 * @param pkey     Private key
 * @param up_ref   If true, increment reference count of the certificate if
 *                 successfully set.
 *                 If false, the reference count is not incremented and
 *                 the ownership of the certificate is passed to the TLS
 *                 context.
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_certificate_openssl(struct tls *tls, X509* cert, EVP_PKEY* pkey,
				bool up_ref)
{
	int r, err = ENOMEM;

	if (!tls || !cert || !pkey)
		return EINVAL;

	r = SSL_CTX_use_certificate(tls->ctx, cert);
	if (r != 1)
		goto out;

	r = SSL_CTX_use_PrivateKey(tls->ctx, pkey);
	if (r != 1) {
		DEBUG_WARNING("set_certificate_openssl: use_PrivateKey"
			      " failed\n");
		goto out;
	}

	if (tls->cert)
		X509_free(tls->cert);

	tls->cert = cert;

	if (up_ref)
		X509_up_ref(tls->cert);

	err = 0;

out:
	if (err)
		ERR_clear_error();

	return err;
}

/**
 * Set the certificate and private key on a TLS context
 *
 * @param tls      TLS Context
 * @param cert     Certificate in PEM format
 * @param len_cert Length of certificate PEM string
 * @param key      Private key in PEM format, will be read from cert if NULL
 * @param len_key  Length of private key PEM string
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_certificate_pem(struct tls *tls, const char *cert, size_t len_cert,
			    const char *key, size_t len_key)
{
	BIO *bio = NULL, *kbio = NULL;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	int r, err = ENOMEM;

	if (!tls || !cert || !len_cert || (key && !len_key))
		return EINVAL;

	if (!key) {
		key = cert;
		len_key = len_cert;
	}

	bio  = BIO_new_mem_buf((char *)cert, (int)len_cert);
	kbio = BIO_new_mem_buf((char *)key, (int)len_key);
	if (!bio || !kbio)
		goto out;

	x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
	pkey = PEM_read_bio_PrivateKey(kbio, NULL, 0, NULL);
	if (!x509 || !pkey)
		goto out;

	r = SSL_CTX_use_certificate(tls->ctx, x509);
	if (r != 1)
		goto out;

	r = SSL_CTX_use_PrivateKey(tls->ctx, pkey);
	if (r != 1) {
		DEBUG_WARNING("set_certificate_pem: use_PrivateKey failed\n");
		goto out;
	}

	if (tls->cert)
		X509_free(tls->cert);

	tls->cert = x509;
	x509 = NULL;

	err = 0;

 out:
	if (x509)
		X509_free(x509);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (bio)
		BIO_free(bio);
	if (kbio)
		BIO_free(kbio);
	if (err)
		ERR_clear_error();

	return err;
}


/**
 * Set the certificate and private key on a TLS context
 *
 * @param tls TLS Context
 * @param pem Certificate and private key in PEM format
 * @param len Length of PEM string
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_certificate(struct tls *tls, const char *pem, size_t len)
{
	return tls_set_certificate_pem(tls, pem, len, NULL, 0);
}


static int verify_trust_all(int ok, X509_STORE_CTX *ctx)
{
	(void)ok;
	(void)ctx;

	return 1;    /* We trust the certificate from peer */
}


/**
 * Set TLS server context to request certificate from peer
 * and set trust all certificates of peer.
 *
 * @param tls    TLS Context
 */
void tls_set_verify_client_trust_all(struct tls *tls)
{
	if (!tls)
		return;

	SSL_CTX_set_verify_depth(tls->ctx, 0);
	SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
			   verify_trust_all);
}


static int tls_verify_handler_ud(int ok, X509_STORE_CTX *ctx)
{
	int ret = ok;
	struct tls_conn_d *d;
	SSL *ssl;
	int err, depth;

	err = X509_STORE_CTX_get_error(ctx);

#if (DEBUG_LEVEL >= 6)
	char    buf[128];
	X509   *err_cert;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 128);
	DEBUG_INFO("%s: subject_name = %s\n", __func__, buf);

	X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 128);
	DEBUG_INFO("%s: issuer_name  = %s\n", __func__, buf);
#endif
	if (err) {
		depth = X509_STORE_CTX_get_error_depth(ctx);
		DEBUG_WARNING("%s: err          = %d\n", __func__, err);
		DEBUG_WARNING("%s: error_string = %s\n", __func__,
				X509_verify_cert_error_string(err));
		DEBUG_WARNING("%s: depth        = %d\n", __func__, depth);
	}

#if (DEBUG_LEVEL >= 6)
	DEBUG_INFO("tls_verify_handler ok = %d\n", ok);
#endif

	ssl = X509_STORE_CTX_get_ex_data(ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());

	if (!ssl) {
		DEBUG_WARNING("X509_STORE_CTX_get_ex_data (SSL*) failed\n");
		return ret;
	}

	d = SSL_get_ex_data(ssl, tls_verify_idx);
	if (!d) {
		DEBUG_WARNING("SSL_get_app_data (struct tls_conn_d) failed\n");
		return ret;
	}

	if (d->verifyh)
		ret = d->verifyh(ok, d->arg);

	return ret;
}


/**
 * Enable request certificate from peer in TLS server connection
 * Set verify handler.
 *
 * @param tc      TLS connection
 * @param depth   Max depth certificate chain accepted.
 *                A negative depth uses default depth.
 * @param verifyh SSL verify handler. If NULL default verify handler is used.
 * @param arg     Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_verify_client_handler(struct tls_conn *tc, int depth,
	int (*verifyh) (int ok, void *arg), void *arg)
{
	int err = 0;
	SSL_verify_cb tls_cb = tls_verify_handler_ud;
	if (!tc)
		return EINVAL;

	if (!verifyh) {
		tls_cb = tls_verify_handler;
	}
	else {
		tc->cd.verifyh = verifyh;
		tc->cd.arg = arg;
		SSL_set_ex_data(tc->ssl, tls_verify_idx, &tc->cd);
	}

	SSL_set_verify_depth(tc->ssl, depth < 0 ?
		SSL_get_verify_depth(tc->ssl) : depth);
	SSL_set_verify(tc->ssl, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
		tls_cb);

	return err;
}


/**
 * Set SRTP suites on TLS context
 *
 * @param tls    TLS Context
 * @param suites Secure-RTP Profiles
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_srtp(struct tls *tls, const char *suites)
{
	if (!tls || !suites)
		return EINVAL;

	if (0 != SSL_CTX_set_tlsext_use_srtp(tls->ctx, suites)) {
		ERR_clear_error();
		return ENOSYS;
	}

	return 0;
}


static int cert_fingerprint(X509 *cert, enum tls_fingerprint type,
			    uint8_t *md, size_t size)
{
	unsigned int len = (unsigned int)size;
	int n;

	switch (type) {

	case TLS_FINGERPRINT_SHA256:
		if (size < 32)
			return EOVERFLOW;

		n = X509_digest(cert, EVP_sha256(), md, &len);
		break;

	default:
		return ENOSYS;
	}

	if (n != 1) {
		ERR_clear_error();
		return ENOENT;
	}

	return 0;
}


/**
 * Get fingerprint of local certificate
 *
 * @param tls  TLS Context
 * @param type Digest type
 * @param md   Buffer for fingerprint digest
 * @param size Buffer size
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_fingerprint(const struct tls *tls, enum tls_fingerprint type,
		    uint8_t *md, size_t size)
{
	if (!tls || !tls->cert || !md)
		return EINVAL;

	return cert_fingerprint(tls->cert, type, md, size);
}


/**
 * Get fingerprint of peer certificate of a TLS connection
 *
 * @param tc   TLS Connection
 * @param type Digest type
 * @param md   Buffer for fingerprint digest
 * @param size Buffer size
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_peer_fingerprint(const struct tls_conn *tc, enum tls_fingerprint type,
			 uint8_t *md, size_t size)
{
	X509 *cert;
	int err;

	if (!tc || !md)
		return EINVAL;

#if OPENSSL_VERSION_MAJOR >= 3
	cert = SSL_get1_peer_certificate(tc->ssl);
#else
	cert = SSL_get_peer_certificate(tc->ssl);
#endif
	if (!cert)
		return ENOENT;

	err = cert_fingerprint(cert, type, md, size);

	X509_free(cert);

	return err;
}


/**
 * Get common name of peer certificate of a TLS connection
 *
 * @param tc   TLS Connection
 * @param cn   Returned common name
 * @param size Size of common name
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_peer_common_name(const struct tls_conn *tc, char *cn, size_t size)
{
	X509 *cert;
	int n;

	if (!tc || !cn || !size)
		return EINVAL;

#if OPENSSL_VERSION_MAJOR >= 3
	cert = SSL_get1_peer_certificate(tc->ssl);
#else
	cert = SSL_get_peer_certificate(tc->ssl);
#endif
	if (!cert)
		return ENOENT;

	n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
				      NID_commonName, cn, (int)size);

	X509_free(cert);

	if (n < 0) {
		ERR_clear_error();
		return ENOENT;
	}

	return 0;
}


/**
 * Verify peer certificate of a TLS connection
 *
 * @param tc TLS Connection
 *
 * @return 0 if verified, otherwise errorcode
 */
int tls_peer_verify(const struct tls_conn *tc)
{
	if (!tc)
		return EINVAL;

	if (SSL_get_verify_result(tc->ssl) != X509_V_OK)
		return EAUTH;

	return 0;
}


/**
 * Get SRTP suite and keying material of a TLS connection
 *
 * @param tc           TLS Connection
 * @param suite        Returned SRTP suite
 * @param cli_key      Client key
 * @param cli_key_size Client key size
 * @param srv_key      Server key
 * @param srv_key_size Server key size
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_srtp_keyinfo(const struct tls_conn *tc, enum srtp_suite *suite,
		     uint8_t *cli_key, size_t cli_key_size,
		     uint8_t *srv_key, size_t srv_key_size)
{
	static const char *label = "EXTRACTOR-dtls_srtp";
	size_t key_size, salt_size, size;
	SRTP_PROTECTION_PROFILE *sel;
	uint8_t keymat[256], *p;

	if (!tc || !suite || !cli_key || !srv_key)
		return EINVAL;

	sel = SSL_get_selected_srtp_profile(tc->ssl);
	if (!sel)
		return ENOENT;

	switch (sel->id) {

	case SRTP_AES128_CM_SHA1_80:
		*suite = SRTP_AES_CM_128_HMAC_SHA1_80;
		key_size  = 16;
		salt_size = 14;
		break;

	case SRTP_AES128_CM_SHA1_32:
		*suite = SRTP_AES_CM_128_HMAC_SHA1_32;
		key_size  = 16;
		salt_size = 14;
		break;

#ifdef SRTP_AEAD_AES_128_GCM
	case SRTP_AEAD_AES_128_GCM:
		*suite = SRTP_AES_128_GCM;
		key_size  = 16;
		salt_size = 12;
		break;
#endif

#ifdef SRTP_AEAD_AES_256_GCM
	case SRTP_AEAD_AES_256_GCM:
		*suite = SRTP_AES_256_GCM;
		key_size  = 32;
		salt_size = 12;
		break;
#endif

	default:
		return ENOSYS;
	}

	size = key_size + salt_size;

	if (cli_key_size < size || srv_key_size < size)
		return EOVERFLOW;

	if (sizeof(keymat) < 2*size)
		return EOVERFLOW;

	if (1 != SSL_export_keying_material(tc->ssl, keymat, 2*size, label,
					    strlen(label), NULL, 0, 0)) {
		ERR_clear_error();
		return ENOENT;
	}

	p = keymat;

	memcpy(cli_key,            p, key_size);  p += key_size;
	memcpy(srv_key,            p, key_size);  p += key_size;
	memcpy(cli_key + key_size, p, salt_size); p += salt_size;
	memcpy(srv_key + key_size, p, salt_size);

	mem_secclean(keymat, sizeof(keymat));

	return 0;
}


/**
 * Get cipher name of a TLS connection
 *
 * @param tc TLS Connection
 *
 * @return name of cipher actually used.
 */
const char *tls_cipher_name(const struct tls_conn *tc)
{
	if (!tc)
		return NULL;

	return SSL_get_cipher_name(tc->ssl);
}


/**
 * Set the ciphers to use for this TLS context
 *
 * @param tls      TLS Context
 * @param cipherv  Vector of cipher names, in order of priority
 * @param count    Number of cipher names in the vector
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_ciphers(struct tls *tls, const char *cipherv[], size_t count)
{
	struct mbuf *mb;
	int r, err;
	size_t i;

	if (!tls || !cipherv || !count)
		return EINVAL;

	mb = mbuf_alloc(32 * count);
	if (!mb)
		return ENOMEM;

	for (i=0; i<count; i++) {

		err = mbuf_printf(mb, "%s%s", i>0 ? ":" : "", cipherv[i]);
		if (err)
			goto out;
	}

	err = mbuf_write_u8(mb, '\0');
	if (err)
		goto out;

	r = SSL_CTX_set_cipher_list(tls->ctx, (char *)mb->buf);
	if (r <= 0) {
		ERR_clear_error();
		err = EPROTO;
		goto out;
	}

 out:
	mem_deref(mb);

	return err;
}


/**
 * Enable verification of server certificate and hostname (SNI)
 *
 * @param tc   TLS Connection
 * @param host Server hostname
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_verify_server(struct tls_conn *tc, const char *host)
{
	struct sa sa;

	if (!tc || !host)
		return EINVAL;

	if (!tc->tls->verify_server)
		return 0;

	if (sa_set_str(&sa, host, 0)) {
		SSL_set_hostflags(tc->ssl,
				X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

		if (!SSL_set1_host(tc->ssl, host)) {
			DEBUG_WARNING("SSL_set1_host error\n");
			ERR_clear_error();
			return EPROTO;
		}

		if (!SSL_set_tlsext_host_name(tc->ssl, host)) {
			DEBUG_WARNING("SSL_set_tlsext_host_name error\n");
			ERR_clear_error();
			return EPROTO;
		}
	}

	SSL_set_verify(tc->ssl, SSL_VERIFY_PEER, tls_verify_handler);

	return 0;
}


/**
 * Enable verification of client certificate
 *
 * @param tc   TLS Connection
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_verify_client(struct tls_conn *tc)
{
	if (!tc)
		return EINVAL;

	if (!tc->tls->verify_client)
		return 0;

	SSL_set_verify(tc->ssl, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
		       tls_verify_handler);

	return 0;
}


static int print_error(const char *str, size_t len, void *unused)
{
	(void)unused;
	DEBUG_WARNING("%b", str, len);

	return 1;
}


void tls_flush_error(void)
{
	ERR_print_errors_cb(print_error, NULL);
}


/**
 * Convert a X509_NAME object into a human-readable form placed in an mbuf
 *
 * @param field  X509_NAME of Cert field
 * @param mb     Memorybuffer to store the readable format
 * @param flags  X509_NAME_print_ex flags
 *
 * @return 0 if success, otherwise errorcode
 */
static int convert_X509_NAME_to_mbuf(X509_NAME *field, struct mbuf *mb,
	unsigned long flags)
{
	BIO *outbio;
	char *p;
	long size;
	int err = ENOMEM;

	if (!field || !mb)
		return EINVAL;

	outbio = BIO_new(BIO_s_mem());
	if (!outbio)
		return ENOMEM;

	if (X509_NAME_print_ex(outbio, field, 1, flags) <= 0)
		goto out;

	if (BIO_eof(outbio))
		goto out;

	size = BIO_get_mem_data(outbio, &p);
	err = mbuf_write_mem(mb, (uint8_t *)p, size);
	if (err)
		goto out;

	err = 0;

 out:
	if (outbio)
		BIO_free(outbio);

	return err;
}


/**
 * Extract a X509 certificate issuer/subject and write the result into an mbuf
 *
 * @param tls           TLS Object
 * @param mb            Memory buffer
 * @param field_getter  Functionpointer to the X509 getter function
 * @param flags         X509_NAME_print_ex flags
 *
 * @return 0 if success, otherwise errorcode
 */
static int tls_get_ca_chain_field(struct tls *tls, struct mbuf *mb,
	tls_get_certfield_h *field_getter, unsigned long flags)
{
	X509 *crt = NULL;
	X509_NAME *field;

	crt = SSL_CTX_get0_certificate(tls->ctx);
	if (!crt)
		return ENOENT;

	field = field_getter(crt);
	if (!field)
		return ENOTSUP;

	return convert_X509_NAME_to_mbuf(field, mb, flags);
}


/**
 * Get the issuers fields of a certificate chain
 *
 * @param tls  TLS Object
 * @param mb   Memory Buffer
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_get_issuer(struct tls *tls, struct mbuf *mb)
{
	if (!tls || !tls->ctx || !mb)
		return EINVAL;

	return tls_get_ca_chain_field(tls, mb, &X509_get_issuer_name,
		XN_FLAG_RFC2253);
}


/**
 * Get the subject fields of a certificate chain
 *
 * @param tls  TLS Object
 * @param mb   Memory Buffer
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_get_subject(struct tls *tls, struct mbuf *mb)
{
	if (!tls || !tls->ctx || !mb)
		return EINVAL;

	return tls_get_ca_chain_field(tls, mb, &X509_get_subject_name,
		XN_FLAG_RFC2253);
}


/**
 * Disables SIP TLS server verifications for following requests
 *
 * @param tls     TLS Object
 */
void tls_disable_verify_server(struct tls *tls)
{
	if (!tls)
		return;

	tls->verify_server = false;
}


/**
 * Enables SIP TLS client verifications for following requests
 *
 * @param tls     TLS Object
 * @param enable  true to enable client verification, false to disable
 */
void tls_enable_verify_client(struct tls *tls, bool enable)
{
	if (!tls)
		return;

	tls->verify_client = enable;
}


/**
 * Set minimum TLS version
 *
 * @param tls     TLS Object
 * @param version Minimum version, e.g.: TLS1_2_VERSION
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_min_proto_version(struct tls *tls, int version)
{
	if (!tls)
		return EINVAL;

	if (SSL_CTX_set_min_proto_version(tls->ctx, version))
		return 0;

	return EACCES;
}


/**
 * Set maximum TLS version
 *
 * @param tls     TLS Object
 * @param version Maximum version, e.g. TLS1_2_VERSION
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_max_proto_version(struct tls *tls, int version)
{
	if (!tls)
		return EINVAL;

	if (SSL_CTX_set_max_proto_version(tls->ctx, version))
		return 0;

	return EACCES;
}


struct session_entry {
	struct le le;
	struct sa peer;
	SSL_SESSION *sess;
};


static void session_destructor(void *arg)
{
	struct session_entry *e = arg;

	hash_unlink(&e->le);
	if (e->sess)
		SSL_SESSION_free(e->sess);
}


static bool session_cmp_handler(struct le *le, void *arg)
{
	const struct session_entry *s = le->data;
	if (!s)
		return false;

	return sa_cmp(&s->peer, arg, SA_ALL);
}


static int tls_session_update_cache(const struct tls_conn *tc,
	SSL_SESSION *sess)
{
	struct sa peer;
	struct session_entry* e = NULL;
	int err = 0;

	if (!tc || !tc->tls) {
		DEBUG_WARNING("%s: no tc or tls.\n", __func__);
		return EINVAL;
	}

	err = tcp_conn_peer_get(tls_get_tcp_conn(tc), &peer);
	if (err) {
		DEBUG_WARNING("%s: tcp_conn_peer_get failed: (%m).\n",
			__func__, err);
		return ENODATA;
	}

	e = list_ledata(hash_lookup(tc->tls->reuse.ht_sessions,
					     sa_hash(&peer, SA_ALL),
					     session_cmp_handler, &peer));
	mem_deref(e);

#if !defined(LIBRESSL_VERSION_NUMBER)
	if (!SSL_SESSION_is_resumable(sess)) {
		return EINVAL;
	}
#endif

	e = mem_zalloc(sizeof(struct session_entry), session_destructor);
	if (!e) {
		DEBUG_WARNING("%s: error allocating session_entry.\n",
			__func__);
		return ENOMEM;
	}

	sa_cpy(&e->peer, &peer);
	e->sess = sess;

	hash_append(tc->tls->reuse.ht_sessions, sa_hash(&e->peer, SA_ALL),
		&e->le, e);

	return err;
}


static int session_new_cb(struct ssl_st *ssl, SSL_SESSION *sess)
{
	BIO *wbio = NULL;
	const struct tls_conn *tc = NULL;

	wbio = SSL_get_wbio(ssl);
	if (!wbio) {
		DEBUG_WARNING("%s: SSL_get_rbio failed.\n", __func__);
		return 0;
	}

	tc = BIO_get_data(wbio);
	if (!tc) {
		DEBUG_WARNING("%s: BIO_get_data tc failed.\n", __func__);
		return 0;
	}

	if (tls_session_update_cache(tc, sess))
		return 0;

	if (!SSL_SESSION_set_ex_data(sess, 0, tc->tls)) {
		DEBUG_WARNING("%s: SSL_SESSION_set_ex_data failed.\n",
			__func__);
		return 0;
	}

	/* openssl will increments reference counter of sess on 1 */
	return 1;
}


static bool remove_handler(struct le *le, void *arg)
{
	struct session_entry *e = le->data;
	if (!e || !arg)
		return false;

	if (e->sess == arg)
		mem_deref(e);

	return false;
}


static void session_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
	struct tls *tls = SSL_SESSION_get_ex_data(sess, 0);
	(void) ctx;
	if (!tls) {
		DEBUG_WARNING("%s: SSL_SESSION_get_ex_data failed.\n",
			__func__);
		return;
	}

	/* iterate over all hash table entries and search for session */
	(void) hash_apply(tls->reuse.ht_sessions, remove_handler, sess);
}


/**
 * Enable/disable TLS session cache.
 *
 * @param tls  TLS Object
 * @param enabled   enabled or disable session cache. Default: disabled
 *
 * Note: session reuse in TLSv1.3 is not yet supported
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_session_reuse(struct tls *tls, int enabled)
{
	if (!tls)
		return EINVAL;

	tls->reuse.enabled = enabled;

	SSL_CTX_set_session_cache_mode(tls->ctx, enabled ?
		SSL_SESS_CACHE_BOTH : SSL_SESS_CACHE_OFF);

	if (!tls->reuse.enabled)
		return 0;

	SSL_CTX_sess_set_new_cb(tls->ctx, session_new_cb);
	SSL_CTX_sess_set_remove_cb(tls->ctx, session_remove_cb);

	return 0;
}


/**
 * Check if session was reused
 *
 * @param tc  tlc connection object
 *
 * @return 1 reused, 0 otherwise
 */
bool tls_session_reused(const struct tls_conn *tc)
{
	if (!tc)
		return false;

	return SSL_session_reused(tc->ssl);
}


/**
 * getter for session reuse enabled
 *
 * @param tc  tlc connection object
 *
 * @return 1 enabled, 0 disabled
 */
bool tls_get_session_reuse(const struct tls_conn *tc)
{
	if (!tc)
		return false;

	return tc->tls->reuse.enabled;
}


/**
 * Reuse session if possible
 *
 * @param tc  tlc connection object
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_reuse_session(const struct tls_conn *tc)
{
	int err = 0;
	struct sa peer;
	struct session_entry *sess = NULL;
	if (!tc || !tc->tls)
		return EINVAL;

	err = tcp_conn_peer_get(tls_get_tcp_conn(tc), &peer);
	if (err) {
		DEBUG_WARNING("%s: tcp_conn_peer_get failed: (%m).\n",
			__func__, err);
		return 0;
	}

	sess = list_ledata(hash_lookup(tc->tls->reuse.ht_sessions,
					     sa_hash(&peer, SA_ALL),
					     session_cmp_handler, &peer));

	if (sess && !SSL_set_session(tc->ssl, sess->sess)) {
		err = EFAULT;
		DEBUG_WARNING("%s: error: %m, ssl_err=%d\n", __func__, err,
			SSL_get_error(tc->ssl, err));
	}

	return err;
}


/**
 * update session cache manually
 *
 * @param tc  tlc connection object
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_update_sessions(const struct tls_conn *tc)
{
	int err = 0;
	SSL_SESSION *sess = NULL;
	if (!tc || !tc->tls)
		return EINVAL;

	sess = SSL_get1_session(tc->ssl);
	if (!sess)
		return EINVAL;

	err = tls_session_update_cache(tc, sess);
	if (err)
		SSL_SESSION_free(sess);

	return err;
}


/**
 * Reuse session if possible
 *
 * @param tls  tls connection object
 *
 * @return SSL_CTX* if set or NULL otherwise
 */
SSL_CTX *tls_ssl_ctx(const struct tls *tls)
{
	if (!tls)
		return NULL;

	return tls->ctx;
}


static void tls_cert_destructor(void *arg)
{
	struct tls_cert *uc = arg;

	mem_deref(uc->host);
	if (uc->ctx)
		SSL_CTX_free(uc->ctx);
}


/**
 * Adds a certificate for Server Name Indication (SNI) based certificate
 * selection. An incoming client hello may contain an SNI extension which
 * is used to select a local server certificate
 *
 * @param tls   TLS context
 * @param certf Filename of the certificate
 * @param host  Hostname that should match the SNI from client hello
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_add_certf(struct tls *tls, const char *certf, const char *host)
{
	struct tls_cert *uc;
	int err = 0;

	if (!tls || !certf)
		return EINVAL;

	uc = mem_zalloc(sizeof(*uc), tls_cert_destructor);
	if (!uc)
		return ENOMEM;

	if (str_isset(host)) {
		err = str_dup(&uc->host, host);
		if (err)
			goto err;
	}

	err = tls_ctx_alloc(&uc->ctx, TLS_METHOD_TLS, certf, NULL, NULL);
	if (err)
		goto err;

	X509_STORE *ca = SSL_CTX_get_cert_store(tls->ctx);
	if (ca) {
		X509_STORE_up_ref(ca);
		SSL_CTX_set_cert_store(uc->ctx, ca);
	}

	list_append(&tls->certs, &uc->le, uc);
	if (list_count(&tls->certs) == 1)
		tls_enable_sni(tls);

	return 0;

err:
	ERR_clear_error();
	mem_deref(uc);

	return err;
}


/**
 * Returns the X509 of the TLS certificate
 *
 * @param hc  TLS certificate
 *
 * @return The OpenSSL X509
 */
X509 *tls_cert_x509(struct tls_cert *hc)
{
	return hc ? SSL_CTX_get0_certificate(hc->ctx) : NULL;
}


SSL_CTX *tls_cert_ctx(struct tls_cert *hc) {

	return hc ? hc->ctx : NULL;
}

/**
 * Returns the host name of the TLS certificate
 *
 * @param hc  TLS certificate
 *
 * @return The host name
 */
const char *tls_cert_host(struct tls_cert *hc)
{
	return hc ? hc->host : NULL;
}


/**
 * Returns the list of TLS certificates
 *
 * @param tls TLS context
 *
 * @return The list
 */
const struct list *tls_certs(const struct tls *tls)
{
	return tls ? &tls->certs : NULL;
}


/**
 * Enable/disable posthandshake
 * Only on client side for TLSv1.3
 *
 * @param tls  tls object
 * @param value posthandshake auth value. 1 enabled, Default: 0
 *
 */
void tls_set_posthandshake_auth(struct tls *tls, int value)
{
	if (!tls)
		return;

	SSL_CTX_set_post_handshake_auth(tls->ctx, value);
}


/**
 * Request client certificate using post handshake
 * Only on client side for TLSv1.3
 *
 * @param tc  tls connection
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_verify_client_post_handshake(struct tls_conn *tc)
{
	int ret;
	int err = 0;
	if (!tc || !tc->ssl)
		return EINVAL;

	if (!(ret=SSL_verify_client_post_handshake(tc->ssl))) {
		err = EFAULT;
		DEBUG_WARNING("SSL_verify_client_post_handshake error: "\
			"%m, ssl_err=%d\n", err, SSL_get_error(tc->ssl, ret));
		ERR_clear_error();
		return err;
	}

	if (!(ret = SSL_do_handshake(tc->ssl))) {
		err = EIO;
		DEBUG_WARNING("SSL_do_handshake error: "\
			"%m, ssl_err=%d\n", err, SSL_get_error(tc->ssl, ret));
		ERR_clear_error();
	}

	return err;
}


/**
 * Set TLS session resumption mode
 *
 * @param tls  TLS Object
 * @param mode TLS session resumption mode
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_set_resumption(struct tls *tls, enum tls_resume_mode mode)
{
	long ok = 1;

	if (!tls)
		return EINVAL;

	if (mode & TLS_RESUMPTION_IDS) {
		ok = SSL_CTX_set_session_cache_mode(tls->ctx,
						    SSL_SESS_CACHE_SERVER);
	}
	else {
		ok = SSL_CTX_set_session_cache_mode(tls->ctx,
						    SSL_SESS_CACHE_OFF);
	}

	if (mode & TLS_RESUMPTION_TICKETS) {
		ok |= SSL_CTX_clear_options(tls->ctx, SSL_OP_NO_TICKET);
		ok |= SSL_CTX_set_num_tickets(tls->ctx, 2);
	}
	else {
		ok |= SSL_CTX_set_options(tls->ctx, SSL_OP_NO_TICKET);
		ok |= SSL_CTX_set_num_tickets(tls->ctx, 0);
	}

	if (!ok) {
		ERR_clear_error();
		return EFAULT;
	}

	return 0;
}


/**
 * Change used certificate+key of an existing SSL object
 *
 * @param tls       TLS Object
 * @param chain     Cert (chain) + Key in PEM format
 * @param len_chain Length of certificate + key PEM string
 *
 * @return int 0 if success, otherwise errorcode
 */
int tls_set_certificate_chain_pem(struct tls *tls, const char *chain,
				  size_t len_chain)
{
	STACK_OF(X509) *cert_stack = NULL;
	BIO *bio_mem = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *leaf_cert = NULL;
	int err = ENOMEM;

	if (!tls || !chain || !len_chain)
		return EINVAL;

	bio_mem = BIO_new_mem_buf(chain, (int)len_chain);
	cert_stack = sk_X509_new_null();
	if (!bio_mem || !cert_stack)
		goto out;

	X509 *cert;
	while ((cert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL)) != NULL) {
		int n = sk_X509_push(cert_stack, cert);
		if (n < 1) {
			X509_free(cert);
			goto out;
		}
	}

	err = EINVAL;

	if (sk_X509_num(cert_stack) == 0)
		goto out;

	leaf_cert = sk_X509_shift(cert_stack);
	long ok = SSL_CTX_use_certificate(tls->ctx, leaf_cert);
	if (ok <= 0) {
		X509_free(leaf_cert);
		goto out;
	}

	if (sk_X509_num(cert_stack)) {
		ok = SSL_CTX_clear_chain_certs(tls->ctx);
		if (!ok)
			goto out;

		while((cert = sk_X509_shift(cert_stack)) != NULL){
			ok = SSL_CTX_add0_chain_cert(tls->ctx, cert);
			if (!ok) {
				X509_free(cert);
				goto out;
			}
		}
	}

	BIO_free(bio_mem);
	bio_mem = BIO_new_mem_buf(chain, (int)len_chain);
	if (!bio_mem) {
		err = ENOMEM;
		goto out;
	}

	pkey = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);
	if (!pkey)
		goto out;

	ok = SSL_CTX_use_PrivateKey(tls->ctx, pkey);
	if (ok <= 0) {
		err = EKEYREJECTED;
		goto out;
	}

	ok = SSL_CTX_check_private_key(tls->ctx);
	if (ok <= 0)
		goto out;

	if (tls->cert)
		X509_free(tls->cert);

	tls->cert = leaf_cert;
	leaf_cert = NULL;

	err = 0;

out:
	if (bio_mem)
		BIO_free(bio_mem);
	if (leaf_cert)
		X509_free(leaf_cert);
	if (cert_stack)
		sk_X509_pop_free(cert_stack, X509_free);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (err)
		ERR_clear_error();

	return err;
}


/**
 * Change used certificate+key of an existing SSL object
 *
 * @param tls  TLS Object
 * @param path Path to Cert (chain) + Key file (PEM format)
 *
 * @return int 0 if success, otherwise errorcode
 */
int tls_set_certificate_chain(struct tls *tls, const char *path)
{
	X509 *cert;
	int ok = 0;

	if (!tls || !path)
		return EINVAL;

	ok = SSL_CTX_use_certificate_chain_file(tls->ctx, path);
	if (ok <= 0) {
		ERR_clear_error();
		return ENOENT;
	}

	ok = SSL_CTX_use_PrivateKey_file(tls->ctx, path, SSL_FILETYPE_PEM);
	if (ok <= 0) {
		ERR_clear_error();
		return EKEYREJECTED;
	}

	cert = SSL_CTX_get0_certificate(tls->ctx);
	if (!cert) {
		ERR_clear_error();
		return ENOENT;
	}

	X509_up_ref(cert);

	if (tls->cert)
		X509_free(tls->cert);

	tls->cert = cert;

	return 0;
}
