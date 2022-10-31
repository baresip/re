/**
 * @file openssl/tls.h TLS backend using OpenSSL (Internal API)
 *
 * Copyright (C) 2010 Creytiv.com
 */

/* also defined by wincrypt.h */
#ifdef WIN32
#undef X509_NAME
#endif

/*
 * Mapping of feature macros
 */


#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	!defined(LIBRESSL_VERSION_NUMBER)
#define SSL_state SSL_get_state
#define SSL_ST_OK TLS_ST_OK
#endif


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
typedef X509_NAME*(tls_get_certfield_h)(const X509 *);
#else
typedef X509_NAME*(tls_get_certfield_h)(X509 *);
#endif

struct tls;
struct tls_cert;

void tls_flush_error(void);
SSL_CTX *tls_ssl_ctx(const struct tls *tls);
X509 *tls_cert_x509(struct tls_cert *hc);
EVP_PKEY *tls_cert_pkey(struct tls_cert *hc);
STACK_OF(X509*) tls_cert_chain(struct tls_cert *hc);
const char *tls_cert_host(struct tls_cert *hc);
const struct list *tls_certs(const struct tls *tls);

SSL *tls_conn_ssl(struct tls_conn *tc);
struct tls *tls_conn_tls(struct tls_conn *tc);

