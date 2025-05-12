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

#if defined(LIBRESSL_VERSION_NUMBER)
typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);
#else
#define SSL_state SSL_get_state
#define SSL_ST_OK TLS_ST_OK
#endif

typedef X509_NAME*(tls_get_certfield_h)(const X509 *);

struct tls;
struct tls_cert;

void tls_flush_error(void);
SSL_CTX *tls_ssl_ctx(const struct tls *tls);
X509 *tls_cert_x509(struct tls_cert *hc);
SSL_CTX *tls_cert_ctx(struct tls_cert *hc);

const char *tls_cert_host(struct tls_cert *hc);
const struct list *tls_certs(const struct tls *tls);

struct tls_cert *tls_cert_for_sni(const struct tls *tls, const char *sni);
void tls_enable_sni(struct tls *tls);
