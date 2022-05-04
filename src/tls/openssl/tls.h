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

void tls_flush_error(void);
