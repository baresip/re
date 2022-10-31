/**
 * @file openssl/sni.h Server Name Indication (Internal API)
 *
 * Copyright (C) 2022 Commend.com - c.spielberger@commend.com
 */

struct tls_cert *tls_cert_for_sni(const struct tls *tls, const struct pl *sni);
int ssl_servername_handler(SSL *s, int *al, void *arg);
int ssl_set_verify_client(SSL *ssl, const char *host);
