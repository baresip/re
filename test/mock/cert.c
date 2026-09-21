/**
 * @file cert.c  TLS Certificate
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include "test.h"


/**
 * X509/PEM certificate with ECDSA keypair
 *
 * Subject/issuer CN and subjectAltName are both set to 127.0.0.1, so that
 * this certificate can be used to verify a TLS server identified by that
 * IP address (OpenSSL never falls back to the CN for IP address checks,
 * only to a matching iPAddress entry in the subjectAltName extension).
 *
 * NOTE: keep this in sync with test/data/server-ecdsa.pem -- both must be
 *       the exact same certificate/key, since the file is also used as a
 *       CA to verify this self-signed certificate.
 *
 *  $ openssl ecparam -out ec_key.pem -name prime256v1 -genkey
 *  $ openssl req -new -key ec_key.pem -x509 -nodes -days 3650 -out cert.pem \
 *      -addext "subjectAltName = IP:127.0.0.1" \
 *      -addext "basicConstraints = critical, CA:TRUE" \
 *      -subj "/C=NO/ST=Some-State/O=Internet Widgits Pty Ltd/CN=127.0.0.1"
 */
const char test_certificate_ecdsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICGTCCAb6gAwIBAgIUeJ/ER0g77W04QN28O4XyijoFYEYwCgYIKoZIzj0EAwIw\r\n"
"WTELMAkGA1UEBhMCTk8xEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\r\n"
"dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2\r\n"
"MDkyMTE4NDcyNVoXDTM2MDkxODE4NDcyNVowWTELMAkGA1UEBhMCTk8xEzARBgNV\r\n"
"BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\r\n"
"ZDESMBAGA1UEAwwJMTI3LjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\r\n"
"5PRCNCNdhNSnpMMB+MUmEseHnhGhZA2EnLHKjOf/fGuwylnbQMc/5UD6pH286SaL\r\n"
"xrcuF4arEaiO7DmKqqngIaNkMGIwDwYDVR0RBAgwBocEfwAAATAPBgNVHRMBAf8E\r\n"
"BTADAQH/MB0GA1UdDgQWBBQYmwp6B2yjw+J1hL+u2xbEfVW8rzAfBgNVHSMEGDAW\r\n"
"gBQYmwp6B2yjw+J1hL+u2xbEfVW8rzAKBggqhkjOPQQDAgNJADBGAiEAiuTv8TYJ\r\n"
"p41dGXW/F+MRDM6B4eVzcvXwMhVqbJTWicYCIQD2KWKwT6TSZxY5h7e1kBXzJzAC\r\n"
"xmnys/+XhMXSuXJDzw==\r\n"
"-----END CERTIFICATE-----\r\n"
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIHLHKJoNeU1Z6VrgM3GXLT5uXiGKSDJD3fdVSWp4eZbloAoGCCqGSM49\r\n"
"AwEHoUQDQgAE5PRCNCNdhNSnpMMB+MUmEseHnhGhZA2EnLHKjOf/fGuwylnbQMc/\r\n"
"5UD6pH286SaLxrcuF4arEaiO7DmKqqngIQ==\r\n"
"-----END EC PRIVATE KEY-----\r\n"
	;
