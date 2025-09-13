/**
 * @file tls/stub.c TLS empty stub
 *
# Copyright (C) 2023 Christian Spielberger
 */
#include <string.h>
#include <re_types.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_srtp.h>
#include <re_tls.h>


int tls_alloc(struct tls **tlsp, enum tls_method method, const char *keyfile,
	      const char *pwd)
{
	(void)tlsp;
	(void)method;
	(void)keyfile;
	(void)pwd;
	return ENOSYS;
}


int tls_add_ca(struct tls *tls, const char *cafile)
{
	(void)tls;
	(void)cafile;
	return ENOSYS;
}

int tls_add_cafile_path(struct tls *tls, const char *cafile,
	const char *capath)
{
	(void)tls;
	(void)cafile;
	(void)capath;
	return ENOSYS;
}


int tls_add_capem(const struct tls *tls, const char *capem)
{
	(void)tls;
	(void)capem;
	return ENOSYS;
}


int tls_add_crlpem(const struct tls *tls, const char *pem)
{
	(void)tls;
	(void)pem;
	return ENOSYS;
}


int tls_set_selfsigned_ec(struct tls *tls, const char *cn,
	const char *curve_n)
{
	(void)tls;
	(void)cn;
	(void)curve_n;
	return ENOSYS;
}


int tls_set_certificate_pem(struct tls *tls, const char *cert, size_t len_cert,
			    const char *key, size_t len_key)
{
	(void)tls;
	(void)cert;
	(void)len_cert;
	(void)key;
	(void)len_key;
	return ENOSYS;
}


int tls_set_certificate(struct tls *tls, const char *pem, size_t len)
{
	(void)tls;
	(void)pem;
	(void)len;
	return ENOSYS;
}


void tls_set_verify_client(struct tls *tls)
{
	(void)tls;
}


void tls_set_verify_client_trust_all(struct tls *tls)
{
	(void)tls;
}


int tls_set_verify_client_handler(struct tls_conn *tc, int depth,
	int (*verifyh) (int ok, void *arg), void *arg)
{
	(void)tc;
	(void)depth;
	(void)verifyh;
	(void)arg;
	return ENOSYS;
}


int tls_set_srtp(struct tls *tls, const char *suites)
{
	(void)tls;
	(void)suites;
	return ENOSYS;
}


int tls_fingerprint(const struct tls *tls, enum tls_fingerprint type,
		    uint8_t *md, size_t size)
{
	(void)tls;
	(void)type;
	(void)md;
	(void)size;
	return ENOSYS;
}


int tls_peer_fingerprint(const struct tls_conn *tc, enum tls_fingerprint type,
			 uint8_t *md, size_t size)
{
	(void)tc;
	(void)type;
	(void)md;
	(void)size;
	return ENOSYS;
}


int tls_peer_common_name(const struct tls_conn *tc, char *cn, size_t size)
{
	(void)tc;
	(void)cn;
	(void)size;
	return ENOSYS;
}


int tls_set_verify_purpose(struct tls *tls, const char *purpose)
{
	(void)tls;
	(void)purpose;
	return ENOSYS;
}


int tls_peer_verify(const struct tls_conn *tc)
{
	(void)tc;
	return ENOSYS;
}


int tls_srtp_keyinfo(const struct tls_conn *tc, enum srtp_suite *suite,
		     uint8_t *cli_key, size_t cli_key_size,
		     uint8_t *srv_key, size_t srv_key_size)
{
	(void)tc;
	(void)suite;
	(void)cli_key;
	(void)cli_key_size;
	(void)srv_key;
	(void)srv_key_size;
	return ENOSYS;
}


const char *tls_cipher_name(const struct tls_conn *tc)
{
	(void)tc;
	return NULL;
}


int tls_set_ciphers(struct tls *tls, const char *cipherv[], size_t count)
{
	(void)tls;
	(void)cipherv;
	(void)count;
	return ENOSYS;
}


int tls_set_verify_server(struct tls_conn *tc, const char *host)
{
	(void)tc;
	(void)host;
	return ENOSYS;
}


int tls_get_issuer(struct tls *tls, struct mbuf *mb)
{
	(void)tls;
	(void)mb;
	return ENOSYS;
}


int tls_get_subject(struct tls *tls, struct mbuf *mb)
{
	(void)tls;
	(void)mb;
	return ENOSYS;
}


void tls_disable_verify_server(struct tls *tls)
{
	(void)tls;
}


int tls_set_min_proto_version(struct tls *tls, int version)
{
	(void)tls;
	(void)version;
	return ENOSYS;
}


int tls_set_max_proto_version(struct tls *tls, int version)
{
	(void)tls;
	(void)version;
	return ENOSYS;
}


int tls_set_session_reuse(struct tls *tls, int enabled)
{
	(void)tls;
	(void)enabled;
	return ENOSYS;
}


bool tls_get_session_reuse(const struct tls_conn *tc)
{
	(void)tc;
	return false;
}


int tls_reuse_session(const struct tls_conn *tc)
{
	(void)tc;
	return ENOSYS;
}


bool tls_session_reused(const struct tls_conn *tc)
{
	(void)tc;
	return false;
}


int tls_update_sessions(const struct tls_conn *tc)
{
	(void)tc;
	return ENOSYS;
}


void tls_set_posthandshake_auth(struct tls *tls, int value)
{
	(void)tls;
	(void)value;
}


int tls_conn_change_cert(struct tls_conn *tc, const char *file)
{
	(void)tc;
	(void)file;
	return ENOSYS;
}


int tls_start_tcp(struct tls_conn **ptc, struct tls *tls,
		  struct tcp_conn *tcp, int layer)
{
	(void)ptc;
	(void)tls;
	(void)tcp;
	(void)layer;
	return ENOSYS;
}


int tls_verify_client_post_handshake(struct tls_conn *tc)
{
	(void)tc;
	return ENOSYS;
}


const struct tcp_conn *tls_get_tcp_conn(const struct tls_conn *tc)
{
	(void)tc;
	return NULL;
}


int dtls_listen(struct dtls_sock **sockp, const struct sa *laddr,
		struct udp_sock *us, uint32_t htsize, int layer,
		dtls_conn_h *connh, void *arg)
{
	(void)sockp;
	(void)laddr;
	(void)us;
	(void)htsize;
	(void)layer;
	(void)connh;
	(void)arg;
	return ENOSYS;
}


struct udp_sock *dtls_udp_sock(struct dtls_sock *sock)
{
	(void)sock;
	return NULL;
}


void dtls_set_mtu(struct dtls_sock *sock, size_t mtu)
{
	(void)sock;
	(void)mtu;
}


int dtls_connect(struct tls_conn **ptc, struct tls *tls,
		 struct dtls_sock *sock, const struct sa *peer,
		 dtls_estab_h *estabh, dtls_recv_h *recvh,
		 dtls_close_h *closeh, void *arg)
{
	(void)ptc;
	(void)tls;
	(void)sock;
	(void)peer;
	(void)estabh;
	(void)recvh;
	(void)closeh;
	(void)arg;
	return ENOSYS;
}


int dtls_accept(struct tls_conn **ptc, struct tls *tls,
		struct dtls_sock *sock,
		dtls_estab_h *estabh, dtls_recv_h *recvh,
		dtls_close_h *closeh, void *arg)
{
	(void)ptc;
	(void)tls;
	(void)sock;
	(void)estabh;
	(void)recvh;
	(void)closeh;
	(void)arg;
	return ENOSYS;
}


int dtls_send(struct tls_conn *tc, struct mbuf *mb)
{
	(void)tc;
	(void)mb;
	return ENOSYS;
}


void dtls_set_handlers(struct tls_conn *tc, dtls_estab_h *estabh,
		       dtls_recv_h *recvh, dtls_close_h *closeh, void *arg)
{
	(void)tc;
	(void)estabh;
	(void)recvh;
	(void)closeh;
	(void)arg;
}


const struct sa *dtls_peer(const struct tls_conn *tc)
{
	(void)tc;
	return NULL;
}


void dtls_set_peer(struct tls_conn *tc, const struct sa *peer)
{
	(void)tc;
	(void)peer;
}


void dtls_recv_packet(struct dtls_sock *sock, const struct sa *src,
		      struct mbuf *mb)
{
	(void)sock;
	(void)src;
	(void)mb;
}


void dtls_set_single(struct dtls_sock *sock, bool single)
{
	(void)sock;
	(void)single;
}


int tls_set_certificate_openssl(struct tls *tls, struct x509_st *cert,
				struct evp_pkey_st *pkey, bool up_ref)
{
	(void)tls;
	(void)cert;
	(void)pkey;
	(void)up_ref;
	return ENOSYS;
}


int tls_add_certf(struct tls *tls, const char *certf, const char *host)
{
	(void)tls;
	(void)certf;
	(void)host;
	return ENOSYS;
}
