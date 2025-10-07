/**
 * @file test.h  Interface to regression testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */

enum test_mode {
	TEST_NONE,
	TEST_REGULAR,
	TEST_MEMORY,
	TEST_PERF,
	TEST_THREAD
};

/*
 * Global test mode
 */
extern enum test_mode test_mode;

/*
 * Special negative error code for a skipped test
 */
#define ESKIPPED (-1000)

#define TEST_EINVAL(func, ...)					\
	err = func(__VA_ARGS__);				\
	if (err != EINVAL)					\
		goto out;

#define TEST_EQUALS(expected, actual)				\
	if ((expected) != (actual)) {				\
		(void)re_fprintf(stderr, "\n");			\
		DEBUG_WARNING("TEST_EQUALS: %s:%u: %s():"	\
			      " expected=%d(0x%x), actual=%d(0x%x)\n",	\
			      __FILE__, __LINE__, __func__,	\
			      (expected), (expected),		\
			      (actual), (actual));		\
		err = EINVAL;					\
		goto out;					\
	}

#define TEST_NOT_EQUALS(expected, actual)			\
	if ((expected) == (actual)) {				\
		(void)re_fprintf(stderr, "\n");			\
		DEBUG_WARNING("TEST_NOT_EQUALS: %s:%u:"		\
			      " expected=%d != actual=%d\n",	\
			      __FILE__, __LINE__,		\
			      (expected), (actual));		\
		err = EINVAL;					\
		goto out;					\
	}

#define TEST_MEMCMP(expected, expn, actual, actn)			\
	if (expn != actn ||						\
	    0 != memcmp((expected), (actual), (expn))) {		\
		(void)re_fprintf(stderr, "\n");				\
		DEBUG_WARNING("TEST_MEMCMP: %s:%u:"			\
			      " %s(): failed\n",			\
			      __FILE__, __LINE__, __func__);		\
		test_hexdump_dual(stderr,				\
				  expected, expn,			\
				  actual, actn);			\
		err = EINVAL;						\
		goto out;						\
	}

#define TEST_STRCMP(expected, expn, actual, actn)			\
	if (expn != actn ||						\
	    0 != memcmp((expected), (actual), (expn))) {		\
		(void)re_fprintf(stderr, "\n");				\
		DEBUG_WARNING("TEST_STRCMP: %s:%u:"			\
			      " failed\n",				\
			      __FILE__, __LINE__);			\
		(void)re_fprintf(stderr,				\
				 "expected string: (%zu bytes)\n"	\
				 "\"%b\"\n",				\
				 (size_t)(expn),			\
				 (expected), (size_t)(expn));		\
		(void)re_fprintf(stderr,				\
				 "actual string: (%zu bytes)\n"		\
				 "\"%b\"\n",				\
				 (size_t)(actn),			\
				 (actual), (size_t)(actn));		\
		err = EINVAL;						\
		goto out;						\
	}

#define TEST_ASSERT(actual)						\
	if (!(actual)) {						\
		(void)re_fprintf(stderr, "\n");				\
		DEBUG_WARNING("TEST_ASSERT: %s:%u:"			\
			      " actual=%d\n",				\
			      __FILE__, __LINE__,			\
			      (actual));				\
		err = EINVAL;						\
		goto out;						\
	}

#define TEST_ERR(err)							\
	if ((err)) {							\
		(void)re_fprintf(stderr, "\n");				\
		DEBUG_WARNING("TEST_ERR: %s:%u:"			\
			      " (%m)\n",				\
			      __FILE__, __LINE__,			\
			      (err));					\
		goto out;						\
	}

#define TEST_SACMP(expect, actual, flags)				\
	if (!sa_cmp((expect), (actual), (flags))) {			\
									\
		(void)re_fprintf(stderr, "\n");				\
		DEBUG_WARNING("TEST_SACMP: %s:%u:"			\
			      " %s(): failed\n",			\
			      __FILE__, __LINE__, __func__);		\
		DEBUG_WARNING("expected: %J\n", (expect));		\
		DEBUG_WARNING("actual:   %J\n", (actual));		\
		err = EADDRNOTAVAIL;					\
		goto out;						\
	}

/*
 * NOTE: try to reuse macros from Gtest.
 */

#define ASSERT_EQ(expected, actual)					\
	if ((expected) != (actual)) {					\
		DEBUG_WARNING("ASSERT_EQ: %s:%u: %s():"			\
			      " expected=%d(0x%x), actual=%d(0x%x)\n",	\
			      __FILE__, __LINE__, __func__,		\
			      (expected), (expected),			\
			      (actual), (actual));			\
		err = EINVAL;						\
		goto out;						\
	}

#define ASSERT_DOUBLE_EQ(expected, actual, prec)			\
	if (!test_cmp_double((expected), (actual), (prec))) {		\
		DEBUG_WARNING("selftest: ASSERT_DOUBLE_EQ: %s:%u:"	\
			" expected=%f, actual=%f\n",			\
			__FILE__, __LINE__,				\
			(double)(expected), (double)(actual));		\
		err = EINVAL;						\
		goto out;						\
	}

#define ASSERT_TRUE(cond)					\
	if (!(cond)) {						\
		DEBUG_WARNING("ASSERT_TRUE: %s:%u:\n",		\
			      __FILE__, __LINE__);		\
		err = EINVAL;					\
		goto out;					\
	}


/* Module API */
int test_aac(void);
int test_aes(void);
int test_aes_gcm(void);
int test_au(void);
int test_aubuf(void);
int test_aulevel(void);
int test_aulength(void);
int test_auposition(void);
int test_auresamp(void);
int test_async(void);
int test_av1(void);
int test_dd(void);
int test_base64(void);
int test_bfcp(void);
int test_bfcp_bin(void);
int test_bfcp_udp(void);
int test_bfcp_tcp(void);
int test_btrace(void);
int test_conf(void);
int test_crc32(void);
int test_dns_hdr(void);
int test_dns_integration(void);
int test_dns_rr(void);
int test_dns_dname(void);
int test_dsp(void);
int test_dtmf(void);
int test_fir(void);
int test_fmt_gmtime(void);
int test_fmt_hexdump(void);
int test_fmt_human_time(void);
int test_fmt_param(void);
int test_fmt_pl(void);
int test_fmt_pl_alloc_str(void);
int test_fmt_pl_float(void);
int test_fmt_pl_i32(void);
int test_fmt_pl_i64(void);
int test_fmt_pl_u32(void);
int test_fmt_pl_u64(void);
int test_fmt_pl_x3264(void);
int test_fmt_print(void);
int test_fmt_regex(void);
int test_fmt_snprintf(void);
int test_fmt_str(void);
int test_fmt_str_bool(void);
int test_fmt_str_error(void);
int test_fmt_str_itoa(void);
int test_fmt_str_wchar(void);
int test_fmt_timestamp(void);
int test_fmt_trim(void);
int test_fmt_unicode(void);
int test_fmt_unicode_decode(void);
int test_g711_alaw(void);
int test_g711_ulaw(void);
int test_h264(void);
int test_h264_sps(void);
int test_h264_packet(void);
int test_h265(void);
int test_h265_packet(void);
int test_hash(void);
int test_hmac_sha1(void);
int test_hmac_sha256(void);
int test_http(void);
int test_http_loop(void);
int test_http_large_body(void);
int test_http_conn(void);
int test_http_conn_large_body(void);
int test_dns_http_integration(void);
int test_dns_cache_http_integration(void);
#ifdef USE_TLS
int test_https_loop(void);
int test_http_client_set_tls(void);
int test_https_large_body(void);
#endif
#ifdef HAVE_TLS1_3_POST_HANDSHAKE_AUTH
int test_https_conn_post_handshake(void);
#endif
int test_httpauth_chall(void);
int test_httpauth_resp(void);
int test_httpauth_basic_request(void);
int test_httpauth_digest_request(void);
int test_httpauth_digest_response(void);
int test_httpauth_digest_verification(void);
int test_ice_loop(void);
int test_ice_cand(void);
int test_json(void);
int test_json_bad(void);
int test_json_file(void);
int test_json_unicode(void);
int test_json_array(void);
int test_list(void);
int test_list_flush(void);
int test_list_ref(void);
int test_list_sort(void);
int test_mbuf(void);
int test_md5(void);
int test_mem(void);
int test_mem_pool(void);
int test_mem_reallocarray(void);
int test_mem_secure(void);
int test_mqueue(void);
int test_net_if(void);
int test_net_dst_source_addr_get(void);
int test_odict(void);
int test_odict_array(void);
int test_odict_pl(void);
int test_pcp(void);
int test_trice_cand(void);
int test_trice_candpair(void);
int test_trice_checklist(void);
int test_trice_loop(void);
int test_remain(void);
int test_re_assert_se(void);
int test_rtmp_play(void);
int test_rtmp_publish(void);
#ifdef USE_TLS
int test_rtmps_publish(void);
#endif
int test_rtp(void);
int test_rtp_listen(void);
int test_rtpext(void);
int test_rtcp_encode(void);
int test_rtcp_encode_afb(void);
int test_rtcp_decode(void);
int test_rtcp_decode_badmsg(void);
int test_rtcp_packetloss(void);
int test_rtcp_twcc(void);
int test_rtcp_xr(void);
int test_rtcp_loop(void);
int test_sa_class(void);
int test_sa_cmp(void);
int test_sa_decode(void);
int test_sa_ntop(void);
int test_sa_pton(void);
int test_sa_pton_linklocal(void);
int test_sdp_all(void);
int test_sdp_bfcp(void);
int test_sdp_parse(void);
int test_sdp_oa(void);
int test_sdp_extmap(void);
int test_sdp_disabled_rejected(void);
int test_sdp_interop(void);
int test_sha1(void);
int test_sip_addr(void);
int test_sip_auth(void);
int test_sip_drequestf(void);
int test_sip_apply(void);
int test_sip_hdr(void);
int test_sip_msg(void);
int test_sip_param(void);
int test_sip_parse(void);
int test_sip_via(void);
#ifdef USE_TLS
int test_sip_transp_add_client_cert(void);
#endif
int test_sipevent(void);
int test_sipreg_udp(void);
int test_sipreg_tcp(void);
#ifdef USE_TLS
int test_sipreg_tls(void);
#endif
int test_sipsess(void);
int test_sipsess_reject(void);
int test_sipsess_blind_transfer(void);
int test_sipsess_100rel_caller_require(void);
int test_sipsess_100rel_supported(void);
int test_sipsess_100rel_answer_not_allowed(void);
int test_sipsess_100rel_420(void);
int test_sipsess_100rel_421(void);
int test_sipsess_update_uac(void);
int test_sipsess_update_uas(void);
int test_sipsess_update_no_sdp(void);
int test_srtp(void);
int test_srtcp(void);
int test_srtp_gcm(void);
int test_srtcp_gcm(void);
int test_stun_req(void);
int test_stun_resp(void);
int test_stun_reqltc(void);
int test_stun(void);
int test_sys_endian(void);
int test_sys_rand(void);
int test_sys_fs_isdir(void);
int test_sys_fs_isfile(void);
int test_sys_fs_fopen(void);
int test_sys_getenv(void);
int test_tcp(void);
int test_tcp_tos(void);
int test_telev(void);
int test_text2pcap(void);
int test_thread(void);
int test_thread_cnd_timedwait(void);
int test_thread_tss(void);
int test_tmr_jiffies(void);
int test_tmr_jiffies_usec(void);
int test_try_into(void);
int test_turn(void);
int test_turn_tcp(void);
int test_turn_thread(void);
int test_udp(void);
int test_udp_tos(void);
int test_unixsock(void);
int test_uri(void);
int test_uri_encode(void);
int test_uri_headers(void);
int test_uri_user(void);
int test_uri_params_headers(void);
int test_uri_escape(void);
int test_vid(void);
int test_vidconv(void);
int test_vidconv_scaling(void);
int test_vidconv_pixel_formats(void);
int test_websock(void);
int test_trace(void);
#ifdef USE_TLS
int test_dtls(void);
int test_dtls_srtp(void);
int test_tls(void);
int test_tls_ec(void);
int test_tls_selfsigned(void);
int test_tls_certificate(void);
int test_tls_false_cafile_path(void);
int test_tls_cli_conn_change_cert(void);
int test_tls_session_reuse_tls_v12(void);
int test_tls_session_reuse(void);
int test_tls_sni(void);
#endif

#ifdef USE_TLS
int test_dtls_turn(void);
#endif


#ifdef USE_TLS
extern const char test_certificate_ecdsa[];
#endif

/* Integration tests */
int  test_integration(const char *name, bool verbose);
int  test_sipevent_network(void);
int  test_sip_drequestf_network(void);

#ifdef __cplusplus
extern "C" {
#endif

int  test_cplusplus(void);

#ifdef __cplusplus
}
#endif

/* High-level API */
int  test_reg(const char *name, bool verbose);
int  test_oom(const char *name, bool verbose);
int  test_perf(const char *name, bool verbose);
int  test_multithread(void);
void test_listcases(void);


void test_hexdump_dual(FILE *f,
		       const void *ep, size_t elen,
		       const void *ap, size_t alen);
bool test_cmp_double(double a, double b, double precision);
int re_main_timeout(uint32_t timeout_ms);
int test_load_file(struct mbuf *mb, const char *filename);
int test_write_file(struct mbuf *mb, const char *filename);
void test_set_datapath(const char *path);
const char *test_datapath(void);
bool test_ipv6_supported(void);


/*
 * Mock objects
 */


struct stunserver {
	struct udp_sock *us;
	struct tcp_sock *ts;
	struct tcp_conn *tc;
	struct mbuf *mb;
	struct sa laddr;
	struct sa laddr_tcp;
	struct sa paddr;
	uint32_t nrecv;
	int err;
};

int stunserver_alloc(struct stunserver **stunp);
const struct sa *stunserver_addr(const struct stunserver *stun, int proto);


struct turnserver {
	struct udp_sock *us;
	struct sa laddr;
	struct tcp_sock *ts;
	struct sa laddr_tcp;
	struct tcp_conn *tc;
	struct sa paddr;
	struct mbuf *mb;
	struct udp_sock *us_relay;
	struct sa cli;
	struct sa relay;
	char addr[64];
	const char *auth_realm;
	uint64_t auth_secret;

	struct channel {
		uint16_t nr;
		struct sa peer;
	} chanv[4];
	size_t chanc;

	struct sa permv[4];
	size_t permc;

	size_t n_allocate;
	size_t n_createperm;
	size_t n_chanbind;
	size_t n_send;
	size_t n_raw;
	size_t n_recv;
};

int turnserver_alloc(struct turnserver **turnp, const char *addr);


enum natbox_type {
	NAT_INBOUND_SNAT,  /* NOTE: must be installed on receiving socket */
	NAT_FIREWALL,
};

/**
 * A simple NAT-box that can be hooked onto a UDP-socket.
 *
 * The NAT behaviour is port-preserving and will rewrite the source
 * IP-address to the public address.
 */
struct nat {
	enum natbox_type type;
	struct sa public_addr;
	struct udp_helper *uh;
	struct udp_sock *us;
	struct sa bindingv[16];
	size_t bindingc;
};

int nat_alloc(struct nat **natp, enum natbox_type type,
	      struct udp_sock *us, const struct sa *public_addr);


/*
 * SIP Server
 */

struct sip_server {
	struct sip *sip;
	struct sip_lsnr *lsnr;
	bool terminate;

	unsigned n_register_req;
	struct sip_msg *sip_msgs[16];
};

int sip_server_alloc(struct sip_server **srvp);
int sip_server_uri(struct sip_server *srv, char *uri, size_t sz,
		   enum sip_transp tp);


/*
 * Mock DNS-Server
 */

struct dns_server {
	struct udp_sock *us;
	struct sa addr;
	struct list rrl;
	bool rotate;
};

int dns_server_alloc(struct dns_server **srvp, bool rotate);
int dns_server_add_a(struct dns_server *srv, const char *name, uint32_t addr,
		     int64_t ttl);
int dns_server_add_aaaa(struct dns_server *srv, const char *name,
			const uint8_t *addr);
int dns_server_add_srv(struct dns_server *srv, const char *name,
		       uint16_t pri, uint16_t weight, uint16_t port,
		       const char *target);
void dns_server_flush(struct dns_server *srv);
