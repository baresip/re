/**
 * @file test.c  Regression testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#define _DEFAULT_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <math.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#ifdef WIN32
#define open _open
#define read _read
#define write _write
#define close _close
#define dup _dup
#define dup2 _dup2
#define fileno _fileno
#endif


typedef int (test_exec_h)(void);

struct test {
	test_exec_h *exec;
	const char *name;
};

#define TEST(a) {a, #a}

static const struct test tests[] = {
	TEST(test_aac),
	TEST(test_aes),
	TEST(test_aes_gcm),
	TEST(test_au),
	TEST(test_aubuf),
	TEST(test_aulength),
	TEST(test_aulevel),
	TEST(test_auposition),
	TEST(test_auresamp),
	TEST(test_async),
	TEST(test_av1),
	TEST(test_dd),
	TEST(test_base64),
	TEST(test_bfcp),
	TEST(test_bfcp_bin),
	TEST(test_bfcp_tcp),
	TEST(test_bfcp_udp),
	TEST(test_btrace),
	TEST(test_conf),
	TEST(test_crc32),
	TEST(test_dns_hdr),
	TEST(test_dns_rr),
	TEST(test_dns_dname),
	TEST(test_dsp),
#ifdef USE_TLS
	TEST(test_dtls),
	TEST(test_dtls_srtp),
#endif
	TEST(test_dtmf),
	TEST(test_fir),
	TEST(test_fmt_gmtime),
	TEST(test_fmt_hexdump),
	TEST(test_fmt_human_time),
	TEST(test_fmt_param),
	TEST(test_fmt_pl),
	TEST(test_fmt_pl_alloc_str),
	TEST(test_fmt_pl_float),
	TEST(test_fmt_pl_i32),
	TEST(test_fmt_pl_i64),
	TEST(test_fmt_pl_u32),
	TEST(test_fmt_pl_u64),
	TEST(test_fmt_pl_x3264),
	TEST(test_fmt_print),
	TEST(test_fmt_regex),
	TEST(test_fmt_snprintf),
	TEST(test_fmt_str),
	TEST(test_fmt_str_bool),
	TEST(test_fmt_str_error),
	TEST(test_fmt_str_itoa),
	TEST(test_fmt_str_wchar),
	TEST(test_fmt_timestamp),
	TEST(test_fmt_unicode),
	TEST(test_fmt_unicode_decode),
	TEST(test_g711_alaw),
	TEST(test_g711_ulaw),
	TEST(test_h264),
	TEST(test_h264_sps),
	TEST(test_h264_packet),
	TEST(test_h265),
	TEST(test_h265_packet),
	TEST(test_hash),
	TEST(test_hmac_sha1),
	TEST(test_hmac_sha256),
	TEST(test_http),
	TEST(test_http_loop),
	TEST(test_http_large_body),
	TEST(test_http_conn),
	TEST(test_http_conn_large_body),
#ifdef USE_TLS
	TEST(test_https_loop),
	TEST(test_http_client_set_tls),
	TEST(test_https_large_body),
#endif
#ifdef HAVE_TLS1_3_POST_HANDSHAKE_AUTH
	TEST(test_https_conn_post_handshake),
#endif
	TEST(test_httpauth_chall),
	TEST(test_httpauth_resp),
	TEST(test_httpauth_basic_request),
	TEST(test_httpauth_digest_request),
	TEST(test_httpauth_digest_response),
	TEST(test_httpauth_digest_verification),
	TEST(test_ice_cand),
	TEST(test_ice_loop),
	TEST(test_json),
	TEST(test_json_file),
	TEST(test_json_unicode),
	TEST(test_json_bad),
	TEST(test_json_array),
	TEST(test_list),
	TEST(test_list_flush),
	TEST(test_list_ref),
	TEST(test_list_sort),
	TEST(test_mbuf),
	TEST(test_md5),
	TEST(test_mem),
	TEST(test_mem_pool),
	TEST(test_mem_reallocarray),
	TEST(test_mem_secure),
	TEST(test_net_if),
	TEST(test_mqueue),
	TEST(test_odict),
	TEST(test_odict_array),
	TEST(test_odict_pl),
	TEST(test_pcp),
	TEST(test_remain),
	TEST(test_re_assert_se),
	TEST(test_rtmp_play),
	TEST(test_rtmp_publish),
#ifdef USE_TLS
	TEST(test_rtmps_publish),
#endif
	TEST(test_rtp),
	TEST(test_rtpext),
	TEST(test_rtcp_encode),
	TEST(test_rtcp_encode_afb),
	TEST(test_rtcp_decode),
	TEST(test_rtcp_decode_badmsg),
	TEST(test_rtcp_packetloss),
	TEST(test_rtcp_twcc),
	TEST(test_rtcp_xr),
	TEST(test_rtcp_loop),
	TEST(test_sa_class),
	TEST(test_sa_cmp),
	TEST(test_sa_decode),
	TEST(test_sa_ntop),
	TEST(test_sa_pton),
	TEST(test_sa_pton_linklocal),
	TEST(test_sdp_all),
	TEST(test_sdp_bfcp),
	TEST(test_sdp_parse),
	TEST(test_sdp_oa),
	TEST(test_sdp_extmap),
	TEST(test_sdp_disabled_rejected),
	TEST(test_sdp_interop),
	TEST(test_sha1),
	TEST(test_sip_addr),
	TEST(test_sip_auth),
	TEST(test_sip_drequestf),
	TEST(test_sip_apply),
	TEST(test_sip_hdr),
	TEST(test_sip_param),
	TEST(test_sip_parse),
	TEST(test_sip_via),
#ifdef USE_TLS
	TEST(test_sip_transp_add_client_cert),
#endif
	TEST(test_sipevent),
	TEST(test_sipsess),
	TEST(test_sipsess_reject),
	TEST(test_sipsess_blind_transfer),
	TEST(test_sipsess_100rel_caller_require),
	TEST(test_sipsess_100rel_supported),
	TEST(test_sipsess_100rel_answer_not_allowed),
	TEST(test_sipsess_100rel_420),
	TEST(test_sipsess_100rel_421),
	TEST(test_sipsess_update_uac),
	TEST(test_sipsess_update_uas),
	TEST(test_sipsess_update_no_sdp),
	TEST(test_srtp),
	TEST(test_srtcp),
	TEST(test_srtp_gcm),
	TEST(test_srtcp_gcm),
	TEST(test_stun_req),
	TEST(test_stun_resp),
	TEST(test_stun_reqltc),
	TEST(test_stun),
	TEST(test_sys_endian),
	TEST(test_sys_rand),
	TEST(test_sys_fs_isdir),
	TEST(test_sys_fs_isfile),
	TEST(test_sys_fs_fopen),
	TEST(test_sys_getenv),
	TEST(test_tcp),
	TEST(test_tcp_tos),
	TEST(test_telev),
	TEST(test_text2pcap),
	TEST(test_fmt_trim),
#ifdef USE_TLS
	TEST(test_tls),
	TEST(test_tls_ec),
	TEST(test_tls_selfsigned),
	TEST(test_tls_certificate),
	TEST(test_tls_false_cafile_path),
	TEST(test_tls_cli_conn_change_cert),
	TEST(test_tls_session_reuse_tls_v12),
	TEST(test_tls_sni),
#endif
	TEST(test_trice_cand),
	TEST(test_trice_candpair),
	TEST(test_trice_checklist),
	TEST(test_trice_loop),
	TEST(test_try_into),
	TEST(test_turn),
	TEST(test_turn_tcp),
	TEST(test_udp),
	TEST(test_udp_tos),
	TEST(test_unixsock),
	TEST(test_uri),
	TEST(test_uri_encode),
	TEST(test_uri_headers),
	TEST(test_uri_user),
	TEST(test_uri_params_headers),
	TEST(test_uri_escape),
	TEST(test_vid),
	TEST(test_vidconv),
	TEST(test_vidconv_scaling),
	TEST(test_vidconv_pixel_formats),
	TEST(test_websock),
	TEST(test_trace),
	TEST(test_thread),
	TEST(test_thread_tss),

#ifdef USE_TLS
	/* combination tests: */
	TEST(test_dtls_turn),
#endif
};


static const struct test tests_integration[] = {
	TEST(test_dns_cache_http_integration),
	TEST(test_dns_http_integration),
	TEST(test_dns_integration),
	TEST(test_net_dst_source_addr_get),
	TEST(test_rtp_listen),
	TEST(test_sip_drequestf_network),
	TEST(test_sipevent_network),
	TEST(test_sipreg_tcp),
#ifdef USE_TLS
	TEST(test_sipreg_tls),
#endif
	TEST(test_sipreg_udp),
	TEST(test_tmr_jiffies),
	TEST(test_tmr_jiffies_usec),
	TEST(test_turn_thread),
	TEST(test_thread_cnd_timedwait),
	TEST(test_cplusplus),
};


#ifdef DATA_PATH
static char datapath[256] = DATA_PATH;
#else
static char datapath[256] = "./test/data";
#endif


static uint32_t timeout_override;
static int dup_stdout;
static int dup_stderr;

enum test_mode test_mode = TEST_NONE;


static void hide_output(void)
{
	dup_stdout = dup(fileno(stdout));
	dup_stderr = dup(fileno(stderr));

#ifdef WIN32
	int mode = _S_IREAD | _S_IWRITE;
#else
	mode_t mode = S_IWUSR | S_IRUSR;
#endif

	int fd_out = open("stdout.out", O_WRONLY | O_CREAT, mode);
	int fd_err = open("stderr.out", O_WRONLY | O_CREAT, mode);
	(void)dup2(fd_out, fileno(stdout));
	(void)dup2(fd_err, fileno(stderr));
}


static void restore_output(int err)
{
	FILE *f = NULL;
	char line[1024];

	fflush(stdout);
	fflush(stderr);

	/* Restore stdout/stderr */
	(void)dup2(dup_stdout, fileno(stdout));
	(void)dup2(dup_stderr, fileno(stderr));

	if (!err)
		goto out;

	f = fopen("stdout.out", "r");
	if (!f)
		goto out;

	while (fgets(line, sizeof(line), f)) {
		re_fprintf(stdout, "%s", line);
	}
	(void)fclose(f);


	f = fopen("stderr.out", "r");
	if (!f)
		goto out;

	while (fgets(line, sizeof(line), f)) {
		re_fprintf(stderr, "%s", line);
	}
	(void)fclose(f);

out:
#ifdef WIN32
	(void)_unlink("stdout.out");
	(void)_unlink("stderr.out");
#else
	(void)unlink("stdout.out");
	(void)unlink("stderr.out");
#endif
}


static const struct test *find_test(const char *name)
{
	size_t i;

	for (i=0; i<RE_ARRAY_SIZE(tests); i++) {

		if (0 == str_casecmp(name, tests[i].name))
			return &tests[i];
	}

	return NULL;
}


static const struct test *find_test_int(const char *name)
{
	for (size_t i=0; i<RE_ARRAY_SIZE(tests_integration); i++) {

		if (0 == str_casecmp(name, tests_integration[i].name))
			return &tests_integration[i];
	}

	return NULL;
}


static int test_exec(const struct test *test)
{
	if (!test)
		return EINVAL;

	struct memstat mstat_before;
	struct memstat mstat_after;

	mem_get_stat(&mstat_before);

	int err = test->exec();
	re_fhs_flush();

	mem_get_stat(&mstat_after);

	if (mstat_after.blocks_cur > mstat_before.blocks_cur) {
		mem_debug();
		re_assert(false && "Test leaks memory blocks");
	}

	if (mstat_after.bytes_cur > mstat_before.bytes_cur) {
		mem_debug();
		re_assert(false && "Test leaks memory bytes");
	}

	return err;
}


/**
 * Run a single testcase in OOM (Out-of-memory) mode.
 *
 * Start with 0 blocks free, and increment by 1 until the test passes.
 *
 *
 *  Blocks
 *  Free
 *
 *    /'\
 *     |
 *   5 |           #
 *     |         # #
 *     |       # # #
 *     |     # # # #
 *   1 |   # # # # #
 *     '--------------> time
 */
static int testcase_oom(const struct test *test, int levels, bool verbose)
{
	int i;
	int err = 0;

	if (verbose)
		(void)re_fprintf(stderr, "  %-26s: ", test->name);

	/* All memory levels */
	for (i=0; i<levels; i++) {

		mem_threshold_set(i);

		err = test_exec(test);
		if (err == 0) {
			/* success, stop now */
			break;
		}
		else if (err == ENOMEM) {
			/* OOM, as expected */
			err = 0;
		}
		else if (err == ETIMEDOUT) {
			/* test timed out, stop now */
			err = 0;
			goto out;
		}
		else if (err == ENOSYS) {
			err = 0;
			break;
		}
		else if (err == ESKIPPED) {
			err = 0;
			break;
		}
		else {
			DEBUG_WARNING("oom: %s: unexpected error code at"
				      " %d blocks free (%m)\n",
				      test->name, i, err);
			goto out;
		}
	}

 out:
	if (verbose)
		(void)re_fprintf(stderr, "oom max %d\n", i);

	return err;
}


int test_oom(const char *name, bool verbose)
{
	size_t i;
	const int levels = 128;
	int err = 0;

	test_mode = TEST_MEMORY;

	if (!verbose)
		hide_output();

	(void)re_fprintf(stderr, "oom tests %u levels: \n", levels);

	if (name) {
		const struct test *test = find_test(name);
		if (!test) {
			(void)re_fprintf(stderr, "no such test: %s\n", name);
			err = ENOENT;
			goto out;
		}

		err = testcase_oom(test, levels, verbose);
	}
	else {
		/* All test cases */
		for (i=0; i<RE_ARRAY_SIZE(tests); i++) {
			err = testcase_oom(&tests[i], levels, verbose);
			if (err)
				break;
		}
	}

	mem_threshold_set(-1);

out:
	if (!verbose)
		restore_output(err);

	if (err) {
		DEBUG_WARNING("oom: %m\n", err);
	}
	else {
		(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\t\n");
	}

	return err;
}


static int test_unit(const char *name, bool verbose)
{
	size_t skipv[RE_ARRAY_SIZE(tests)] = {0};
	size_t i;
	int err = 0;

	if (!verbose)
		hide_output();

	if (name) {
		const struct test *test = find_test(name);
		if (!test) {
			(void)re_fprintf(stderr, "no such test: %s\n", name);
			err = ENOENT;
			goto out;
		}

		err = test_exec(test);
		if (err) {
			DEBUG_WARNING("%s: test failed (%m)\n", name, err);
			goto out;
		}
	}
	else {
		unsigned n_skipped = 0;

		for (i=0; i<RE_ARRAY_SIZE(tests); i++) {

			if (verbose) {
				re_printf("test %zu -- %s\n",
					  i, tests[i].name);
			}

			err = tests[i].exec();
			if (err) {
				if (err == ESKIPPED || err == ENOSYS) {

					skipv[n_skipped] = i;

					++n_skipped;
					err = 0;
					continue;
				}

				DEBUG_WARNING("%s: test failed (%m)\n",
					      tests[i].name, err);
				goto out;
			}
		}

		if (n_skipped) {
			re_fprintf(stderr, "skipped:%u\n", n_skipped);

			/* show any skipped testcase */
			for (i=0; i<n_skipped; i++) {
				size_t ix = skipv[i];
				re_fprintf(stderr, "skip %s\n",
					   tests[ix].name );
			}
		}
	}

out:
	if (!verbose)
		restore_output(err);

	return err;
}


/* baseunits here is [usec] (micro-seconds) */
static int testcase_perf(const struct test *test, double *usec_avgp)
{
#define DRYRUN_MIN        2
#define DRYRUN_MAX      100
#define DRYRUN_USEC 10*1000

#define REPEATS_MIN         3
#define REPEATS_MAX      1000
#define REPEATS_USEC 100*1000

	uint64_t usec_start, usec_stop;
	double usec_avg;
	size_t i, n;
	int err = 0;

	/* dry run */
	usec_start = tmr_jiffies_usec();
	for (i = 1; i <= DRYRUN_MAX; i++) {

		err = test_exec(test);
		if (err)
			return err;

		usec_stop = tmr_jiffies_usec();

		if ((usec_stop - usec_start) > DRYRUN_USEC)
			break;
	}

	usec_avg = 1.0 * (usec_stop - usec_start) / (double)i;

	n = usec_avg ? (size_t)(REPEATS_USEC / usec_avg) : 0;
	n = min(REPEATS_MAX, max(n, REPEATS_MIN));

	/* now for the real measurement */
	usec_start = tmr_jiffies_usec();
	for (i=0; i<n; i++) {
		err = test_exec(test);
		if (err)
			return err;
	}
	usec_stop = tmr_jiffies_usec();

	if (usec_stop <= usec_start) {
		DEBUG_WARNING("perf: cannot measure, test is too fast\n");
		return EINVAL;
	}

	usec_avg = (1.0 * (usec_stop - usec_start)) / i;

	if (usec_avgp)
		*usec_avgp = usec_avg;

	re_printf("%-32s:  %10.2f usec  [%6zu repeats]\n",
		  test->name, usec_avg, i);

	return 0;
}


struct timing {
	const struct test *test;
	uint64_t nsec_avg;
};


/*
 * The comparison function must return an integer less than, equal to,
 * or greater than zero if the first argument  is  considered to  be
 * respectively  less  than,  equal  to, or greater than the second.
 *
 * If two members compare as equal, their order in the sorted array
 * is undefined.
 */
static int timing_cmp(const void *p1, const void *p2)
{
	const struct timing *v1 = p1;
	const struct timing *v2 = p2;

	if (v1->nsec_avg < v2->nsec_avg)
		return 1;
	else if (v1->nsec_avg > v2->nsec_avg)
		return -1;
	else
		return 0;
}


int test_perf(const char *name, bool verbose)
{
	int err = 0;
	unsigned i;
	(void)verbose;

	test_mode = TEST_PERF;

	if (name) {
		const struct test *test;

		test = find_test(name);
		if (!test) {
			(void)re_fprintf(stderr, "no such test: %s\n", name);
			return ENOENT;
		}

		err = testcase_perf(test, NULL);
		if (err)
			return err;
	}
	else {
		struct timing timingv[RE_ARRAY_SIZE(tests)];

		memset(&timingv, 0, sizeof(timingv));

		/* All test cases */
		for (i=0; i<RE_ARRAY_SIZE(tests); i++) {

			struct timing *tim = &timingv[i];
			double usec_avg;

			if (!verbose)
				hide_output();

			tim->test = &tests[i];

			err = testcase_perf(&tests[i],
					    &usec_avg);

			if (!verbose)
				restore_output(err);

			if (err) {
				if (err == ESKIPPED || err == ENOSYS) {
					re_printf("skipped: %s\n",
						  tests[i].name);
					tim->test = NULL;
					continue;
				}
				DEBUG_WARNING("perf: %s failed (%m)\n",
					      tests[i].name, err);
				return err;
			}

			tim->nsec_avg = (uint64_t)(1000.0 * usec_avg);
		}

		/* sort the timing table by average time */
		qsort(timingv, RE_ARRAY_SIZE(timingv), sizeof(timingv[0]),
		      timing_cmp);

		re_fprintf(stderr,
			   "\nsorted by average timing (slowest on top):\n");

		for (i=0; i<RE_ARRAY_SIZE(timingv); i++) {

			struct timing *tim = &timingv[i];
			double usec_avg = tim->nsec_avg / 1000.0;

			if (!tim->test)
				continue;

			re_fprintf(stderr, "%-34s: %10.2f usec\n",
				   tim->test->name, usec_avg);
		}
		re_fprintf(stderr, "\n");
	}

	return err;
}


int test_reg(const char *name, bool verbose)
{
	int err;

	test_mode = TEST_REGULAR;

	timeout_override = 10000;

	(void)re_fprintf(stderr, "regular tests:       ");
	err = test_unit(name, verbose);
	if (err)
		return err;
	(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\n");

	timeout_override = 0;

	return 0;
}


struct thread {
	const struct test *test;
	thrd_t tid;
	int err;
};


static int thread_handler(void *arg)
{
	struct thread *thr = arg;
	int err;

	err = re_thread_init();
	if (err) {
		DEBUG_WARNING("thread: re_thread_init failed %m\n", err);
		thr->err = err;
		return 0;
	}

	err = thr->test->exec();
	if (err) {
		if (err == ESKIPPED) {
			err = 0;
		}
		else {
			DEBUG_WARNING("%s: test failed (%m)\n",
					thr->test->name, err);
		}
	}

	re_thread_close();

	/* safe to write it, main thread is waiting for us */
	thr->err = err;

	return 0;
}


/* Run all test-cases in multiple threads */
int test_multithread(void)
{
#define NUM_REPEAT 2
#define NUM_TOTAL  (NUM_REPEAT * RE_ARRAY_SIZE(tests))

	struct thread threadv[NUM_TOTAL];
	size_t test_index=0;
	size_t i;
	int err = 0;

	test_mode = TEST_THREAD;

	timeout_override = 20000;

	memset(threadv, 0, sizeof(threadv));

	(void)re_fprintf(stderr, "multithread: %zu tests"
			 " with %d repeats (total %zu threads): ",
			 RE_ARRAY_SIZE(tests), NUM_REPEAT, NUM_TOTAL);

	for (i=0; i<RE_ARRAY_SIZE(threadv); i++) {

		size_t ti = (test_index++ % RE_ARRAY_SIZE(tests));

		threadv[i].test = &tests[ti];
		threadv[i].err = -1;           /* error not set */

		err = thrd_success != thrd_create(&threadv[i].tid,
						  thread_handler,
						  (void *)&threadv[i]);
		if (err) {
			err = EAGAIN;
			DEBUG_WARNING("thread_create failed (%m)\n", err);
			break;
		}
	}

	for (i=0; i<RE_ARRAY_SIZE(threadv); i++) {

		thrd_join(threadv[i].tid, NULL);
	}

	for (i=0; i<RE_ARRAY_SIZE(threadv); i++) {

		if (threadv[i].err != 0) {
			re_printf("%zu failed: %-30s  [%d] [%m]\n", i,
				  threadv[i].test->name,
				  threadv[i].err, threadv[i].err);
			err = threadv[i].err;
		}
	}

	if (err)
		return err;
	(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\n");

	timeout_override = 0;

	return 0;
}


void test_listcases(void)
{
	size_t i, n, nh;

	n = RE_ARRAY_SIZE(tests);
	nh = (n+1)/2;

	(void)re_printf("\n%zu test cases:\n", n);

	for (i=0; i<nh; i++) {

		size_t ih = i + nh;

		re_printf("    %-32s", tests[i].name);

		if (ih < n)
			re_printf("    %s", tests[ih].name);

		re_printf("\n");
	}

	(void)re_printf("\n");
}


bool test_cmp_double(double a, double b, double precision)
{
	return fabs(a - b) < precision;
}


void test_hexdump_dual(FILE *f,
		       const void *ep, size_t elen,
		       const void *ap, size_t alen)
{
	const uint8_t *ebuf = ep;
	const uint8_t *abuf = ap;
	size_t i, j, len;
#define WIDTH 8

	if (!f || !ep || !ap)
		return;

	len = max(elen, alen);

	(void)re_fprintf(f, "\nOffset:   Expected (%zu bytes):    "
			 "   Actual (%zu bytes):\n", elen, alen);

	for (i=0; i < len; i += WIDTH) {

		(void)re_fprintf(f, "0x%04zx   ", i);

		for (j=0; j<WIDTH; j++) {
			const size_t pos = i+j;
			if (pos < elen) {
				bool wrong = pos >= alen;

				if (wrong)
					(void)re_fprintf(f, "\x1b[35m");
				(void)re_fprintf(f, " %02x", ebuf[pos]);
				if (wrong)
					(void)re_fprintf(f, "\x1b[;m");
			}
			else
				(void)re_fprintf(f, "   ");
		}

		(void)re_fprintf(f, "    ");

		for (j=0; j<WIDTH; j++) {
			const size_t pos = i+j;
			if (pos < alen) {
				bool wrong;

				if (pos < elen)
					wrong = ebuf[pos] != abuf[pos];
				else
					wrong = true;

				if (wrong)
					(void)re_fprintf(f, "\x1b[33m");
				(void)re_fprintf(f, " %02x", abuf[pos]);
				if (wrong)
					(void)re_fprintf(f, "\x1b[;m");
			}
			else
				(void)re_fprintf(f, "   ");
		}

		(void)re_fprintf(f, "\n");
	}

	(void)re_fprintf(f, "\n");
}


static void oom_watchdog_timeout(void *arg)
{
	int *err = arg;

	*err = ETIMEDOUT;

	re_cancel();
}


static void signal_handler(int sig)
{
	re_fprintf(stderr, "test interrupted by signal %d\n", sig);
	re_cancel();
}


int re_main_timeout(uint32_t timeout_ms)
{
	struct tmr tmr;
	int err = 0;

	tmr_init(&tmr);

	if (timeout_override != 0)
		timeout_ms = timeout_override;

#ifdef TEST_TIMEOUT
	timeout_ms = TEST_TIMEOUT;
#endif

	tmr_start(&tmr, timeout_ms, oom_watchdog_timeout, &err);
	(void)re_main(signal_handler);

	tmr_cancel(&tmr);
	return err;
}


int test_load_file(struct mbuf *mb, const char *filename)
{
	int err = 0, fd = open(filename, O_RDONLY);
	if (fd < 0)
		return errno;

	for (;;) {
		uint8_t buf[1024];

		const ssize_t n = read(fd, (void *)buf, sizeof(buf));
		if (n < 0) {
			err = errno;
			break;
		}
		else if (n == 0)
			break;

		err = mbuf_write_mem(mb, buf, n);
		if (err)
			break;
	}

	(void)close(fd);

	return err;
}


int test_write_file(struct mbuf *mb, const char *filename)
{
	int err = 0, fd = open(filename, O_CREAT | O_WRONLY, 0644);
	if (fd < 0)
		return errno;

	for (;;) {
		uint8_t buf[1024];
		size_t count;

		count = min(sizeof(buf), mbuf_get_left(mb));
		if (count == 0)
			break;

		err = mbuf_read_mem(mb, buf, count);
		if (err)
			break;

		ssize_t n = write(fd, (void *)buf, (unsigned int)count);
		if (n < 0) {
			err = errno;
			break;
		}
		else if (n == 0)
			break;

	}

	(void)close(fd);

	return err;
}


void test_set_datapath(const char *path)
{
	str_ncpy(datapath, path, sizeof(datapath));
}


const char *test_datapath(void)
{
	return datapath;
}


int test_integration(const char *name, bool verbose)
{
	size_t i;
	int err = 0;
	const struct test *test;
	(void) verbose;

	(void)re_fprintf(stderr, "integration tests\n");

	if (name) {
		test = find_test_int(name);
		if (!test) {
			(void)re_fprintf(stderr, "no such test: %s\n", name);
			return ENOENT;
		}

		if (!test->name)
			return EINVAL;

		(void)re_fprintf(stderr, "  %-24s: ", test->name);

		if (test->exec)
			err = test->exec();

		if (err)
			DEBUG_WARNING("  %-24s: NOK: %m\n", test->name, err);
		else
			(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\n");

		return err;
	}

	for (i=0; i<RE_ARRAY_SIZE(tests_integration); i++) {

		test = &tests_integration[i];
		if (str_isset(name) && test->name)
			continue;

		(void)re_fprintf(stderr, "  %-32s: ", test->name);

		if (test->exec)
			err = test->exec();

		if (err) {
			DEBUG_WARNING("  %-24s: NOK: %m\n", test->name, err);
			break;
		}
		else {
			(void)re_fprintf(stderr, "\x1b[32mOK\x1b[;m\t\n");
		}
	}

	return err;
}
