# libre Changelog

All notable changes to libre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v4.1.0 - 2025-09-10

### What's Changed
* ci: temporary workaround for choco openssl failure by @alfredh in https://github.com/baresip/re/pull/1395
* test: add support for IPv6 on UDP-test by @alfredh in https://github.com/baresip/re/pull/1390
* ci: enable Windows testing when OpenSSL is disabled by @alfredh in https://github.com/baresip/re/pull/1392
* websock: remove unused peer member by @alfredh in https://github.com/baresip/re/pull/1396
* test: add testing of udp_rxsz_set() and udp_sockbuf_set() by @alfredh in https://github.com/baresip/re/pull/1397
* ci/build: select xcode version 16.2 by @sreimers in https://github.com/baresip/re/pull/1400
* udp: combine udp_recv_helper() and udp_recv_packet() by @alfredh in https://github.com/baresip/re/pull/1398
* test: add support for UDP multicast test by @alfredh in https://github.com/baresip/re/pull/1402
* ci: update actions/checkout@v5 by @sreimers in https://github.com/baresip/re/pull/1403
* uri: remove uri_escape_user() by @alfredh in https://github.com/baresip/re/pull/1401
* uri: remove some unused escape functions by @alfredh in https://github.com/baresip/re/pull/1404
* test: add support for IPv6 and TURN by @alfredh in https://github.com/baresip/re/pull/1405
* test: add support for testing more DTLS-SRTP suites by @alfredh in https://github.com/baresip/re/pull/1408
* dtls: remove dtls_set_handlers() -- unused by @alfredh in https://github.com/baresip/re/pull/1407
* tls: remove tls_set_certificate_der() -- unused by @alfredh in https://github.com/baresip/re/pull/1410
* test: set low MTU in DTLS-test by @alfredh in https://github.com/baresip/re/pull/1411
* test: add support for TURN mock-server authentication by @alfredh in https://github.com/baresip/re/pull/1409
* tls: tls_set_resumption() -- change const enum to enum by @alfredh in https://github.com/baresip/re/pull/1412
* ci/abi: bump old abi by @sreimers in https://github.com/baresip/re/pull/1417
* ci/coverage: bump min coverage by @sreimers in https://github.com/baresip/re/pull/1416


**Full Changelog**: https://github.com/baresip/re/compare/v4.0.0...v4.1.0


## v4.0.0 - 2025-08-06

### What's Changed

This major release drops obsolete API functions, OpenSSL 1.1.1 support and support for old OS versions.
The breaking changes are discussed here: https://github.com/baresip/re/discussions/1372

* rem: remove backwards wrapper for au_calc_nsamp() by @alfredh in https://github.com/baresip/re/pull/1366
* rem: remove local macros, include stdint.h instead by @alfredh in https://github.com/baresip/re/pull/1369
* mod: remove unused MOD_PRE macro by @alfredh in https://github.com/baresip/re/pull/1370
* tcp: remove special case for mingw32/wine by @alfredh in https://github.com/baresip/re/pull/1367
* dd: update AV1 and DD docs by @alfredh in https://github.com/baresip/re/pull/1376
* test: fix formatted string arguments in URI testcode by @alfredh in https://github.com/baresip/re/pull/1375
* tls: drop OpenSSL 1.1.1 support by @sreimers in https://github.com/baresip/re/pull/1371
* Update supported OS versions by @sreimers in https://github.com/baresip/re/pull/1373
* readme: update supported compilers by @sreimers in https://github.com/baresip/re/pull/1374
* tls: disable tls_conn_change_cert for LibreSSL by @sreimers in https://github.com/baresip/re/pull/1377
* ci/ssl: bump ssl tools assets by @sreimers in https://github.com/baresip/re/pull/1127
* aubuf: remove unused struct auframe in ajb.c by @alfredh in https://github.com/baresip/re/pull/1378
* aubuf: remove unused private function plot_underrun() by @alfredh in https://github.com/baresip/re/pull/1380
* readme: bump supported GNU C library (glibc) 2.31 by @sreimers in https://github.com/baresip/re/pull/1379
* misc: remove deprecated functions/params by @sreimers in https://github.com/baresip/re/pull/1384
* uri: remove password field by @alfredh in https://github.com/baresip/re/pull/1382
* websock: increase test coverage by @alfredh in https://github.com/baresip/re/pull/1381
* udp: remove obsolete todo in udp_local_get() by @alfredh in https://github.com/baresip/re/pull/1386
* av1: remove av1_packetize_new() -- backwards compat wrapper by @alfredh in https://github.com/baresip/re/pull/1385
* tls: remove tls_set_selfsigned_rsa() -- use Elliptic Curve instead by @alfredh in https://github.com/baresip/re/pull/1388
* test: enable dtls_set_single() for DTLS client test by @alfredh in https://github.com/baresip/re/pull/1387


**Full Changelog**: https://github.com/baresip/re/compare/v3.24.0...v4.0.0

## v3.24.0 - 2025-07-09

### What's Changed
* list: add LIST_FOREACH_SAFE helper macro by @sreimers in https://github.com/baresip/re/pull/1343
* test: SDP interop testing by @alfredh in https://github.com/baresip/re/pull/1341
* ci/abi: bump old ref version by @sreimers in https://github.com/baresip/re/pull/1344
* list: improve already linked warning by @sreimers in https://github.com/baresip/re/pull/1345
* ci/mingw: use windows-latest by @sreimers in https://github.com/baresip/re/pull/1346
* ci/clang: use clang-20 by @sreimers in https://github.com/baresip/re/pull/1348
* av1: rename av1_packetize_new() and add wrapper by @alfredh in https://github.com/baresip/re/pull/1349
* trice: update header to match filename by @alfredh in https://github.com/baresip/re/pull/1350
* rtp/rr: fix fraction left shift promotion by @sreimers in https://github.com/baresip/re/pull/1353
* test/sipsess: cast rel100_mode by @sreimers in https://github.com/baresip/re/pull/1354
* test: print trice_debug to buffer to test debug functions by @alfredh in https://github.com/baresip/re/pull/1352
* trice: update doxygen documentation by @alfredh in https://github.com/baresip/re/pull/1351
* rtp: add rtp_seq_less inline function helper by @sreimers in https://github.com/baresip/re/pull/1355
* trice: remove trice_set_software() by @alfredh in https://github.com/baresip/re/pull/1359
* trice: always enable PRFLX candidates by @alfredh in https://github.com/baresip/re/pull/1360
* rtp: add TWCC packet definition helpers by @sreimers in https://github.com/baresip/re/pull/1357
* test: add support check for SRTP GCM test cases by @alfredh in https://github.com/baresip/re/pull/1361
* trice: add more doxygen comments by @alfredh in https://github.com/baresip/re/pull/1362
* prepare for release -- bump version to 3.24.0 by @alfredh in https://github.com/baresip/re/pull/1365


**Full Changelog**: https://github.com/baresip/re/compare/v3.23.0...v3.24.0


## v3.23.0 - 2025-06-04

### What's Changed
* fmt/pl: optimize pl_bool return early by @sreimers in https://github.com/baresip/re/pull/1311
* ci/coverage: bump min_cov by @sreimers in https://github.com/baresip/re/pull/1312
* av1: allow OBU type 0 (RESERVED) by @alfredh in https://github.com/baresip/re/pull/1313
* ci: remove step to install ninja on macOS by @alfredh in https://github.com/baresip/re/pull/1315
* rtp: remove unused function ntp2unix() by @alfredh in https://github.com/baresip/re/pull/1314
* tls: fix compiler warning with libressl 4.1.0 by @alfredh in https://github.com/baresip/re/pull/1318
* vhprintf: change from char to int to store error number from %m by @alfredh in https://github.com/baresip/re/pull/1319
* http: cancel verify_cert_tmr and skip init by @alfredh in https://github.com/baresip/re/pull/1317
* mem: update doxygen comments in mem_pool.c by @alfredh in https://github.com/baresip/re/pull/1320
* tls: fix LibreSSL SSL_verify_cb by @sreimers in https://github.com/baresip/re/pull/1322
* cmake,http: add HAVE_TLS1_3_POST_HANDSHAKE_AUTH by @sreimers in https://github.com/baresip/re/pull/1323
* av1: remove deprecated av1_packetize_high() by @alfredh in https://github.com/baresip/re/pull/1321
* tls: fix SSL_SESSION_is_resumable LibreSSL by @sreimers in https://github.com/baresip/re/pull/1324
* sip: exposed ltag and rtag in sip dialog by @gordongrech in https://github.com/baresip/re/pull/1326
* sipsess: add cancel reason to close handler by @KillingSpark in https://github.com/baresip/re/pull/1325
* h265: add H265_NAL_RSV_IRAP_VCL{22,23} by @alfredh in https://github.com/baresip/re/pull/1327
* test/httpauth: fix debug warning for digest response by @cspiel1 in https://github.com/baresip/re/pull/1332
* sha: use PROV_RSA_AES for CryptAcquireContext by @alfredh in https://github.com/baresip/re/pull/1331
* test: Add test for thread tss by @weili-jiang in https://github.com/baresip/re/pull/1334
* 100rel improvements by @maximilianfridrich in https://github.com/baresip/re/pull/1333
* test/async: Remove unsupported AI_V4MAPPED on Android by @weili-jiang in https://github.com/baresip/re/pull/1336
* test/sys: Use writeable datapath for fs_open test by @weili-jiang in https://github.com/baresip/re/pull/1335
* net: Support ifaddrs on Android API level >= 24 by @weili-jiang in https://github.com/baresip/re/pull/1338
* ci: Enable testing on Android by @weili-jiang in https://github.com/baresip/re/pull/1337
* test/sipsess: fix test_sipsess_100rel_answer_not_allowed by @maximilianfridrich in https://github.com/baresip/re/pull/1340

### New Contributors
* @gordongrech made their first contribution in https://github.com/baresip/re/pull/1326
* @KillingSpark made their first contribution in https://github.com/baresip/re/pull/1325

**Full Changelog**: https://github.com/baresip/re/compare/v3.22.0...v3.23.0


## v3.22.0 - 2025-04-30

### What's Changed
* rtp: remove unused int proto by @alfredh in https://github.com/baresip/re/pull/1296
* mbuf: null pointer checks for inline functions by @cspiel1 in https://github.com/baresip/re/pull/1294
* test: more coverage in rtcp_loop by @alfredh in https://github.com/baresip/re/pull/1295
* ci: remove version from choco install openssl by @alfredh in https://github.com/baresip/re/pull/1297
* net/linux/addrs: use malloc for buffer by @sreimers in https://github.com/baresip/re/pull/1298
* cmake: update cmake_minimum_required 3.18...4.0 by @sreimers in https://github.com/baresip/re/pull/1291
* ci: upgrade mingw to openssl 3.5.0 by @alfredh in https://github.com/baresip/re/pull/1299
* ci/abi: bump ref version by @sreimers in https://github.com/baresip/re/pull/1300
* rtp: RTCP Extended report by @shrim27 in https://github.com/baresip/re/pull/1302
* test: move test_rtcp_xr_rrtr to rtcp.c by @alfredh in https://github.com/baresip/re/pull/1306
* Handle "w" properly in the AV1 packetizer by @npcook in https://github.com/baresip/re/pull/1305
* test: add coverage of RTCP-XR DLRR by @alfredh in https://github.com/baresip/re/pull/1307
* av1: remove deprecated av1_packetize_one_w() by @alfredh in https://github.com/baresip/re/pull/1308

## New Contributors
* @shrim27 made their first contribution in https://github.com/baresip/re/pull/1302
* @npcook made their first contribution in https://github.com/baresip/re/pull/1305

**Full Changelog**: https://github.com/baresip/re/compare/v3.21.1...v3.22.0

## v3.21.1 - 2025-04-04

### What's Changed
* vidconv: fix vidconv_center underflows by @sreimers in https://github.com/baresip/re/pull/1287
* mem: fix buffer overflow in mem_realloc by @maximilianfridrich in https://github.com/baresip/re/pull/1289
* mem/mem_pool: use pointer-pointer to prevent heap-use-after-free by @sreimers in https://github.com/baresip/re/pull/1290

**Full Changelog**: https://github.com/baresip/re/compare/v3.21.0...v3.21.1


## v3.21.0 - 2025-03-26

### What's Changed
* fmt/pl: add pl_strncasecmp and tests by @sreimers in https://github.com/baresip/re/pull/1277
* ci: upgrade run-on-arch-action to fix random segfaults by @alfredh in https://github.com/baresip/re/pull/1280
* test: add testing of RTCP FIR-RFC5104 by @alfredh in https://github.com/baresip/re/pull/1281
* rtpext: add rtpext_find by @sreimers in https://github.com/baresip/re/pull/1282
* rtp: add rtp_ prefix to member functions by @alfredh in https://github.com/baresip/re/pull/1283
* rtp/rtcp: add rtcp_send_twcc and rtcp_rtpfb_twcc_encode by @sreimers in https://github.com/baresip/re/pull/1285
* list: optimize list_count by @sreimers in https://github.com/baresip/re/pull/1284
* bump version to 3.21.0 by @alfredh in https://github.com/baresip/re/pull/1286


**Full Changelog**: https://github.com/baresip/re/compare/v3.20.0...v3.21.0


## v3.20.0 - 2025-02-18

### What's Changed
* http/server: increase BUFSIZE_MAX to 1 MB and add http_set_max_body_size by @sreimers in https://github.com/baresip/re/pull/1262
* test: init err to zero (fixes cppcheck warning) by @alfredh in https://github.com/baresip/re/pull/1265
* test: add RTCP_APP to RTCP test by @alfredh in https://github.com/baresip/re/pull/1266
* mem,aubuf: add pre-allocated memory pool management by @sreimers in https://github.com/baresip/re/pull/1255
* test: increase test_oom levels and oom fixes by @sreimers in https://github.com/baresip/re/pull/1260
* mem/mem_pool: fix mem_pool_extend new member destructor by @sreimers in https://github.com/baresip/re/pull/1267
* ci: bump version and min_cov by @sreimers in https://github.com/baresip/re/pull/1268
* av1: remove duplicate/unused getbit.c by @alfredh in https://github.com/baresip/re/pull/1272
* test/cmake: link C++ lib by @sreimers in https://github.com/baresip/re/pull/1269
* http: restart timer for each chunk by @fAuernigg in https://github.com/baresip/re/pull/1273
* ci/valgrind: use ubuntu-latest by @sreimers in https://github.com/baresip/re/pull/1274

**Full Changelog**: https://github.com/baresip/re/compare/v3.19.0...v3.20.0


## v3.19.0 - 2025-01-15

### What's Changed
* fmt: fix pl trim methods and add tests by @maximilianfridrich in https://github.com/baresip/re/pull/1226
* sipsess: add sipsess_msg getter function by @cspiel1 in https://github.com/baresip/re/pull/1225
* rtp/sess: fix missing srate_tx locking by @sreimers in https://github.com/baresip/re/pull/1231
* rtcp: use rtcp_rtpfb_gnack_encode() function by @alfredh in https://github.com/baresip/re/pull/1233
* net/linux: add net_netlink_addrs by @sreimers in https://github.com/baresip/re/pull/1232
* tcp,udp: set TOS (TCLASS) for IPv6 sockets by @maximilianfridrich in https://github.com/baresip/re/pull/1218
* sys/fs: fix fs_fopen return null check by @sreimers in https://github.com/baresip/re/pull/1237
* test: remove mock tcp-server (unused) by @alfredh in https://github.com/baresip/re/pull/1235
* rtp: remove rtcp_psfb_sli_encode() (unused) by @alfredh in https://github.com/baresip/re/pull/1234
* ci/clang: bump clang-18 and use ubuntu 24.04 by @sreimers in https://github.com/baresip/re/pull/1236
* net/linux/addrs: fix point-to-point peer address bug by @sreimers in https://github.com/baresip/re/pull/1239
* ci/coverage: bump min_cov by @sreimers in https://github.com/baresip/re/pull/1241
* ci/sanitizers: bump clang and ubuntu by @sreimers in https://github.com/baresip/re/pull/1242
* net/linux/addrs: fix netlink kernel warnings by @sreimers in https://github.com/baresip/re/pull/1243
* rem: add au_ prefix to calc_nsamp() by @alfredh in https://github.com/baresip/re/pull/1244
* rem/vidconv: add vidconv_center and x and y source offsets by @sreimers in https://github.com/baresip/re/pull/1240
* test: add testcode for rem au-module by @alfredh in https://github.com/baresip/re/pull/1245
* mem: remove peak from memstat by @alfredh in https://github.com/baresip/re/pull/1238
* debian: replace with CPack DEB Generator by @sreimers in https://github.com/baresip/re/pull/1247
* copyright: happy new year 2025 by @sreimers in https://github.com/baresip/re/pull/1246
* test/vidconv: remove static struct test by @sreimers in https://github.com/baresip/re/pull/1248
* net/linux/addrs: use list instead of fixed array for interface up by @sreimers in https://github.com/baresip/re/pull/1251
* test: optional IPv6 for tcp/udp tos test by @alfredh in https://github.com/baresip/re/pull/1252
* cmake: update min requirement and use range by @sreimers in https://github.com/baresip/re/pull/1253
* rem/vid/frame: fix vidframe init by @sreimers in https://github.com/baresip/re/pull/1257
* atomic: fix compilation for C++ and Windows-ARM64 by @alfredh in https://github.com/baresip/re/pull/1259
* test: add test for C++ applications by @alfredh in https://github.com/baresip/re/pull/1254
* ci: use ubuntu-22.04 were needed by @sreimers in https://github.com/baresip/re/pull/1261
* cmake: enable compiler warnings for C only by @alfredh in https://github.com/baresip/re/pull/1263


**Full Changelog**: https://github.com/baresip/re/compare/v3.18.0...v3.19.0


## v3.18.0 - 2024-12-11

### What's Changed
* odict: add odict_pl_add() by @cspiel1 in https://github.com/baresip/re/pull/1208
* ci/build: remove Ubuntu 20.04, add 24.04, use GCC 14 on 24.04 by @robert-scheck in https://github.com/baresip/re/pull/1210
* test: vertical alignment of integration test names by @alfredh in https://github.com/baresip/re/pull/1212
* sip: update doxygen comment by @alfredh in https://github.com/baresip/re/pull/1215
* test/http: decrease test runs from 20 to 3 to decrease test time by @fAuernigg in https://github.com/baresip/re/pull/1216
* sip/transp: allow requests w/o Max-Forwards header by @cspiel1 in https://github.com/baresip/re/pull/1217
* test: remove unused fuzz mock by @alfredh in https://github.com/baresip/re/pull/1220
* rtp: use rtp_pt_is_rtcp() for RTCP demultiplexing by @alfredh in https://github.com/baresip/re/pull/1221
* aes: remove 192-bits CTR-mode (looks unused) by @alfredh in https://github.com/baresip/re/pull/1219
* rtp: send all RTCP packets as compound packets by @maximilianfridrich in https://github.com/baresip/re/pull/1222
* rtp/sess.c: lock rtcp_sess in rtcp_set_srate_tx to fix data race by @maximilianfridrich in https://github.com/baresip/re/pull/1223
* Update Doxyfile by @alfredh in https://github.com/baresip/re/pull/1224
* test: remove unused packet-filter mock by @alfredh in https://github.com/baresip/re/pull/1227
* bump version to 3.18.0 by @alfredh in https://github.com/baresip/re/pull/1230


**Full Changelog**: https://github.com/baresip/re/compare/v3.17.0...v3.18.0


## v3.17.0 - 2024-11-06

### What's Changed
* types: remove old BREAKPOINT macro by @alfredh in https://github.com/baresip/re/pull/1194
* dnsc: Fallback to getaddrinfo without any DNS servers by @weili-jiang in https://github.com/baresip/re/pull/1195
* dns/client: return ENOTSUP if no server or not getaddrinfo by @sreimers in https://github.com/baresip/re/pull/1196
* conf: add conf_get_float by @juha-h in https://github.com/baresip/re/pull/1198
* ci/run-on-arch: use ubuntu 22.04 by @sreimers in https://github.com/baresip/re/pull/1204
* thread: fix thrd_equal win32 handle by @sreimers in https://github.com/baresip/re/pull/1203
* test: add pktsize to test_h264_packet_base() by @alfredh in https://github.com/baresip/re/pull/1205
* tls: make tls_verify_handler() static by @alfredh in https://github.com/baresip/re/pull/1201
* types: fix clang-tidy warning (gcc bit fields workaround) by @sreimers in https://github.com/baresip/re/pull/1206

### New Contributors
* @weili-jiang made their first contribution in https://github.com/baresip/re/pull/1195

**Full Changelog**: https://github.com/baresip/re/compare/v3.16.0...v3.17.0


## v3.16.0 - 2024-10-02

### What's Changed
* thread: fix pthread_setname_np NetBSD by @leleliu008 in https://github.com/baresip/re/pull/1182
* ice: AI_V4MAPPED macro is missing on some BSD systems by @leleliu008 in https://github.com/baresip/re/pull/1181
* rtp/rtcp: add RTCP Generic NACK packet send (RFC 4585 6.2.1) by @sreimers in https://github.com/baresip/re/pull/1186
* main/fd_listen: return EMFILE if maxfds is reached by @sreimers in https://github.com/baresip/re/pull/1185
* ci: build retest for android by @alfredh in https://github.com/baresip/re/pull/1187
* test: minor cmake cleanup by @alfredh in https://github.com/baresip/re/pull/1188
* test: fix re_printf format string for multithread test by @alfredh in https://github.com/baresip/re/pull/1190
* ci: run retest on Fedora by @alfredh in https://github.com/baresip/re/pull/1191

### New Contributors
* @leleliu008 made their first contribution in https://github.com/baresip/re/pull/1182

**Full Changelog**: https://github.com/baresip/re/compare/v3.15.0...v3.16.0


## v3.15.0 - 2024-08-28

### What's Changed
* misc: remove HAVE_INET6 by @sreimers in https://github.com/baresip/re/pull/1159
* dns/rr: fix dns_rr_print underflow by @sreimers in https://github.com/baresip/re/pull/1162
* test/async: remove AI_ADDRCONFIG by @sreimers in https://github.com/baresip/re/pull/1165
* retest: update usage message by @robert-scheck in https://github.com/baresip/re/pull/1166
* add filter_registrar option by @maximilianfridrich in https://github.com/baresip/re/pull/1160
* sa: add utility function to check if address is multicast by @cmfitch1 in https://github.com/baresip/re/pull/1168
* tls/sni: skip SNI check if we are client or server_name absent by @maximilianfridrich in https://github.com/baresip/re/pull/1169
* tls/sni: do not enable client verification when SNI matching is done by @maximilianfridrich in https://github.com/baresip/re/pull/1172
* dd: Dependency Descriptor RTP header extension by @alfredh in https://github.com/baresip/re/pull/1170
* aubuf: add AUBUF_TRACE mode with id by @sreimers in https://github.com/baresip/re/pull/1174
* sip/transp: add client certificate to all TLS transports by @maximilianfridrich in https://github.com/baresip/re/pull/1173
* tmr: add TMR_INIT by @sreimers in https://github.com/baresip/re/pull/1177
* sipsess/reply: fix heap-use-after-free bug by @sreimers in https://github.com/baresip/re/pull/1179
* version 3.15.0 by @alfredh in https://github.com/baresip/re/pull/1180

### New Contributors
* @cmfitch1 made their first contribution in https://github.com/baresip/re/pull/1168

**Full Changelog**: https://github.com/baresip/re/compare/v3.14.0...v3.15.0


## [v3.14.0] - 2024-07-23

### What's Changed
* aumix: use mutex_alloc() by @alfredh in https://github.com/baresip/re/pull/1142
* sipreg/reg.c: stop retrying registers early after 401/407 by @maximilianfridrich in https://github.com/baresip/re/pull/1143
* aumix: add locking in aumix_source_count() by @alfredh in https://github.com/baresip/re/pull/1145
* test: init err in test_sip_auth_encode() by @alfredh in https://github.com/baresip/re/pull/1146
* sipreg: refactor response_handler else optimization by @sreimers in https://github.com/baresip/re/pull/1147
* vidmix: improve mutex usage by @alfredh in https://github.com/baresip/re/pull/1148
* udp/mcast: use group scopeid as interface for IPv6 by @maximilianfridrich in https://github.com/baresip/re/pull/1149
* .clangd: suppress -Wgnu-zero-variadic-macro-arguments by @maximilianfridrich in https://github.com/baresip/re/pull/1150
* ci/build: use only macos-latest by @sreimers in https://github.com/baresip/re/pull/1153
* cmake: fix resolv on FreeBSD by @sreimers in https://github.com/baresip/re/pull/1152
* test: use h264_stap_decode_annexb() by @alfredh in https://github.com/baresip/re/pull/1151
* sipsess/reply: terminate session if no (PR)ACK received after 64*T1 by @maximilianfridrich in https://github.com/baresip/re/pull/1155
* rtcp: send BYE manually by @alfredh in https://github.com/baresip/re/pull/1154
* cmake: check accept4 only on linux by @sreimers in https://github.com/baresip/re/pull/1157
* cmake: fix iOS HAVE_ROUTE_LIST and darwin dns by @sreimers in https://github.com/baresip/re/pull/1158
* test: check if header and payload is set by @alfredh in https://github.com/baresip/re/pull/1161


**Full Changelog**: https://github.com/baresip/re/compare/v3.13.0...v3.14.0


## [v3.13.0] - 2024-06-19

### What's Changed
* http/client: use dynamically sized buffers for PEM setters by @maximilianfridrich in https://github.com/baresip/re/pull/1117
* tls: allow secure TLS renegotiation by @maximilianfridrich in https://github.com/baresip/re/pull/1121
* tls: always enable USE_OPENSSL_SRTP by @alfredh in https://github.com/baresip/re/pull/1122
* main: remove call to openssl init by @alfredh in https://github.com/baresip/re/pull/1120
* sip/transp: Allow ACK w/o Max-Forwards header by @juha-h in https://github.com/baresip/re/pull/1124
* net: remove NET_ADDRSTRLEN by @alfredh in https://github.com/baresip/re/pull/1123
* ci/ios: increase min deployment target by @sreimers in https://github.com/baresip/re/pull/1126
* tls/http: add certificate chain setters by @maximilianfridrich in https://github.com/baresip/re/pull/1125
* sipsess/connect: set sess->established immediately on 200 receival by @maximilianfridrich in https://github.com/baresip/re/pull/1128
* test/cmake: add crypt32 linking for WIN32 by @sreimers in https://github.com/baresip/re/pull/1130
* ci/sanitizers: use clang-17 by @sreimers in https://github.com/baresip/re/pull/1131
* ci/sanitizer: add undefined behavior sanitizer by @sreimers in https://github.com/baresip/re/pull/1132
* sip: verify call-id, to-tag, cseq of INVITE response by @maximilianfridrich in https://github.com/baresip/re/pull/1129
* ci: remove one unneeded directory change by @alfredh in https://github.com/baresip/re/pull/1134
* test: change GENERATOR_SSRC from define to type by @alfredh in https://github.com/baresip/re/pull/1133
* tls: refactoring SNI ctx usage for libressl support by @sreimers in https://github.com/baresip/re/pull/1136
* test: add test_rtcp_loop() by @alfredh in https://github.com/baresip/re/pull/1137
* ci/coverage: increase min coverage by @sreimers in https://github.com/baresip/re/pull/1138
* ci/coverage: use json summary and upload html details by @sreimers in https://github.com/baresip/re/pull/1139
* sip: add host param to sip_send_conn by @sreimers in https://github.com/baresip/re/pull/1141


**Full Changelog**: https://github.com/baresip/re/compare/v3.12.0...v3.13.0

## [v3.12.0] - 2024-05-15

### What's Changed
* cmake: fix static library build (vcpkg) by @alfredh in https://github.com/baresip/re/pull/1096
* h264: add STAP-A decode with long startcodes by @alfredh in https://github.com/baresip/re/pull/1101
* sess,request: deref request and ctrans immediately by @maximilianfridrich in https://github.com/baresip/re/pull/1099
* ua: enforce magic cookie in Via branch by @maximilianfridrich in https://github.com/baresip/re/pull/1102
* sip/auth: SHA-256 digest algorithm support by @sreimers in https://github.com/baresip/re/pull/1103
* ci/coverage: increase min. coverage by @sreimers in https://github.com/baresip/re/pull/1106
* rtp: fix correct logging text by @alfredh in https://github.com/baresip/re/pull/1109
* types: fix RE_ARG_SIZE gcc bit fields by @sreimers in https://github.com/baresip/re/pull/1110
* fmt: use re_fprintf instead of DEBUG_WARNING to avoid deadlock by @alfredh in https://github.com/baresip/re/pull/1112
* dbg: remove support for logfile by @alfredh in https://github.com/baresip/re/pull/1111
* test: add usage of rtcp_msg_print() by @alfredh in https://github.com/baresip/re/pull/1105
* http/client: add setter to disable tls server verification by @maximilianfridrich in https://github.com/baresip/re/pull/1114
* dbg: mutex should be unlocked while calling print handler by @alfredh in https://github.com/baresip/re/pull/1113
* Update README.md by @alfredh in https://github.com/baresip/re/pull/1115
* http/request: reset body mbuf pos on re-sending by @maximilianfridrich in https://github.com/baresip/re/pull/1116
* bump version by @alfredh in https://github.com/baresip/re/pull/1118
* cmake: bump soversion by @alfredh in https://github.com/baresip/re/pull/1119


**Full Changelog**: https://github.com/baresip/re/compare/v3.11.0...v3.12.0


## [v3.11.0] - 2024-04-09

### What's Changed
* ci/clang-analyze: bump clang version and fix status-bugs by @sreimers in https://github.com/baresip/re/pull/1079
* main: Flush list of deleted fhs on `fd_poll` errors by @Lastique in https://github.com/baresip/re/pull/1081
* main: Use slist for fhs delete list. by @Lastique in https://github.com/baresip/re/pull/1082
* http/server: fix wrong sizeof in verify_msg by @akscf in https://github.com/baresip/re/pull/1083
* ci/sanitizers: add mmap rnd_bits workaround by @sreimers in https://github.com/baresip/re/pull/1086
* rtcp: add printing of TWCC packet by @alfredh in https://github.com/baresip/re/pull/1084
* include: add re_h264.h to re.h by @alfredh in https://github.com/baresip/re/pull/1087
* sdp: add sdp media lattr apply function the same way as for rattr by @cHuberCoffee in https://github.com/baresip/re/pull/1089
* av1: improve packetizer by @alfredh in https://github.com/baresip/re/pull/1088
* test: minor H.264 improvements by @alfredh in https://github.com/baresip/re/pull/1090
* tls: add session resumption setter by @maximilianfridrich in https://github.com/baresip/re/pull/1091
* thread/posix: optimize handler and fix gcc arm32 warning by @sreimers in https://github.com/baresip/re/pull/1093
* h264: fix for Annex-B bitstreams with 4-byte startcode by @alfredh in https://github.com/baresip/re/pull/1092
* ci/arch: add armv7 check by @sreimers in https://github.com/baresip/re/pull/1085
* main,httpauth: fix different from the declaration by @jobo-zt in https://github.com/baresip/re/pull/1095
* httpauth: fix doxygen comment by @alfredh in https://github.com/baresip/re/pull/1097

### New Contributors
* @akscf made their first contribution in https://github.com/baresip/re/pull/1083

**Full Changelog**: https://github.com/baresip/re/compare/v3.10.0...v3.11.0


## [v3.10.0] - 2024-03-06

## What's Changed
* transp: deref qent only if qentp is not set by @maximilianfridrich in https://github.com/baresip/re/pull/1061
* sipsess: fix doxygen comments by @alfredh in https://github.com/baresip/re/pull/1062
* aufile: fix doxygen comment by @alfredh in https://github.com/baresip/re/pull/1063
* ci/codeql: bump action v3 by @sreimers in https://github.com/baresip/re/pull/1064
* misc: text2pcap helpers (RTP/RTCP capturing) by @sreimers in https://github.com/baresip/re/pull/1065
* ci/mingw: bump upload/download-artifact and cache versions by @sreimers in https://github.com/baresip/re/pull/1066
* transp,tls: add TLS client verification by @maximilianfridrich in https://github.com/baresip/re/pull/1059
* fmt/text2pcap: cleanup by @sreimers in https://github.com/baresip/re/pull/1067
* ci/android: cache openssl build by @sreimers in https://github.com/baresip/re/pull/1068
* ci/misc: fix double push/pull runs by @sreimers in https://github.com/baresip/re/pull/1069
* fmt/text2pcap: fix coverity return value warning by @sreimers in https://github.com/baresip/re/pull/1070
* sipsess/listen: improve glare handling by @maximilianfridrich in https://github.com/baresip/re/pull/1071
* conf: add conf_get_i32 by @sreimers in https://github.com/baresip/re/pull/1072


**Full Changelog**: https://github.com/baresip/re/compare/v3.9.0...v3.10.0


## [v3.9.0] - 2024-01-31

## What's Changed
* http: fix doxygen by @cspiel1 in https://github.com/baresip/re/pull/1033
* types: remove old ARRAY_SIZE macro by @alfredh in https://github.com/baresip/re/pull/1034
* cmake: bump minimum to version 3.14 by @alfredh in https://github.com/baresip/re/pull/1030
* test: use re_is_aligned() by @alfredh in https://github.com/baresip/re/pull/1035
* sipsess: refactor and simplify SDP negotiation state by @maximilianfridrich in https://github.com/baresip/re/pull/1016
* bump year by @sreimers in https://github.com/baresip/re/pull/1038
* cmake,pc: fix static library build by @alfredh in https://github.com/baresip/re/pull/1036
* rx thread activate by @cspiel1 in https://github.com/baresip/re/pull/1037
* test: fix cppcheck warnings by @alfredh in https://github.com/baresip/re/pull/1040
* test: move test_rtcp_decode_badmsg() to separate testcase by @alfredh in https://github.com/baresip/re/pull/1041
* rtp: lock more fields from rtcp_sess by @cspiel1 in https://github.com/baresip/re/pull/1039
* rtp: lock rtcp_set_srate() by @cspiel1 in https://github.com/baresip/re/pull/1043
* test: HAVE_INET6 is always defined by @alfredh in https://github.com/baresip/re/pull/1046
* ci: add run-on-arch for ARM64 linux by @alfredh in https://github.com/baresip/re/pull/1045
* httpauth: digest verification rfc 7616 by @cHuberCoffee in https://github.com/baresip/re/pull/1044
* tmr: prevent race condition on cancel by @sreimers in https://github.com/baresip/re/pull/1048
* aubuf: fix coverity defect by @alfredh in https://github.com/baresip/re/pull/1051
* btrace: fix coverity warning by @alfredh in https://github.com/baresip/re/pull/1049
* ci/win: downgrade openssl by @sreimers in https://github.com/baresip/re/pull/1054
* docs: update README by @alfredh in https://github.com/baresip/re/pull/1053
* http: client - set scopeid fixes HTTP requests for IPv6ll by @cspiel1 in https://github.com/baresip/re/pull/1055
* rtp: add rtp_source_ prefix to RTP source api by @alfredh in https://github.com/baresip/re/pull/1052
* rtp: make struct rtp_source public by @alfredh in https://github.com/baresip/re/pull/1057
* rtp: sess - fix coverity warning by @cspiel1 in https://github.com/baresip/re/pull/1058
* mk: bump version to 3.9.0 by @alfredh in https://github.com/baresip/re/pull/1060


**Full Changelog**: https://github.com/baresip/re/compare/v3.8.0...v3.9.0


## [v3.8.0] - 2023-12-27

## What's Changed
* Update README.md by @alfredh in https://github.com/baresip/re/pull/1013
* rem/aufile: aufile_get_length use aufmt_sample_size by @larsimmisch in https://github.com/baresip/re/pull/1011
* rem/aufile: test and fix aufile_set_position nread by @larsimmisch in https://github.com/baresip/re/pull/1010
* ci/ssl: bump assets release by @sreimers in https://github.com/baresip/re/pull/1014
* readme: update supported openssl versions by @sreimers in https://github.com/baresip/re/pull/1015
* ci: upgrade android to openssl 3.2.0 by @alfredh in https://github.com/baresip/re/pull/1017
* sipsess/connect: don't create a dialog for 100 responses by @maximilianfridrich in https://github.com/baresip/re/pull/1018
* aubuf: fix build with re_trace_event by @cspiel1 in https://github.com/baresip/re/pull/1019
* trace: fix coverity warnings by @alfredh in https://github.com/baresip/re/pull/1024
* aumix: fix coverity defect in destructor by @alfredh in https://github.com/baresip/re/pull/1025
* main: fix doxygen comment by @alfredh in https://github.com/baresip/re/pull/1026
* connect: do not enforce Contact header in 1XX responses with To tag by @maximilianfridrich in https://github.com/baresip/re/pull/1028
* test/sipsess: test re-INVITE with wait for ACK by @cspiel1 in https://github.com/baresip/re/pull/1027
* dialog: fix rtags of forking INVITE by @maximilianfridrich in https://github.com/baresip/re/pull/1023
* cmake: add RE_LIBS config and add atomic check by @sreimers in https://github.com/baresip/re/pull/1029
* ci: use actions/checkout@v4 by @robert-scheck in https://github.com/baresip/re/pull/1031

**Full Changelog**: https://github.com/baresip/re/compare/v3.7.0...v3.8.0


## [v3.7.0] - 2023-11-06

## What's Changed
* trace: add id handling by @sreimers in https://github.com/baresip/re/pull/981
* fmt/pl: add pl_alloc_str by @sreimers in https://github.com/baresip/re/pull/983
* ci/freebsd: limit runtime to 20 mins by @sreimers in https://github.com/baresip/re/pull/985
* Httpauth digest response by @cHuberCoffee in https://github.com/baresip/re/pull/944
* dialog: REVERT fix rtags of forking INVITE with 100rel (#947) by @juha-h in https://github.com/baresip/re/pull/986
* ice: AI_V4MAPPED doesn't exist on OpenBSD by @landryb in https://github.com/baresip/re/pull/989
* test: call - add call on-hold/resume test by @cspiel1 in https://github.com/baresip/re/pull/990
* async: fix re_async_cancel mqueue handling by @sreimers in https://github.com/baresip/re/pull/995
* async: clear callback function pointer after use (#992) by @cspiel1 in https://github.com/baresip/re/pull/993
* Update README.md: Fix link in section Examples. by @Wolf-SO in https://github.com/baresip/re/pull/991
* ci/abi: bump version by @sreimers in https://github.com/baresip/re/pull/1000
* rtp: make flag rtcp_mux atomic by @cspiel1 in https://github.com/baresip/re/pull/997
* cmake,udp: improve QOS_FLOWID and PQOS_FLOWID detection by @sreimers in https://github.com/baresip/re/pull/1002
* types: extend RE_ARG to 32 by @sreimers in https://github.com/baresip/re/pull/1003
* sip/transp: add win32 local transport addr fallback by @sreimers in https://github.com/baresip/re/pull/1001
* cmake/config: set HAVE_THREADS only if threads.h by @sreimers in https://github.com/baresip/re/pull/1005
* ci/freebsd: update vmactions/freebsd-vm@v1 by @sreimers in https://github.com/baresip/re/pull/1006
* Coverity httpauth fixes by @sreimers in https://github.com/baresip/re/pull/1007
* rem/aufile: fix aufile_get_length calculations by @larsimmisch in https://github.com/baresip/re/pull/1008

## New Contributors
* @Wolf-SO made their first contribution in https://github.com/baresip/re/pull/991

**Full Changelog**: https://github.com/baresip/re/compare/v3.6.0...v3.7.0

## [v3.6.2] - 2023-11-06

## What's Changed
sip/transp: add win32 local transport addr fallback (fixes TCP/TLS register)


## [v3.6.1] - 2023-11-03

## What's Changed
ice: AI_V4MAPPED doesn't exist on OpenBSD #989
dialog: REVERT fix rtags of forking INVITE with 100rel (#947) #986
debian: fix version number


## [v3.6.0] - 2023-10-17

## What's Changed
* ci/coverage: increase min. coverage by @sreimers in https://github.com/baresip/re/pull/958
* Implement aufile_set_position by @larsimmisch in https://github.com/baresip/re/pull/943
* dialog: fix rtags of forking INVITE with 100rel by @maximilianfridrich in https://github.com/baresip/re/pull/947
* tls/alloc: set default min proto TLS 1.2 by @sreimers in https://github.com/baresip/re/pull/948
* test: init err to 0 in sdp test (cppcheck) by @alfredh in https://github.com/baresip/re/pull/959
* main: fd_listen fhs alloc rewrite by @sreimers in https://github.com/baresip/re/pull/805
* Expand RE_BREAKPOINT macro on ARM64 by @larsimmisch in https://github.com/baresip/re/pull/961
* jbuf: trace data for plot by @cspiel1 in https://github.com/baresip/re/pull/964
* trace: use global trace log by @sreimers in https://github.com/baresip/re/pull/965
* main: use ifdef for RE_TRACE_ENABLED by @sreimers in https://github.com/baresip/re/pull/966
* test/hexdump: hide output by @sreimers in https://github.com/baresip/re/pull/968
* trace: remove global default trace json by @sreimers in https://github.com/baresip/re/pull/969
* ci/ssl: use tools repo and new assets by @sreimers in https://github.com/baresip/re/pull/972
* fmt: doxygen correction in print.c by @cspiel1 in https://github.com/baresip/re/pull/973
* trace: use only explicit RE_TRACE_ENABLED by cmake by @sreimers in https://github.com/baresip/re/pull/974
* cmake: enable C11 for Windows (not MINGW) by @alfredh in https://github.com/baresip/re/pull/970
* ci/coverage: lower min. coverage by @sreimers in https://github.com/baresip/re/pull/975
* jbuf: move jbuf to baresip by @cspiel1 in https://github.com/baresip/re/pull/971
* ci/coverage: improve coverage (enable trace) by @sreimers in https://github.com/baresip/re/pull/976
* ci: bump pr-dependency-action@v0.6 by @sreimers in https://github.com/baresip/re/pull/977
* ice: mDNS refactoring by @sreimers in https://github.com/baresip/re/pull/934
* trace: add flush worker and optimize memory usage by @sreimers in https://github.com/baresip/re/pull/967
* rtp: fix video jitter calculation and add arrival time rtp header by @sreimers in https://github.com/baresip/re/pull/978
* ci: remove DARWIN compile flag from iOS build by @alfredh in https://github.com/baresip/re/pull/979
* thread: add trace thread name logging by @sreimers in https://github.com/baresip/re/pull/980
* ci/coverage: reduce min. coverage by @sreimers in https://github.com/baresip/re/pull/982


**Full Changelog**: https://github.com/baresip/re/compare/v3.5.1...v3.6.0

## [v3.5.1] - 2023-09-12

## What's Changed
* cmake: fix RELEASE definition for older cmake releases by @sreimers in https://github.com/baresip/re/pull/953
* ci/build: add release build check by @sreimers in https://github.com/baresip/re/pull/954
* cmake: fix definitions for older cmake by @sreimers in https://github.com/baresip/re/pull/955

**Full Changelog**: https://github.com/baresip/re/compare/v3.5.0...v3.5.1

## [v3.5.0] - 2023-09-12

## What's Changed
* ci/sonar: update scanner and java version by @sreimers in https://github.com/baresip/re/pull/895
* ci/sonar: fix java distribution by @sreimers in https://github.com/baresip/re/pull/897
* udp: add doxygen comments by @alfredh in https://github.com/baresip/re/pull/896
* tls: fix some doxygen warnings by @alfredh in https://github.com/baresip/re/pull/894
* mk: add release target by @sreimers in https://github.com/baresip/re/pull/901
* types: add re_assert and re_assert_se definition by @sreimers in https://github.com/baresip/re/pull/900
* btrace improvements by @sreimers in https://github.com/baresip/re/pull/902
* Safe RE_VA_ARG helpers by @sreimers in https://github.com/baresip/re/pull/758
* mbuf: add safe mbuf_printf by @sreimers in https://github.com/baresip/re/pull/899
* auth: cast time_t timestamp by @sreimers in https://github.com/baresip/re/pull/903
* mbuf: add mbuf_write_ptr and mbuf_read_ptr by @sreimers in https://github.com/baresip/re/pull/898
* ci/mingw: remove cmake workaround by @sreimers in https://github.com/baresip/re/pull/906
* tls: assume OpenSSL version 1.1.1 or later by @alfredh in https://github.com/baresip/re/pull/907
* cmake: cleanup, remove unused define USE_OPENSSL_DTLS by @alfredh in https://github.com/baresip/re/pull/908
* test/turn: use mutex instead atomic  by @sreimers in https://github.com/baresip/re/pull/909
* stun: remove unused struct members by @alfredh in https://github.com/baresip/re/pull/910
* stun: complete doxygen for struct by @alfredh in https://github.com/baresip/re/pull/912
* tcp,udp: full IPv6 dual-stack socket support by @sreimers in https://github.com/baresip/re/pull/911
* aufile: add methods to get size in bytes/length in ms by @larsimmisch in https://github.com/baresip/re/pull/913
* async: signal ESHUTDOWN to all open worker callbacks by @sreimers in https://github.com/baresip/re/pull/915
* dns/client: fix async getaddr query abort (not thread safe) by @sreimers in https://github.com/baresip/re/pull/914
* async,dns/client: replace ESHUTDOWN with ECANCELED and optimize err handling by @sreimers in https://github.com/baresip/re/pull/918
* sip: remove unused local variable by @cspiel1 in https://github.com/baresip/re/pull/920
* dns/client: optimize udp timeout by @sreimers in https://github.com/baresip/re/pull/916
* ice: add candidate sdp mdns support by @sreimers in https://github.com/baresip/re/pull/917
* ice/icesdp: fix freeaddrinfo by @sreimers in https://github.com/baresip/re/pull/923
* retest: fix format string in test_listcases for size_t argument by @cHuberCoffee in https://github.com/baresip/re/pull/922
* httpauth: http digest challenge request using RFC 7616 by @cHuberCoffee in https://github.com/baresip/re/pull/919
* types: fix RE_ARG_SIZE default argument promotions by @sreimers in https://github.com/baresip/re/pull/924
* sip: fix TCP source port by @cspiel1 in https://github.com/baresip/re/pull/921
* fmt/print: add 64-bit length modifier %Li, %Ld and %Lu by @sreimers in https://github.com/baresip/re/pull/905
* fmt/print: improve print RE_VA_ARG debugging by @sreimers in https://github.com/baresip/re/pull/925
* sip/request: fix check return code (found by coverity) by @sreimers in https://github.com/baresip/re/pull/926
* httpauth/digest: use %L instead of PRI*64 macros by @sreimers in https://github.com/baresip/re/pull/927
* types: add RE_ARG_SIZE struct pl (avoids wrong print fmt %r usage) by @sreimers in https://github.com/baresip/re/pull/928
* dns/client: fix getaddrinfo err handling and mem_ref dnsc by @sreimers in https://github.com/baresip/re/pull/929
* rtp/rtp_debug: fix printf size format by @sreimers in https://github.com/baresip/re/pull/933
* main: optimize re_lock and re_unlock by @alfredh in https://github.com/baresip/re/pull/935
* hexdump: fix format and add test by @alfredh in https://github.com/baresip/re/pull/936
* test: fix bug in performance test format by @alfredh in https://github.com/baresip/re/pull/937
* types: remove some duplicated error codes by @alfredh in https://github.com/baresip/re/pull/939
* test: minor improvements in remain test by @alfredh in https://github.com/baresip/re/pull/931
* dbg: remove unused functions by @sreimers in https://github.com/baresip/re/pull/941
* cmake/re-config: add default CMAKE_BUILD_TYPE and fix RELEASE definition by @sreimers in https://github.com/baresip/re/pull/945

## New Contributors
* @larsimmisch made their first contribution in https://github.com/baresip/re/pull/913

**Full Changelog**: https://github.com/baresip/re/compare/v3.4.0...v3.5.0

## [v3.4.0] - 2023-08-09

## What's Changed
* rtpext: uniform parameter name fixes doxygen warning by @cspiel1 in https://github.com/baresip/re/pull/868
* mk: add rem to doxygen inputs by @cspiel1 in https://github.com/baresip/re/pull/869
* vidmix: allow different pixel format by @sreimers in https://github.com/baresip/re/pull/864
* ajb doxygen by @cspiel1 in https://github.com/baresip/re/pull/870
* aes: correct parameters for stub by @cspiel1 in https://github.com/baresip/re/pull/872
* ci/build: fail on cmake and compile warnings by @sreimers in https://github.com/baresip/re/pull/873
* fmt: fix format string in fmt_timestamp() by @alfredh in https://github.com/baresip/re/pull/874
* hmac,md5,sha: add mbedtls backend by @cspiel1 in https://github.com/baresip/re/pull/871
* test: no need to rewind freshly allocated mbuf by @alfredh in https://github.com/baresip/re/pull/876
* httpauth: basic challenge creation and verification functions by @cHuberCoffee in https://github.com/baresip/re/pull/875
* Fix include of re_thread.h in re_tmr.h by @nielsavonds in https://github.com/baresip/re/pull/879
* btrace: fix WIN32_LEAN_AND_MEAN macro redefine by @jobo-zt in https://github.com/baresip/re/pull/880
* aumix: add record sum handler by @sreimers in https://github.com/baresip/re/pull/877
* ci/win: disable x86 testing by @sreimers in https://github.com/baresip/re/pull/883
* sipsess: allow UPDATE and INFO in early dialog by @maximilianfridrich in https://github.com/baresip/re/pull/878
* prefix macro VERSION by @cspiel1 in https://github.com/baresip/re/pull/882
* main: use HAVE_SIGNAL in init.c by @cspiel1 in https://github.com/baresip/re/pull/881
* test: change to ASSERT_XXX macros, remove EXPECT_XXX macros by @alfredh in https://github.com/baresip/re/pull/885
* fmt: handy functions for pointer-length objects by @cHuberCoffee in https://github.com/baresip/re/pull/884
* test: add TWCC test from Chrome 114 packet by @alfredh in https://github.com/baresip/re/pull/886
* sipsess/listen: Fix target_refresh_handler by @maximilianfridrich in https://github.com/baresip/re/pull/888
* ci/mingw: downgrade cmake by @sreimers in https://github.com/baresip/re/pull/890
* cmake: fix target include path for subdir projects by @sreimers in https://github.com/baresip/re/pull/891

## New Contributors
* @nielsavonds made their first contribution in https://github.com/baresip/re/pull/879
* @jobo-zt made their first contribution in https://github.com/baresip/re/pull/880

**Full Changelog**: https://github.com/baresip/re/compare/v3.3.0...v3.4.0

## [v3.3.0] - 2023-07-05

## What's Changed
* jbuf: use float ratio by @sreimers in https://github.com/baresip/re/pull/817
* src: fix some typos by @alfredh in https://github.com/baresip/re/pull/828
* jbuf: constant jbuf_put() by @cspiel1 in https://github.com/baresip/re/pull/821
* ci/coverity: split up prepare and make steps by @sreimers in https://github.com/baresip/re/pull/832
* vidmix: coverity fix by @alfredh in https://github.com/baresip/re/pull/830
* sys/fs: fix fs_stdio_hide resource leak by @sreimers in https://github.com/baresip/re/pull/833
* http: coverity fix by @alfredh in https://github.com/baresip/re/pull/834
* avc: fix coverity by @alfredh in https://github.com/baresip/re/pull/835
* sys: fix return value by @alfredh in https://github.com/baresip/re/pull/836
* Do not automatically make new call when 3xx response is received by @juha-h in https://github.com/baresip/re/pull/829
* sipreg: supports PNS custom contact URI by @codyit in https://github.com/baresip/re/pull/837
* ci: add iOS platform by @alfredh in https://github.com/baresip/re/pull/838
* ci/mingw: use cv2pdb for debug info conversion by @sreimers in https://github.com/baresip/re/pull/839
* main: fix warning on Windows by @alfredh in https://github.com/baresip/re/pull/842
* http: add compile-time check for USE_TLS by @alfredh in https://github.com/baresip/re/pull/841
* test: check if USE_TLS is defined by @alfredh in https://github.com/baresip/re/pull/843
* thread: fix WIN32 mingw warning by @sreimers in https://github.com/baresip/re/pull/844
* src: fix doxygen warnings by @alfredh in https://github.com/baresip/re/pull/847
* rtpext: add doxygen comments by @alfredh in https://github.com/baresip/re/pull/846
* jbuf: enable old frame drop warnings by @sreimers in https://github.com/baresip/re/pull/848
* md5: add support for native Windows Wincrypt API by @alfredh in https://github.com/baresip/re/pull/850
* rtpext: add support for Two-Byte headers by @alfredh in https://github.com/baresip/re/pull/849
* sha: add support for Windows native API by @alfredh in https://github.com/baresip/re/pull/851
* cmake: change '-lm' to 'm' in LINKLIBS by @alfredh in https://github.com/baresip/re/pull/854
* hmac: add support for native Windows API by @alfredh in https://github.com/baresip/re/pull/853
* CI: Add support for building Windows ARM by @alfredh in https://github.com/baresip/re/pull/855
* async: add work mutex handling by @sreimers in https://github.com/baresip/re/pull/857
* SIP/TCP use source port for Via header by @cspiel1 in https://github.com/baresip/re/pull/824
* sip: use TCP source port for Contact header by @cspiel1 in https://github.com/baresip/re/pull/858
* cmake: remove obsolete $<INSTALL_INTERFACE:include for re-objs by @alfredh in https://github.com/baresip/re/pull/860
* vidmix: always clear frames (avoid artifacts) by @sreimers in https://github.com/baresip/re/pull/861
* http: use correct formatting %zu for size_t by @alfredh in https://github.com/baresip/re/pull/866

## New Contributors
* @codyit made their first contribution in https://github.com/baresip/re/pull/837

**Full Changelog**: https://github.com/baresip/re/compare/v3.2.0...v3.3.0


## [v3.2.0] - 2023-05-31

## What's Changed
* btrace: add win32 support by @sreimers in https://github.com/baresip/re/pull/767
* cmake,thread: OpenBSD support by @landryb in https://github.com/baresip/re/pull/773
* main/init: add exception signal handlers by @sreimers in https://github.com/baresip/re/pull/765
* ua: unescape incoming Refer-To header by @maximilianfridrich in https://github.com/baresip/re/pull/770
* main: add debug boolean to re\_thread\_check() by @sreimers in https://github.com/baresip/re/pull/775
* btrace: add addr2line handling by @sreimers in https://github.com/baresip/re/pull/764
* cmake: add optional static and shared build options by @sreimers in https://github.com/baresip/re/pull/778
* main/init: enable win32 signal handler by @sreimers in https://github.com/baresip/re/pull/779
* uric/contact: fix display name and contact header uri escaping by @maximilianfridrich in https://github.com/baresip/re/pull/762
* ci/analyze: update clang and use analyze-build by @sreimers in https://github.com/baresip/re/pull/781
* main: use mtx\_recursive by @sreimers in https://github.com/baresip/re/pull/782
* test: fix printf formating by @alfredh in https://github.com/baresip/re/pull/783
* main: add re\_thread\_enter/leave polling check by @sreimers in https://github.com/baresip/re/pull/784
* main/init: remove ContextRecord-\>Rip (not available on all platforms) by @sreimers in https://github.com/baresip/re/pull/790
* sipsess: fix RSeq header and rel\_seq numbering by @maximilianfridrich in https://github.com/baresip/re/pull/796
* websock: add proto support by @sreimers in https://github.com/baresip/re/pull/798
* sip/transp: fix websock\_accept proto by @sreimers in https://github.com/baresip/re/pull/800
* sip/transp: remove unneeded websocket tcp tmr by @sreimers in https://github.com/baresip/re/pull/801
* aubuf: activate overrun/underrun statistics by @cspiel1 in https://github.com/baresip/re/pull/803
* cmake: add libre namespace export by @sreimers in https://github.com/baresip/re/pull/786
* revert uri escaping commits by @maximilianfridrich in https://github.com/baresip/re/pull/802
* jbuf: refactor frame calculation by @sreimers in https://github.com/baresip/re/pull/788
* jbuf: frame fixes by @sreimers in https://github.com/baresip/re/pull/806
* sip: add missing WS and WSS transport decoder for VIA headers by @pitti98 in https://github.com/baresip/re/pull/809
* ice: Fix conncheck callback called multiple times by @pitti98 in https://github.com/baresip/re/pull/807
* jbuf: JBUF\_FIXED should also keep min wish size by @sreimers in https://github.com/baresip/re/pull/813
* ci: compile choco openssl with --x86 for 32-bits by @alfredh in https://github.com/baresip/re/pull/814
* jbuf: fix possible division by zero by @sreimers in https://github.com/baresip/re/pull/815
* fix some cppcheck warnings by @alfredh in https://github.com/baresip/re/pull/816
* test/ice: fix cppcheck by @sreimers in https://github.com/baresip/re/pull/818
* tls/openssl: fix cppcheck warnings by @sreimers in https://github.com/baresip/re/pull/820
* base64: fix cppcheck warnings by @sreimers in https://github.com/baresip/re/pull/819
* main/init: fix upper signal handling by @sreimers in https://github.com/baresip/re/pull/822
* include: fix some typos by @alfredh in https://github.com/baresip/re/pull/825

## New Contributors
* @landryb made their first contribution in https://github.com/baresip/re/pull/773
* @pitti98 made their first contribution in https://github.com/baresip/re/pull/809

**Full Changelog**: https://github.com/baresip/re/compare/v3.1.0...v3.2.0

## [v3.1.0] - 2023-04-27

## What's Changed
* ci: bump mingw openssl to 3.1.0 by @alfredh in https://github.com/baresip/re/pull/738
* thread: add cnd_timedwait() by @sreimers in https://github.com/baresip/re/pull/736
* Add tls and http apis for post handshake by @fAuernigg in https://github.com/baresip/re/pull/713
* ci/sanitizers: add multi thread testing by @sreimers in https://github.com/baresip/re/pull/741
* ci/win: use separate retest step by @sreimers in https://github.com/baresip/re/pull/742
* thread: fix pthread_setname_np thread pointer deref by @sreimers in https://github.com/baresip/re/pull/744
* ci: add FreeBSD test by @sreimers in https://github.com/baresip/re/pull/745
* cmake: bump minimum version of OpenSSL to 1.1.1 by @alfredh in https://github.com/baresip/re/pull/746
* ci: avoid hardcoded OpenSSL path on macOS by @robert-scheck in https://github.com/baresip/re/pull/747
* sip,uri,test: Escape SIP URIs by @maximilianfridrich in https://github.com/baresip/re/pull/740
* udp: add a lock for the helpers list by @cspiel1 in https://github.com/baresip/re/pull/732
* rem/vidmix: add position index handling by @sreimers in https://github.com/baresip/re/pull/749
* aubuf: set auframe fields correct in read_auframe loop by @cspiel1 in https://github.com/baresip/re/pull/750
* list: refactor/optimize list_insert_sorted by @sreimers in https://github.com/baresip/re/pull/748
* ci/freebsd: remove openssl-devel by @sreimers in https://github.com/baresip/re/pull/755
* tmr: add tmr_continue() by @vanrein in https://github.com/baresip/re/pull/754
* ci,cmake: replace C99 check by strict C99 and C11 checks by @sreimers in https://github.com/baresip/re/pull/759
* atomic: Fix missing memory order arguments in MSVC atomic functions by @Lastique in https://github.com/baresip/re/pull/766
* thread: remove win32 SetThreadDescription  by @sreimers in https://github.com/baresip/re/pull/768

**Full Changelog**: https://github.com/baresip/re/compare/v3.0.0...v3.1.0

---

## [v3.0.0] - 2023-03-20

## What's Changed
* main: allow poll_method change only before setup by @sreimers in https://github.com/baresip/re/pull/681
* main: add more details to re_debug() by @alfredh in https://github.com/baresip/re/pull/689
* merge rem into re by @alfredh in https://github.com/baresip/re/pull/683
* tmr,main: thread safe tmr handling by @sreimers in https://github.com/baresip/re/pull/690
* tmr,main: add tmrl_count by @sreimers in https://github.com/baresip/re/pull/694
* main: add re_thread_async_main_id and re_thread_async_main_cancel by @sreimers in https://github.com/baresip/re/pull/697
* merge retest into re by @alfredh in https://github.com/baresip/re/pull/695
* tls: add doxygen comment to dtls_recv_packet() by @alfredh in https://github.com/baresip/re/pull/699
* test: use TEST_ERR by @sreimers in https://github.com/baresip/re/pull/700
* test: use TEST_ERR by @sreimers in https://github.com/baresip/re/pull/701
* hmac: remove unused SHA_BLOCKSIZE by @alfredh in https://github.com/baresip/re/pull/703
* async: fix cancel memory leaks by @sreimers in https://github.com/baresip/re/pull/705
* ci: windows Debug/Release by @alfredh in https://github.com/baresip/re/pull/704
* cmake: add extra source files for aes and hmac by @alfredh in https://github.com/baresip/re/pull/708
* test: remove libpthread from LINKLIBS by @alfredh in https://github.com/baresip/re/pull/710
* hmac: add stateless HMAC-SHA256 wrapper by @alfredh in https://github.com/baresip/re/pull/706
* thread: add thread name handling by @sreimers in https://github.com/baresip/re/pull/709
* ci: add support for Android by @alfredh in https://github.com/baresip/re/pull/707
* test: fix convert C99 by @sreimers in https://github.com/baresip/re/pull/717
* dbg: remove pre-C99 fallbacks by @sreimers in https://github.com/baresip/re/pull/718
* test: remove CMAKE_C_STANDARD by @alfredh in https://github.com/baresip/re/pull/714
* sdp/media: fix ccheck list_unlink warning by @sreimers in https://github.com/baresip/re/pull/715
* jbuf: allocate mutex and lock also jbuf_debug() by @cspiel1 in https://github.com/baresip/re/pull/693
* sys/fs: fix fs_fopen read only mode (should not create file) by @sreimers in https://github.com/baresip/re/pull/719
* ci/ssl: update OpenSSL/LibreSSL by @sreimers in https://github.com/baresip/re/pull/720
* http: fix read_file on win32 (wrong filesize) and use mbuf by @fAuernigg in https://github.com/baresip/re/pull/711
* sys: add sys_getenv() by @sreimers in https://github.com/baresip/re/pull/721
* rtp: Don't check RTCP socket if rtcp-mux is enabled by @Lastique in https://github.com/baresip/re/pull/723
* tls: remove return statement that is not needed by @alfredh in https://github.com/baresip/re/pull/724
* sha: add sha256_printf() by @alfredh in https://github.com/baresip/re/pull/725
* cmake: add rem headers to install by @sreimers in https://github.com/baresip/re/pull/727
* cmake: merge REM_HEADERS by @sreimers in https://github.com/baresip/re/pull/728
* tls: set mbuf pos and end at the same time by @alfredh in https://github.com/baresip/re/pull/729
* misc: add Makefile helpers and exclude retest from all target by @sreimers in https://github.com/baresip/re/pull/726
* sa: add sa_struct_get_size() to check size by @alfredh in https://github.com/baresip/re/pull/730
* rtcp: make rtcp_calc_rtt() public by @alfredh in https://github.com/baresip/re/pull/731
* test: add HAVE_UNIXSOCK=0 support by @sreimers in https://github.com/baresip/re/pull/734
* aubuf: set sample format when frame is read by @cspiel1 in https://github.com/baresip/re/pull/737


**Full Changelog**: https://github.com/baresip/re/compare/v2.12.0...v3.0.0

---

## [v2.12.0] - 2023-02-15

## What's Changed
* tls: remove ifdef DTLS_CTRL_HANDLE_TIMEOUT by @alfredh in https://github.com/baresip/re/pull/634
* cmake: increment required version by @cspiel1 in https://github.com/baresip/re/pull/642
* dtls: add logging of DTLS packet content-type by @alfredh in https://github.com/baresip/re/pull/641
* dtls: add single connection mode by @alfredh in https://github.com/baresip/re/pull/643
* ice: reduce conncheck start timer by @alfredh in https://github.com/baresip/re/pull/640
* async,main: make re_thread_async itself thread safe by @sreimers in https://github.com/baresip/re/pull/644
* av1: remove old packetizer by @alfredh in https://github.com/baresip/re/pull/645
* av1: fix chrome interop by @alfredh in https://github.com/baresip/re/pull/646
* av1: minor cleanups by @alfredh in https://github.com/baresip/re/pull/649
* trace: fix new json start by @sreimers in https://github.com/baresip/re/pull/648
* make rtcp interval configureable by @sreimers in https://github.com/baresip/re/pull/650
* sa: proposal to always enable struct sockaddr_in6 by @alfredh in https://github.com/baresip/re/pull/651
* ci: rename ccheck to lint by @alfredh in https://github.com/baresip/re/pull/653
* ci: extend coverage test with retest+select by @alfredh in https://github.com/baresip/re/pull/652
* main: remove poll support by @sreimers in https://github.com/baresip/re/pull/654
* ci: use Ninja as CMake generator by @alfredh in https://github.com/baresip/re/pull/656
* ci/abi: fix abidiff paths by @sreimers in https://github.com/baresip/re/pull/657
* PRACK refactoring by @maximilianfridrich in https://github.com/baresip/re/pull/630
* types: add RE_ prefix to ARRAY_SIZE() by @alfredh in https://github.com/baresip/re/pull/658
* cmake: add USE_TRACE option (default OFF) by @sreimers in https://github.com/baresip/re/pull/660
* add re prefix by @alfredh in https://github.com/baresip/re/pull/659
* tcp: add RE_TCP_BACKLOG by @sreimers in https://github.com/baresip/re/pull/661
* Fix doxygen warnings by @alfredh in https://github.com/baresip/re/pull/662
* mbuf: docs and setters/getters by @alfredh in https://github.com/baresip/re/pull/663
* tcp,cmake: use accept4 if supported by @sreimers in https://github.com/baresip/re/pull/665
* tcp: remove SO_LINGER socket option by @sreimers in https://github.com/baresip/re/pull/664
* rtcp: update documentation by @alfredh in https://github.com/baresip/re/pull/666
* tcp: check SO_ERROR only for active connections by @sreimers in https://github.com/baresip/re/pull/667
* cmake: add HAVE_RESOLV by @sreimers in https://github.com/baresip/re/pull/668
* hash: add hash_debug by @sreimers in https://github.com/baresip/re/pull/670
* list: improve list_apply performance by @sreimers in https://github.com/baresip/re/pull/669
* rtp: add doxygen comments by @alfredh in https://github.com/baresip/re/pull/671
* rtp: extra dox for rtcp_encode by @alfredh in https://github.com/baresip/re/pull/672
* ci: add thread and address sanitizer by @sreimers in https://github.com/baresip/re/pull/673
* Do not change glibc feature selection macros in unsupported ways by @fweimer-rh in https://github.com/baresip/re/pull/674
* auth: replace ETIME with ETIMEDOUT by @sreimers in https://github.com/baresip/re/pull/675
* cmake: add min. OpenSSL 1.1.0 version requirement by @sreimers in https://github.com/baresip/re/pull/680
* ci: fix flaky azure mirrors by @sreimers in https://github.com/baresip/re/pull/682
* tls: remove obsolete openssl version check and fix libressl build by @cspiel1 in https://github.com/baresip/re/pull/679
* ci/ssl: fix openssl root dir by @sreimers in https://github.com/baresip/re/pull/677
* main: add re_thread_async_main for re_global only by @sreimers in https://github.com/baresip/re/pull/685
* atomic: fix win32 atomic load const warnings by @sreimers in https://github.com/baresip/re/pull/688
* atomic: fix __iso_volatile_load64 deref by @sreimers in https://github.com/baresip/re/pull/691
* bump version numbers to 2.12.0 by @alfredh in https://github.com/baresip/re/pull/692

## New Contributors
* @fweimer-rh made their first contribution in https://github.com/baresip/re/pull/674

**Full Changelog**: https://github.com/baresip/re/compare/v2.11.0...v2.12.0

---

## [v2.11.0] - 2023-01-11

## What's Changed
* net/types: move socket helpers and rename RE_ERRNO_SOCK and RE_BAD_SOCK by @sreimers in https://github.com/baresip/re/pull/608
* sys: fix fileno warning by @alfredh in https://github.com/baresip/re/pull/612
* tls: clear session callbacks in destructor by @cspiel1 in https://github.com/baresip/re/pull/611
* tls: use long SSL state strings for logging by @cspiel1 in https://github.com/baresip/re/pull/613
* tls: Set session only once before Client Hello by @cspiel1 in https://github.com/baresip/re/pull/607
* udp: add optional send/recv handler by @alfredh in https://github.com/baresip/re/pull/602
* tls: remove deprecated tls_set_selfsigned() by @alfredh in https://github.com/baresip/re/pull/614
* main: allow for init twice by @alfredh in https://github.com/baresip/re/pull/615
* cmake: add check_c_compiler_flag for atomic-implicit-seq-cst warning by @sreimers in https://github.com/baresip/re/pull/617
* http,tcp: add http_listen_fd and tcp_sock_alloc_fd by @sreimers in https://github.com/baresip/re/pull/618
* tcp_sock_alloc_fd: fix fdc initializing by @sreimers in https://github.com/baresip/re/pull/619
* sa,unixsock: add unix domain socket support by @sreimers in https://github.com/baresip/re/pull/600
* mk: remove makefiles by @sreimers in https://github.com/baresip/re/pull/620
* RTP Resend by @sreimers in https://github.com/baresip/re/pull/626
* TLS server support SNI based certificate selection by @cspiel1 in https://github.com/baresip/re/pull/596
* sipsess/request.c: return error code in sipsess_request_alloc by @maximilianfridrich in https://github.com/baresip/re/pull/631
* ice: add ANSI output with Green and Red colors by @alfredh in https://github.com/baresip/re/pull/632
* docs: update reference to TLS 1.2 by @alfredh in https://github.com/baresip/re/pull/633
* cmake, sa: enable unix sockets, if HAVE_UNIXSOCK is undefined by @fAuernigg in https://github.com/baresip/re/pull/636
* trice: refresh doxygen comments by @alfredh in https://github.com/baresip/re/pull/635
* tls: add error handling for BIO_reset by @cspiel1 in https://github.com/baresip/re/pull/638
* dns/client: fix rrlv reference cache handling by @sreimers in https://github.com/baresip/re/pull/637


**Full Changelog**: https://github.com/baresip/re/compare/v2.10.0...v2.11.0

---

## [v2.10.0] - 2022-12-06

## What's Changed
* h264: add STAP-A by @alfredh in https://github.com/baresip/re/pull/584
* tls: SSL_get_peer_certificate is deprecated by @sreimers in https://github.com/baresip/re/pull/585
* sipreg fix contact handler `expires` evaluation by @cspiel1 in https://github.com/baresip/re/pull/581
* ice: local candidate policy config by @sreimers in https://github.com/baresip/re/pull/589
* h265: add missing NAL types by @alfredh in https://github.com/baresip/re/pull/590
* rtpext: move from baresip to re by @alfredh in https://github.com/baresip/re/pull/591
* mk: add rtpext to Makefile build by @cspiel1 in https://github.com/baresip/re/pull/594
* mk: add makefile deprecation warning by @sreimers in https://github.com/baresip/re/pull/595
* fs: use dup/dup2 for stdio hide and restore by @sreimers in https://github.com/baresip/re/pull/597
* dns: fix dnsc_conf_set memory leak by @alfredh in https://github.com/baresip/re/pull/598
* cmake: add TRACE_SSL compile definition by @cspiel1 in https://github.com/baresip/re/pull/599
* cmake: add ZLIB_INCLUDE_DIRS by @sreimers in https://github.com/baresip/re/pull/601
* cmake/pkgconfig: fix prefix variable by @cspiel1 in https://github.com/baresip/re/pull/603
* ci/valgrind: use ubuntu-20.04 by @sreimers in https://github.com/baresip/re/pull/606

**Full Changelog**: https://github.com/baresip/re/compare/v2.9.0...v2.10.0

---

## [v2.9.0] - 2022-11-01

## What's Changed
* cmake,make: bump version and set dev identifier by @cspiel1 in https://github.com/baresip/re/pull/553
* udp: remove udp_send_anon() by @alfredh in https://github.com/baresip/re/pull/550
* cmake: enable export symbols for backtrace by @sreimers in https://github.com/baresip/re/pull/554
* README.md: Update build instructions for cmake by @robert-scheck in https://github.com/baresip/re/pull/556
* cmake: improve kqueue and epoll detection by @sreimers in https://github.com/baresip/re/pull/558
* fs: add fs_stdio_hide() and fs_stdio_restore() helpers by @sreimers in https://github.com/baresip/re/pull/559
* json: remove unknown type warning by @alfredh in https://github.com/baresip/re/pull/560
* http: fix warning arguments by @alfredh in https://github.com/baresip/re/pull/561
* net_if_getlinklocal: use AF from input parameter by @alfredh in https://github.com/baresip/re/pull/565
* fmt: add str_itoa by @sreimers in https://github.com/baresip/re/pull/569
* SDP support for <proto> udp by @vanrein in https://github.com/baresip/re/pull/538
* tls: remove some warnings by @alfredh in https://github.com/baresip/re/pull/567
* fmt: add pl_trim functions by @cspiel1 in https://github.com/baresip/re/pull/557
* aes/openssl: remove obsolete version check by @alfredh in https://github.com/baresip/re/pull/572
* http: use str_dup() instead of unsafe strcpy() by @alfredh in https://github.com/baresip/re/pull/574
* doxygen: update comments by @alfredh in https://github.com/baresip/re/pull/577
* reg: remove obsolete void cast by @cspiel1 in https://github.com/baresip/re/pull/576
* Tls connect debug by @alfredh in https://github.com/baresip/re/pull/573
* mk: update doxygen file by @alfredh in https://github.com/baresip/re/pull/578
* ci: use actions/checkout@v3 by @sreimers in https://github.com/baresip/re/pull/579
* tls: remove ifdef from public API by @alfredh in https://github.com/baresip/re/pull/580
* sip: sip_conncfg_set pass by reference by @alfredh in https://github.com/baresip/re/pull/582
* dnsc get conf and skip hash alloc without hash size changes by @fAuernigg in https://github.com/baresip/re/pull/575
* sdp/media: fix reorder codecs (restore old behavior) by @juha-h in https://github.com/baresip/re/pull/583
* list: fix list_flush head and tail by @sreimers in https://github.com/baresip/re/pull/586
* prepare 2.9.0 by @alfredh in https://github.com/baresip/re/pull/587

## New Contributors
* @vanrein made their first contribution in https://github.com/baresip/re/pull/538

**Full Changelog**: https://github.com/baresip/re/compare/v2.8.0...v2.9.0

---

## [v2.8.0] - 2022-10-01

* Update README.md by @alfredh in https://github.com/baresip/re/pull/503
* thread: fix win32 thrd\_create return values by @sreimers in https://github.com/baresip/re/pull/506
* cmake: bump min. version 3.10 by @sreimers in https://github.com/baresip/re/pull/504
* cmake: add USE\_JBUF option by @alfredh in https://github.com/baresip/re/pull/507
* http/https requests with large body by @fAuernigg in https://github.com/baresip/re/pull/485
* http/client: fix possible null pointer dereference by @sreimers in https://github.com/baresip/re/pull/509
* ci: test choco install no-progress by @alfredh in https://github.com/baresip/re/pull/510
* bitv: remove deprecated module by @alfredh in https://github.com/baresip/re/pull/513
* types,fmt: use re\_restrict by @sreimers in https://github.com/baresip/re/pull/514
* refer out of dialog by @cspiel1 in https://github.com/baresip/re/pull/508
* UPDATE bugfix by @maximilianfridrich in https://github.com/baresip/re/pull/516
* sip/auth: fix mem\_zalloc return check by @sreimers in https://github.com/baresip/re/pull/518
* Update media fixes by @cspiel1 in https://github.com/baresip/re/pull/515
* dns, http: add dnsc\_getaddrinfo\_enabled. prevent reset of getaddrinfo enabled by @fAuernigg in https://github.com/baresip/re/pull/519
* rtp: Improve media synchronization by @Lastique in https://github.com/baresip/re/pull/418
* conf: check if returned size is larger than buffer by @alfredh in https://github.com/baresip/re/pull/523
* udp: remove very old iOS hack by @alfredh in https://github.com/baresip/re/pull/524
* tcp: remove very old iOS hack by @alfredh in https://github.com/baresip/re/pull/525
* Use CMake for debian packages by @sreimers in https://github.com/baresip/re/pull/522
* crc32: add re wrapper by @alfredh in https://github.com/baresip/re/pull/526
* ci: convert valgrind to cmake by @alfredh in https://github.com/baresip/re/pull/529
* ci: convert ssl build to cmake by @alfredh in https://github.com/baresip/re/pull/530
* ci: convert fedora to cmake by @alfredh in https://github.com/baresip/re/pull/531
* ci: convert coverage to cmake by @alfredh in https://github.com/baresip/re/pull/532
* ci: migrate to cmake by @alfredh in https://github.com/baresip/re/pull/533
* cmake: add LINKLIBS and make backtrace and zlib optional by @sreimers in https://github.com/baresip/re/pull/534
* C99 compatibility by @sreimers in https://github.com/baresip/re/pull/536
* pcp: fix cppcheck warning by @alfredh in https://github.com/baresip/re/pull/540
* fmt/print: fix cppcheck overflow warning by @sreimers in https://github.com/baresip/re/pull/542
* tls: remove SHA1 fingerprint (deprecated) by @alfredh in https://github.com/baresip/re/pull/527
* send DTMF via hidden call by @cspiel1 in https://github.com/baresip/re/pull/537
* sipreg: avoid sending un-REGISTER periodically by @cspiel1 in https://github.com/baresip/re/pull/543
* cmake,mk: bump the tentative next release with pre-release identifier by @sreimers in https://github.com/baresip/re/pull/546
* sipsess/update: Add Contact header to UPDATE by @maximilianfridrich in https://github.com/baresip/re/pull/545
* cmake: fix shared API soversion (aligned with make) by @sreimers in https://github.com/baresip/re/pull/549

---

## [v2.7.0] - 2022-09-01

* async: add re_thread_async by @sreimers in https://github.com/baresip/re/pull/462
* atomic: Add support for gcc __sync intrinsics by @Lastique in https://github.com/baresip/re/pull/467
* btrace: fix gcc 4.3.5 warnings by @cspiel1 in https://github.com/baresip/re/pull/468
* h264: fix gcc 4.3.5 warnings by @cspiel1 in https://github.com/baresip/re/pull/469
* async: add guard by @sreimers in https://github.com/baresip/re/pull/474
* dns/client: add async getaddrinfo usage by @sreimers in https://github.com/baresip/re/pull/470
* async: make work handler and callback optional by @sreimers in https://github.com/baresip/re/pull/481
* BareSip. Add a state update action to the main loop to unblock pollin… by @viordash in https://github.com/baresip/re/pull/480
* dns,net: fix build of asyn_getaddrinfo on gcc 4.3.5 (#482) by @cspiel1 in https://github.com/baresip/re/pull/483
* dns/client: fix getaddrinfo duplicates by @sreimers in https://github.com/baresip/re/pull/486
* http/client: fix dnsc_conf initialization by @sreimers in https://github.com/baresip/re/pull/487
* tmr: tmr_start_dbg use const char for file arg by @sreimers in https://github.com/baresip/re/pull/488
* base64: Encoding/Decoding with URL and Filename Safe Alphabet by @sreimers in https://github.com/baresip/re/pull/471
* misc: fix c11 err handling by @sreimers in https://github.com/baresip/re/pull/476
* cmake: move definitions to re-config.cmake by @sreimers in https://github.com/baresip/re/pull/491
* ci/mingw: fix make retest by @sreimers in https://github.com/baresip/re/pull/492
* cmake: add pkgconfig by @sreimers in https://github.com/baresip/re/pull/493
* Fix error: ‘NI_MAXSERV’ undeclared by @widgetii in https://github.com/baresip/re/pull/495
* Fix error: storage size of ‘ifrr’ isn’t known by @widgetii in https://github.com/baresip/re/pull/496
* ci/musl: add alpine/musl build by @sreimers in https://github.com/baresip/re/pull/499
* Correctly update local media format ids to match those in the offer by @juha-h in https://github.com/baresip/re/pull/498
* debian: fix prefix by @juha-h in https://github.com/baresip/re/pull/501

---

## [v2.6.0] - 2022-08-01

* ice: change one warning to notice by @alfredh in https://github.com/baresip/re/pull/421
* Fix compilation error on musl: __GNUC_PREREQ macro defined only for libc library by @widgetii in https://github.com/baresip/re/pull/422
* sip: add RFC 3262 support by @maximilianfridrich in https://github.com/baresip/re/pull/419
* bfcp: Add support for TCP transport for BFCP by @Lastique in https://github.com/baresip/re/pull/411
* strans/accept: fix cancel/rejection by @maximilianfridrich in https://github.com/baresip/re/pull/423
* hash: add hash_list_idx() by @sreimers in https://github.com/baresip/re/pull/427
* tls: Add a method to set OpenSSL certificate by @Lastique in https://github.com/baresip/re/pull/426
* sipsess: fix PRACK offer/answer behavior by @maximilianfridrich in https://github.com/baresip/re/pull/430
* thread: thrd_error fixes by @sreimers in https://github.com/baresip/re/pull/431
* sipsess: fix coverity warnings by @maximilianfridrich in https://github.com/baresip/re/pull/433
* main: add re_nfds() and poll_method_get() getters by @sreimers in https://github.com/baresip/re/pull/435
* fmt/print: fix local_itoa casting by @sreimers in https://github.com/baresip/re/pull/437
* leb128: switch to uint64_t by @alfredh in https://github.com/baresip/re/pull/436
* types,mk: remove HAVE_STDBOOL_H by @sreimers in https://github.com/baresip/re/pull/439
* fmt/print: snprintf restrict declarations by @sreimers in https://github.com/baresip/re/pull/438
* net: minor cleanup in linux route code by @alfredh in https://github.com/baresip/re/pull/440
* sip: add RFC 3311 support by @maximilianfridrich in https://github.com/baresip/re/pull/425
* rtmp: check upper bound for amf array by @alfredh in https://github.com/baresip/re/pull/441
* rtcp: check TWCC count range (Coverity fix) by @alfredh in https://github.com/baresip/re/pull/442
* mem: Align data to natural alignment by @Lastique in https://github.com/baresip/re/pull/416
* ci/misc: bump pr-dependency-action@v0.5 by @sreimers in https://github.com/baresip/re/pull/444
* net: linux/rt: init gw to correct af by @alfredh in https://github.com/baresip/re/pull/447
* rtp: Add `rtcp_send` declaration to the public header by @Lastique in https://github.com/baresip/re/pull/448
* Main method best by @alfredh in https://github.com/baresip/re/pull/449
* cmake: add explicit /volatile:ms (required for arm) by @sreimers in https://github.com/baresip/re/pull/451
* mem: Make nrefs atomic by @Lastique in https://github.com/baresip/re/pull/446
* atomic: add some short atomic alias helpers by @sreimers in https://github.com/baresip/re/pull/452
* ci/build: replace deprecated macos-10.15 by @sreimers in https://github.com/baresip/re/pull/454
* Improve RFC 3262 by @maximilianfridrich in https://github.com/baresip/re/pull/450
* atomic: rename helpers by @sreimers in https://github.com/baresip/re/pull/455
* cmake,make: add clang atomic-implicit-seq-cst warning by @sreimers in https://github.com/baresip/re/pull/453
* cmake: add missing includes to install by @paresy in https://github.com/baresip/re/pull/456
* Fix prack handling by @maximilianfridrich in https://github.com/baresip/re/pull/457
* mem: Correct memory clobbering size by @Lastique in https://github.com/baresip/re/pull/458
* mem: Correct calculation of total mem size in mem_status by @Lastique in https://github.com/baresip/re/pull/459
* tls: Securely clear memory from private key material by @Lastique in https://github.com/baresip/re/pull/460
* fmt/str_error: always print error number by @sreimers in https://github.com/baresip/re/pull/461
* thread: add cnd_broadcast posix/win32 fallbacks by @sreimers in https://github.com/baresip/re/pull/463
* list: add list_move() helper by @sreimers in https://github.com/baresip/re/pull/464
* thread: fix thread_create_name ENOMEM by @sreimers in https://github.com/baresip/re/pull/465

---

## [v2.5.0] - 2022-07-01

* av1: add doxygen comments by @alfredh in https://github.com/baresip/re/pull/384
* rtp: add function to calc sequence number diff by @alfredh in https://github.com/baresip/re/pull/385
* CI fixes by @sreimers in https://github.com/baresip/re/pull/387
* trace: C11 mutex by @alfredh in https://github.com/baresip/re/pull/390
* trace: init refactor by @sreimers in https://github.com/baresip/re/pull/391
* jbuf: use C11 mutex by @alfredh in https://github.com/baresip/re/pull/392
* av1: define and make AV1_AGGR_HDR_SIZE public by @alfredh in https://github.com/baresip/re/pull/393
* main: add re_thread_check() for NON-RE thread calls by @sreimers in https://github.com/baresip/re/pull/389
* cmake: add HAVE_SIGNAL on UNIX by @sreimers in https://github.com/baresip/re/pull/394
* av1: add av1_obu_count() by @alfredh in https://github.com/baresip/re/pull/395
* thread: add mtx_alloc by @sreimers in https://github.com/baresip/re/pull/396
* rtp: C11 mutex by @alfredh in https://github.com/baresip/re/pull/397
* lock: remove deprecated module by @alfredh in https://github.com/baresip/re/pull/398
* Added sippreg_unregister API function by @juha-h in https://github.com/baresip/re/pull/400
* av1 work by @alfredh in https://github.com/baresip/re/pull/402
* rtp: add rtp_is_rtcp_packet() by @alfredh in https://github.com/baresip/re/pull/405
* Fix mutex alloc destroy by @sreimers in https://github.com/baresip/re/pull/406
* av1: minor fixes and doxygen comments by @alfredh in https://github.com/baresip/re/pull/407
* rtp: Add support for RFC5104 PSFB FIR by @Lastique in https://github.com/baresip/re/pull/408
* jbuf: Add drain method by @Lastique in https://github.com/baresip/re/pull/409
* uag: add timestamps to SIP trace by @cspiel1 in https://github.com/baresip/re/pull/412
* fmt/fmt_timestamp: some cleanup by @sreimers in https://github.com/baresip/re/pull/413
* main: refactor libre_init and re_global handling by @sreimers in https://github.com/baresip/re/pull/404
* main: Add support for external threads attaching/detaching re context by @Lastique in https://github.com/baresip/re/pull/414
* mem: Fix formatting for nrefs and size. by @Lastique in https://github.com/baresip/re/pull/415

---

## [v2.4.0] - 2022-06-01

## What's Changed
* ci: test centos -> fedora by @alfredh in https://github.com/baresip/re/pull/340
* Tls bio opaque by @alfredh in https://github.com/baresip/re/pull/341
* main: remove usage of crypto_set_id_callback() by @alfredh in https://github.com/baresip/re/pull/342
* jbuf: in adaptive mode do not manipulate min buffer size by @cspiel1 in https://github.com/baresip/re/pull/343
* av1 obu by @alfredh in https://github.com/baresip/re/pull/345
* jbuf: improve adaptive mode by @cspiel1 in https://github.com/baresip/re/pull/344
* av1 packetizer by @alfredh in https://github.com/baresip/re/pull/346
* av1: depacketizer by @alfredh in https://github.com/baresip/re/pull/347
* h265: move from rem to re by @alfredh in https://github.com/baresip/re/pull/348
* jbuf: avoid reducing of wish size too early by @cspiel1 in https://github.com/baresip/re/pull/349
* ci/build: add ubuntu 22.04 (beta) by @sreimers in https://github.com/baresip/re/pull/351
* h264: move from rem to re by @alfredh in https://github.com/baresip/re/pull/350
* add C11 thread, mutex and condition API by @sreimers in https://github.com/baresip/re/pull/249
* thread: use pthread as default fallback by @sreimers in https://github.com/baresip/re/pull/354
* mem: use new C11 mutex locking by @sreimers in https://github.com/baresip/re/pull/352
* dbg: use C11 thread mutex by @sreimers in https://github.com/baresip/re/pull/356
* thread: add thread-local storage functions by @sreimers in https://github.com/baresip/re/pull/355
* main/openssl: cleanup by @sreimers in https://github.com/baresip/re/pull/358
* cmake: sort warning flags by @alfredh in https://github.com/baresip/re/pull/359
* doxygen: update comments by @alfredh in https://github.com/baresip/re/pull/360
* main: use C11 thread mutex by @sreimers in https://github.com/baresip/re/pull/357
* make: disable warning flag -Wdeclaration-after-statement by @alfredh in https://github.com/baresip/re/pull/363
* cleanup pthread by @sreimers in https://github.com/baresip/re/pull/362
* update doxygen comments by @alfredh in https://github.com/baresip/re/pull/366
* ci/coverage: downgrade gcovr by @sreimers in https://github.com/baresip/re/pull/365
* tls: print openssl error queue if accept failed by @alfredh in https://github.com/baresip/re/pull/367
* main: fd_setsize -1 for RLIMIT_NOFILE value by @sreimers in https://github.com/baresip/re/pull/368
* jbuf: flush on RTP timeout by @cspiel1 in https://github.com/baresip/re/pull/370
* thread: add mtx_destroy by @sreimers in https://github.com/baresip/re/pull/371
* dns: add query cache by @sreimers in https://github.com/baresip/re/pull/369
* mem,btrace: fix struct alignment by @sreimers in https://github.com/baresip/re/pull/372
* av1: change start flag to continuation flag (inverse) by @alfredh in https://github.com/baresip/re/pull/375
* tmr: add tmr_start_dbg by @sreimers in https://github.com/baresip/re/pull/373
* ice: rename to local pref by @alfredh in https://github.com/baresip/re/pull/376
* tls: Switch from EVP_sha1() to EVP_sha256() when using it for X509_sign() by @robert-scheck in https://github.com/baresip/re/pull/377

---

## [v2.3.0] - 2022-05-01

* cmake: use static build as default target (improves subdirectory usage) by @sreimers in https://github.com/baresip/re/pull/311
* jbuf: fix RELEASE build with DEBUG_LEVEL 6 by @cspiel1 in https://github.com/baresip/re/pull/313
* fmt/pl: use unsigned type before negation by @sreimers in https://github.com/baresip/re/pull/312
* fmt/pl: rewrite negative handling (avoid undefined behavior) by @sreimers in https://github.com/baresip/re/pull/314
* http/request: fix possbile null pointer dereference by @sreimers in https://github.com/baresip/re/pull/316
* sdp: check sdp_bandwidth lower bound by @sreimers in https://github.com/baresip/re/pull/317
* main: use re_sock_t by @sreimers in https://github.com/baresip/re/pull/315
* ccheck: check all CMakeLists.txt files by @sreimers in https://github.com/baresip/re/pull/320
* list: O(1) sorted insert if we expect append in most cases by @cspiel1 in https://github.com/baresip/re/pull/318
* add pcp protocol by @alfredh in https://github.com/baresip/re/pull/321
* cmake: define RELEASE for release builds by @alfredh in https://github.com/baresip/re/pull/323
* Mem lock win32 by @alfredh in https://github.com/baresip/re/pull/324
* pcp: fix win32 warning by @alfredh in https://github.com/baresip/re/pull/325
* ci/msvc: treat all compiler warnings as errors by @sreimers in https://github.com/baresip/re/pull/326
* cmake: add MSVC /W3 compile option by @sreimers in https://github.com/baresip/re/pull/327
* cmake: add FreeBSD and OpenBSD by @sreimers in https://github.com/baresip/re/pull/329
* md5: remove fallback implementation by @sreimers in https://github.com/baresip/re/pull/328
* cmake: add runtime and development install components by @sreimers in https://github.com/baresip/re/pull/330
* mem: remove low/high block size stats by @alfredh in https://github.com/baresip/re/pull/331
* mem: add error about missing locking by @alfredh in https://github.com/baresip/re/pull/332
* set TCP source port in Via and Contact header by @cspiel1 in https://github.com/baresip/re/pull/334
* remove sys_rel_get and epoll_check by @alfredh in https://github.com/baresip/re/pull/335
* support tls session reuse   by @fAuernigg in https://github.com/baresip/re/pull/333
* rand: init only needed for libc rand by @alfredh in https://github.com/baresip/re/pull/336
* tls: fix crash in debug warn msg by @fAuernigg in https://github.com/baresip/re/pull/337
* mem: init g_memLock directly by @alfredh in https://github.com/baresip/re/pull/339
* prepare for version 2.3.0 by @alfredh in https://github.com/baresip/re/pull/338

---

## [v2.2.2] - 2022-04-09

* sha256: add wrapper by @alfredh in https://github.com/baresip/re/pull/306
* workflow: upgrade to openssl 3.0.2 by @alfredh in https://github.com/baresip/re/pull/305
* aubuf adaptive jitter buffer by @cspiel1 in https://github.com/baresip/re/pull/303
* Improve WIN32 UDP socket handling by @sreimers in https://github.com/baresip/re/pull/296
* tcp: remove tcp_conn_fd by @alfredh in https://github.com/baresip/re/pull/308
* tcp: improve win32 socket and error handling by @sreimers in https://github.com/baresip/re/pull/309

---

## [v2.2.1] - 2022-04-01

* cmake: add packaging by @sreimers in https://github.com/baresip/re/pull/299
* sha: add sha 256 and 512 digest length OpenSSL compats by @sreimers in https://github.com/baresip/re/pull/300
* main: use Winsock2.h by @sreimers in https://github.com/baresip/re/pull/302
* cmake: for Android platform dont enable ifaddrs/getifaddrs by @alfredh in https://github.com/baresip/re/pull/304
* sa/sa_is_loopback: check full IPv4 loopback range (127.0.0.0/8) by @sreimers in https://github.com/baresip/re/pull/301

---

## [v2.2.0] - 2022-03-28

* tls: fix coverity defect by @alfredh in https://github.com/baresip/re/pull/270
* http/client: read_file check ftell return value by @sreimers in https://github.com/baresip/re/pull/272
* udp: fix coverity defect by @alfredh in https://github.com/baresip/re/pull/271
* cmake: add detection of HAVE_ARC4RANDOM by @alfredh in https://github.com/baresip/re/pull/269
* Fix coverity issues by @sreimers in https://github.com/baresip/re/pull/273
* Support adding CRLs by @fAuernigg in https://github.com/baresip/re/pull/274
* json/decode: fix possible out of bound access, if code changes by @sreimers in https://github.com/baresip/re/pull/275
* tls/tls_add_crlpem: use const by @sreimers in https://github.com/baresip/re/pull/276
* udp: fix coverity defect by @alfredh in https://github.com/baresip/re/pull/279
* dns: fix Coverity Defect by @alfredh in https://github.com/baresip/re/pull/278
* tls: use const pointer for tls_add_capem() by @cspiel1 in https://github.com/baresip/re/pull/277
* srtp/srtcp: add sanity check for rtcp->tag_len by @sreimers in https://github.com/baresip/re/pull/280
* shim: new module from rew by @alfredh in https://github.com/baresip/re/pull/282
* Trice module by @alfredh in https://github.com/baresip/re/pull/283
* retest trice by @alfredh in https://github.com/baresip/re/pull/284
* Add try_into conversion helper and drop gcc 4.8 support by @sreimers in https://github.com/baresip/re/pull/286
* rtp: fix signed/unsigned warning on WIN32 by @alfredh in https://github.com/baresip/re/pull/287
* fix build error on openbsd arm64 (raspberry pi) by @jimying in https://github.com/baresip/re/pull/290
* cmake: disable C extensions (like make) by @sreimers in https://github.com/baresip/re/pull/292
* fmt: add bool decode from struct pl by @cspiel1 in https://github.com/baresip/re/pull/293
* sdp: a utility function for decoding SDP direction by @cspiel1 in https://github.com/baresip/re/pull/294
* sa/sa_ntop: check inet_ntop() return value by @sreimers in https://github.com/baresip/re/pull/295
* sa_pton: use sa_addrinfo for interface suffix by @alfredh in https://github.com/baresip/re/pull/297

### New Contributors
* @jimying made their first contribution in https://github.com/baresip/re/pull/290

---

## [v2.1.1] - 2022-03-12

### Fixes

* mk: fix ABI versioning [#268](https://github.com/baresip/re/issues/268)

---

## [v2.1.0] - 2022-03-11

### What's Changed
* Tls sipcert per acc by @cHuberCoffee in https://github.com/baresip/re/pull/96
* ToS for video and sip by @cspiel1 in https://github.com/baresip/re/pull/98
* sdp: in media_decode() reset rdir if port is zero by @cspiel1 in https://github.com/baresip/re/pull/99
* mk/re: add variable length array (-Wvla) compiler warning by @sreimers in https://github.com/baresip/re/pull/100
* Macos openssl by @sreimers in https://github.com/baresip/re/pull/105
* pkg-config version check by @sreimers in https://github.com/baresip/re/pull/107
* sa: add setter and getter for scope id by @cspiel1 in https://github.com/baresip/re/pull/108
* net: in net_dst_source_addr_get() make parameter dst const by @cspiel1 in https://github.com/baresip/re/pull/109
* Avoid 'ISO C90 forbids mixed declarations and code' warnings by @juha-h in https://github.com/baresip/re/pull/112
* SIP redirect callbackfunction by @cHuberCoffee in https://github.com/baresip/re/pull/111
* add secure websocket tls context by @sreimers in https://github.com/baresip/re/pull/113
* fmt: add string to bool function by @cspiel1 in https://github.com/baresip/re/pull/115
* fix clang analyze warnings by @sreimers in https://github.com/baresip/re/pull/114
* fmt: support different separators for parameter parsing by @cspiel1 in https://github.com/baresip/re/pull/117
* Refactor inet_ntop and inet_pton by @sreimers in https://github.com/baresip/re/pull/118
* add essential fields check by @I-mpossible in https://github.com/baresip/re/pull/119
* sa: add support for interface suffix for IPv6ll by @cspiel1 in https://github.com/baresip/re/pull/116
* net: fix net_if_getname IPv6 support by @sreimers in https://github.com/baresip/re/pull/120
* udp: add udp_recv_helper by @alfredh in https://github.com/baresip/re/pull/122
* sa: fix build for old systems by @cspiel1 in https://github.com/baresip/re/pull/121
* sa/addrinfo: fix openbsd (drop AI_V4MAPPED flag) by @sreimers in https://github.com/baresip/re/pull/125
* ci/codeql: add scan-build by @sreimers in https://github.com/baresip/re/pull/128
* Fixed debian changelog version by @juha-h in https://github.com/baresip/re/pull/129
* IPv6 link local support by @cspiel1 in https://github.com/baresip/re/pull/106
* sip: add fallback transport for transp_find() by @cspiel1 in https://github.com/baresip/re/pull/132
* SIP default protocol by @cspiel1 in https://github.com/baresip/re/pull/131
* remove orphaned files by @viordash in https://github.com/baresip/re/pull/136
* outgoing calls early callid by @cspiel1 in https://github.com/baresip/re/pull/135
* sip: fix possible "???" dns srv queries by skipping lines without srvid by @cHuberCoffee in https://github.com/baresip/re/pull/133
* odict: hide struct odict_entry by @sreimers in https://github.com/baresip/re/pull/130
* tls: add keylogger callback function by @cHuberCoffee in https://github.com/baresip/re/pull/140
* http/client: support other auth token types besides bearer by @fAuernigg in https://github.com/baresip/re/pull/142
* tls: fix client certificate replacement by @cHuberCoffee in https://github.com/baresip/re/pull/145
* http/client: support dns ipv6 by @fAuernigg in https://github.com/baresip/re/pull/141
* rtp: add payload-type helper by @alfredh in https://github.com/baresip/re/pull/148
* sip: check consistency between CSeq method and that of request line by @I-mpossible in https://github.com/baresip/re/pull/146
* Fix win32 by @viordash in https://github.com/baresip/re/pull/149
* fix warnings from PVS-Studio C++ static analyzer by @viordash in https://github.com/baresip/re/pull/150
* RTP inbound telephone events should not lead to packet loss by @cspiel1 in https://github.com/baresip/re/pull/151
* support inet6 by default in Win32 project by @viordash in https://github.com/baresip/re/pull/154
* sdp: differentiate between media line disabled or rejected by @cHuberCoffee in https://github.com/baresip/re/pull/134
* move network check to module by @cspiel1 in https://github.com/baresip/re/pull/152
* odict: move odict_compare from retest to re by @fAuernigg in https://github.com/baresip/re/pull/153
* sip: reuse transport protocol of first request in dialog (#143) by @cspiel1 in https://github.com/baresip/re/pull/144
* json: fix parsing json containing only single value by @fAuernigg in https://github.com/baresip/re/pull/155
* ice: fix checklist by @alfredh in https://github.com/baresip/re/pull/156
* mk: add compile_commands.json (clang only) by @sreimers in https://github.com/baresip/re/pull/157
* sdp: debug print session and media direction by @cspiel1 in https://github.com/baresip/re/pull/158
* add btrace module (linux/unix only) by @sreimers in https://github.com/baresip/re/pull/160
* mk: add CC_TEST header check by @sreimers in https://github.com/baresip/re/pull/162
* init dst address by @cspiel1 in https://github.com/baresip/re/pull/164
* ice: check if candpair exist before adding by @alfredh in https://github.com/baresip/re/pull/165
* mk: add CC_TEST cache by @sreimers in https://github.com/baresip/re/pull/163
* btrace: use HAVE_EXECINFO by @sreimers in https://github.com/baresip/re/pull/166
* Coverity by @sreimers in https://github.com/baresip/re/pull/170
* icem: remove dead code (found by coverity 240639) by @sreimers in https://github.com/baresip/re/pull/171
* hash: switch to simpler "fast algorithm" by @ydroneaud in https://github.com/baresip/re/pull/173
* dns: fix dnsc_alloc with IPv6 disabled by @sreimers in https://github.com/baresip/re/pull/174
* mk: deprecate HAVE_INET6 by @sreimers in https://github.com/baresip/re/pull/175
* Fix for btrace print for memory leaks by @cspiel1 in https://github.com/baresip/re/pull/177
* set sdp laddr to SIP src address by @cspiel1 in https://github.com/baresip/re/pull/172
* sdp: include all media formats in SDP offer by @cHuberCoffee in https://github.com/baresip/re/pull/176
* ci: add centos 7 build test by @sreimers in https://github.com/baresip/re/pull/179
* sip: move sip_auth_encode to public api for easier testing by @sreimers in https://github.com/baresip/re/pull/181
* sipsess: do not call desc handler on shutdown by @cspiel1 in https://github.com/baresip/re/pull/182
* stream flush rtp socket by @cspiel1 in https://github.com/baresip/re/pull/185
* ci: fix macos openssl build by @sreimers in https://github.com/baresip/re/pull/188
* http: HTTP Host header conform to RFC for IPv6 addresses by @cspiel1 in https://github.com/baresip/re/pull/189
* Increased debian compatibility level from 9 to 10 by @juha-h in https://github.com/baresip/re/pull/192
* mk: move darwin dns LFLAGS to re.mk (fixes static builds) by @sreimers in https://github.com/baresip/re/pull/193
* build infrastructure: silent and verbose modes by @abrodkin in https://github.com/baresip/re/pull/194
* mk: use posix regex for sed CC major version detection by @sreimers in https://github.com/baresip/re/pull/195
* dns: fix parse_resolv_conf for OpenBSD by @sreimers in https://github.com/baresip/re/pull/196
* sip: add optional TCP source port by @cspiel1 in https://github.com/baresip/re/pull/198
* ci: add mingw build and test by @sreimers in https://github.com/baresip/re/pull/199
* net: remove net_hostaddr by @sreimers in https://github.com/baresip/re/pull/200
* ci/centos7: add openssl by @sreimers in https://github.com/baresip/re/pull/203
* hmac: use HMAC() api (fixes OpenSSL 3.0 deprecations) by @sreimers in https://github.com/baresip/re/pull/202
* md5: use EVP_Digest for newer openssl versions by @sreimers in https://github.com/baresip/re/pull/204
* sha: add new sha1() api by @sreimers in https://github.com/baresip/re/pull/205
* OpenSSL 3.0 by @sreimers in https://github.com/baresip/re/pull/206
* udp: add win32 qos support by @sreimers in https://github.com/baresip/re/pull/186
* ci/mingw: fix dependency checkout by @sreimers in https://github.com/baresip/re/pull/207
* ice: remove ice_mode by @alfredh in https://github.com/baresip/re/pull/147
* Codeql security by @sreimers in https://github.com/baresip/re/pull/208
* aubuf insert auframes sorted by @cspiel1 in https://github.com/baresip/re/pull/209
* ci: add valgrind by @sreimers in https://github.com/baresip/re/pull/214
* tls: remove code for openssl 0.9.5 by @alfredh in https://github.com/baresip/re/pull/215
* ice: remove unused file by @alfredh in https://github.com/baresip/re/pull/217
* main: remove obsolete OPENWRT epoll check by @alfredh in https://github.com/baresip/re/pull/218
* dns,http,sa: fix HAVE_INET6 off warnings by @sreimers in https://github.com/baresip/re/pull/219
* preliminary support for cmake by @alfredh in https://github.com/baresip/re/pull/220
* make,cmake: set SOVERSION to major version by @sreimers in https://github.com/baresip/re/pull/221
* mk: remove MSVC project files, use cmake instead by @alfredh in https://github.com/baresip/re/pull/223
* natbd: remove module (deprecated) by @alfredh in https://github.com/baresip/re/pull/225
* sha: remove backup implementation by @alfredh in https://github.com/baresip/re/pull/224
* sha,hmac: use Apple CommonCrypto if defined by @alfredh in https://github.com/baresip/re/pull/226
* stun: add stun_generate_tid by @alfredh in https://github.com/baresip/re/pull/227
* add cmakelint by @sreimers in https://github.com/baresip/re/pull/228
* Cmake version by @alfredh in https://github.com/baresip/re/pull/229
* cmake: add option to enable/disable rtmp module by @alfredh in https://github.com/baresip/re/pull/230
* lock: use rwlock by default by @sreimers in https://github.com/baresip/re/pull/232
* cmake: fixes for MSVC 16 by @alfredh in https://github.com/baresip/re/pull/233
* json: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/234
* ci: add cmake build by @sreimers in https://github.com/baresip/re/pull/222
* mqueue: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/235
* tcp: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/236
* cmake: fix target_link_libraries for win32 by @alfredh in https://github.com/baresip/re/pull/238
* stun: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/237
* udp: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/239
* tls: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/241
* remove HAVE_INTTYPES_H by @alfredh in https://github.com/baresip/re/pull/231
* udp: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/242
* cmake: minor fixes by @alfredh in https://github.com/baresip/re/pull/244
* cmake: fix MSVC ninja by @sreimers in https://github.com/baresip/re/pull/243
* tcp: fix win32 warnings by @alfredh in https://github.com/baresip/re/pull/245
* udp: fix win32 msvc warnings by @sreimers in https://github.com/baresip/re/pull/246
* rtmp: fix win32 warning by @sreimers in https://github.com/baresip/re/pull/247
* bfcp: fix win32 warning by @sreimers in https://github.com/baresip/re/pull/248
* tls: fix libressl 3.5 by @sreimers in https://github.com/baresip/re/pull/250
* fix coverity scan warnings by @sreimers in https://github.com/baresip/re/pull/251
* Allow hanging up call that has not been ACKed yet by @juha-h in https://github.com/baresip/re/pull/252
* mk,cmake: add backtrace support and fix linking on OpenBSD by @sreimers in https://github.com/baresip/re/pull/254
* github: add CMake and Windows workflow by @alfredh in https://github.com/baresip/re/pull/255
* Windows (VS 2022/Ninja) by @sreimers in https://github.com/baresip/re/pull/257
* cmake: fixes for Android by @alfredh in https://github.com/baresip/re/pull/258
* tmr: reuse tmr_jiffies_usec by @alfredh in https://github.com/baresip/re/pull/259
* trace: use gettid as thread_id on linux by @sreimers in https://github.com/baresip/re/pull/213
* tmr: use CLOCK_MONOTONIC_RAW if defined by @alfredh in https://github.com/baresip/re/pull/260
* add atomic support by @sreimers in https://github.com/baresip/re/pull/261
* Sonarcloud by @sreimers in https://github.com/baresip/re/pull/262
* sip: fix gcc 6.3.0 warning for logical expression (#256) by @cspiel1 in https://github.com/baresip/re/pull/263
* add transport-cc rtcp feedback support by @fippo in https://github.com/baresip/re/pull/264

### New Contributors
* @I-mpossible made their first contribution in https://github.com/baresip/re/pull/119
* @viordash made their first contribution in https://github.com/baresip/re/pull/136
* @ydroneaud made their first contribution in https://github.com/baresip/re/pull/173
* @abrodkin made their first contribution in https://github.com/baresip/re/pull/194

---

## [v2.0.1] - 2021-04-22

### Fixed

- tmr: fix FreeBSD and OpenBSD [#97]
- mk: fix clang analyze CFLAGS

### Changed

- tls: different return values for tls_get_ca_chain_field() [#94]

---

## [v2.0.0] - 2021-04-10

### Added

- .gitignore: add ctags and vim swp files to gitignore [#31]
- tls: add tls_add_capem() for adding CA cert as PEM string [#33]
- httpauth: Add digest support for http clients [#33]
- httpauth: Add basic authentication for HTTP clients [#33]
- dns: add set function for DNS config [#33]
- http/client: support IPv6 [#33]
- http/client: use const parameter for set laddr(6) functions [#33]
- http/client: add set function for timeout [#33]
- http/client: add http_client_add_capem() [#33]
- http/client: add set functions for client certificate and private key [#33]
- http: add HTTP request connection with authorization [#33]
- http: setting of timeouts for http client [#35]
- http: set default path for http requests [#35]
- tls: set selfsigned Elliptic Curve (EC) function [#17]
- tls: extend server verification by host name check (SNI) [#45]
- jbuf: adapative jitter buffer [#41]
- tmr: add tmr_jiffies_usec() - get accurate microseconds [#52]
- fmt: add pl_i32() that converts pl to int32_t [#60]
- fmt: add pl_i64() that converts pl to int64_t [#60]
- mk/re: add C11 and Atomic detection [#61]
- ci: add abi check [#39]
- trace: add re_trace api [#48]
- Add function that resets the timeout timer for a connection of the HTTP server. [#88]
- add error trace helpers [#87]
- sip/auth: add algorithm=MD5 [#86]
- sys: filesystem isdir function
- tls: use ENOENT in tls_add_cafile_path as error code
- tls: more generic function to set cafile and capath
- mk: add .so name versioning, resolves #32
- mk/re: add clang shorten-64-to-32 warning
- mk/re: document new library/header prioritised order with custom SYSROOT
- mk/re: info double colon rule (#64) [#64]
- udp: Add function udp_open for socket without bind
- rtp: Add rtp_open which creates an RTP object only for sending. [#77]
- sip: add decode function for SIP transport
- sip: SIP/TLS Server Name Indication (#67) [#67]
- transp: add flag to disable SIP TLS server verification [#76]

### Removed

- openssl: remove obsolete function tls_set_hostname() [#33]
- mk/re: remove gcc 2.x/3.x support [#58]
- ci: drop ubuntu 16.04 support - end of life

### Changed

- http/client: cleanup doxygen [#33]
- http/client: use host of http_req for the host name validation [#37]
- main: disable MAIN_DEBUG, TMR_DEBUG and increase MAX_BLOCKING to 500ms [#43]
- sipreg: dont't force digest challenge for register [#49]
- mk/re: do not override LIBRE_INC, LIBRE_SO and LIBRE_PATH [#62]
- readme: update supported systems and add tiers [#81]
- tls: use ENOTDIR in tls_add_cafile_path if capath is not a dir [#84]
- tls: check capath is directory
- net: get default source addr from udp local test socket [#66]
- Update chklist.c [#70]
- Update icesdp.c [#69]
- mk: cross build changes (#63) [#63]
- sip: use sip_transp_decode() [#71]
- tls: tls_get_issuer/subject return the info of the first loaded ca [#80]

### Fixed

- dns/client: fix HAVE_INET6 and win32/vcxproj: updates [#28]
- http: fix segfault in response.c [#35]
- http/request: parameter NULL check for http_reqconn_send() [#37]
- http/client: fix conn_idle [#46]
- http/httpreq: mem leak fix [#47]
- sip/request: fix msg->scode null pointer dereference
- rtmp/conn: initialize err
- mk/re: fix LIBRE_SO static detection
- dns/res: Properly process IPV4 and IPV6 addresses (DARWIN) [#56]
- sip/keepalive: fix codeql cpp/integer-multiplication-cast-to-long
- fmt/time: fix codeql gmtime warning
- mk/re: fix gcc 4.x and newer compiler warnings
- sys: add _BSD_SOURCE 1 for compatibility reasons [#92]
- fix weak self-signed certificates [#68]
- net/tls: fixing shorten-64-to-32 warnings [#65]
- http: add missing newline to warning [#78]
- http: fix file read for client certificates
- mk/re: do not override LIBRE_INC, LIBRE_SO and LIBRE_PATH [#62]
- tls: safety NULL pointer check in tls_add_ca() [#79]

### Contributors (many thanks)

- [sreimers](https://github.com/sreimers)
- [cHuberCoffee](https://github.com/cHuberCoffee)
- [RobertMi21](https://github.com/RobertMi21)
- [cspiel1](https://github.com/cspiel1)
- [alfredh](https://github.com/alfredh)
- [fippo](https://github.com/fippo)
- [jurjen-van-dijk](https://github.com/jurjen-van-dijk)
- [rolizo](https://github.com/rolizo)


## [v1.1.0] - 2020-10-04

### Added

- tls: functions to get the certificate issuer and subject [#18]
- uri: Added path field to struct uri and its decode to uri_decode [#22]
- tcp: add tcp_connect_bind [#24]
- http: support bind to laddr in http_request [#24]
- sipreg: support Cisco REGISTER keep-alives [#19]
- sip: websocket support [#26]

### Fixed

- tls/openssl: fix X509_NAME win32/wincrypt.h conflict
- dns: listen on IPv4 and IPv6 socket [#27]
- main: fix/optimize windows file descriptors [#25]

### Contributors (many thanks)

- Alfred E. Heggestad
- Christian Spielberger
- Christoph Huber
- Franz Auernigg
- Juha Heinanen
- johnjuuljensen
- Sebastian Reimers


## [v1.0.0] - 2020-09-08

### Added

- sip: add trace
- sdp: sdp_media_disabled API function [#2]
- tls: add tls_set_selfsigned_rsa [#6]
- tls: add functions to verify server cert, purpose and hostname [#10]
- http: client should set SNI [#10]
- http: client should use tls functions to verify server certs, purpose
  and hostname [#10]
- sipreg: add proxy expires field and get function [#13]
- sipreg: make re-register interval configurable [#13]

### Changed

- debian: Automatic cleanup after building debian package

### Fixed

- Set SDK path (SYSROOT) using xcrun (fix building on macOS 10.14)
- tcp: close socket on windows if connection is aborted or reset [#1]
- rtmp: Fix URL path parsing (creytiv#245)
- ice: various fixes [baresip/baresip#925]
- openssl/tls: replace deprecated openssl 1.1.0 functions [#5]

### Contributors (many thanks)

- Alfred E. Heggestad
- Christian Spielberger
- Christoph Huber
- Franz Auernigg
- juha-h
- Juha Heinanen
- Richard Aas
- Sebastian Reimers

[#97]: https://github.com/baresip/re/pull/97
[#94]: https://github.com/baresip/re/pull/94
[#81]: https://github.com/baresip/re/pull/81
[#48]: https://github.com/baresip/re/pull/48
[#92]: https://github.com/baresip/re/pull/92
[#88]: https://github.com/baresip/re/pull/88
[#87]: https://github.com/baresip/re/pull/87
[#86]: https://github.com/baresip/re/pull/86
[#84]: https://github.com/baresip/re/pull/84
[#83]: https://github.com/baresip/re/pull/83
[#82]: https://github.com/baresip/re/pull/82
[#80]: https://github.com/baresip/re/pull/80
[#79]: https://github.com/baresip/re/pull/79
[#78]: https://github.com/baresip/re/pull/78
[#77]: https://github.com/baresip/re/pull/77
[#76]: https://github.com/baresip/re/pull/76
[#39]: https://github.com/baresip/re/pull/39
[#66]: https://github.com/baresip/re/pull/66
[#74]: https://github.com/baresip/re/pull/74
[#67]: https://github.com/baresip/re/pull/67
[#71]: https://github.com/baresip/re/pull/71
[#70]: https://github.com/baresip/re/pull/70
[#69]: https://github.com/baresip/re/pull/69
[#68]: https://github.com/baresip/re/pull/68
[#65]: https://github.com/baresip/re/pull/65
[#63]: https://github.com/baresip/re/pull/63
[#64]: https://github.com/baresip/re/pull/64
[#62]: https://github.com/baresip/re/pull/62
[#61]: https://github.com/baresip/re/pull/61
[#60]: https://github.com/baresip/re/pull/60
[#58]: https://github.com/baresip/re/pull/58
[#56]: https://github.com/baresip/re/pull/56
[#52]: https://github.com/baresip/re/pull/52
[#49]: https://github.com/baresip/re/pull/49
[#47]: https://github.com/baresip/re/pull/47
[#46]: https://github.com/baresip/re/pull/46
[#45]: https://github.com/baresip/re/pull/45
[#43]: https://github.com/baresip/re/pull/43
[#41]: https://github.com/baresip/re/pull/41
[#37]: https://github.com/baresip/re/pull/37
[#35]: https://github.com/baresip/re/pull/35
[#33]: https://github.com/baresip/re/pull/33
[#31]: https://github.com/baresip/re/pull/31
[#28]: https://github.com/baresip/re/pull/28
[#27]: https://github.com/baresip/re/pull/27
[#26]: https://github.com/baresip/re/pull/26
[#25]: https://github.com/baresip/re/pull/25
[#19]: https://github.com/baresip/re/pull/19
[#24]: https://github.com/baresip/re/pull/24
[#22]: https://github.com/baresip/re/pull/22
[#18]: https://github.com/baresip/re/pull/18
[#17]: https://github.com/baresip/re/pull/17
[#13]: https://github.com/baresip/re/pull/13
[#10]: https://github.com/baresip/re/pull/10
[#6]: https://github.com/baresip/re/pull/6
[#5]: https://github.com/baresip/re/pull/5
[#2]: https://github.com/baresip/re/pull/2
[#1]: https://github.com/baresip/re/pull/1

[Unreleased]: https://github.com/baresip/re/compare/v2.7.0...HEAD
[v2.7.0]: https://github.com/baresip/re/compare/v2.6.0...v2.7.0
[v2.6.0]: https://github.com/baresip/re/compare/v2.5.0...v2.6.0
[v2.5.0]: https://github.com/baresip/re/compare/v2.4.0...v2.5.0
[v2.4.0]: https://github.com/baresip/re/compare/v2.3.0...v2.4.0
[v2.3.0]: https://github.com/baresip/re/compare/v2.2.2...v2.3.0
[v2.2.2]: https://github.com/baresip/re/compare/v2.2.1...v2.2.2
[v2.2.1]: https://github.com/baresip/re/compare/v2.2.0...v2.2.1
[v2.2.0]: https://github.com/baresip/re/compare/v2.1.1...v2.2.0
[v2.1.1]: https://github.com/baresip/re/compare/v2.1.0...v2.1.1
[v2.1.0]: https://github.com/baresip/re/compare/v2.0.1...v2.1.0
[v2.0.1]: https://github.com/baresip/re/compare/v2.0.0...v2.0.1
[v2.0.0]: https://github.com/baresip/re/compare/v1.1.0...v2.0.0
[v1.1.0]: https://github.com/baresip/re/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/baresip/re/compare/v0.6.1...v1.0.0
