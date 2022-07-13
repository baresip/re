# libre Changelog

All notable changes to libre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/baresip/re/compare/v2.4.0...HEAD
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
