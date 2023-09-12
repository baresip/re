# libre Changelog

All notable changes to libre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
