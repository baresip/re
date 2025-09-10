#
# CMakeLists.txt
#
# Copyright (C) 2010 - 2025 Alfred E. Heggestad
# Copyright (C) 2022 - 2025 Sebastian Reimers
# Copyright (C) 2023 - 2025 Christian Spielberger
#

##############################################################################
#
# Versioning
#

cmake_minimum_required(VERSION 3.18...4.0)

project(re
  VERSION 4.1.0
  LANGUAGES C
  HOMEPAGE_URL https://github.com/baresip/re
  DESCRIPTION "Generic library for real-time communications"
)

set(PROJECT_SOVERSION 37) # bump if ABI breaks

# Pre-release identifier, comment out on a release
# Increment for breaking changes (dev2, dev3...)
#set(PROJECT_VERSION_PRE dev)

if(PROJECT_VERSION_PRE)
  set(PROJECT_VERSION_FULL ${PROJECT_VERSION}-${PROJECT_VERSION_PRE})
else()
  set(PROJECT_VERSION_FULL ${PROJECT_VERSION})
endif()

if(WIN32 AND NOT MINGW)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std:c11")
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

##############################################################################
#
# Module/Package Includes
#
include(GNUInstallDirs)
include(CheckCCompilerFlag)

##############################################################################
#
# Options
#

option(USE_REM "Enable Librem" ON)
option(USE_BFCP "Enable BFCP" ON)
option(USE_PCP "Enable PCP" ON)
option(USE_RTMP "Enable RTMP" ON)
option(USE_SIP "Enable SIP" ON)
option(LIBRE_BUILD_SHARED "Build shared library" ON)
option(LIBRE_BUILD_STATIC "Build static library" ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
  add_compile_options("/W3")
else()

  set(c_flags
    -pedantic
    -Wall
    -Wbad-function-cast
    -Wcast-align
    -Wextra
    -Wmissing-declarations
    -Wmissing-prototypes
    -Wnested-externs
    -Wno-strict-aliasing
    -Wold-style-definition
    -Wshadow
    -Wstrict-prototypes
    -Wuninitialized
    -Wvla
  )

  add_compile_options(
    "$<$<COMPILE_LANGUAGE:C>:${c_flags}>"
  )
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(
      -Wno-gnu-zero-variadic-macro-arguments
      -Wno-c2x-extensions
    )
    add_compile_options("$<$<COMPILE_LANGUAGE:C>:-Wshorten-64-to-32>")
endif()

check_c_compiler_flag("-Watomic-implicit-seq-cst" COMPILER_SUPPORTS_WATOMIC)
if(COMPILER_SUPPORTS_WATOMIC)
  add_compile_options("$<$<COMPILE_LANGUAGE:C>:-Watomic-implicit-seq-cst>")
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  # Ensure struct mem is aligned (used as fat pointer)
  set_source_files_properties(src/mem/mem.c PROPERTIES COMPILE_FLAGS -Wpadded)
endif()

set(re_DIR ${CMAKE_CURRENT_LIST_DIR}/cmake)
include("${CMAKE_CURRENT_LIST_DIR}/cmake/re-config.cmake")

list(APPEND RE_DEFINITIONS
  -DRE_VERSION="${PROJECT_VERSION_FULL}"
  -DVER_MAJOR=${PROJECT_VERSION_MAJOR}
  -DVER_MINOR=${PROJECT_VERSION_MINOR}
  -DVER_PATCH=${PROJECT_VERSION_PATCH}
  -D_GNU_SOURCE
)

if(DEFINED TRACE_SSL)
  list(APPEND RE_DEFINITIONS
    -DTRACE_SSL="${TRACE_SSL}")
endif()

##############################################################################
#
# Source/Header section
#

set(HEADERS
  include/re.h
  include/re_aes.h
  include/re_async.h
  include/re_atomic.h
  include/re_av1.h
  include/re_base64.h
  include/re_bfcp.h
  include/re_btrace.h
  include/re_conf.h
  include/re_convert.h
  include/re_crc32.h
  include/re_dbg.h
  include/re_dd.h
  include/re_dns.h
  include/re_fmt.h
  include/re_h264.h
  include/re_h265.h
  include/re_hash.h
  include/re_hmac.h
  include/re_http.h
  include/re_httpauth.h
  include/re_ice.h
  include/re_json.h
  include/re_list.h
  include/re_main.h
  include/re_mbuf.h
  include/re_md5.h
  include/re_mem.h
  include/re_mod.h
  include/re_mqueue.h
  include/re_msg.h
  include/re_net.h
  include/re_odict.h
  include/re_pcp.h
  include/re_rtmp.h
  include/re_rtp.h
  include/re_rtpext.h
  include/re_sa.h
  include/re_sdp.h
  include/re_sha.h
  include/re_shim.h
  include/re_sip.h
  include/re_sipevent.h
  include/re_sipreg.h
  include/re_sipsess.h
  include/re_srtp.h
  include/re_stun.h
  include/re_sys.h
  include/re_tcp.h
  include/re_telev.h
  include/re_thread.h
  include/re_tls.h
  include/re_tmr.h
  include/re_trace.h
  include/re_trice.h
  include/re_turn.h
  include/re_types.h
  include/re_udp.h
  include/re_uri.h
  include/re_websock.h
  include/rem_aac.h
  include/rem_aubuf.h
  include/rem_auconv.h
  include/rem_audio.h
  include/rem_aufile.h
  include/rem_auframe.h
  include/rem_au.h
  include/rem_aulevel.h
  include/rem_aumix.h
  include/rem_auresamp.h
  include/rem_autone.h
  include/rem_avc.h
  include/rem_dsp.h
  include/rem_dtmf.h
  include/rem_fir.h
  include/rem_flv.h
  include/rem_g711.h
  include/rem_goertzel.h
  include/rem.h
  include/rem_vidconv.h
  include/rem_video.h
  include/rem_vid.h
  include/rem_vidmix.h
)

if(USE_UNIXSOCK)
  list(APPEND HEADERS
    include/re_unixsock.h
  )
endif()

set(SRCS

  src/av1/depack.c
  src/av1/obu.c
  src/av1/pkt.c

  src/async/async.c

  src/base64/b64.c

  src/btrace/btrace.c

  src/conf/conf.c

  src/dbg/dbg.c

  src/dd/dd.c
  src/dd/dd_enc.c
  src/dd/putbit.c

  src/dns/client.c
  src/dns/cstr.c
  src/dns/dname.c
  src/dns/hdr.c
  src/dns/ns.c
  src/dns/rr.c
  src/dns/rrlist.c

  src/fmt/ch.c
  src/fmt/hexdump.c
  src/fmt/pl.c
  src/fmt/print.c
  src/fmt/prm.c
  src/fmt/regex.c
  src/fmt/str.c
  src/fmt/str_error.c
  src/fmt/text2pcap.c
  src/fmt/time.c
  src/fmt/unicode.c

  src/h264/getbit.c
  src/h264/nal.c
  src/h264/sps.c

  src/h265/nal.c

  src/hash/func.c
  src/hash/hash.c

  src/hmac/hmac_sha1.c

  src/http/auth.c
  src/http/chunk.c
  src/http/client.c
  src/http/msg.c
  src/http/request.c
  src/http/server.c

  src/httpauth/basic.c
  src/httpauth/digest.c

  src/ice/cand.c
  src/ice/candpair.c
  src/ice/chklist.c
  src/ice/comp.c
  src/ice/connchk.c
  src/ice/icem.c
  src/ice/icesdp.c
  src/ice/icestr.c
  src/ice/stunsrv.c
  src/ice/util.c

  src/json/decode.c
  src/json/decode_odict.c
  src/json/encode.c

  src/list/list.c

  src/main/init.c
  src/main/main.c
  src/main/method.c

  src/mbuf/mbuf.c

  src/md5/wrap.c

  src/mem/mem.c
  src/mem/mem_pool.c
  src/mem/secure.c

  src/mod/mod.c

  src/mqueue/mqueue.c

  src/msg/ctype.c
  src/msg/param.c

  src/net/if.c
  src/net/net.c
  src/net/netstr.c
  src/net/rt.c
  src/net/sock.c
  src/net/sockopt.c

  src/odict/entry.c
  src/odict/get.c
  src/odict/odict.c
  src/odict/type.c

  src/rtp/fb.c
  src/rtp/member.c
  src/rtp/ntp.c
  src/rtp/pkt.c
  src/rtp/rr.c
  src/rtp/rtcp.c
  src/rtp/rtp.c
  src/rtp/sdes.c
  src/rtp/sess.c
  src/rtp/source.c

  src/rtpext/rtpext.c

  src/sa/printaddr.c
  src/sa/sa.c

  src/sdp/attr.c
  src/sdp/format.c
  src/sdp/media.c
  src/sdp/msg.c
  src/sdp/session.c
  src/sdp/str.c
  src/sdp/util.c

  src/sha/wrap.c

  src/shim/shim.c

  src/srtp/misc.c
  src/srtp/replay.c
  src/srtp/srtcp.c
  src/srtp/srtp.c
  src/srtp/stream.c

  src/stun/addr.c
  src/stun/attr.c
  src/stun/ctrans.c
  src/stun/dnsdisc.c
  src/stun/hdr.c
  src/stun/ind.c
  src/stun/keepalive.c
  src/stun/msg.c
  src/stun/rep.c
  src/stun/req.c
  src/stun/stun.c
  src/stun/stunstr.c

  src/sys/daemon.c
  src/sys/endian.c
  src/sys/fs.c
  src/sys/rand.c
  src/sys/sleep.c
  src/sys/sys.c

  src/tcp/tcp.c
  src/tcp/tcp_high.c

  src/telev/telev.c

  src/thread/thread.c

  src/tmr/tmr.c

  src/trace/trace.c

  src/trice/cand.c
  src/trice/candpair.c
  src/trice/chklist.c
  src/trice/connchk.c
  src/trice/lcand.c
  src/trice/rcand.c
  src/trice/stunsrv.c
  src/trice/tcpconn.c
  src/trice/trice.c

  src/turn/chan.c
  src/turn/perm.c
  src/turn/turnc.c

  src/udp/mcast.c
  src/udp/udp.c

  src/uri/uri.c
  src/uri/uric.c

  src/websock/websock.c
)

set(REM_SRCS
  rem/aac/aac.c
  rem/au/fmt.c
  rem/au/util.c
  rem/aubuf/aubuf.c
  rem/aubuf/ajb.c
  rem/auconv/auconv.c
  rem/aufile/aufile.c
  rem/aufile/wave.c
  rem/auframe/auframe.c
  rem/aulevel/aulevel.c
  rem/aumix/aumix.c
  rem/auresamp/resamp.c
  rem/autone/tone.c
  rem/avc/config.c
  rem/dtmf/dec.c
  rem/fir/fir.c
  rem/g711/g711.c
  rem/goertzel/goertzel.c
  rem/vid/draw.c
  rem/vid/fmt.c
  rem/vid/frame.c
  rem/vidconv/vconv.c
  rem/vidmix/vidmix.c
)

if(USE_UNIXSOCK)
  list(APPEND SRCS
    src/unixsock/unixsock.c
  )
endif()

if(USE_BFCP)
  list(APPEND SRCS
    src/bfcp/attr.c
    src/bfcp/conn.c
    src/bfcp/msg.c
    src/bfcp/reply.c
    src/bfcp/request.c
  )
endif()


if(USE_PCP)
  list(APPEND SRCS
    src/pcp/msg.c
    src/pcp/option.c
    src/pcp/payload.c
    src/pcp/pcp.c
    src/pcp/reply.c
    src/pcp/request.c
  )
endif()


if(USE_RTMP)
  list(APPEND SRCS
    src/rtmp/amf.c
    src/rtmp/amf_dec.c
    src/rtmp/amf_enc.c
    src/rtmp/chunk.c
    src/rtmp/conn.c
    src/rtmp/control.c
    src/rtmp/ctrans.c
    src/rtmp/dechunk.c
    src/rtmp/hdr.c
    src/rtmp/stream.c
  )
endif()


if(USE_SIP)
  list(APPEND SRCS
    src/sip/addr.c
    src/sip/auth.c
    src/sip/contact.c
    src/sip/cseq.c
    src/sip/ctrans.c
    src/sip/dialog.c
    src/sip/keepalive.c
    src/sip/keepalive_udp.c
    src/sip/msg.c
    src/sip/rack.c
    src/sip/reply.c
    src/sip/request.c
    src/sip/sip.c
    src/sip/strans.c
    src/sip/transp.c
    src/sip/via.c

    src/sipevent/listen.c
    src/sipevent/msg.c
    src/sipevent/notify.c
    src/sipevent/subscribe.c

    src/sipreg/reg.c

    src/sipsess/accept.c
    src/sipsess/ack.c
    src/sipsess/close.c
    src/sipsess/connect.c
    src/sipsess/info.c
    src/sipsess/listen.c
    src/sipsess/modify.c
    src/sipsess/prack.c
    src/sipsess/reply.c
    src/sipsess/request.c
    src/sipsess/sess.c
    src/sipsess/update.c
  )
endif()


if(USE_OPENSSL)
  list(APPEND SRCS
    src/main/openssl.c
    src/aes/openssl/aes.c
    src/tls/openssl/tls_tcp.c
    src/tls/openssl/tls_udp.c
    src/tls/openssl/tls.c
    src/tls/openssl/sni.c
    src/hmac/openssl/hmac.c
  )
elseif(APPLE)
  list(APPEND SRCS
    src/aes/apple/aes.c
    src/hmac/apple/hmac.c
  )
else()
  list(APPEND SRCS
    src/aes/stub.c
    src/hmac/hmac.c
    src/tls/stub.c
  )
endif()


if(WIN32)
  list(APPEND SRCS
    src/dns/win32/srv.c
    src/mod/win32/dll.c
    src/mqueue/win32/pipe.c
    src/net/win32/wif.c
  )
elseif(UNIX)
  list(APPEND SRCS
    src/mod/dl.c
    src/net/posix/pif.c
  )
  if(HAVE_GETIFADDRS)
    list(APPEND SRCS
      src/net/ifaddrs.c
    )
  endif()
endif()

list(APPEND SRCS
  src/crc32/crc32.c
)

if(HAVE_THREADS)
  #Do nothing
elseif(CMAKE_USE_WIN32_THREADS_INIT)
  list(APPEND SRCS
    src/thread/win32.c
  )
else()
  list(APPEND SRCS
    src/thread/posix.c
  )
endif()

if(HAVE_RESOLV)
  list(APPEND SRCS
    src/dns/res.c
  )
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  list(APPEND SRCS
    src/dns/darwin/srv.c
    src/net/bsd/brt.c
  )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "iOS")
  list(APPEND SRCS
    src/dns/darwin/srv.c
  )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  list(APPEND SRCS
    src/net/bsd/brt.c
  )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  list(APPEND SRCS
    src/net/bsd/brt.c
  )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  list(APPEND SRCS
    src/net/linux/rt.c
    src/net/linux/addrs.c
  )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Android")
  list(APPEND SRCS
    src/net/linux/rt.c
  )
endif()

if(USE_REM)
  list(APPEND SRCS ${REM_SRCS})
endif()


##############################################################################
#
# Main target object
#

add_library(re-objs OBJECT ${SRCS} ${HEADERS})

set_target_properties(re-objs PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_definitions(re-objs PRIVATE ${RE_DEFINITIONS})

target_include_directories(re-objs PRIVATE include)
target_include_directories(re-objs PRIVATE
  ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIRS})


##############################################################################
#
# Shared target libre.[so|dll|dylib]
#

if(LIBRE_BUILD_SHARED)
  list(APPEND RE_INSTALL_TARGETS re-shared)
  add_library(re-shared SHARED $<TARGET_OBJECTS:re-objs>)
  target_link_libraries(re-shared PRIVATE ${RE_LIBS})
  set_target_properties(re-shared PROPERTIES VERSION
    ${PROJECT_SOVERSION}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})
  set_target_properties(re-shared PROPERTIES SOVERSION ${PROJECT_SOVERSION})
  set_target_properties(re-shared PROPERTIES OUTPUT_NAME "re")
  add_library(libre::re-shared ALIAS re-shared)
endif()


##############################################################################
#
# Static target libre.a
#

if(LIBRE_BUILD_STATIC)
  list(APPEND RE_INSTALL_TARGETS re)
  add_library(re STATIC $<TARGET_OBJECTS:re-objs>)
  target_link_libraries(re PRIVATE ${RE_LIBS})
  target_include_directories(re PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  )
  add_library(libre::re ALIAS re)

  if(MSVC)
    set_target_properties(re PROPERTIES OUTPUT_NAME "re-static")
    if(NOT LIBRE_BUILD_SHARED)
      set(PC_LIBNAME "re-static")
    endif()
  endif()
endif()


##############################################################################
#
# PKGCONF section
#

if(NOT PC_LIBNAME)
  set(PC_LIBNAME "re")
endif()
set(PC_REQUIRES "")
set(PC_LINKLIBS "")
foreach(item IN LISTS RE_LIBS)
  if(item STREQUAL "Threads::Threads")
    list(APPEND PC_LINKLIBS ${CMAKE_THREADS_LIBS_INIT})
  elseif(item STREQUAL "OpenSSL::Crypto")
    list(APPEND PC_REQUIRES "libcrypto")
  elseif(item STREQUAL "OpenSSL::SSL")
    list(APPEND PC_REQUIRES "libssl")
  elseif(item STREQUAL "ZLIB::ZLIB")
    list(APPEND PC_REQUIRES "zlib")
  elseif(item MATCHES "^-|/")
    list(APPEND PC_LINKLIBS "${item}")
  else()
    list(APPEND PC_LINKLIBS "-l${item}")
  endif()
endforeach()
list(JOIN PC_LINKLIBS " " PC_LINKLIBS)
list(JOIN PC_REQUIRES " " PC_REQUIRES)
configure_file(packaging/libre.pc.in libre.pc @ONLY)


##############################################################################
#
# Install section
#

install(TARGETS ${RE_INSTALL_TARGETS}
  EXPORT libre
  RUNTIME
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Libraries
  LIBRARY
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT Libraries
    NAMELINK_SKIP
  ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT Development
  INCLUDES
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/re
)

install(FILES ${HEADERS}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/re
  COMPONENT Development
)

install(EXPORT libre
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libre
  FILE libre-targets.cmake
  NAMESPACE libre::
  COMPONENT Development
)

if(LIBRE_BUILD_SHARED)
  install(TARGETS re-shared
    LIBRARY
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      NAMELINK_ONLY
      COMPONENT Development
  )
endif()

install(FILES cmake/re-config.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/re
  COMPONENT Development
)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/libre-config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/cmake/libre-config.cmake" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cmake/libre-config.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libre
  COMPONENT Development
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libre.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
  COMPONENT Development
)


##############################################################################
#
# Packaging section
#

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  add_subdirectory(packaging)
endif()


##############################################################################
# Test
#

add_subdirectory(test EXCLUDE_FROM_ALL)
