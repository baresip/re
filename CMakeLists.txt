#
# CMakeLists.txt
#
# Copyright (C) 2010 - 2022 Alfred E. Heggestad
# Copyright (C) 2022 Sebastian Reimers
#

##############################################################################
#
# Versioning
#

cmake_minimum_required(VERSION 3.7)

project(re VERSION 2.0.1 LANGUAGES C)

# Pre-release identifier, comment out on a release
# Increment for breaking changes (dev.2, dev.3...)
set(PROJECT_VERSION_PRE dev13)

if(PROJECT_VERSION_PRE)
  set(PROJECT_VERSION_FULL ${PROJECT_VERSION}-${PROJECT_VERSION_PRE})
else()
  set(PROJECT_VERSION_FULL ${PROJECT_VERSION})
endif()


##############################################################################
#
# Compile options
#

find_package(OpenSSL)

option(USE_OPENSSL "Enable OpenSSL" ${OPENSSL_FOUND})
option(USE_BFCP "Enable BFCP" ON)
option(USE_RTMP "Enable RTMP" ON)
option(USE_SIP "Enable SIP" ON)


set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)

if(NOT MSVC)
  add_compile_options(
    -Wall -Wextra -Wmissing-declarations -Wmissing-prototypes
    -Wstrict-prototypes -Wbad-function-cast -Wnested-externs
    -Wshadow -Waggregate-return -Wcast-align -Wold-style-definition
    -Wdeclaration-after-statement -Wvla
  )
endif()


if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wshorten-64-to-32)
endif()


add_definitions(
  -DHAVE_INET6
  -DHAVE_SELECT
  )


if(UNIX)
  add_definitions(
    -DHAVE_GETIFADDRS
    -DHAVE_POLL
    -DHAVE_PTHREAD
    -DHAVE_PWD_H
    -DHAVE_ROUTE_LIST
    -DHAVE_SETRLIMIT
    -DHAVE_STRERROR_R
    -DHAVE_STRINGS_H
    -DHAVE_SYS_TIME_H
    -DHAVE_UNAME
    -DHAVE_UNISTD_H
    )
endif()


if(MSVC)
  add_definitions(
    -DHAVE_IO_H
    -D_CRT_SECURE_NO_WARNINGS
  )
endif()


if(USE_OPENSSL)
  add_definitions(
    -DUSE_DTLS
    -DUSE_OPENSSL
    -DUSE_OPENSSL_AES
    -DUSE_OPENSSL_DTLS
    -DUSE_OPENSSL_HMAC
    -DUSE_OPENSSL_SRTP
    -DUSE_TLS
  )
endif()


if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_definitions(-DDARWIN -DHAVE_KQUEUE)
  include_directories(/opt/local/include)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  add_definitions(-DHAVE_EPOLL)
endif()


add_definitions(
  -DARCH="${CMAKE_SYSTEM_PROCESSOR}"
  -DOS="${CMAKE_SYSTEM_NAME}"
  -DVERSION="${CMAKE_PROJECT_VERSION}"
  -DVER_MAJOR=${PROJECT_VERSION_MAJOR}
  -DVER_MINOR=${PROJECT_VERSION_MINOR}
  -DVER_PATCH=${PROJECT_VERSION_PATCH}
)

##############################################################################
#
# Source section
#

set(SRCS

  src/base64/b64.c

  src/btrace/btrace.c

  src/conf/conf.c

  src/crc32/crc32.c

  src/dbg/dbg.c

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
  src/fmt/time.c
  src/fmt/unicode.c

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

  src/jbuf/jbuf.c

  src/json/decode.c
  src/json/decode_odict.c
  src/json/encode.c

  src/list/list.c

  src/main/init.c
  src/main/main.c
  src/main/method.c

  src/mbuf/mbuf.c

  src/md5/md5.c
  src/md5/wrap.c

  src/mem/mem.c
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

  src/tmr/tmr.c

  src/trace/trace.c

  src/turn/chan.c
  src/turn/perm.c
  src/turn/turnc.c

  src/udp/mcast.c
  src/udp/udp.c

  src/uri/uri.c
  src/uri/uric.c

  src/websock/websock.c
)


if(USE_BFCP)
  list(APPEND SRCS
    src/bfcp/attr.c
    src/bfcp/conn.c
    src/bfcp/msg.c
    src/bfcp/reply.c
    src/bfcp/request.c
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
    src/sipsess/reply.c
    src/sipsess/request.c
    src/sipsess/sess.c
  )
endif()


if(USE_OPENSSL)
  list(APPEND SRCS
    src/main/openssl.c
    src/aes/openssl/aes.c
    src/tls/openssl/tls_tcp.c
    src/tls/openssl/tls_udp.c
    src/tls/openssl/tls.c
    src/hmac/openssl/hmac.c
  )
endif()


if(WIN32)
  list(APPEND SRCS
    src/dns/win32/srv.c
    src/lock/win32/lock.c
    src/mod/win32/dll.c
    src/mqueue/win32/pipe.c
    src/net/win32/wif.c
  )
elseif(UNIX)
  list(APPEND SRCS
    src/lock/lock.c
    src/mod/dl.c
    src/net/ifaddrs.c
    src/net/posix/pif.c
  )
endif()


if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  list(APPEND SRCS
    src/dns/darwin/srv.c
    src/net/bsd/brt.c
  )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  list(APPEND SRCS
    src/net/linux/rt.c
    src/main/epoll.c
  )
endif()


##############################################################################
#
# Main target object
#

add_library(re OBJECT ${SRCS})

set_target_properties(re PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(re PRIVATE .)
target_include_directories(re PRIVATE include ${OPENSSL_INCLUDE_DIR})


##############################################################################
#
# Shared target libre.[so|dll|dylib]
#

add_library(re-shared SHARED $<TARGET_OBJECTS:re>)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  target_link_libraries(re-shared
    PRIVATE "-framework SystemConfiguration" "-framework CoreFoundation"
  )
endif()

if(WIN32)
  target_link_libraries(re-shared PRIVATE
    ${OPENSSL_LIBRARIES}
    qwave
    iphlpapi
    wsock32
    ws2_32
  )
else()
  target_link_libraries(re-shared
    PRIVATE -L/opt/local/lib ${OPENSSL_LIBRARIES} -lpthread)
endif()

set_target_properties(re-shared PROPERTIES PUBLIC_HEADER include/re.h)
set_target_properties(re-shared PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(re-shared PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
set_target_properties(re-shared PROPERTIES OUTPUT_NAME "re")


##############################################################################
#
# Static target libre.a
#

add_library(re-static STATIC $<TARGET_OBJECTS:re>)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  target_link_libraries(re-static
    PUBLIC "-framework SystemConfiguration" "-framework CoreFoundation"
  )
endif()
target_link_libraries(re-static
  PUBLIC ${OPENSSL_LIBRARIES} -lpthread
  PRIVATE -L/opt/local/lib
)

set_target_properties(re-static PROPERTIES PUBLIC_HEADER include/re.h)
if(NOT MSVC)
set_target_properties(re-static PROPERTIES OUTPUT_NAME "re")
endif()
