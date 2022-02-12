#
# CMakeLists.txt
#
# Copyright (C) 2010 - 2022 Alfred E. Heggestad
#

cmake_minimum_required(VERSION 3.12)

project(re VERSION 2.0.1 LANGUAGES C)

find_package(OpenSSL)

option(USE_OPENSSL "Enable OpenSSL" ${OPENSSL_FOUND})


if (MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall)
endif()


add_compile_definitions(
  HAVE_GETIFADDRS
  HAVE_INET6
  HAVE_INTTYPES_H
  HAVE_NET_ROUTE_H
  HAVE_POLL
  HAVE_PTHREAD
  HAVE_PWD_H
  HAVE_ROUTE_LIST
  HAVE_SELECT
  HAVE_SETRLIMIT
  HAVE_STRERROR_R
  HAVE_STRINGS_H
  HAVE_SYS_SYSCTL_H
  HAVE_SYS_TIME_H
  HAVE_UNAME
  HAVE_UNISTD_H
  )


if(USE_OPENSSL)
  add_compile_definitions(
    USE_DTLS
    USE_OPENSSL
    USE_OPENSSL_AES
    USE_OPENSSL_DTLS
    USE_OPENSSL_HMAC
    USE_OPENSSL_SRTP
    USE_TLS
  )
endif()


if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_compile_definitions(DARWIN HAVE_KQUEUE)
  include_directories(/opt/local/include)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  add_compile_definitions(HAVE_EPOLL)
endif()


add_compile_definitions(
  ARCH="${CMAKE_SYSTEM_PROCESSOR}"
  OS="${CMAKE_SYSTEM_NAME}"
  VERSION="${CMAKE_PROJECT_VERSION}"
  VER_MAJOR=${PROJECT_VERSION_MAJOR}
  VER_MINOR=${PROJECT_VERSION_MINOR}
  VER_PATCH=${PROJECT_VERSION_PATCH}
)


set(SRCS

  src/base64/b64.c

  src/bfcp/attr.c
  src/bfcp/conn.c
  src/bfcp/msg.c
  src/bfcp/reply.c
  src/bfcp/request.c

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

  src/lock/lock.c

  src/main/init.c
  src/main/main.c
  src/main/method.c
  src/main/openssl.c

  src/mbuf/mbuf.c

  src/md5/md5.c
  src/md5/wrap.c

  src/mem/mem.c
  src/mem/secure.c

  src/mod/dl.c
  src/mod/mod.c

  src/mqueue/mqueue.c

  src/msg/ctype.c
  src/msg/param.c

  src/net/if.c
  src/net/ifaddrs.c
  src/net/net.c
  src/net/netstr.c
  src/net/posix/pif.c
  src/net/rt.c
  src/net/sock.c
  src/net/sockopt.c

  src/odict/entry.c
  src/odict/get.c
  src/odict/odict.c
  src/odict/type.c

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


if(USE_OPENSSL)
  list(APPEND SRCS
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
    src/mod/win32/mod.c
    src/mqueue/win32/mqueue.c
    src/net/win32/wif.c
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

add_library(re OBJECT ${SRCS})

add_library(re-shared SHARED $<TARGET_OBJECTS:re>)
add_library(re-static STATIC $<TARGET_OBJECTS:re>)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  target_link_libraries(re "-framework SystemConfiguration" "-framework CoreFoundation" )
endif()

target_link_libraries(re -L/opt/local/lib -lssl -lcrypto -lpthread)

set_target_properties(re PROPERTIES POSITION_INDEPENDENT_CODE 1)
set_target_properties(re PROPERTIES PUBLIC_HEADER include/re.h)

set_target_properties(re-shared PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(re-shared PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
set_target_properties(re-shared PROPERTIES OUTPUT_NAME "re")

set_target_properties(re-static PROPERTIES OUTPUT_NAME "re")

target_include_directories(re PRIVATE .)
target_include_directories(re PRIVATE include)
