#
# CMakeLists.txt
#
# Copyright (C) 2010 - 2022 Alfred E. Heggestad
#

##############################################################################
#
# Versioning
#

project(retest C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)


##############################################################################
#
# Module/Package Includes
#


##############################################################################
#
# Compile options/definitions
#

option(USE_SANITIZER "Sanitizers like: address, thread, undefined, memory")
include(sanitizer)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 11)

if(MSVC)
  add_compile_options("/W3")
else()

  set(c_flags
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
  add_compile_options("$<$<COMPILE_LANGUAGE:C>:-Wshorten-64-to-32>")
endif()

include_directories(
  .
)

find_package(re CONFIG REQUIRED HINTS ../cmake)

##############################################################################
#
# Source/Header section
#

set(SRCS
  aac.c
  aes.c
  async.c
  au.c
  aubuf.c
  aulength.c
  aulevel.c
  aupos.c
  auresamp.c
  av1.c
  base64.c
  bfcp.c
  btrace.c
  conf.c
  convert.c
  crc32.c
  dd.c
  dns.c
  dsp.c
  dtmf.c
  fir.c
  fmt.c
  g711.c
  h264.c
  h265.c
  hash.c
  hmac.c
  http.c
  httpauth.c
  ice.c
  json.c
  list.c
  main.c
  mbuf.c
  md5.c
  mem.c
  mem_pool.c
  mock/dnssrv.c
  mock/nat.c
  mock/sipsrv.c
  mock/stunsrv.c
  mock/turnsrv.c
  mqueue.c
  net.c
  odict.c
  pcp.c
  remain.c
  rtcp.c
  rtmp.c
  rtp.c
  rtpext.c
  sa.c
  sdp.c
  sha.c
  sip.c
  sipauth.c
  sipevent.c
  sipreg.c
  sipsess.c
  srtp.c
  stun.c
  sys.c
  tcp.c
  telev.c
  test.c
  thread.c
  tmr.c
  trace.c
  trice.c
  turn.c
  types.c
  udp.c
  unixsock.c
  uri.c
  vid.c
  vidconv.c
  websock.c
)

if(USE_OPENSSL)
  list(APPEND SRCS
    tls.c
    dtls.c
    combo/dtls_turn.c
    mock/cert.c
  )
endif()

list(APPEND SRCS cplusplus.cpp)


##############################################################################
#
# Main target object
#

set(LINKLIBS re ${OPENSSL_LIBRARIES})
if(WIN32)
  list(APPEND LINKLIBS qwave iphlpapi wsock32 ws2_32 crypt32)
else()
  list(APPEND LINKLIBS m ${RESOLV_LIBRARY} stdc++)
endif()

if(ZLIB_FOUND)
  list(APPEND LINKLIBS ZLIB::ZLIB)
endif()

add_executable(${PROJECT_NAME} ${SRCS})
set_property(TARGET ${PROJECT_NAME} PROPERTY ENABLE_EXPORTS 1)

target_link_libraries(${PROJECT_NAME} PRIVATE ${LINKLIBS})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${RE_DEFINITIONS})

if(USE_OPENSSL)
  target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
