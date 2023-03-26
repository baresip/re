include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckSymbolExists)

find_package(Backtrace)
find_package(Threads REQUIRED)
find_package(ZLIB)
find_package(OpenSSL "1.1.1")

option(USE_OPENSSL "Enable OpenSSL" ${OPENSSL_FOUND})
option(USE_UNIXSOCK "Enable Unix Domain Sockets" ON)
option(USE_TRACE "Enable Tracing helpers" OFF)

check_symbol_exists("arc4random" "stdlib.h" HAVE_ARC4RANDOM)
if(HAVE_ARC4RANDOM)
  list(APPEND RE_DEFINITIONS -DHAVE_ARC4RANDOM)
endif()

if(ZLIB_FOUND)
  list(APPEND RE_DEFINITIONS -DUSE_ZLIB)
endif()

check_include_file(syslog.h HAVE_SYSLOG_H)
if(HAVE_SYSLOG_H)
  list(APPEND RE_DEFINITIONS -DHAVE_SYSLOG)
endif()

check_include_file(getopt.h HAVE_GETOPT_H)
if(HAVE_GETOPT_H)
  list(APPEND RE_DEFINITIONS -DHAVE_GETOPT)
endif()

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
  list(APPEND RE_DEFINITIONS -DHAVE_UNISTD_H)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  check_symbol_exists(res_init resolv.h HAVE_RESOLV)
else()
  check_symbol_exists(res_ninit resolv.h HAVE_RESOLV)
endif()
if(HAVE_RESOLV)
  find_library(RESOLV_LIBRARY resolv)
  list(APPEND RE_DEFINITIONS -DHAVE_RESOLV)
else()
  set(RESOLV_LIBRARY)
endif()

if(Backtrace_FOUND)
  list(APPEND RE_DEFINITIONS -DHAVE_EXECINFO)
else()
  set(Backtrace_LIBRARIES)
endif()

check_function_exists(thrd_create HAVE_THREADS)
if(HAVE_THREADS)
  list(APPEND RE_DEFINITIONS -DHAVE_THREADS)
endif()

check_function_exists(accept4 HAVE_ACCEPT4)
if(HAVE_ACCEPT4)
  list(APPEND RE_DEFINITIONS -DHAVE_ACCEPT4)
endif()

if(CMAKE_USE_PTHREADS_INIT)
  list(APPEND RE_DEFINITIONS -DHAVE_PTHREAD)
  set(HAVE_PTHREAD ON)
endif()

if(UNIX)
  check_symbol_exists(epoll_create "sys/epoll.h" HAVE_EPOLL)
  if(HAVE_EPOLL)
    list(APPEND RE_DEFINITIONS -DHAVE_EPOLL)
  endif()
  check_symbol_exists(kqueue "sys/event.h" HAVE_KQUEUE)
  if(HAVE_KQUEUE)
    list(APPEND RE_DEFINITIONS -DHAVE_KQUEUE)
  endif()
endif()

check_include_file(sys/prctl.h HAVE_PRCTL)
if(HAVE_PRCTL)
  list(APPEND RE_DEFINITIONS -DHAVE_PRCTL)
endif()


list(APPEND RE_DEFINITIONS
  -DHAVE_ATOMIC
  -DHAVE_INET6
  -DHAVE_SELECT
  )

if(UNIX)
  list(APPEND RE_DEFINITIONS
    -DHAVE_PWD_H
    -DHAVE_ROUTE_LIST
    -DHAVE_SETRLIMIT
    -DHAVE_STRERROR_R
    -DHAVE_STRINGS_H
    -DHAVE_SYS_TIME_H
    -DHAVE_UNAME
    -DHAVE_SELECT_H
    -DHAVE_SIGNAL
    -DHAVE_FORK
    )
  if(NOT ANDROID)
    list(APPEND RE_DEFINITIONS -DHAVE_GETIFADDRS)
  endif()
endif()


if(MSVC)
  list(APPEND RE_DEFINITIONS
    -DHAVE_IO_H
    -D_CRT_SECURE_NO_WARNINGS
  )
endif()

if(WIN32)
  list(APPEND RE_DEFINITIONS
    -DWIN32 -D_WIN32_WINNT=0x0600
  )
endif()

if(USE_OPENSSL)
  list(APPEND RE_DEFINITIONS
    -DUSE_DTLS
    -DUSE_OPENSSL
    -DUSE_OPENSSL_AES
    -DUSE_OPENSSL_DTLS
    -DUSE_OPENSSL_HMAC
    -DUSE_OPENSSL_SRTP
    -DUSE_TLS
  )
endif()

if(USE_UNIXSOCK)
  list(APPEND RE_DEFINITIONS
    -DHAVE_UNIXSOCK=1
  )
else()
  list(APPEND RE_DEFINITIONS
    -DHAVE_UNIXSOCK=0
  )
endif()

if(USE_TRACE)
  list(APPEND RE_DEFINITIONS
    -DRE_TRACE_ENABLED
  )
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  list(APPEND RE_DEFINITIONS -DDARWIN)
  include_directories(/opt/local/include)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  list(APPEND RE_DEFINITIONS -DFREEBSD)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  list(APPEND RE_DEFINITIONS -DOPENBSD)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  list(APPEND RE_DEFINITIONS -DLINUX)
endif()


list(APPEND RE_DEFINITIONS
  -DARCH="${CMAKE_SYSTEM_PROCESSOR}"
  -DOS="${CMAKE_SYSTEM_NAME}"
)

if(${CMAKE_BUILD_TYPE} MATCHES "[Rr]el")
  list(APPEND RE_DEFINITIONS -DRELEASE)
else()
  if(Backtrace_FOUND)
    set(CMAKE_ENABLE_EXPORTS ON)
  endif()
endif()
