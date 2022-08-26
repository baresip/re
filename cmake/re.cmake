find_package(Backtrace)
find_package(Threads REQUIRED)
find_package(OpenSSL)

option(USE_OPENSSL "Enable OpenSSL" ${OPENSSL_FOUND})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
  add_compile_options("/W3")
else()
  add_compile_options(
    -Wall
    -Wbad-function-cast
    -Wcast-align
    -Wextra
    -Wmissing-declarations
    -Wmissing-prototypes
    -Wnested-externs
    -Wold-style-definition
    -Wshadow -Waggregate-return
    -Wstrict-prototypes
    -Wvla
  )
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wshorten-64-to-32 -Watomic-implicit-seq-cst)
endif()

check_symbol_exists("arc4random" "stdlib.h" HAVE_ARC4RANDOM)
if(HAVE_ARC4RANDOM)
  add_definitions(-DHAVE_ARC4RANDOM)
endif()

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
  add_definitions(-DHAVE_UNISTD_H)
endif()

if(Backtrace_FOUND)
  add_definitions(-DHAVE_EXECINFO)
else()
  set(Backtrace_LIBRARIES)
endif()

check_function_exists(thrd_create HAVE_THREADS)
if(HAVE_THREADS)
  add_definitions(-DHAVE_THREADS)
endif()

if(CMAKE_USE_PTHREADS_INIT)
  add_definitions(-DHAVE_PTHREAD)
  set(HAVE_PTHREAD ON)
endif()

add_definitions(
  -DHAVE_ATOMIC
  -DHAVE_INET6
  -DHAVE_SELECT
  )

if(UNIX)
  add_definitions(
    -DHAVE_POLL
    -DHAVE_PWD_H
    -DHAVE_ROUTE_LIST
    -DHAVE_SETRLIMIT
    -DHAVE_STRERROR_R
    -DHAVE_STRINGS_H
    -DHAVE_SYS_TIME_H
    -DHAVE_UNAME
    -DHAVE_SELECT_H
    -DHAVE_SIGNAL
    )
  if(NOT ANDROID)
    add_definitions(-DHAVE_GETIFADDRS)
  endif()
endif()


if(MSVC)
  add_definitions(
    -DHAVE_IO_H
    -D_CRT_SECURE_NO_WARNINGS
  )
endif()

if(WIN32)
  add_definitions(
    -DWIN32 -D_WIN32_WINNT=0x0600
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
  add_definitions(-DHAVE_KQUEUE -DDARWIN)
  include_directories(/opt/local/include)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  add_definitions(-DHAVE_KQUEUE -DFREEBSD)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  add_definitions(-DHAVE_KQUEUE -DOPENBSD)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  add_definitions(-DHAVE_EPOLL -DLINUX)
endif()


add_definitions(
  -DARCH="${CMAKE_SYSTEM_PROCESSOR}"
  -DOS="${CMAKE_SYSTEM_NAME}"
  -DVERSION="${PROJECT_VERSION}"
  -DVER_MAJOR=${PROJECT_VERSION_MAJOR}
  -DVER_MINOR=${PROJECT_VERSION_MINOR}
  -DVER_PATCH=${PROJECT_VERSION_PATCH}
)

if(${CMAKE_BUILD_TYPE} MATCHES "[Rr]el")
  add_definitions(-DRELEASE)
endif()
