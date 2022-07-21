#
# re.mk - common make rules
#
# Copyright (C) 2010 Creytiv.com
#
# Imported variables:
#
#   ARCH           Target architecture
#   CC             Compiler
#   CROSS_COMPILE  Cross-compiler prefix (optional)
#   LIBRE_PATH     Libre path (optional)
#   LIBRE_INC      Libre include path (optional)
#   LIBRE_SO       Libre library search path (optional)
#   EXTRA_CFLAGS   Extra compiler flags appended to CFLAGS
#   EXTRA_LFLAGS   Extra linker flags appended to LFLAGS
#   GCOV           If non-empty, enable GNU Coverage testing
#   GPROF          If non-empty, enable GNU Profiling
#   OPT_SIZE       If non-empty, optimize for size
#   OPT_SPEED      If non-empty, optimize for speed
#   PROJECT        Project name
#   RELEASE        Release build
#   TRACE_ERR      Trace error codes
#   TRACE_SSL      Log SSL key material = [/path/to/log/file.log]
#   SYSROOT        System root of library and include files
#   SYSROOT_ALT    Alternative system root of library and include files
#   USE_OPENSSL    If non-empty, link to libssl library
#   OPENSSL_OPT    If non-empty, link to extra libssl library
#   USE_ZLIB       If non-empty, link to libz library
#   VERSION        Version number
#
# Exported variables:
#
#   APP_LFLAGS     Linker flags for applications using modules
#   BIN_SUFFIX     Suffix for binary executables
#   CC             Compiler
#   CCACHE         Compiler ccache tool
#   CFLAGS         Compiler flags
#   DFLAGS         Dependency generator flags
#   CXXDFLAGS      Dependency generator flags (C++)
#   LFLAGS         Common linker flags
#   LIBS           Libraries to link against
#   LIB_SUFFIX     Suffix for shared libraries
#   MOD_LFLAGS     Linker flags for dynamic modules
#   MOD_SUFFIX     Suffix for dynamic modules
#   SH_LFLAGS      Linker flags for shared libraries
#   USE_TLS        Defined if TLS is available
#   USE_DTLS       Defined if DTLS is available
#   PKG_CONFIG     Defined if pkg-config available
#


ifneq ($(RELEASE),)
CFLAGS  += -DRELEASE
OPT_SPEED=1
endif

ifneq ($(TRACE_ERR),)
CFLAGS  += -DTRACE_ERR
endif

ifneq ($(TRACE_SSL),)
CFLAGS  += -DTRACE_SSL="\"${TRACE_SSL}\""
endif


# Default system root
ifeq ($(SYSROOT),)
SYSROOT := /usr
endif

# Alternative Systemroot
ifeq ($(SYSROOT_ALT),)
SYSROOT_ALT := $(shell [ -d /sw/include ] && echo "/sw")
endif
ifeq ($(SYSROOT_ALT),)
SYSROOT_ALT := $(shell [ -d /opt/local/include ] && echo "/opt/local")
endif

ifneq ($(SYSROOT_ALT),)
CFLAGS  += -I$(SYSROOT_ALT)/include
LFLAGS  += -L$(SYSROOT_ALT)/lib
endif

# Compiler dependency flags
DFLAGS	  = -MD -MF $(@:.o=.d) -MT $@
CXXDFLAGS = -MD -MF $(@:.o=.d) -MT $@

##############################################################################
#
# Compiler section
#
# find compiler name & version

ifeq ($(CC),)
	CC := gcc
endif
ifeq ($(CC),cc)
	CC := gcc
endif
LD := $(CC)

CC_LONGVER  := $(shell $(CC) --version|head -n 1)
CC_SHORTVER := $(shell $(CC) -dumpversion)
CC_MAJORVER := $(shell echo $(CC_SHORTVER) |\
			sed -E 's/([0-9]+).[0-9]+.[0-9]+/\1/g')

# find-out the compiler's name

ifneq (,$(findstring gcc, $(CC_LONGVER)))
	CC_NAME := gcc
	CC_VER := $(CC) $(CC_SHORTVER) ($(CC_MAJORVER).x)
	MKDEP := $(CC) -MM
ifneq ($(CC_MAJORVER), 4)
	CC_C11 := 1
endif
endif

ifeq ($(CC_NAME),)
ifneq (,$(findstring clang, $(CC_LONGVER)))
	CC_NAME := clang
	CC_VER := $(CC) $(CC_SHORTVER) ($(CC_MAJORVER).x)
	MKDEP := $(CC) -MM
ifneq ($(CC_MAJORVER), 4)
	DFLAGS += -MJ $@.json
	CC_C11 := 1
endif
endif
endif


ifeq (,$(CC_NAME))
#not found
	CC_NAME     := $(CC)
	CC_SHORTVER := unknown
	CC_VER      := unknown
	MKDEP       := gcc -MM
$(warning	Unknown compiler $(CC)\; supported compilers: \
			gcc, clang)
endif


# Compiler warning flags
CFLAGS	+= -Wall
CFLAGS	+= -Wextra
CFLAGS	+= -Wmissing-declarations
CFLAGS	+= -Wmissing-prototypes
CFLAGS	+= -Wstrict-prototypes
CFLAGS	+= -Wbad-function-cast
CFLAGS	+= -Wsign-compare
CFLAGS	+= -Wnested-externs
CFLAGS	+= -Wshadow
CFLAGS	+= -Waggregate-return
CFLAGS	+= -Wcast-align
CFLAGS	+= -Wold-style-definition
CFLAGS	+= -Wvla # Avoid insecure variable-length arrays
ifeq ($(CC_NAME), clang)
CFLAGS	+= -Wshorten-64-to-32
CFLAGS  += -Watomic-implicit-seq-cst
endif

CFLAGS  += -g
ifneq ($(OPT_SPEED),)
CFLAGS  += -O3  # Optimize for speed - takes longer to compile!
OPTIMIZE := 1
endif
ifneq ($(OPT_SIZE),)
CFLAGS  += -Os  # Optimize for size - takes longer to compile!
OPTIMIZE := 1
endif

ifneq ($(OPTIMIZE),)
CFLAGS	+= -Wuninitialized
CFLAGS	+= -Wno-strict-aliasing
endif


##############################################################################
#
# OS section
#

MACHINE   := $(shell $(CC) -dumpmachine)

ifeq ($(CROSS_COMPILE),)
OS        := $(shell uname -s | sed -e s/SunOS/solaris/ | tr "[A-Z]" "[a-z]")
endif


ifneq ($(strip $(filter i386-mingw32 i486-mingw32 i586-mingw32msvc \
	i686-w64-mingw32 x86_64-w64-mingw32 mingw32, \
	$(MACHINE))),)
	OS   := win32
ifeq ($(MACHINE), mingw32)
	CROSS_COMPILE :=
endif
endif

PKG_CONFIG := $(shell pkg-config --version)

# default
LIB_SUFFIX	:= .so
MOD_SUFFIX	:= .so
BIN_SUFFIX	:=

ifeq ($(OS),solaris)
	CFLAGS		+= -fPIC -DSOLARIS
	LIBS		+= -ldl -lresolv -lsocket -lnsl
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -G
	MOD_LFLAGS	+=
	APP_LFLAGS	+=
	AR		:= ar
	AFLAGS		:= cru
endif
ifeq ($(OS),linux)
	CFLAGS		+= -fPIC -DLINUX
	LIBS		+= -ldl
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -rdynamic
	AR		:= ar
	AFLAGS		:= crD
endif
ifeq ($(OS),gnu)
	CFLAGS		+= -fPIC -DGNU
	LIBS		+= -ldl
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -rdynamic
	AR		:= ar
	AFLAGS		:= cru
endif
ifeq ($(OS),darwin)
	CFLAGS		+= -fPIC -dynamic -DDARWIN
ifneq (,$(findstring Apple, $(CC_LONGVER)))
	CFLAGS		+= -Wshorten-64-to-32
endif
	DFLAGS		:= -MD
	LIBS		+= -lresolv
	LFLAGS		+= -fPIC
	# add libraries for darwin dns servers
	LFLAGS		+= -framework SystemConfiguration \
			   -framework CoreFoundation
	SH_LFLAGS	+= -dynamiclib
ifeq ($(CC_NAME),gcc)
	SH_LFLAGS	+= -dylib
endif
ifneq ($(ABI_CUR),)
	SH_LFLAGS	+= -current_version \
		$(shell expr $(ABI_CUR) + 1).$(ABI_REV)
	SH_LFLAGS	+= -compatibility_version $(shell expr $(ABI_CUR) + 1)
endif
	MOD_LFLAGS	+= -undefined dynamic_lookup
	APP_LFLAGS	+=
	AR		:= ar
	AFLAGS		:= cru
	LIB_SUFFIX	:= .dylib
	HAVE_KQUEUE	:= 1
	SYSROOT		:= $(shell xcrun --show-sdk-path)/usr
endif
ifeq ($(OS),netbsd)
	CFLAGS		+= -fPIC -DNETBSD
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -rdynamic
	AR		:= ar
	AFLAGS		:= cru
	HAVE_KQUEUE	:= 1
endif
ifeq ($(OS),freebsd)
	CFLAGS		+= -fPIC -DFREEBSD
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -rdynamic
	AR		:= ar
	AFLAGS		:= cru
	HAVE_KQUEUE	:= 1
endif
ifeq ($(OS),gnu/kfreebsd)
	CFLAGS		+= -fPIC -DKFREEBSD -D_GNU_SOURCE
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -rdynamic
	AR		:= ar
	AFLAGS		:= cru
	HAVE_KQUEUE	:= 1
endif
ifeq ($(OS),dragonfly)
	CFLAGS		+= -fPIC -DDRAGONFLY
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -rdynamic
	AR		:= ar
	AFLAGS		:= cru
	HAVE_KQUEUE	:= 1
endif
ifeq ($(OS),openbsd)
	CFLAGS		+= -fPIC -DOPENBSD
	LFLAGS		+= -fPIC
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -rdynamic
	AR		:= ar
	AFLAGS		:= cru
	HAVE_KQUEUE	:= 1
	HAVE_ARC4RANDOM	:= 1
# openbsd has an incompatible pkg-config version
	PKG_CONFIG	:=
endif
ifeq ($(OS),win32)
	CFLAGS		+= -DWIN32 -D_WIN32_WINNT=0x0600 -D__ssize_t_defined
	LIBS		+= -lwsock32 -lws2_32 -liphlpapi
	LFLAGS		+=
	SH_LFLAGS	+= -shared
	MOD_LFLAGS	+=
	APP_LFLAGS	+= -Wl,--export-all-symbols
	AR		:= ar
	AFLAGS		:= cru
	CROSS_COMPILE	?= $(MACHINE)-
	RANLIB		:= $(CROSS_COMPILE)ranlib
	LIB_SUFFIX	:= .dll
	MOD_SUFFIX	:= .dll
	BIN_SUFFIX	:= .exe
	SYSROOT		:= /usr/$(MACHINE)/
endif

CFLAGS	+= -DOS=\"$(OS)\"

ifeq ($(CC_C11),)
CFLAGS  += -std=c99
else
CFLAGS  += -std=c11
HAVE_ATOMIC := 1
endif

ifneq ($(HAVE_ATOMIC),)
CFLAGS  += -DHAVE_ATOMIC
CFLAGS  += -pedantic
endif


ifeq ($(OS),)
$(warning Could not detect OS)
endif


##############################################################################
#
# Architecture section
#


ifeq ($(ARCH),)
ifeq ($(CC_NAME),$(filter $(CC_NAME),gcc clang))
PREDEF	:= $(shell $(CC) -dM -E -x c $(EXTRA_CFLAGS) $(CFLAGS) /dev/null)

ifneq ($(strip $(filter i386 __i386__ __i386 _M_IX86 __X86__ _X86_, \
	$(PREDEF))),)
ARCH	:= i386
endif

ifneq ($(strip $(filter __i486__,$(PREDEF))),)
ARCH	:= i486
endif

ifneq ($(strip $(filter __i586__,$(PREDEF))),)
ARCH	:= i586
endif

ifneq ($(strip $(filter __i686__ ,$(PREDEF))),)
ARCH	:= i686
endif

ifneq ($(strip $(filter __amd64__ __amd64 __x86_64__ __x86_64, \
	$(PREDEF))),)
ARCH	:= x86_64
endif

ifneq ($(strip $(filter __arm__ __thumb__,$(PREDEF))),)

ifneq ($(strip $(filter __ARM_ARCH_6__,$(PREDEF))),)
ARCH	:= arm6
else
ARCH	:= arm
endif

endif

ifneq ($(strip $(filter __arm64__ __aarch64__,$(PREDEF))),)
ARCH   := arm64
endif

ifneq ($(strip $(filter __mips__ __mips, $(PREDEF))),)
ARCH	:= mips
endif

ifneq ($(strip $(filter __powerpc __powerpc__ __POWERPC__ __ppc__ \
	_ARCH_PPC, $(PREDEF))),)
ARCH	:= ppc
endif

ifneq ($(strip $(filter __ppc64__ _ARCH_PPC64 , $(PREDEF))),)
ARCH	:= ppc64
endif

ifneq ($(strip $(filter __sparc__ __sparc __sparcv8 , $(PREDEF))),)

ifneq ($(strip $(filter __sparcv9 __sparc_v9__ , $(PREDEF))),)
ARCH	:= sparc64
else
ARCH	:= sparc
endif

endif

endif
endif


ifeq ($(ARCH),)
$(warning Could not detect ARCH)
endif


CFLAGS	+= -DARCH=\"$(ARCH)\"

ifeq ($(ARCH),mipsel)
CFLAGS += -march=mips32
endif

BUILD   := build-$(ARCH)

##############################################################################
#
# CC Check Header
#
CC_TEST = [ -d .cache/$(PROJECT)/cc_test-$(ARCH)/$(1) ] && \
	echo "yes" && exit 0 || \
	echo '\#include <$(1)>' | \
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -E - >/dev/null 2>&1 && echo "yes" && \
	mkdir -p .cache/$(PROJECT)/cc_test-$(ARCH)/$(1)

CC_TEST_AND = [ -d .cache/$(PROJECT)/cc_test_and-$(ARCH)/$(1) ] && \
	[ -d .cache/$(PROJECT)/cc_test_and-$(ARCH)/$(2) ] && \
	echo "yes" && exit 0 || \
	echo '\#include <$(1)>' | \
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -E - >/dev/null 2>&1 && \
	mkdir -p .cache/$(PROJECT)/cc_test_and-$(ARCH)/$(1) && \
	echo '\#include <$(2)>' | \
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -E - >/dev/null 2>&1 && echo "yes" && \
	mkdir -p .cache/$(PROJECT)/cc_test_and-$(ARCH)/$(2)

##############################################################################
#
# External libraries section
#
OPENSSL_OPT := $(shell [ -f /usr/local/opt/openssl/include/openssl/ssl.h ] \
	&& echo "/usr/local/opt/openssl")

ifneq ($(OPENSSL_OPT),)
CFLAGS  += -I$(OPENSSL_OPT)/include
LFLAGS  += -L$(OPENSSL_OPT)/lib
endif

USE_OPENSSL := $(shell $(call CC_TEST,openssl/ssl.h))

ifneq ($(USE_OPENSSL),)
CFLAGS  += -DUSE_OPENSSL -DUSE_TLS
LIBS    += -lssl -lcrypto
USE_TLS := yes

USE_OPENSSL_DTLS := $(shell $(call CC_TEST,openssl/dtls1.h))
USE_OPENSSL_SRTP := $(shell $(call CC_TEST,openssl/srtp.h))

ifneq ($(USE_OPENSSL_DTLS),)
CFLAGS  += -DUSE_OPENSSL_DTLS -DUSE_DTLS
USE_DTLS := yes
endif

ifneq ($(USE_OPENSSL_SRTP),)
CFLAGS  += -DUSE_OPENSSL_SRTP -DUSE_DTLS_SRTP
USE_DTLS_SRTP := yes
endif

USE_OPENSSL_AES		:= yes
USE_OPENSSL_HMAC	:= yes

endif

USE_ZLIB := $(shell $(call CC_TEST,zlib.h))

ifneq ($(USE_ZLIB),)
CFLAGS  += -DUSE_ZLIB
LIBS    += -lz
endif

HAVE_THREADS := $(shell $(call CC_TEST,threads.h))
ifneq ($(HAVE_THREADS),)
CFLAGS  += -DHAVE_THREADS
endif

HAVE_PTHREAD := $(shell $(call CC_TEST,pthread.h))
ifneq ($(HAVE_PTHREAD),)
HAVE_PTHREAD_RWLOCK := 1
CFLAGS  += -DHAVE_PTHREAD
HAVE_LIBPTHREAD := 1
ifneq ($(HAVE_LIBPTHREAD),)
LIBS	+= -lpthread
endif
endif

ifneq ($(OS),win32)

ifneq ($(ARCH),mipsel)
HAVE_GETIFADDRS := $(shell $(call CC_TEST,ifaddrs.h))
ifneq ($(HAVE_GETIFADDRS),)
CFLAGS  += -DHAVE_GETIFADDRS
endif
endif

HAVE_STRERROR_R	:= 1
ifneq ($(HAVE_STRERROR_R),)
CFLAGS += -DHAVE_STRERROR_R
endif

endif #!win32

HAVE_GETOPT     := $(shell $(call CC_TEST,getopt.h))
ifneq ($(HAVE_GETOPT),)
CFLAGS  += -DHAVE_GETOPT
endif

HAVE_NET_ROUTE_H := $(shell $(call CC_TEST,net/route.h))
ifneq ($(HAVE_NET_ROUTE_H),)
CFLAGS  += -DHAVE_NET_ROUTE_H
endif

HAVE_SYS_SYSCTL_H := $(shell $(call CC_TEST,sys/sysctl.h))
ifneq ($(HAVE_SYS_SYSCTL_H),)
CFLAGS  += -DHAVE_SYS_SYSCTL_H
endif

HAVE_INET6      := 1
ifneq ($(HAVE_INET6),)
CFLAGS  += -DHAVE_INET6
else
ifeq ($(HAVE_INET6_IGNORE_DEPRECATED),)
$(warning HAVE_INET6= is deprecated, add HAVE_INET6_IGNORE_DEPRECATED=1 to \
	ignore this warning.)
$(error This will be removed in the next release, please report any problems \
	with HAVE_INET6 enabled here: https://github.com/baresip/re/issues)
endif
endif

ifeq ($(OS),win32)
CFLAGS  += -DHAVE_SELECT
CFLAGS  += -DHAVE_IO_H
else
HAVE_SYSLOG  := $(shell $(call CC_TEST,syslog.h))
ifneq ($(HAVE_SYSLOG),)
CFLAGS  += -DHAVE_SYSLOG
endif

HAVE_DLFCN_H := $(shell $(call CC_TEST,dlfcn.h))

ifneq ($(OS),darwin)
HAVE_EPOLL   := $(shell $(call CC_TEST,sys/epoll.h))
endif

HAVE_RESOLV := $(shell $(call CC_TEST,resolv.h))
ifneq ($(HAVE_RESOLV),)
CFLAGS  += -DHAVE_RESOLV
endif

HAVE_EXECINFO := $(shell $(call CC_TEST,execinfo.h))
ifneq ($(HAVE_EXECINFO),)
CFLAGS  += -DHAVE_EXECINFO
ifeq ($(OS),openbsd)
LFLAGS  += -lexecinfo
endif
endif

CFLAGS  += -DHAVE_FORK

CFLAGS  += -DHAVE_PWD_H
ifneq ($(OS),darwin)
CFLAGS  += -DHAVE_POLL	# Darwin: poll() does not support devices
endif
CFLAGS  += -DHAVE_SELECT -DHAVE_SELECT_H
CFLAGS  += -DHAVE_SETRLIMIT
CFLAGS  += -DHAVE_SIGNAL
CFLAGS  += -DHAVE_SYS_TIME_H
ifneq ($(HAVE_EPOLL),)
CFLAGS  += -DHAVE_EPOLL
endif
ifneq ($(HAVE_KQUEUE),)
CFLAGS  += -DHAVE_KQUEUE
endif
CFLAGS  += -DHAVE_UNAME
CFLAGS  += -DHAVE_UNISTD_H
CFLAGS  += -DHAVE_STRINGS_H
endif # win32

ifneq ($(HAVE_ARC4RANDOM),)
CFLAGS  += -DHAVE_ARC4RANDOM
endif


##############################################################################
#
# Misc tools section
#
CCACHE	:= $(shell [ -e /usr/bin/ccache ] 2>/dev/null \
	|| [ -e /opt/local/bin/ccache ] \
	&& echo "ccache")
CFLAGS  += -DVERSION=\"$(VERSION)\"
CFLAGS  += \
	-DVER_MAJOR=$(VER_MAJOR) \
	-DVER_MINOR=$(VER_MINOR) \
	-DVER_PATCH=$(VER_PATCH)

# Enable gcov Coverage testing
#
# - generated during build: .gcno files
# - generated during exec:  .gcda files
#
ifneq ($(GCOV),)
CFLAGS += -fprofile-arcs -ftest-coverage
LFLAGS += -fprofile-arcs -ftest-coverage
# Disable ccache
CCACHE :=
endif

# gprof - GNU Profiling
#
# - generated during exec:  gmon.out
#
ifneq ($(GPROF),)
CFLAGS += -pg
LFLAGS += -pg
# Disable ccache
CCACHE :=
endif

CC	:= $(CCACHE) $(CC)
CFLAGS	+= $(EXTRA_CFLAGS)
LFLAGS	+= $(EXTRA_LFLAGS)


default:	all

.PHONY: distclean
distclean:
	@rm -rf build* *core*
	@rm -f *stamp $(BIN)
	@rm -f `find . -name "*.[oda]"` `find . -name "*.so"`
	@rm -f `find . -name "*~"` `find . -name "\.\#*"`
	@rm -f `find . -name "*.orig"` `find . -name "*.rej"`
	@rm -f `find . -name "*.previous"` `find . -name "*.gcov"`
	@rm -f `find . -name "*.exe"` `find . -name "*.dll"`
	@rm -f `find . -name "*.dylib"`
	@rm -f *.pc
	@rm -rf .cache/$(PROJECT)
	@rm -f compile_commands.json

.PHONY: info
info::
	@echo "info - $(PROJECT) version $(VERSION)"
	@echo "  MODULES:       $(MODULES)"
#	@echo "  SRCS:          $(SRCS)"
	@echo "  MACHINE:       $(MACHINE)"
	@echo "  ARCH:          $(ARCH)"
	@echo "  OS:            $(OS)"
	@echo "  BUILD:         $(BUILD)"
	@echo "  PKG_CONFIG:    $(PKG_CONFIG)"
	@echo "  CCACHE:        $(CCACHE)"
	@echo "  CC:            $(CC_VER)"
	@echo "  CFLAGS:        $(CFLAGS)"
	@echo "  DFLAGS:        $(DFLAGS)"
	@echo "  LFLAGS:        $(LFLAGS)"
	@echo "  SH_LFLAGS:     $(SH_LFLAGS)"
	@echo "  MOD_LFLAGS:    $(MOD_LFLAGS)"
	@echo "  APP_LFLAGS:    $(APP_LFLAGS)"
	@echo "  LIBS:          $(LIBS)"
	@echo "  LIBRE_MK:      $(LIBRE_MK)"
	@echo "  LIBRE_PATH:    $(LIBRE_PATH)"
	@echo "  LIBRE_INC:     $(LIBRE_INC)"
	@echo "  LIBRE_SO:      $(LIBRE_SO)"
	@echo "  OPENSSL_OPT:   $(OPENSSL_OPT)"
	@echo "  USE_OPENSSL:   $(USE_OPENSSL)"
	@echo "  USE_OPENSSL_AES:   $(USE_OPENSSL_AES)"
	@echo "  USE_OPENSSL_HMAC:  $(USE_OPENSSL_HMAC)"
	@echo "  USE_TLS:       $(USE_TLS)"
	@echo "  USE_DTLS:      $(USE_DTLS)"
	@echo "  USE_DTLS_SRTP: $(USE_DTLS_SRTP)"
	@echo "  USE_ZLIB:      $(USE_ZLIB)"
	@echo "  GCOV:          $(GCOV)"
	@echo "  GPROF:         $(GPROF)"
	@echo "  CROSS_COMPILE: $(CROSS_COMPILE)"
	@echo "  SYSROOT:       $(SYSROOT)"
	@echo "  SYSROOT_ALT:   $(SYSROOT_ALT)"
	@echo "  LIB_SUFFIX:    $(LIB_SUFFIX)"
	@echo "  MOD_SUFFIX:    $(MOD_SUFFIX)"
	@echo "  BIN_SUFFIX:    $(BIN_SUFFIX)"


.PHONY: cmake
cmake:
	cmake -B build && cmake --build build --parallel


.PHONY: ninja
ninja:
	cmake -B build -G Ninja && cmake --build build

##############################################################################
#
# Packaging section
#
TAR_SRC   := $(PROJECT)-$(VERSION)

release:
	git archive --format=tar --prefix=$(TAR_SRC)/ v$(VERSION) \
		| gzip > ../$(TAR_SRC).tar.gz


snapshot:
	git archive --format=tar --prefix=$(TAR_SRC)/ HEAD \
		| gzip > ../$(TAR_SRC).tar.gz


# Debian
.PHONY: deb
deb:
	dpkg-buildpackage -rfakeroot --post-clean


# RPM
RPM := $(shell [ -d /usr/src/rpm ] 2>/dev/null && echo "rpm")
ifeq ($(RPM),)
RPM := $(shell [ -d /usr/src/redhat ] 2>/dev/null && echo "redhat")
endif
.PHONY: rpm
rpm:    tar
	sudo cp ../$(PROJECT)-$(VERSION).tar.gz /usr/src/$(RPM)/SOURCES
	sudo rpmbuild -ba rpm/$(PROJECT).spec


##############################################################################
#
# Library and header files location section - in prioritised order
#
# - relative path
# - custom SYSROOT
# - local installation
# - system installation
#

ifndef LIBRE_PATH
LIBRE_PATH := $(shell [ -d ../re ] && echo "../re")
endif

ifeq ($(LIBRE_PATH),)
ifneq ($(SYSROOT),/usr)
LIBRE_PATH := $(shell [ -f $(SYSROOT)/include/re/re.h ] && \
	echo "$(SYSROOT)")
endif
endif

# Include path
ifeq ($(LIBRE_INC),)
LIBRE_INC := $(shell [ -f $(LIBRE_PATH)/include/re.h ] && \
	echo "$(LIBRE_PATH)/include")
endif
ifeq ($(LIBRE_INC),)
LIBRE_INC := $(shell [ -f $(LIBRE_PATH)/include/re/re.h ] && \
	echo "$(LIBRE_PATH)/include/re")
endif
ifeq ($(LIBRE_INC),)
LIBRE_INC := $(shell [ -f /usr/local/include/re/re.h ] && \
	echo "/usr/local/include/re")
endif
ifeq ($(LIBRE_INC),)
LIBRE_INC := $(shell [ -f /usr/include/re/re.h ] && echo "/usr/include/re")
endif

# Library path
ifeq ($(LIBRE_SO),)
LIBRE_SO  := $(shell [ -f $(LIBRE_PATH)/libre.a ] \
	&& echo "$(LIBRE_PATH)")
endif
ifeq ($(LIBRE_SO),)
LIBRE_SO  := $(shell [ -f $(LIBRE_PATH)/libre$(LIB_SUFFIX) ] \
	&& echo "$(LIBRE_PATH)")
endif
ifeq ($(LIBRE_SO),)
LIBRE_SO  := $(shell [ -f $(LIBRE_PATH)/lib/libre$(LIB_SUFFIX) ] \
	&& echo "$(LIBRE_PATH)/lib")
endif
ifeq ($(LIBRE_SO),)
LIBRE_SO  := $(shell [ -f /usr/local/lib/libre$(LIB_SUFFIX) ] \
	&& echo "/usr/local/lib")
endif
ifeq ($(LIBRE_SO),)
LIBRE_SO  := $(shell [ -f /usr/lib/libre$(LIB_SUFFIX) ] && echo "/usr/lib")
endif
ifeq ($(LIBRE_SO),)
LIBRE_SO  := $(shell [ -f /usr/lib64/libre$(LIB_SUFFIX) ] && echo "/usr/lib64")
endif


###############################################################################
#
# Clang section
#

CLANG_OPTIONS := -Iinclude -I$(LIBRE_INC)
CLANG_IGNORE  :=
CLANG_SRCS    += $(filter-out $(CLANG_IGNORE), $(patsubst %,src/%,$(SRCS)))

.PHONY:
clang:
	@clang --analyze $(CLANG_OPTIONS) $(CFLAGS) $(CLANG_SRCS)
	@rm -f *.plist

.PHONY: compile_commands.json
compile_commands.json:
	@rm -f $@
	@find $(BUILD) -name "*.o.json" | grep . > /dev/null
	@sed -e '1s/^/[/' -e '$$s/,$$/]/' \
		$(shell find $(BUILD) -name "*.o.json") > $@

###############################################################################
#
# Documentation section
#
DOX_DIR=../$(PROJECT)-dox
DOX_TAR=$(PROJECT)-dox-$(VERSION)

$(DOX_DIR):
	@mkdir $@

$(DOX_DIR)/Doxyfile: mk/Doxyfile Makefile
	@cp $< $@
	@perl -pi -e 's/PROJECT_NUMBER\s*=.*/PROJECT_NUMBER = $(VERSION)/' \
	$(DOX_DIR)/Doxyfile

.PHONY:
dox:	$(DOX_DIR) $(DOX_DIR)/Doxyfile
	@doxygen $(DOX_DIR)/Doxyfile 2>&1 | grep -v DEBUG_ ; true
	@cd .. && rm -f $(DOX_TAR).tar.gz && \
	tar -zcf $(DOX_TAR).tar.gz $(PROJECT)-dox > /dev/null && \
	echo "Doxygen docs in `pwd`/$(DOX_TAR).tar.gz"
