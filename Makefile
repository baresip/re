#
# Makefile
#
# Copyright (C) 2010 Creytiv.com
#

# Main version number
VER_MAJOR := 2
VER_MINOR := 2
VER_PATCH := 2

# Development version, comment out on a release
# Increment for breaking changes (dev2, dev3...)
# VER_PRE   := dev

# bump Major if ABI breaks
ABI_MAJOR := 4
ABI_AGE   := $(VER_MINOR)
ABI_REV   := $(VER_PATCH)

# Verbose and silent build modes
ifeq ($(V),)
HIDE=@
endif

PROJECT   := re
ifeq ($(VER_PRE),)
VERSION   := $(VER_MAJOR).$(VER_MINOR).$(VER_PATCH)
else
VERSION   := $(VER_MAJOR).$(VER_MINOR).$(VER_PATCH)-$(VER_PRE)
endif

MK	:= mk/re.mk

include $(MK)

# List of modules
MODULES += sip sipevent sipreg sipsess
MODULES += uri http httpauth msg websock
MODULES += stun turn ice
MODULES += rtp sdp jbuf telev
MODULES += dns
MODULES += md5 crc32 sha hmac base64
MODULES += udp sa net tcp tls
MODULES += list mbuf hash
MODULES += fmt tmr trace btrace main mem dbg sys lock mqueue
MODULES += mod conf
MODULES += bfcp
MODULES += aes srtp
MODULES += odict
MODULES += json
MODULES += rtmp
MODULES += shim
MODULES += trice
MODULES += pcp

INSTALL := install
ifeq ($(DESTDIR),)
PREFIX  ?= /usr/local
else
PREFIX  ?= /usr
endif
ifeq ($(LIBDIR),)
LIBDIR  := $(PREFIX)/lib
endif
INCDIR  := $(PREFIX)/include/re
MKDIR   := $(PREFIX)/share/re
CFLAGS	+= -Iinclude

MODMKS         := $(patsubst %,src/%/mod.mk,$(MODULES))
SHARED         := libre$(LIB_SUFFIX)
SHARED_SONAME  := $(SHARED).$(ABI_MAJOR)
SHARED_FILE    := $(SHARED).$(ABI_MAJOR).$(ABI_AGE).$(ABI_REV)
STATIC         := libre.a

ifeq ($(OS),linux)
SH_LFLAGS      += -Wl,-soname,$(SHARED_SONAME)
endif

include $(MODMKS)


OBJS	?= $(patsubst %.c,$(BUILD)/%.o,$(SRCS))


all: $(SHARED) $(STATIC)


-include $(OBJS:.o=.d)


$(SHARED): $(OBJS) libre.pc
	@echo "  LD      $@"
	$(HIDE)$(LD) $(LFLAGS) $(SH_LFLAGS) $(OBJS) $(LIBS) -o $@


$(STATIC): $(OBJS) libre.pc
	@echo "  AR      $@"
	$(HIDE)$(AR) $(AFLAGS) $@ $(OBJS)
ifneq ($(RANLIB),)
	$(HIDE)$(RANLIB) $@
endif

libre.pc: Makefile
	@echo 'prefix='$(PREFIX) > libre.pc
	@echo 'exec_prefix=$${prefix}' >> libre.pc
	@echo 'libdir=$(LIBDIR)' >> libre.pc
	@echo 'includedir=$${prefix}/include/re' >> libre.pc
	@echo '' >> libre.pc
	@echo 'Name: libre' >> libre.pc
	@echo 'Description: Generic library for real-time' \
	      'communications with async IO support' >> libre.pc
	@echo 'Version: '$(VERSION) >> libre.pc
	@echo 'URL: https://github.com/baresip/re' >> libre.pc
	@echo 'Libs: -L$${libdir} -lre' >> libre.pc
	@echo 'Libs.private: -L$${libdir} -lre ${LIBS}' >> libre.pc
	@echo 'Cflags: -I$${includedir}' >> libre.pc

$(BUILD)/%.o: src/%.c $(BUILD) Makefile $(MK) $(MODMKS)
	@echo "  CC      $@"
	$(HIDE)$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)


$(BUILD): Makefile $(MK) $(MODMKS)
	$(HIDE)mkdir -p $(patsubst %,$(BUILD)/%,$(sort $(dir $(SRCS))))
	$(HIDE)touch $@


.PHONY: clean
clean:
	$(HIDE)rm -rf $(SHARED) $(STATIC) libre.pc test.d test.o test \
		build $(BUILD) .cache/re
	$(HIDE)rm -f compile_commands.json


install: $(SHARED) $(STATIC) libre.pc
	$(HIDE)mkdir -p $(DESTDIR)$(LIBDIR) $(DESTDIR)$(LIBDIR)/pkgconfig \
		$(DESTDIR)$(INCDIR) $(DESTDIR)$(MKDIR)
	$(INSTALL) -m 0644 $(shell find include -name "*.h") \
		$(DESTDIR)$(INCDIR)
ifeq ($(OS),linux)
	$(INSTALL) -m 0755 $(SHARED) $(DESTDIR)$(LIBDIR)/$(SHARED_FILE)
	cd $(DESTDIR)$(LIBDIR) && ln -sf $(SHARED_FILE) $(SHARED) && \
		ln -sf $(SHARED_FILE) $(SHARED_SONAME)
else
	$(INSTALL) -m 0755 $(SHARED) $(DESTDIR)$(LIBDIR)
endif
	$(INSTALL) -m 0755 $(STATIC) $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 0644 libre.pc $(DESTDIR)$(LIBDIR)/pkgconfig
	$(INSTALL) -m 0644 $(MK) $(DESTDIR)$(MKDIR)

uninstall:
	$(HIDE)rm -rf $(DESTDIR)$(INCDIR)
	$(HIDE)rm -rf $(DESTDIR)$(MKDIR)
	$(HIDE)rm -f $(DESTDIR)$(LIBDIR)/$(SHARED)
	$(HIDE)rm -f $(DESTDIR)$(LIBDIR)/$(SHARED_SONAME)
	$(HIDE)rm -f $(DESTDIR)$(LIBDIR)/$(STATIC)
	$(HIDE)rm -f $(DESTDIR)$(LIBDIR)/pkgconfig/libre.pc

-include test.d

test.o:	test.c Makefile $(MK)
	@echo "  CC      $@"
	$(HIDE)$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)

test$(BIN_SUFFIX): test.o $(SHARED) $(STATIC)
	@echo "  LD      $@"
	$(HIDE)$(LD) $(LFLAGS) $< -L. -lre $(LIBS) -o $@

sym:	$(SHARED)
	$(HIDE)nm $(SHARED) | grep " U " | perl -pe 's/\s*U\s+(.*)/$${1}/' \
		> docs/symbols.txt
	$(HIDE)echo \
		"$(SHARED) is using `cat docs/symbols.txt | wc -l ` symbols"
