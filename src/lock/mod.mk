#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

ifdef HAVE_PTHREAD
SRCS	+= lock/lock.c
else ifeq ($(OS),win32)
SRCS	+= lock/win32/lock.c
endif
