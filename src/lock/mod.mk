#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

ifeq ($(OS),win32)
SRCS	+= lock/win32/lock.c
else
SRCS	+= lock/lock.c
endif
