PROJECT := mktest
EXTRA_CFLAGS := -I../include

include re.mk

# Cleanup
$(shell rm -rf .cache/mktest)

##############################################################################
#
# CC_TEST & CC_TEST_AND
#
CC_TEST_CACHE := .cache/mktest/cc_test-$(ARCH)/
CC_TEST_AND_CACHE := .cache/mktest/cc_test_and-$(ARCH)/

ifeq ($(shell $(call CC_TEST,errno.h)),)
$(error CC_TEST failed, errno.h not found)
else
ifneq ($(shell [ -d $(CC_TEST_CACHE)/errno.h ] || echo fail),)
$(error CC_TEST errno.h cache failed)
endif
endif

ifneq ($(shell $(call CC_TEST,fake.h)),)
$(error CC_TEST failed, fake.h found)
endif

$(shell mkdir -p $(CC_TEST_CACHE)/fake.h)
ifeq ($(shell $(call CC_TEST,fake.h)),)
$(error CC_TEST cache failed, fake.h not found)
endif

ifeq ($(shell $(call CC_TEST_AND,errno.h,re.h)),)
$(error CC_TEST_AND failed)
else
ifneq ($(shell [ -d $(CC_TEST_AND_CACHE)/errno.h ] || echo fail),)
$(error CC_TEST_AND errno.h cache failed)
endif
ifneq ($(shell [ -d $(CC_TEST_AND_CACHE)/re.h ] || echo fail),)
$(error CC_TEST_AND re.h cache failed)
endif
endif

ifneq ($(shell $(call CC_TEST_AND,errno.h,fake.h)),)
$(error CC_TEST_AND failed, fake.h found)
endif

ifneq ($(shell $(call CC_TEST_AND,fake.h,errno.h)),)
$(error CC_TEST_AND failed, fake.h found)
endif

ifneq ($(shell $(call CC_TEST_AND,fake.h,fake.h)),)
$(error CC_TEST_AND failed, fake.h found)
endif

$(shell mkdir -p $(CC_TEST_AND_CACHE)/fake.h)
ifeq ($(shell $(call CC_TEST_AND,fake.h,re.h)),)
$(error CC_TEST_AND cache failed, fake.h not found)
endif

ifeq ($(shell $(call CC_TEST_AND,re.h,fake.h)),)
$(error CC_TEST_AND cache failed, fake.h not found)
endif

##############################################################################

all:
	@echo "all makefile tests successful"
