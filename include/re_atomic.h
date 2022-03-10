/**
 * @file re_atomic.h  Atomic support
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#ifndef RE_H_ATOMIC__
#define RE_H_ATOMIC__

#ifdef __cplusplus
extern "C" {
#endif

/* C11 */
#if defined(HAVE_ATOMIC) && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>

/* With MSVC volatile is atomic */
#elif defined(_MSC_VER)
#define _Atomic volatile

/* C99 compiler builtin fallbacks */
#elif defined(__clang__)
#define __CLANG_ATOMICS

#elif defined(__GNUC__)
#if __GNUC_PREREQ(4, 9)
#define __SYNC_ATOMICS
#else
#error "Atomic requires gcc >= 4.9"
#endif /* __GNUC_PREREQ */

#else
#error "Your compiler does not support atomics"
#endif /* HAVE_ATOMIC */

#ifdef __cplusplus
}
#endif

#endif /* RE_H_ATOMIC__ */
