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
#error "Compiler does not support atomics"
#endif /* HAVE_ATOMIC */

#ifdef _MSC_VER
/* With MSVC volatile is atomic */
#define RE_ATOMIC volatile
#else
#define RE_ATOMIC _Atomic
#endif

#ifdef __cplusplus
}
#endif

#endif /* RE_H_ATOMIC__ */
