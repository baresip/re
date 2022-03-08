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

#ifdef HAVE_ATOMIC
#include <stdatomic.h>

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
#endif

#ifdef __cplusplus
}
#endif

#endif /* RE_H_ATOMIC__ */
