/**
 * @file re_types.h  Defines basic types
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
#define restrict
#endif

#ifdef _MSC_VER
#include <stdlib.h>

#include <BaseTsd.h>
typedef SSIZE_T ssize_t;

#endif

/*
 * Basic integral types and boolean from C99
 */
#include <inttypes.h>
#include <stdbool.h>


/* Needed for MS compiler */
#ifdef _MSC_VER
#ifndef __cplusplus
#define inline _inline
#endif
#endif


/*
 * Misc macros
 */

/** Defines the NULL pointer */
#ifndef NULL
#define NULL ((void *)0)
#endif

/** Get number of elements in an array */
#define RE_ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))

/* Backwards compat */
#define ARRAY_SIZE RE_ARRAY_SIZE


/** Align a value to the boundary of mask */
#define RE_ALIGN_MASK(x, mask)    (((x)+(mask))&~(mask))

/** Check alignment of pointer (p) and byte count (c) **/
#define re_is_aligned(p, c) (((uintptr_t)(const void *)(p)) % (c) == 0)
#define is_aligned re_is_aligned

/** Get the minimal value */
#undef MIN
#define MIN(a,b) (((a)<(b)) ? (a) : (b))

/** Get the maximal value */
#undef MAX
#define MAX(a,b) (((a)>(b)) ? (a) : (b))

#ifndef __cplusplus

/** Get the minimal value */
#undef min
#define min(x,y) MIN(x, y)

/** Get the maximal value */
#undef max
#define max(x,y) MAX(x, y)

#endif

/** Defines a soft breakpoint */
#if (defined(__i386__) || defined(__x86_64__))
#define RE_BREAKPOINT __asm__("int $0x03")
#else
#define RE_BREAKPOINT
#endif

/* Backwards compat */
#define BREAKPOINT RE_BREAKPOINT


/* Error return/goto debug helpers */
#ifdef TRACE_ERR
#define PRINT_TRACE_ERR(err)						\
		(void)re_fprintf(stderr, "TRACE_ERR: %s:%u: %s():"	\
			      " %m (%d)\n",				\
			      __FILE__, __LINE__, __func__,		\
			      (err), (err));
#else
#define PRINT_TRACE_ERR(err)
#endif

#define IF_ERR_GOTO_OUT(err)		\
	if ((err)) {			\
		PRINT_TRACE_ERR((err))	\
		goto out;		\
	}

#define IF_ERR_GOTO_OUT1(err)		\
	if ((err)) {			\
		PRINT_TRACE_ERR((err))	\
		goto out1;		\
	}

#define IF_ERR_GOTO_OUT2(err)		\
	if ((err)) {			\
		PRINT_TRACE_ERR((err))	\
		goto out2;		\
	}

#define IF_ERR_RETURN(err)		\
	if ((err)) {			\
		PRINT_TRACE_ERR((err))	\
		return (err);		\
	}

#define IF_RETURN_EINVAL(exp)		\
	if ((exp)) {			\
		PRINT_TRACE_ERR(EINVAL)	\
		return (EINVAL);	\
	}

#define RETURN_ERR(err)			\
	if ((err)) {			\
		PRINT_TRACE_ERR((err))	\
	}				\
	return (err);


/* Error codes */
#include <errno.h>

/* Duplication of error codes. Values are from linux asm-generic/errno.h */

/** No data available */
#ifndef ENODATA
#define ENODATA 200
#endif

/** Protocol error */
#ifndef EPROTO
#define EPROTO 201
#endif

/** Not a data message */
#ifndef EBADMSG
#define EBADMSG 202
#endif

/** Value too large for defined data type */
#ifndef EOVERFLOW
#define EOVERFLOW 203
#endif

/** Accessing a corrupted shared library */
#ifndef ELIBBAD
#define ELIBBAD 204
#endif

/** Destination address required */
#ifndef EDESTADDRREQ
#define EDESTADDRREQ 205
#endif

/** Protocol not supported */
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 206
#endif

/** Operation not supported */
#ifndef ENOTSUP
#define ENOTSUP 207
#endif

/** Address family not supported by protocol */
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 208
#endif

/** Cannot assign requested address */
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 209
#endif

/** Software caused connection abort */
#ifndef ECONNABORTED
#define ECONNABORTED 210
#endif

/** Connection reset by peer */
#ifndef ECONNRESET
#define ECONNRESET 211
#endif

/** Transport endpoint is not connected */
#ifndef ENOTCONN
#define ENOTCONN 212
#endif

/** Connection timed out */
#ifndef ETIMEDOUT
#define ETIMEDOUT 213
#endif

/** Connection refused */
#ifndef ECONNREFUSED
#define ECONNREFUSED 214
#endif

/** Operation already in progress */
#ifndef EALREADY
#define EALREADY 215
#endif

/** Operation now in progress */
#ifndef EINPROGRESS
#define EINPROGRESS 216
#endif

/** Authentication error */
#ifndef EAUTH
#define EAUTH 217
#endif

/** No STREAM resources */
#ifndef ENOSR
#define ENOSR 218
#endif

/** Key was rejected by service */
#ifndef EKEYREJECTED
#define EKEYREJECTED 129
#endif


/*
 * Give the compiler a hint which branch is "likely" or "unlikely" (inspired
 * by linux kernel and C++20/C2X)
 */
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x) x
#define unlikely(x) x
#endif

#ifdef WIN32
#define re_restrict __restrict
#else
#define re_restrict restrict
#endif

/* Socket helpers */
#ifdef WIN32
#define RE_ERRNO_SOCK WSAGetLastError()
#define RE_BAD_SOCK INVALID_SOCKET
typedef size_t re_sock_t;
#else
#define RE_ERRNO_SOCK errno
#define RE_BAD_SOCK -1
typedef int re_sock_t;
#endif
