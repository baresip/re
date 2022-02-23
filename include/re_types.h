/**
 * @file re_types.h  Defines basic types
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <sys/types.h>

#ifdef _MSC_VER
#include <stdlib.h>

#include <BaseTsd.h>
typedef SSIZE_T ssize_t;

#endif

/*
 * Basic integral types from C99
 */

#include <inttypes.h>


/*
 * Boolean type
 * see http://www.opengroup.org/onlinepubs/000095399/basedefs/stdbool.h.html
 *     www.gnu.org/software/autoconf/manual/html_node/Particular-Headers.html
 */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# ifndef HAVE__BOOL
#  ifdef __cplusplus
typedef bool _Bool;
#  else
#   define _Bool signed char
#  endif
# endif
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif

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
#undef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))

/** Align a value to the boundary of mask */
#define ALIGN_MASK(x, mask)    (((x)+(mask))&~(mask))


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
#define BREAKPOINT __asm__("int $0x03")
#else
#define BREAKPOINT
#endif

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
 * Any C compiler conforming to C99 or later MUST support __func__
 */
#if __STDC_VERSION__ >= 199901L
#define __REFUNC__ (const char *)__func__
#else
#define __REFUNC__ __FUNCTION__
#endif

/*
 * Give the compiler a hint which branch is "likely" or "unlikely" (inspired
 * by linux kernel and C++20/C2X)
 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
