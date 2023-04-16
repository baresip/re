/**
 * @file init.c  Main initialisation routine
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#if defined(HAVE_SIGNAL) && defined(SIGNAL_BTRACE)
#include <signal.h>
#endif
#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_net.h>
#include <re_sys.h>
#include <re_main.h>
#include <re_btrace.h>
#include "main.h"


#if defined(HAVE_SIGNAL) && defined(SIGNAL_BTRACE)
static void signal_handler(int sig)
{
	struct btrace bt;

	btrace(&bt);
	re_fprintf(stderr, "Error: Signal (%d) %H\n", sig, btrace_println,
		   &bt);
	fflush(stderr);

	exit(128 + sig);
}
#endif


#if defined(WIN32) && defined(SIGNAL_BTRACE)
LONG WINAPI exception_handler(EXCEPTION_POINTERS *ExceptionInfo)
{
	struct btrace bt;

	if (EXCEPTION_STACK_OVERFLOW !=
	    ExceptionInfo->ExceptionRecord->ExceptionCode) {
		btrace(&bt);
		re_fprintf(stderr, "%H\n", btrace_println, &bt);
	}
	else {
		re_fprintf(stderr, "stack overflow: %p\n",
			  (void *)ExceptionInfo->ContextRecord->Rip);
	}

	switch (ExceptionInfo->ExceptionRecord->ExceptionCode) {
	case EXCEPTION_ACCESS_VIOLATION:
		re_fprintf(stderr, "Error: EXCEPTION_ACCESS_VIOLATION\n");
		break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		re_fprintf(stderr, "Error: EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
		break;
	case EXCEPTION_BREAKPOINT:
		re_fprintf(stderr, "Error: EXCEPTION_BREAKPOINT\n");
		break;
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		re_fprintf(stderr, "Error: EXCEPTION_DATATYPE_MISALIGNMENT\n");
		break;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		re_fprintf(stderr, "Error: EXCEPTION_FLT_DENORMAL_OPERAND\n");
		break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		re_fprintf(stderr, "Error: EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
		break;
	case EXCEPTION_FLT_INEXACT_RESULT:
		re_fprintf(stderr, "Error: EXCEPTION_FLT_INEXACT_RESULT\n");
		break;
	case EXCEPTION_FLT_INVALID_OPERATION:
		re_fprintf(stderr, "Error: EXCEPTION_FLT_INVALID_OPERATION\n");
		break;
	case EXCEPTION_FLT_OVERFLOW:
		re_fprintf(stderr, "Error: EXCEPTION_FLT_OVERFLOW\n");
		break;
	case EXCEPTION_FLT_STACK_CHECK:
		re_fprintf(stderr, "Error: EXCEPTION_FLT_STACK_CHECK\n");
		break;
	case EXCEPTION_FLT_UNDERFLOW:
		re_fprintf(stderr, "Error: EXCEPTION_FLT_UNDERFLOW\n");
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		re_fprintf(stderr, "Error: EXCEPTION_ILLEGAL_INSTRUCTION\n");
		break;
	case EXCEPTION_IN_PAGE_ERROR:
		re_fprintf(stderr, "Error: EXCEPTION_IN_PAGE_ERROR\n");
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		re_fprintf(stderr, "Error: EXCEPTION_INT_DIVIDE_BY_ZERO\n");
		break;
	case EXCEPTION_INT_OVERFLOW:
		re_fprintf(stderr, "Error: EXCEPTION_INT_OVERFLOW\n");
		break;
	case EXCEPTION_INVALID_DISPOSITION:
		re_fprintf(stderr, "Error: EXCEPTION_INVALID_DISPOSITION\n");
		break;
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		re_fprintf(stderr,
			   "Error: EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
		break;
	case EXCEPTION_PRIV_INSTRUCTION:
		re_fprintf(stderr, "Error: EXCEPTION_PRIV_INSTRUCTION\n");
		break;
	case EXCEPTION_SINGLE_STEP:
		re_fprintf(stderr, "Error: EXCEPTION_SINGLE_STEP\n");
		break;
	case EXCEPTION_STACK_OVERFLOW:
		re_fprintf(stderr, "Error: EXCEPTION_STACK_OVERFLOW\n");
		break;
	default:
		re_fprintf(stderr, "Error: Unrecognized Exception\n");
		break;
	}

	fflush(stderr);

	return EXCEPTION_EXECUTE_HANDLER;
}
#endif


/**
 * Initialise main library
 *
 * @return 0 if success, errorcode if failure
 */
int libre_init(void)
{
	int err;

#if defined(HAVE_SIGNAL) && defined(SIGNAL_BTRACE)
	(void)signal(SIGSEGV, signal_handler);
	(void)signal(SIGABRT, signal_handler);
	(void)signal(SIGILL, signal_handler);
#endif

#if defined(WIN32) && defined(SIGNAL_BTRACE)
	SetUnhandledExceptionFilter(exception_handler);
#endif

#ifdef USE_OPENSSL
	err = openssl_init();
	if (err)
		return err;
#endif

	err = net_sock_init();
	if (err) {
		net_sock_close();
		return err;
	}

	err = re_thread_init();

	return err;
}


/**
 * Close library and free up all resources
 */
void libre_close(void)
{
	(void)fd_setsize(0);
	net_sock_close();
	re_thread_close();
}
