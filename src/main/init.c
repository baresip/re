/**
 * @file init.c  Main initialisation routine
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#ifdef HAVE_SIGNAL
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
#include <re_trace.h>
#include <re_btrace.h>
#include "main.h"


static bool exception_btrace = false;


#ifdef HAVE_SIGNAL
static void signal_handler(int sig)
{
	struct btrace bt;

	(void)signal(sig, NULL);

	if (!exception_btrace)
		return;

	btrace(&bt);
	re_fprintf(stderr, "Error: Signal (%d) %H\n", sig, btrace_println,
		   &bt);
	fflush(stderr);
}
#endif


#ifdef WIN32
static LONG WINAPI exception_handler(EXCEPTION_POINTERS *ExceptionInfo)
{
	struct btrace bt;

	if (!exception_btrace)
		return EXCEPTION_CONTINUE_SEARCH;

	if (EXCEPTION_STACK_OVERFLOW !=
	    ExceptionInfo->ExceptionRecord->ExceptionCode) {
		btrace(&bt);
		re_fprintf(stderr, "%H\n", btrace_println, &bt);
	}
	else {
		re_fprintf(stderr, "stack overflow\n");
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

	if (exception_btrace) {
#ifdef HAVE_SIGNAL
		(void)signal(SIGSEGV, signal_handler);
		(void)signal(SIGABRT, signal_handler);
		(void)signal(SIGILL, signal_handler);
#endif
#ifdef WIN32
		SetUnhandledExceptionFilter(exception_handler);
#endif
	}

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


/**
 * Enable/Disable exception signal handling (SIGSEGV, SIGABRT, SIGILL...)
 *
 * @param enable True to enable, false to disable
 */
void libre_exception_btrace(bool enable)
{
	exception_btrace = enable;
}
