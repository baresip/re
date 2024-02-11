/**
 * @file trace.c  Trace testcode
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <re.h>
#include "test.h"

#define DEBUG_MODULE "test_trace"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

static void test_loop(int count)
{
	int i;

	for (i=0; i < count; i++) {
		RE_TRACE_INSTANT_I("test", "Instant", i);
	}
}

int test_trace(void)
{
	int err;

	if (test_mode == TEST_THREAD)
		return ESKIPPED;

	err = re_trace_init("test_trace.json");
	TEST_ERR(err);

	RE_TRACE_PROCESS_NAME("retest");
	RE_TRACE_THREAD_NAME("test_trace");
	RE_TRACE_BEGIN("test", "Test Loop Start");

	test_loop(100);

	RE_TRACE_BEGIN("test", "Flush");
	err = re_trace_flush();
	TEST_ERR(err);

	RE_TRACE_END("test", "Flush");

	test_loop(25);

	RE_TRACE_BEGIN_FUNC();

	err = re_trace_flush();
	TEST_ERR(err);

	RE_TRACE_END_FUNC();

	RE_TRACE_END("test", "Test Loop End");

	err = re_trace_close();
	TEST_ERR(err);

	/* Test TRACE after close - should do nothing */
	RE_TRACE_BEGIN("test", "test after close");

#ifdef WIN32
	(void)_unlink("test_trace.json");
#else
	(void)unlink("test_trace.json");
#endif

out:
	if (err)
		re_trace_close();
	return err;
}
