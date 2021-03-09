/**
 * @file re_trace.h RE_TRACE helpers
 * JSON traces (chrome://tracing)
 */

typedef enum {
	RE_TRACE_ARG_NONE,
	RE_TRACE_ARG_INT,
	RE_TRACE_ARG_STRING_CONST,
	RE_TRACE_ARG_STRING_COPY,
} re_trace_arg_type;


int re_trace_init(const char *json_file);
int re_trace_close(void);
int re_trace_flush(void);
void re_trace_event(const char *cat, const char *name, char ph, void *id,
		   re_trace_arg_type arg_type, const char *arg_name,
		   void *arg_value);

#if !defined(RELEASE) && !defined(RE_TRACE_ENABLED)
#define RE_TRACE_ENABLED 1
#endif

#ifdef RE_TRACE_ENABLED

#define RE_TRACE_BEGIN(c, n) \
	re_trace_event(c, n, 'B', 0, RE_TRACE_ARG_NONE, NULL, NULL)
#define RE_TRACE_END(c, n) \
	re_trace_event(c, n, 'E', 0, RE_TRACE_ARG_NONE, NULL, NULL)
#define RE_TRACE_INSTANT(c, n) \
	re_trace_event(c, n, 'I', 0, RE_TRACE_ARG_NONE, NULL, NULL)
#define RE_TRACE_INSTANT_C(c, n, vname, str) \
	re_trace_event(c, n, 'I', 0, RE_TRACE_ARG_STRING_CONST, \
	vname, (void *)(str))
#define RE_TRACE_INSTANT_I(c, n, i) \
	re_trace_event(c, n, 'I', 0, RE_TRACE_ARG_INT, \
	n, (void *)(intptr_t)i)
#define RE_TRACE_PROCESS_NAME(n) \
	re_trace_event("", "process_name", 'M', 0, RE_TRACE_ARG_STRING_COPY, \
	"name", (void *)(n))
#define RE_TRACE_THREAD_NAME(n) \
	re_trace_event("", "thread_name", 'M', 0, RE_TRACE_ARG_STRING_COPY, \
	"name", (void *)(n))

#else

#define RE_TRACE_BEGIN(c, n)
#define RE_TRACE_END(c, n)
#define RE_TRACE_INSTANT(c, n)
#define RE_TRACE_INSTANT_C(c, n, str)
#define RE_TRACE_INSTANT_I(c, n, i)
#define RE_TRACE_META_PROCESS_NAME(n)
#define RE_TRACE_THREAD_NAME(n)

#endif

#define RE_TRACE_BEGIN_FUNC() RE_TRACE_BEGIN(__FILE__, __func__)
#define RE_TRACE_END_FUNC() RE_TRACE_END(__FILE__, __func__)
