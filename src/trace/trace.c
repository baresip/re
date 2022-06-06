/**
 * @file trace.c RE_TRACE helpers
 * JSON traces (chrome://tracing)
 */
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1

#include <re_types.h>
#include <re_mem.h>
#include <re_trace.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_thread.h>
#include <re_sys.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#if defined(WIN32)
#include <windows.h>
#endif

#ifdef LINUX
#include <sys/syscall.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define TRACE_BUFFER_SIZE 1000000

struct trace_event {
	const char *name;
	const char *cat;
	void *id;
	uint64_t ts;
	int pid;
	unsigned long tid;
	char ph;
	re_trace_arg_type arg_type;
	const char *arg_name;
	union {
		const char *a_str;
		int a_int;
	} arg;
};

/** Trace configuration */
static struct {
	int process_id;
	FILE *f;
	int event_count;
	struct trace_event *event_buffer;
	struct trace_event *event_buffer_flush;
	mtx_t lock;
	bool init;
	uint64_t start_time;
} trace = {
	.init = false
};


static inline unsigned long get_thread_id(void)
{
#if defined(WIN32)
	return (unsigned long)GetCurrentThreadId();
#elif defined(LINUX)
	return (unsigned long)syscall(SYS_gettid);
#elif defined(HAVE_PTHREAD)
#if defined(DARWIN) || defined(FREEBSD) || defined(OPENBSD) || \
	defined(NETBSD) || defined(DRAGONFLY)
	return (unsigned long)(void *)pthread_self();
#else
	return (unsigned long)pthread_self();
#endif
#else
	return 0;
#endif
}


static inline int get_process_id(void)
{
#if defined(WIN32)
	return (int)GetCurrentProcessId();
#else
	return (int)getpid();
#endif
}


int re_trace_init(const char *json_file)
{
	int err = 0;

#ifndef RE_TRACE_ENABLED
	return 0;
#endif

	if (!json_file)
		return EINVAL;

	trace.event_buffer = mem_zalloc(
		TRACE_BUFFER_SIZE * sizeof(struct trace_event), NULL);
	if (!trace.event_buffer)
		return ENOMEM;

	trace.event_buffer_flush = mem_zalloc(
		TRACE_BUFFER_SIZE * sizeof(struct trace_event), NULL);
	if (!trace.event_buffer_flush) {
		mem_deref(trace.event_buffer);
		return ENOMEM;
	}

	err = mtx_init(&trace.lock, mtx_plain);
	if (err)
		goto out;

	err = fs_fopen(&trace.f, json_file, "w+");
	if (err)
		goto out;

	(void)re_fprintf(trace.f, "{\t\n\t\"traceEvents\": [\n");
	(void)fflush(trace.f);

	trace.start_time = tmr_jiffies_usec();
	trace.init = true;

out:
	if (err) {
		trace.init = false;
		mem_deref(trace.event_buffer);
		mem_deref(trace.event_buffer_flush);
	}

	return err;
}


int re_trace_close(void)
{
	int err = 0;

#ifndef RE_TRACE_ENABLED
	return 0;
#endif

	re_trace_flush();

	trace.event_buffer = mem_deref(trace.event_buffer);
	trace.event_buffer_flush = mem_deref(trace.event_buffer_flush);
	mtx_destroy(&trace.lock);
	trace.init = false;

	(void)re_fprintf(trace.f, "\n\t]\n}\n");
	if (trace.f)
		err = fclose(trace.f);

	if (err)
		return errno;

	trace.f = NULL;

	return 0;
}


int re_trace_flush(void)
{
	int i, flush_count;
	struct trace_event *event_tmp;
	struct trace_event *e;
	char json_arg[256];
	char name[128];
	static bool first = true;

#ifndef RE_TRACE_ENABLED
	return 0;
#endif

	if (!trace.init)
		return 0;

	mtx_lock(&trace.lock);
	event_tmp = trace.event_buffer_flush;
	trace.event_buffer_flush = trace.event_buffer;
	trace.event_buffer = event_tmp;

	flush_count = trace.event_count;
	trace.event_count = 0;
	mtx_unlock(&trace.lock);

	for (i = 0; i < flush_count; i++)
	{
		e = &trace.event_buffer_flush[i];

		switch (e->arg_type) {
		case RE_TRACE_ARG_NONE:
			json_arg[0] = '\0';
			break;
		case RE_TRACE_ARG_INT:
			(void)re_snprintf(json_arg, sizeof(json_arg),
					", \"args\":{\"%s\":%i}",
					e->arg_name, e->arg.a_int);
			break;
		case RE_TRACE_ARG_STRING_CONST:
			(void)re_snprintf(json_arg, sizeof(json_arg),
					", \"args\":{\"%s\":\"%s\"}",
					e->arg_name, e->arg.a_str);
			break;
		case RE_TRACE_ARG_STRING_COPY:
			(void)re_snprintf(json_arg, sizeof(json_arg),
					", \"args\":{\"%s\":\"%s\"}",
					e->arg_name, e->arg.a_str);

			mem_deref((void *)e->arg.a_str);
			break;
		}

		re_snprintf(name, sizeof(name), "\"name\":\"%s\"", e->name);

		(void)re_fprintf(trace.f,
			"%s{\"cat\":\"%s\",\"pid\":%i,\"tid\":%lu,\"ts\":%llu,"
			"\"ph\":\"%c\",%s%s}",
			first ? "" : ",\n",
			e->cat, e->pid, e->tid, e->ts - trace.start_time,
			e->ph, name, str_isset(json_arg) ? json_arg : "");
		first = false;
	}

	(void)fflush(trace.f);
	return 0;
}


void re_trace_event(const char *cat, const char *name, char ph, void *id,
                    int32_t custom_id, re_trace_arg_type arg_type,
                    const char *arg_name, void *arg_value)
{
	struct trace_event *e;

#ifndef RE_TRACE_ENABLED
	return;
#endif

	if (!trace.init)
		return;

	mtx_lock(&trace.lock);
	if (trace.event_count >= TRACE_BUFFER_SIZE) {
		mtx_unlock(&trace.lock);
		return;
	}
	e = &trace.event_buffer[trace.event_count];
	++trace.event_count;
	mtx_unlock(&trace.lock);

	e->ts = tmr_jiffies_usec();
	e->id = id;
	e->ph = ph;
	e->cat = cat;
	e->name = name;
	e->pid = get_process_id();
	if (custom_id) {
		e->tid = custom_id;
	}
	else {
		e->tid = get_thread_id();
	}
	e->arg_type = arg_type;
	e->arg_name = arg_name;

	switch (arg_type) {
	case RE_TRACE_ARG_NONE:
		break;
	case RE_TRACE_ARG_INT:
		e->arg.a_int = (int)(intptr_t)arg_value;
		break;
	case RE_TRACE_ARG_STRING_CONST:
		e->arg.a_str = (const char *)arg_value;
		break;
	case RE_TRACE_ARG_STRING_COPY:
		str_dup((char **)&e->arg.a_str,
			(const char *)arg_value);
		break;
	}
}
