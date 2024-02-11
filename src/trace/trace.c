/**
 * @file trace.c RE_TRACE helpers
 * JSON traces (chrome://tracing)
 */
#include <re_types.h>
#include <re_mem.h>
#include <re_trace.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_thread.h>
#include <re_atomic.h>
#include <re_sys.h>
#include <re_main.h>

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

#define DEBUG_MODULE "trace"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

#ifndef TRACE_BUFFER_SIZE
#define TRACE_BUFFER_SIZE 100000
#endif

#ifndef TRACE_FLUSH_THRESHOLD
#define TRACE_FLUSH_THRESHOLD 1000
#endif

#ifndef TRACE_FLUSH_TMR
#define TRACE_FLUSH_TMR 1000
#endif


#ifdef RE_TRACE_ENABLED

struct trace_event {
	const char *name;
	const char *cat;
	struct pl *id;
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
	RE_ATOMIC bool init;
	int process_id;
	FILE *f;
	int event_count;
	struct trace_event *event_buffer;
	struct trace_event *event_buffer_flush;
	mtx_t lock;
	bool new;
	uint64_t start_time;
	struct tmr flush_tmr;
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


static int flush_worker(void *arg)
{
	(void)arg;

	mtx_lock(&trace.lock);
	if (trace.event_count < TRACE_FLUSH_THRESHOLD) {
		mtx_unlock(&trace.lock);
		return 0;
	}
	mtx_unlock(&trace.lock);

	re_trace_flush();

	return 0;
}


static void flush_tmr(void *arg)
{
	(void)arg;

	re_thread_async(flush_worker, NULL, NULL);

	tmr_start(&trace.flush_tmr, TRACE_FLUSH_TMR, flush_tmr, NULL);
}
#endif


/**
 * Init new trace json file
 *
 * @param json_file  json file for trace events
 *
 * @return 0 if success, otherwise errorcode
 */
int re_trace_init(const char *json_file)
{
#ifdef RE_TRACE_ENABLED
	int err = 0;

	if (!json_file)
		return EINVAL;

	if (re_atomic_rlx(&trace.init))
		return EALREADY;

	trace.event_buffer = mem_zalloc(
		TRACE_BUFFER_SIZE * sizeof(struct trace_event), NULL);
	if (!trace.event_buffer)
		return ENOMEM;

	trace.event_buffer_flush = mem_zalloc(
		TRACE_BUFFER_SIZE * sizeof(struct trace_event), NULL);
	if (!trace.event_buffer_flush) {
		trace.event_buffer = mem_deref(trace.event_buffer);
		return ENOMEM;
	}

	err = mtx_init(&trace.lock, mtx_plain) != thrd_success;
	if (err) {
		err = ENOMEM;
		goto out;
	}

	err = fs_fopen(&trace.f, json_file, "w+");
	if (err)
		goto out;

	(void)re_fprintf(trace.f, "{\t\n\t\"traceEvents\": [\n");
	(void)fflush(trace.f);

	trace.start_time = tmr_jiffies_usec();
	re_atomic_rlx_set(&trace.init, true);
	trace.new = true;

	tmr_init(&trace.flush_tmr);
	tmr_start(&trace.flush_tmr, TRACE_FLUSH_TMR, flush_tmr, NULL);

out:
	if (err) {
		re_atomic_rlx_set(&trace.init, false);
		trace.event_buffer	 = mem_deref(trace.event_buffer);
		trace.event_buffer_flush = mem_deref(trace.event_buffer_flush);
	}

	return err;
#else
	(void)json_file;
	return 0;
#endif
}


/**
 * Close and flush trace file
 *
 * @return 0 if success, otherwise errorcode
 */
int re_trace_close(void)
{
#ifdef RE_TRACE_ENABLED
	int err = 0;

	tmr_cancel(&trace.flush_tmr);
	re_trace_flush();
	re_atomic_rlx_set(&trace.init, false);

	trace.event_buffer = mem_deref(trace.event_buffer);
	trace.event_buffer_flush = mem_deref(trace.event_buffer_flush);
	mtx_destroy(&trace.lock);

	(void)re_fprintf(trace.f, "\n\t]\n}\n");
	if (trace.f)
		err = fclose(trace.f);

	if (err)
		return errno;

	trace.f = NULL;

	return 0;
#else
	return 0;
#endif
}


/**
 * Flush trace buffer (can be called multiple times)
 *
 * @return 0 if success, otherwise errorcode
 */
int re_trace_flush(void)
{
#ifdef RE_TRACE_ENABLED
	int flush_count;
	struct trace_event *event_tmp;
	struct trace_event *e;
	char *json_arg;
	char name[128]	 = {0};
	char id_str[128] = {0};

	if (!re_atomic_rlx(&trace.init))
		return 0;

	mtx_lock(&trace.lock);
	event_tmp = trace.event_buffer_flush;
	trace.event_buffer_flush = trace.event_buffer;
	trace.event_buffer = event_tmp;

	flush_count = trace.event_count;
	trace.event_count = 0;
	mtx_unlock(&trace.lock);

	size_t json_arg_sz = 4096;
	json_arg = mem_zalloc(json_arg_sz, NULL);
	if (!json_arg) {
		for (int i = 0; i < flush_count; i++) {
			e = &trace.event_buffer_flush[i];
			if (e->arg_type == RE_TRACE_ARG_STRING_COPY)
				mem_deref((void *)e->arg.a_str);

			if (e->id)
				mem_deref(e->id);
		}
		return ENOMEM;
	}

	for (int i = 0; i < flush_count; i++)
	{
		e = &trace.event_buffer_flush[i];

		switch (e->arg_type) {
		case RE_TRACE_ARG_NONE:
			json_arg[0] = '\0';
			break;
		case RE_TRACE_ARG_INT:
			(void)re_snprintf(json_arg, json_arg_sz,
					", \"args\":{\"%s\":%i}",
					e->arg_name, e->arg.a_int);
			break;
		case RE_TRACE_ARG_STRING_CONST:
			(void)re_snprintf(json_arg, json_arg_sz,
					", \"args\":{\"%s\":\"%s\"}",
					e->arg_name, e->arg.a_str);
			break;
		case RE_TRACE_ARG_STRING_COPY:
			(void)re_snprintf(json_arg, json_arg_sz,
					", \"args\":{\"%s\":\"%s\"}",
					e->arg_name, e->arg.a_str);

			mem_deref((void *)e->arg.a_str);
			break;
		}

		re_snprintf(name, sizeof(name), "\"name\":\"%s\"", e->name);

		if (e->id) {
			re_snprintf(id_str, sizeof(id_str), ", \"id\":\"%r\"",
				    e->id);
			mem_deref(e->id);
		}

		(void)re_fprintf(trace.f,
			"%s{\"cat\":\"%s\",\"pid\":%i,\"tid\":%lu,\"ts\":%Lu,"
			"\"ph\":\"%c\",%s%s%s}",
			trace.new ? "" : ",\n",
			e->cat, e->pid, e->tid, e->ts - trace.start_time,
			e->ph, name,
			e->id ? id_str : "",
			str_isset(json_arg) ? json_arg : "");
		trace.new = false;
	}

	mem_deref(json_arg);

	(void)fflush(trace.f);
	return 0;
#else
	return 0;
#endif
}


void re_trace_event(const char *cat, const char *name, char ph, struct pl *id,
		    re_trace_arg_type arg_type, const char *arg_name,
		    void *arg_value)
{
#ifdef RE_TRACE_ENABLED
	struct trace_event *e;

	if (!re_atomic_rlx(&trace.init))
		return;

	mtx_lock(&trace.lock);
	if (trace.event_count >= TRACE_BUFFER_SIZE) {
		DEBUG_WARNING("Increase TRACE_BUFFER_SIZE\n");
		mtx_unlock(&trace.lock);
		return;
	}
	e = &trace.event_buffer[trace.event_count];
	++trace.event_count;
	mtx_unlock(&trace.lock);

	e->ts = tmr_jiffies_usec();
	e->id = mem_ref(id);
	e->ph = ph;
	e->cat = cat;
	e->name = name;
	e->pid = get_process_id();
	e->tid = get_thread_id();
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
#else
	(void)cat;
	(void)name;
	(void)ph;
	(void)id;
	(void)arg_type;
	(void)arg_name;
	(void)arg_value;
#endif
}
