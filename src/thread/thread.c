#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_thread.h>
#include <re_trace.h>
#ifdef HAVE_PRCTL
#include <sys/prctl.h>
#endif
#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <processthreadsapi.h>
#endif
#ifdef HAVE_PTHREAD
#include <pthread.h>
#ifdef OPENBSD
#include <pthread_np.h>
#endif
#endif


struct thread {
	thrd_t *thr;
	const char *name;
	thrd_start_t func;
	void *arg;
};


static void mutex_destructor(void *data)
{
	mtx_t *mtx = data;

	mtx_destroy(mtx);
}


static int _mutex_alloc(mtx_t **mtx, int type)
{
	mtx_t *m;
	int err;

	if (!mtx)
		return EINVAL;

	m = mem_alloc(sizeof(mtx_t), NULL);
	if (!m)
		return ENOMEM;

	err = mtx_init(m, type) != thrd_success;
	if (err) {
		err = ENOMEM;
		goto out;
	}

	mem_destructor(m, mutex_destructor);

	*mtx = m;

out:
	if (err)
		mem_deref(m);

	return err;
}


int mutex_alloc(mtx_t **mtx)
{
	return _mutex_alloc(mtx, mtx_plain);
}


int mutex_alloc_tp(mtx_t **mtx, int type)
{
	return _mutex_alloc(mtx, type);
}


static int handler(void *p)
{
	struct thread th = *(struct thread *)p;

	mem_deref(p);

#ifdef HAVE_PRCTL
	(void)prctl(PR_SET_NAME, th.name);
#elif defined(WIN32)
	/* Not implemented */
#elif defined(DARWIN)
	(void)pthread_setname_np(th.name);
#elif defined(HAVE_PTHREAD)
#if defined(OPENBSD)
	(void)pthread_set_name_np(*th.thr, th.name);
#elif defined(__NetBSD__)
	(void)pthread_setname_np(*th.thr, "%s", th.name);
#else
	(void)pthread_setname_np(*th.thr, th.name);
#endif
#endif
	RE_TRACE_THREAD_NAME(th.name);

	return th.func(th.arg);
}


int thread_create_name(thrd_t *thr, const char *name, thrd_start_t func,
		       void *arg)
{
	struct thread *th;
	int ret;

	if (!thr || !func)
		return EINVAL;

	th = mem_alloc(sizeof(struct thread), NULL);
	if (!th)
		return ENOMEM;

	th->thr = thr;
	th->name = name;
	th->func = func;
	th->arg	 = arg;

	ret = thrd_create(thr, handler, th);
	if (ret == thrd_success)
		return 0;

	mem_deref(th);

	if (ret == thrd_nomem)
		return ENOMEM;

	return EAGAIN;
}
