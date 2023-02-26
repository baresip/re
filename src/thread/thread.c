#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_thread.h>
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
#endif


struct thread {
	const char *name;
	thrd_start_t func;
	void *arg;
};


static void mutex_destructor(void *data)
{
	mtx_t *mtx = data;

	mtx_destroy(mtx);
}


int mutex_alloc(mtx_t **mtx)
{
	mtx_t *m;
	int err;

	if (!mtx)
		return EINVAL;

	m = mem_alloc(sizeof(mtx_t), NULL);
	if (!m)
		return ENOMEM;

	err = mtx_init(m, mtx_plain) != thrd_success;
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


static int handler(void *p)
{
	struct thread th = *(struct thread *)p;

	mem_deref(p);

#ifdef HAVE_PRCTL
	(void)prctl(PR_SET_NAME, th.name);
#elif defined(WIN32)
	wchar_t *name = str_wchar(th.name);
	if (name) {
		(void)SetThreadDescription(GetCurrentThread(), name);
		mem_deref(name);
	}
#elif defined(HAVE_PTHREAD)
	(void)pthread_setname_np(th.name);
#endif

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
