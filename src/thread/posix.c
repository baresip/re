/**
 * @file posix.c  Pthread C11 thread implementation
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#include <pthread.h>
#include <re_types.h>
#include <re_lock.h>
#include <re_mem.h>
#include <re_thread.h>


struct thread {
	thrd_start_t func;
	void *arg;
};


static void *thrd_handler(void *p)
{
	struct thread th = *(struct thread *)p;

	mem_deref(p);

	return (void *)(intptr_t)th.func(th.arg);
}


int thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
{
	struct thread *th;
	int err;

	if (!thr || !func)
		return EINVAL;

	th = mem_alloc(sizeof(struct thread), NULL);
	if (!th)
		return ENOMEM;

	th->func = func;
	th->arg	 = arg;

	err = pthread_create(thr, NULL, thrd_handler, th);
	if (err)
		mem_deref(th);

	return err;
}


int thrd_equal(thrd_t lhs, thrd_t rhs)
{
	return pthread_equal(lhs, rhs);
}


thrd_t thrd_current(void)
{
	return pthread_self();
}


int thrd_detach(thrd_t thr)
{
	return pthread_detach(thr);
}


int thrd_join(thrd_t thr, int *res)
{
	void *code;
	int err;

	err = pthread_join(thr, &code);

	if (res)
		*res = (int)(intptr_t)code;

	return err;
}


void call_once(thrd_once_flag *flag, void (*func)(void))
{
	pthread_once(flag, func);
}


void thrd_exit(int res)
{
	pthread_exit((void *)(intptr_t)res);
}


int cnd_init(cnd_t *cnd)
{
	if (!cnd)
		return EINVAL;

	return pthread_cond_init(cnd, NULL);
}


int cnd_signal(cnd_t *cnd)
{
	if (!cnd)
		return EINVAL;

	return pthread_cond_signal(cnd);
}


int cnd_wait(cnd_t *cnd, struct lock *lock)
{
	if (!cnd || !lock)
		return EINVAL;

	return pthread_cond_wait(cnd, lock_mutex(lock));
}
