/**
 * @file posix.c  WIN32 thread implementation
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#include <re_types.h>
#include <re_lock.h>
#include <re_mem.h>
#include <re_thread.h>


struct thread {
	thrd_start_t func;
	void *arg;
};


static unsigned __stdcall *thrd_handler(void *p)
{
	struct thread th = *(struct thread *)p;

	mem_deref(p);

	return (void *)(intptr_t)th.func(th.arg);
}


int thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
{
	struct thread *th;
	int err = 0;
	uintptr_t handle;

	if (!thr || !func)
		return EINVAL;

	th = mem_alloc(sizeof(struct thread), NULL);
	if (!th)
		return ENOMEM;

	th->func = func;
	th->arg	 = arg;

	handle = _beginthreadex(NULL, 0, thrd_handler, th, 0, NULL);
	if (handle == 0) {
		if (errno == EAGAIN || errno == EACCES) {
			err = thrd_nomem;
			goto out;
		}
		err = thrd_error;
		goto out;
	}

	*thr = (thrd_t)handle;
out:
	if (err)
		mem_deref(th);

	return err;
}


int thrd_equal(thrd_t lhs, thrd_t rhs)
{
	return GetThreadId(lhs) == GetThreadId(rhs);
}


thrd_t thrd_current(void)
{
	return GetCurrentThread();
}


int thrd_detach(thrd_t thr)
{
	CloseHandle(thr);
	return thrd_success;
}


int thrd_join(thrd_t thr, int *res)
{
	DWORD w, code;

	w = WaitForSingleObject(thr, INFINITE);
	if (w != WAIT_OBJECT_0)
		return thrd_error;

	if (res) {
		if (!GetExitCodeThread(thr, &code)) {
			CloseHandle(thr);
			return thrd_error;
		}
		*res = (int)code;
	}

	CloseHandle(thr);
	return thrd_success;
}


struct impl_call_once_param {
	void (*func)(void);
};
static BOOL CALLBACK call_once_callback(PINIT_ONCE InitOnce, PVOID Parameter,
					PVOID *Context)
{
	struct impl_call_once_param *param =
		(struct impl_call_once_param *)Parameter;
	(param->func)();
	((void)InitOnce);
	((void)Context);
	return true;
}


void call_once(thrd_once_flag *flag, void (*func)(void))
{
	struct impl_call_once_param param;
	param.func = func;
	InitOnceExecuteOnce(flag, call_once_callback, (PVOID)&param, NULL);
}


void thrd_exit(int res)
{
	_endthreadex((unsigned)res);
}


int cnd_init(cnd_t *cnd)
{
	if (!cnd)
		return thrd_error;

	InitializeConditionVariable(&cond->condvar);

	return thrd_success;
}


int cnd_signal(cnd_t *cnd)
{
	if (!cnd)
		return thrd_error;

	WakeConditionVariable(&cond->condvar);

	return thrd_success;
}


int cnd_wait(cnd_t *cnd, mtx_t *mtx)
{
	if (!cnd || !lock)
		return thrd_error;

	SleepConditionVariableCS(&cond->condvar, &mtx->cs, INFINITE);

	return thrd_success;
}
