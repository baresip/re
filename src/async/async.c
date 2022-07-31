/**
 * @file async.c Async API
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#include <re_types.h>
#include <re_mem.h>
#include <re_list.h>
#include <re_thread.h>
#include <re_async.h>
#include <re_atomic.h>
#include <re_tmr.h>
#include <re_mqueue.h>

#define DEBUG_MODULE "async"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

struct async_work {
	struct le le;
	re_async_work_h *work;
	re_async_h *cb;
	void *arg;
	int err;
};

struct re_async {
	thrd_t *thrd;
	uint16_t workers;
	RE_ATOMIC bool run;
	cnd_t wait;
	mtx_t mtx;
	struct list workl;
	struct list curl;
	struct tmr tmr;
	struct mqueue *mqueue;
};


static int worker_thread(void *arg)
{
	struct re_async *a = arg;
	struct le *le;
	struct async_work *work;

	while (re_atomic_rlx(&a->run)) {
		mtx_lock(&a->mtx);
		if (list_isempty(&a->workl))
			cnd_wait(&a->wait, &a->mtx);

		if (list_isempty(&a->workl) || !re_atomic_rlx(&a->run)) {
			mtx_unlock(&a->mtx);
			continue;
		}

		le = list_head(&a->workl);
		list_move(le, &a->curl);
		mtx_unlock(&a->mtx);

		work	  = le->data;
		work->err = work->work(work->arg);
		mqueue_push(a->mqueue, 0, work);
	}

	return 0;
}


static void async_destructor(void *data)
{
	struct re_async *async = data;

	tmr_cancel(&async->tmr);

	mtx_lock(&async->mtx);
	re_atomic_rlx_set(&async->run, false);
	cnd_broadcast(&async->wait);
	mtx_unlock(&async->mtx);

	for (int i = 0; i < async->workers; i++) {
		thrd_join(async->thrd[i], NULL);
	}

	list_flush(&async->workl);
	list_flush(&async->curl);
	cnd_destroy(&async->wait);
	mtx_destroy(&async->mtx);
	mem_deref(async->mqueue);
	mem_deref(async->thrd);
}


static void worker_check(void *arg)
{
	struct re_async *async = arg;

	mtx_lock(&async->mtx);
	if (!list_isempty(&async->workl)) {
		if (async->workers == list_count(&async->curl))
			DEBUG_WARNING("all async workers are busy\n");
		else
			cnd_broadcast(&async->wait);
	}
	mtx_unlock(&async->mtx);

	tmr_start(&async->tmr, 100, worker_check, async);
}


/* called by re main event loop */
static void queueh(int id, void *data, void *arg)
{
	struct async_work *work = data;
	struct re_async *async	= arg;
	(void)id;

	work->cb(work->err, work->arg);

	mtx_lock(&async->mtx);
	list_unlink(&work->le);
	mtx_unlock(&async->mtx);

	mem_deref(work);
}


/**
 * Allocate a new async object
 *
 * @param asyncp Pointer to allocated async object
 * @param nthrds Number of worker threads
 *
 * @return 0 if success, otherwise errorcode
 */
int re_async_alloc(struct re_async **asyncp, uint16_t workers)
{
	int err;
	struct re_async *async;

	if (!asyncp || !workers)
		return EINVAL;

	async = mem_zalloc(sizeof(struct re_async), NULL);
	if (!async)
		return ENOMEM;

	err = mqueue_alloc(&async->mqueue, queueh, async);
	if (err) {
		mem_deref(async);
		return err;
	}

	async->thrd = mem_zalloc(sizeof(thrd_t) * workers, NULL);
	if (!async->thrd) {
		mem_deref(async->mqueue);
		mem_deref(async);
		return ENOMEM;
	}

	mtx_init(&async->mtx, mtx_plain);
	cnd_init(&async->wait);
	tmr_init(&async->tmr);

	mem_destructor(async, async_destructor);

	re_atomic_rlx_set(&async->run, true);

	for (int i = 0; i < workers; i++) {
		err = thread_create_name(&async->thrd[i],
					 "async worker thread", worker_thread,
					 async);
		if (err) {
			mem_deref(async);
			return err;
		}

		async->workers++;
	}

	tmr_start(&async->tmr, 10, worker_check, async);

	*asyncp = async;

	return 0;
}


/**
 * Execute work handler async and get a callback from re main thread
 *
 * @param async Pointer to async object
 * @param work  Work handler
 * @param cb    Callback handler (called by re main thread)
 * @param arg   Handler argument (has to be thread-safe)
 *
 * @return 0 if success, otherwise errorcode
 */
int re_async(struct re_async *async, re_async_work_h *work, re_async_h *cb,
	     void *arg)
{
	int err = 0;
	struct async_work *async_work;

	if (!async || !work || !cb)
		return EINVAL;

	async_work = mem_zalloc(sizeof(struct async_work), NULL);
	if (!async_work)
		return ENOMEM;

	async_work->work = work;
	async_work->cb	 = cb;
	async_work->arg	 = arg;

	mtx_lock(&async->mtx);
	list_append(&async->workl, &async_work->le, async_work);
	cnd_signal(&async->wait);
	mtx_unlock(&async->mtx);

	return err;
}
