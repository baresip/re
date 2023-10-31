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
#include <re_tmr.h>
#include <re_mqueue.h>

#define DEBUG_MODULE "async"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

struct async_work {
	struct le le;
	mtx_t *mtx;
	re_async_work_h *workh;
	re_async_h *cb;
	void *arg;
	int err;
	intptr_t id;
};

struct re_async {
	thrd_t *thrd;
	uint16_t workers;
	volatile bool run;
	cnd_t wait;
	mtx_t mtx;
	struct list freel;
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

	for (;;) {
		mtx_lock(&a->mtx);
		if (!a->run) {
			mtx_unlock(&a->mtx);
			break;
		}

		if (list_isempty(&a->workl)) {
			cnd_wait(&a->wait, &a->mtx);

			if (list_isempty(&a->workl) || !a->run) {
				mtx_unlock(&a->mtx);
				continue;
			}
		}

		le = list_head(&a->workl);
		list_move(le, &a->curl);
		mtx_unlock(&a->mtx);

		work = le->data;
		mtx_lock(work->mtx);
		if (work->workh) {
			work->err = work->workh(work->arg);
			work->workh = NULL;
		}
		mtx_unlock(work->mtx);

		mtx_lock(&a->mtx);
		mqueue_push(a->mqueue, 0, work);
		mtx_unlock(&a->mtx);
	}

	return 0;
}


static void async_destructor(void *data)
{
	struct re_async *async = data;

	tmr_cancel(&async->tmr);

	mtx_lock(&async->mtx);
	async->run = false;
	cnd_broadcast(&async->wait);
	mtx_unlock(&async->mtx);

	for (int i = 0; i < async->workers; i++) {
		thrd_join(async->thrd[i], NULL);
	}

	/* Notify worker callbacks (so they can call destructors) */
	struct le *le;
	LIST_FOREACH(&async->workl, le)
	{
		struct async_work *work = le->data;
		if (work->cb) {
			work->cb(ECANCELED, work->arg);
			work->cb = NULL;
		}
	}
	LIST_FOREACH(&async->curl, le)
	{
		struct async_work *work = le->data;
		if (work->cb) {
			work->cb(ECANCELED, work->arg);
			work->cb = NULL;
		}
	}

	list_flush(&async->workl);
	list_flush(&async->curl);
	list_flush(&async->freel);
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

	mtx_lock(work->mtx);
	if (work->cb) {
		work->cb(work->err, work->arg);
		work->cb =NULL;
	}
	mtx_unlock(work->mtx);

	mtx_lock(&async->mtx);
	list_move(&work->le, &async->freel);
	mtx_unlock(&async->mtx);
}


static void work_destruct(void *arg)
{
	struct async_work *work = arg;
	mem_deref(work->mtx);
}


static int work_alloc(struct async_work **workp)
{
	int err;
	struct async_work *work;

	work = mem_zalloc(sizeof(struct async_work), NULL);
	if (!work) {
		err = ENOMEM;
		return err;
	}

	err = mutex_alloc(&work->mtx);
	if (err) {
		mem_deref(work);
		return err;
	}

	mem_destructor(work, work_destruct);

	*workp = work;

	return 0;
}


/**
 * Allocate a new async object
 *
 * @param asyncp  Pointer to allocated async object
 * @param workers Number of worker threads
 *
 * @return 0 if success, otherwise errorcode
 */
int re_async_alloc(struct re_async **asyncp, uint16_t workers)
{
	int err;
	struct re_async *async;
	struct async_work *work;

	if (!asyncp || !workers)
		return EINVAL;

	async = mem_zalloc(sizeof(struct re_async), NULL);
	if (!async)
		return ENOMEM;

	err = mqueue_alloc(&async->mqueue, queueh, async);
	if (err)
		goto err;

	async->thrd = mem_zalloc(sizeof(thrd_t) * workers, NULL);
	if (!async->thrd) {
		err = ENOMEM;
		mem_deref(async->mqueue);
		goto err;
	}

	mtx_init(&async->mtx, mtx_plain);
	cnd_init(&async->wait);
	tmr_init(&async->tmr);

	mem_destructor(async, async_destructor);

	async->run = true;

	for (int i = 0; i < workers; i++) {
		err = thread_create_name(&async->thrd[i],
					 "async worker thread", worker_thread,
					 async);
		if (err)
			goto err;

		async->workers++;

		/* preallocate */
		err = work_alloc(&work);
		if (err)
			goto err;

		list_append(&async->freel, &work->le, work);
	}

	tmr_start(&async->tmr, 10, worker_check, async);

	*asyncp = async;

	return 0;

err:
	mem_deref(async);
	return err;
}


/**
 * Execute work handler async and get a callback from re main thread
 *
 * @param async Pointer to async object
 * @param id    Work identifier
 * @param workh Work handler
 * @param cb    Callback handler (called by re main thread)
 * @param arg   Handler argument (has to be thread-safe)
 *
 * @return 0 if success, otherwise errorcode
 */
int re_async(struct re_async *async, intptr_t id, re_async_work_h *workh,
	     re_async_h *cb, void *arg)
{
	int err = 0;
	struct async_work *work;

	if (unlikely(!async))
		return EINVAL;

	mtx_lock(&async->mtx);
	if (unlikely(list_isempty(&async->freel))) {

		err = work_alloc(&work);
		if (err)
			goto out;
	}
	else {
		work = list_head(&async->freel)->data;
		list_unlink(&work->le);
	}

	work->workh = workh;
	work->cb    = cb;
	work->arg   = arg;
	work->id    = id;

	list_append(&async->workl, &work->le, work);
	cnd_signal(&async->wait);

out:
	mtx_unlock(&async->mtx);

	return err;
}


/**
 * Cancel pending async work and callback
 *
 * @param async Pointer to async object
 * @param id    Work identifier
 */
void re_async_cancel(struct re_async *async, intptr_t id)
{
	struct le *le;

	if (unlikely(!async))
		return;

	mtx_lock(&async->mtx);

	le = list_head(&async->workl);
	while (le) {
		struct async_work *w = le->data;

		le = le->next;

		if (w->id != id)
			continue;

		mtx_lock(w->mtx);
		w->id	 = 0;
		w->workh = NULL;
		w->cb	 = NULL;
		w->arg	 = mem_deref(w->arg);
		list_move(&w->le, &async->freel);
		mtx_unlock(w->mtx);
	}

	le = list_head(&async->curl);
	while (le) {
		struct async_work *w = le->data;

		le = le->next;

		if (w->id != id)
			continue;

		mtx_lock(w->mtx);
		w->id	 = 0;
		w->workh = NULL;
		w->cb	 = NULL;
		w->arg	 = mem_deref(w->arg);
		/* No move to free list since queueh must always handled if
		 * mqueue_push is called */
		mtx_unlock(w->mtx);
	}

	mtx_unlock(&async->mtx);
}
