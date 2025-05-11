/**
 * @file mem_pool.c  Pre-Allocated Memory pool management
 *
 * Copyright (C) 2025 Sebastian Reimers
 */

#include <string.h>

#include <re_types.h>
#include <re_mem.h>
#include <re_thread.h>


#define DEBUG_MODULE "mem_pool"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct mem_pool {
	size_t nmemb;
	size_t membsize;
	struct mem_pool_entry *freel; /* single linked list */
	mem_destroy_h *membdh;
	struct mem_pool_entry **objs;
	mtx_t *lock;
};

struct mem_pool_entry {
	struct mem_pool_entry *next;
	void *member;
};


static void mem_pool_destroy(void *data)
{
	struct mem_pool *p = data;

	for (size_t i = 0; i < p->nmemb; i++) {
		if (p->objs[i])
			mem_deref(p->objs[i]->member);
		mem_deref(p->objs[i]);
	}

	mem_deref(p->objs);
	mem_deref(p->lock);
}


static inline void next_free(struct mem_pool *pool, struct mem_pool_entry *e)
{
	e->next	    = pool->freel;
	pool->freel = e;
}


/**
 * @brief Allocate a memory pool
 *
 * This function initializes a memory pool with a specified number of elements,
 * each of a given size. Optionally, a destructor callback can be provided
 * to handle cleanup when a member is released or pool is destroyed
 *
 * @param  poolp    Pointer to the memory pool pointer to be initialized
 * @param  nmemb    Number of elements to allocate in the pool
 * @param  membsize Size of each element in the pool
 * @param  dh       Optional destructor callback for pool cleanup (can be
 *                  NULL)
 *
 * @return 0 for success, otherwise error code
 */
int mem_pool_alloc(struct mem_pool **poolp, size_t nmemb, size_t membsize,
		   mem_destroy_h *dh)
{
	int err;

	if (!poolp || !nmemb || !membsize)
		return EINVAL;

	struct mem_pool *p = mem_zalloc(sizeof(struct mem_pool), NULL);
	if (!p)
		return ENOMEM;

	p->nmemb    = nmemb;
	p->membsize = membsize;
	p->membdh   = dh;

	p->objs = mem_zalloc(nmemb * sizeof(struct mem_pool_entry *), NULL);
	if (!p->objs) {
		err = ENOMEM;
		goto error;
	}

	mem_destructor(p, mem_pool_destroy);

	err = mutex_alloc(&p->lock);
	if (err)
		goto error;

	for (size_t i = 0; i < nmemb; i++) {
		p->objs[i] = mem_zalloc(sizeof(struct mem_pool_entry), NULL);
		if (!p->objs[i]) {
			err = ENOMEM;
			goto error;
		}
		p->objs[i]->member = mem_zalloc(membsize, dh);
		if (!p->objs[i]->member) {
			err = ENOMEM;
			goto error;
		}
		next_free(p, p->objs[i]);
	}

	*poolp = p;

	return 0;

error:
	mem_deref(p);
	return err;
}


/**
 * @brief Extend an existing memory pool
 *
 * Adds additional elements to an existing memory pool
 *
 * @param pool Pointer to the memory pool to extend
 * @param num  Number of additional elements to add to the pool
 *
 * @return 0 for success, otherwise error code
 */
int mem_pool_extend(struct mem_pool *pool, size_t num)
{
	if (!pool || !num)
		return EINVAL;

	mtx_lock(pool->lock);
	size_t nmemb = pool->nmemb + num;

	struct mem_pool_entry **objs;
	objs = mem_zalloc(nmemb * sizeof(struct mem_pool_entry *), NULL);
	if (!objs) {
		mtx_unlock(pool->lock);
		return ENOMEM;
	}

	/* Copy old members */
	size_t i = 0;
	for (; i < pool->nmemb; i++) {
		objs[i] = pool->objs[i];
	}

	/* Allocate new members */
	for (; i < nmemb; i++) {
		objs[i] = mem_zalloc(sizeof(struct mem_pool_entry), NULL);
		if (!objs[i]) {
			mem_deref(objs);
			mtx_unlock(pool->lock);
			return ENOMEM;
		}
		objs[i]->member = mem_zalloc(pool->membsize, pool->membdh);
		if (!objs[i]->member) {
			mem_deref(objs[i]);
			mem_deref(objs);
			mtx_unlock(pool->lock);
			return ENOMEM;
		}
		next_free(pool, objs[i]);
	}

	mem_deref(pool->objs);
	pool->objs  = objs;
	pool->nmemb = nmemb;

	mtx_unlock(pool->lock);

	return 0;
}


/**
 * @brief Borrow an entry from the memory pool
 *
 * Retrieves an unused entry from the memory pool for temporary use
 *
 * @param pool Pointer to the memory pool
 *
 * @return Pointer to a memory pool entry, or NULL if no entries are available
 */
struct mem_pool_entry *mem_pool_borrow(struct mem_pool *pool)
{
	if (!pool)
		return NULL;

	mtx_lock(pool->lock);
	struct mem_pool_entry *e = pool->freel;
	if (e) {
		pool->freel = e->next;
		mtx_unlock(pool->lock);
		return e;
	}
	mtx_unlock(pool->lock);

	return NULL;
}


/**
 * Borrow an entry from the memory pool, extend the pool if necessary
 *
 * @param pool Pointer to the memory pool
 *
 * @return Pointer to a memory pool entry, or NULL on error
 */
struct mem_pool_entry *mem_pool_borrow_extend(struct mem_pool *pool)
{
	struct mem_pool_entry *e = mem_pool_borrow(pool);
	if (e)
		return e;

	mem_pool_extend(pool, pool->nmemb * 2);

	return mem_pool_borrow(pool);
}


/**
 * @brief Release a borrowed entry back to the memory pool
 *
 * Returns a previously borrowed memory pool entry back to the pool
 * When the entry is released, the member destructor callback (if provided)
 * is called to perform any necessary cleanup. Additionally, the memory
 * associated with the entry is re-initialized to zero to ensure a clean state
 * for future use
 *
 * @param pool  Pointer to the memory pool
 * @param e     Pointer to the memory pool entry to release
 *
 * @return Always NULL
 */
void *mem_pool_release(struct mem_pool *pool, struct mem_pool_entry *e)
{
	if (!pool || !e)
		return NULL;

	mtx_lock(pool->lock);

	if (pool->membdh)
		pool->membdh(e->member);

	memset(e->member, 0, pool->membsize);
	next_free(pool, e);

	mtx_unlock(pool->lock);

	return NULL;
}


/**
 * Flush mem_pool members
 *
 * @param pool Pointer to the memory pool entry
 */
void mem_pool_flush(struct mem_pool *pool)
{
	mtx_lock(pool->lock);
	for (size_t i = 0; i < pool->nmemb; i++) {
		struct mem_pool_entry *e = pool->objs[i];
		if (pool->membdh)
			pool->membdh(e->member);
		memset(e->member, 0, pool->membsize);
		next_free(pool, e);
	}
	mtx_unlock(pool->lock);
}


/**
 * Return Pool member
 *
 * @param entry Pointer to the memory pool entry
 *
 * @return Pointer to the data associated with the memory pool entry or NULL
 */
void *mem_pool_member(const struct mem_pool_entry *entry)
{
	return entry ? entry->member : NULL;
}
