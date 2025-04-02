/**
 * @file mem.c  Memory management with reference counting
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <re_types.h>
#include <re_list.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_mem.h>
#include <re_btrace.h>
#include <re_thread.h>
#include <re_atomic.h>


#define DEBUG_MODULE "mem"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#ifndef RELEASE
#define MEM_DEBUG 1  /**< Enable memory debugging */
#endif


/** Defines a reference-counting memory object */
struct mem {
	RE_ATOMIC uint32_t nrefs; /**< Number of references  */
	uint32_t size;         /**< Size of memory object */
	mem_destroy_h *dh;     /**< Destroy handler       */
#if MEM_DEBUG
	size_t magic;          /**< Magic number          */
	struct le le;          /**< Linked list element   */
	struct btrace btraces; /**< Backtrace array       */
#endif
};

#if MEM_DEBUG
/* Memory debugging */
static struct list meml = LIST_INIT;
static const size_t mem_magic = 0xe7fb9ac4;
static ssize_t threshold = -1;  /**< Memory threshold, disabled by default */

static struct memstat memstat = {
	0,0
};

static once_flag flag = ONCE_FLAG_INIT;
static mtx_t mtx;

static void mem_lock_init(void)
{
	mtx_init(&mtx, mtx_plain);
}

static inline void mem_lock(void)
{
	call_once(&flag, mem_lock_init);

	mtx_lock(&mtx);
}

static inline void mem_unlock(void)
{
	mtx_unlock(&mtx);
}

/** Update statistics for mem_zalloc() */
#define STAT_ALLOC(_m, _size) \
	mem_lock(); \
	memstat.bytes_cur += (_size); \
	++memstat.blocks_cur; \
	mem_unlock(); \
	(_m)->size = (uint32_t)(_size); \
	(_m)->magic = mem_magic;

/** Update statistics for mem_realloc() */
#define STAT_REALLOC(_m, _size) \
	mem_lock(); \
	memstat.bytes_cur += ((_size) - (_m)->size); \
	mem_unlock(); \
	(_m)->size = (uint32_t)(_size)

/** Update statistics for mem_deref() */
#define STAT_DEREF(_m) \
	mem_lock(); \
	memstat.bytes_cur -= (_m)->size; \
	--memstat.blocks_cur; \
	mem_unlock(); \
	memset((_m), 0xb5, (size_t)mem_header_size + (_m)->size)

/** Check magic number in memory object */
#define MAGIC_CHECK(_m) \
	if (mem_magic != (_m)->magic) { \
		DEBUG_WARNING("%s: magic check failed 0x%08zx (%p)\n", \
			__func__, (_m)->magic, get_mem_data((_m)));    \
		RE_BREAKPOINT;					      \
	}
#else
#define STAT_ALLOC(_m, _size) (_m)->size = (uint32_t)(_size);
#define STAT_REALLOC(_m, _size) (_m)->size = (uint32_t)(_size);
#define STAT_DEREF(_m)
#define MAGIC_CHECK(_m)
#endif


enum {
#if defined(__x86_64__)
	/* Use 16-byte alignment on x86-x32 as well */
	mem_alignment = 16u,
#else
	mem_alignment = sizeof(void*) >= 8u ? 16u : 8u,
#endif
	alignment_mask = mem_alignment - 1u,
	mem_header_size = (sizeof(struct mem) + alignment_mask) &
		(~(size_t)alignment_mask)
};

#define MEM_SIZE_MAX \
	(size_t)(sizeof(size_t) > sizeof(uint32_t) ? \
		(~(uint32_t)0u) : (~(size_t)0u) - mem_header_size)


static inline struct mem *get_mem(void *p)
{
	return (struct mem *)(void *)(((unsigned char *)p) - mem_header_size);
}


static inline void *get_mem_data(struct mem *m)
{
	return (void *)(((unsigned char *)m) + mem_header_size);
}


/**
 * Allocate a new reference-counted memory object
 *
 * @param size Size of memory object
 * @param dh   Optional destructor, called when destroyed
 *
 * @return Pointer to allocated object
 */
void *mem_alloc(size_t size, mem_destroy_h *dh)
{
	struct mem *m;

	if (size > MEM_SIZE_MAX)
		return NULL;

#if MEM_DEBUG
	mem_lock();
	if (-1 != threshold && (memstat.blocks_cur >= (size_t)threshold)) {
		mem_unlock();
		return NULL;
	}
	mem_unlock();
#endif

	m = malloc(mem_header_size + size);
	if (!m)
		return NULL;

#if MEM_DEBUG
	btrace(&m->btraces);
	memset(&m->le, 0, sizeof(struct le));
	mem_lock();
	list_append(&meml, &m->le, m);
	mem_unlock();
#endif
	re_atomic_rlx_set(&m->nrefs, 1u);
	m->dh    = dh;

	STAT_ALLOC(m, size);

	return get_mem_data(m);
}


/**
 * Allocate a new reference-counted memory object. Memory is zeroed.
 *
 * @param size Size of memory object
 * @param dh   Optional destructor, called when destroyed
 *
 * @return Pointer to allocated object
 */
void *mem_zalloc(size_t size, mem_destroy_h *dh)
{
	void *p;

	p = mem_alloc(size, dh);
	if (!p)
		return NULL;

	memset(p, 0, size);

	return p;
}


/**
 * Re-allocate a reference-counted memory object
 *
 * @param data Memory object
 * @param size New size of memory object
 *
 * @return New pointer to allocated object
 *
 * @note Realloc NULL pointer is not supported
 */
void *mem_realloc(void *data, size_t size)
{
	struct mem *m, *m2;

	if (!data)
		return NULL;

	if (size > MEM_SIZE_MAX)
		return NULL;

	m = get_mem(data);

	MAGIC_CHECK(m);

	if (re_atomic_acq(&m->nrefs) > 1u) {
		void* p = mem_alloc(size, m->dh);
		if (p) {
			memcpy(p, data, (m->size < size) ? m->size : size);
			mem_deref(data);
		}
		return p;
	}

#if MEM_DEBUG
	mem_lock();

	/* Simulate OOM */
	if (-1 != threshold && size > m->size) {
		if (memstat.blocks_cur >= (size_t)threshold) {
			mem_unlock();
			return NULL;
		}
	}

	list_unlink(&m->le);

	mem_unlock();
#endif

	m2 = realloc(m, mem_header_size + size);

#if MEM_DEBUG
	mem_lock();
	list_append(&meml, m2 ? &m2->le : &m->le, m2 ? m2 : m);
	mem_unlock();
#endif

	if (!m2) {
		return NULL;
	}

	STAT_REALLOC(m2, size);

	return get_mem_data(m2);
}


/**
 * Re-allocate a reference-counted array
 *
 * @param ptr      Pointer to existing array, NULL to allocate a new array
 * @param nmemb    Number of members in array
 * @param membsize Number of bytes in each member
 * @param dh       Optional destructor, only used when ptr is NULL
 *
 * @return New pointer to allocated array
 */
void *mem_reallocarray(void *ptr, size_t nmemb, size_t membsize,
		       mem_destroy_h *dh)
{
	size_t tsize;

	if (membsize && nmemb > MEM_SIZE_MAX / membsize) {
		return NULL;
	}

	tsize = nmemb * membsize;

	if (ptr) {
		return mem_realloc(ptr, tsize);
	}
	else {
		return mem_alloc(tsize, dh);
	}
}


/**
 * Set or unset a destructor for a memory object
 *
 * @param data Memory object
 * @param dh   called when destroyed, NULL for remove
 */
void mem_destructor(void *data, mem_destroy_h *dh)
{
	struct mem *m;

	if (!data)
		return;

	m = get_mem(data);

	MAGIC_CHECK(m);

	m->dh = dh;
}


/**
 * Reference a reference-counted memory object
 *
 * @param data Memory object
 *
 * @return Memory object (same as data)
 */
void *mem_ref(void *data)
{
	struct mem *m;

	if (!data)
		return NULL;

	m = get_mem(data);

	MAGIC_CHECK(m);

	re_atomic_rlx_add(&m->nrefs, 1u);

	return data;
}


/**
 * Dereference a reference-counted memory object. When the reference count
 * is zero, the destroy handler will be called (if present) and the memory
 * will be freed
 *
 * @param data Memory object
 *
 * @return Always NULL
 */
/* coverity[-tainted_data_sink: arg-0] */
void *mem_deref(void *data)
{
	struct mem *m;

	if (!data)
		return NULL;

	m = get_mem(data);

	MAGIC_CHECK(m);

	if (re_atomic_acq_sub(&m->nrefs, 1u) > 1u) {
		return NULL;
	}

	if (m->dh)
		m->dh(data);

	/* NOTE: check if the destructor called mem_ref() */
	if (re_atomic_rlx(&m->nrefs) > 0u)
		return NULL;

#if MEM_DEBUG
	mem_lock();
	list_unlink(&m->le);
	mem_unlock();
#endif

	STAT_DEREF(m);

	free(m);

	return NULL;
}


/**
 * Get number of references to a reference-counted memory object
 *
 * @param data Memory object
 *
 * @return Number of references
 */
uint32_t mem_nrefs(const void *data)
{
	struct mem *m;

	if (!data)
		return 0;

	m = get_mem((void*)data);

	MAGIC_CHECK(m);

	return (uint32_t)re_atomic_acq(&m->nrefs);
}


#if MEM_DEBUG
static bool debug_handler(struct le *le, void *arg)
{
	struct mem *m = le->data;
	const uint8_t *p = get_mem_data(m);
	size_t i;

	(void)arg;

	(void)re_fprintf(stderr, "  %p: nrefs=%-2u", p,
		(uint32_t)re_atomic_rlx(&m->nrefs));

	(void)re_fprintf(stderr, " size=%-7u", m->size);

	(void)re_fprintf(stderr, " [");

	for (i=0; i<16; i++) {
		if (i >= m->size)
			(void)re_fprintf(stderr, "   ");
		else
			(void)re_fprintf(stderr, "%02x ", p[i]);
	}

	(void)re_fprintf(stderr, "] [");

	for (i=0; i<16; i++) {
		if (i >= m->size)
			(void)re_fprintf(stderr, " ");
		else
			(void)re_fprintf(stderr, "%c",
					 isprint(p[i]) ? p[i] : '.');
	}

	(void)re_fprintf(stderr, "]");

	MAGIC_CHECK(m);

	(void)re_fprintf(stderr, "\n");

	re_fprintf(stderr, "%H\n", btrace_println, &m->btraces);

	return false;
}
#endif


/**
 * Debug all allocated memory objects
 */
void mem_debug(void)
{
#if MEM_DEBUG
	uint32_t n;

	mem_lock();
	n = list_count(&meml);
	mem_unlock();

	if (!n)
		return;

	DEBUG_WARNING("Memory leaks (%u):\n", n);

	mem_lock();
	(void)list_apply(&meml, true, debug_handler, NULL);
	mem_unlock();
#endif
}


/**
 * Set the memory allocation threshold. This is only used for debugging
 * and out-of-memory simulation
 *
 * @param n Threshold value
 */
void mem_threshold_set(ssize_t n)
{
#if MEM_DEBUG
	mem_lock();
	threshold = n;
	mem_unlock();
#else
	(void)n;
#endif
}


/**
 * Print memory status
 *
 * @param pf     Print handler for debug output
 * @param unused Unused parameter
 *
 * @return 0 if success, otherwise errorcode
 */
int mem_status(struct re_printf *pf, void *unused)
{
#if MEM_DEBUG
	struct memstat stat;
	uint32_t c;
	int err = 0;

	(void)unused;

	mem_lock();
	memcpy(&stat, &memstat, sizeof(stat));
	c = list_count(&meml);
	mem_unlock();

	err |= re_hprintf(pf,
			  "Memory status: (%zu bytes overhead per block)\n",
			  (size_t)mem_header_size);
	err |= re_hprintf(pf,
			  " Cur:  %zu blocks, %zu bytes (total %zu bytes)\n",
			  stat.blocks_cur, stat.bytes_cur,
			  stat.bytes_cur
			  + (stat.blocks_cur * (size_t)mem_header_size));
	err |= re_hprintf(pf, " Total %u blocks allocated\n", c);

	return err;
#else
	(void)pf;
	(void)unused;
	return 0;
#endif
}


/**
 * Get memory statistics
 *
 * @param mstat Returned memory statistics
 *
 * @return 0 if success, otherwise errorcode
 */
int mem_get_stat(struct memstat *mstat)
{
	if (!mstat)
		return EINVAL;
#if MEM_DEBUG
	mem_lock();
	memcpy(mstat, &memstat, sizeof(*mstat));
	mem_unlock();
	return 0;
#else
	return ENOSYS;
#endif
}
