/**
 * @file re_thread.h  Thread support (Experimental)
 *
 * Inspired by C11 thread support this provides a cross platform interface to
 * thread handling (C11, POSIX and Windows Threads). For mutex locking see
 * re_lock.h
 *
 * Prefered order:
 *
 * - C11 threads (glibc>=2.28, musl, FreeBSD>=10)
 * - POSIX PTHREAD (Linux/UNIX, winpthreads)
 * - Windows Thread API
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#if defined(HAVE_THREADS)
#include <threads.h>

#else

#if defined(HAVE_PTHREAD)

#include <pthread.h>
#include <time.h>
#define THREAD_ONCE_FLAG_INIT PTHREAD_ONCE_INIT
typedef pthread_once_t thrd_once_flag;
typedef pthread_t thrd_t;
typedef pthread_cond_t cnd_t;

#elif defined(WIN32)

#include <windows.h>
#define THREAD_ONCE_FLAG_INIT INIT_ONCE_STATIC_INIT
typedef INIT_ONCE thrd_once_flag;
typedef HANDLE thrd;
typedef CONDITION_VARIABLE cnd_t;

#endif


/* Exit and error codes.  */
enum {
	thrd_success  = 0,
	thrd_busy     = 1,
	thrd_error    = 2,
	thrd_nomem    = 3,
	thrd_timedout = 4
};

typedef int (*thrd_start_t)(void *);


/******************************************************************************
 * Thread functions
 *****************************************************************************/

/**
 * Creates a new thread
 *
 * @param thr   Pointer to new thread
 * @param func  Function to execute
 * @param arg   Argument to pass to the function
 *
 * @return 0 if success, otherwise errorcode
 */
int thrd_create(thrd_t *thr, thrd_start_t func, void *arg);


/**
 * Checks whether `lhs` and `rhs` refer to the same thread.
 *
 * @return Non-zero value if lhs and rhs refer to the same value, 0 otherwise.
 */
int thrd_equal(thrd_t lhs, thrd_t rhs);


/**
 * Return the identifier of the calling thread.
 */
thrd_t thrd_current(void);


/**
 * Detaches the thread identified by `thr` from the current environment.
 *
 * @return 0 if success, otherwise errorcode
 */
int thrd_detach(thrd_t thr);


/**
 * Blocks the current thread until the thread identified by `thr` finishes
 * execution
 *
 * @param thr  Thread
 * @param res  Result code location
 *
 * @return 0 if success, otherwise errorcode
 */
int thrd_join(thrd_t thr, int *res);


/**
 * Calls a function exactly once
 *
 * @param flag  Pointer to object initialized by THREAD_ONCE_FLAG_INIT
 * @param func  The function to execute only once
 */
void call_once(thrd_once_flag *flag, void (*func)(void));


/**
 * Terminates the calling thread
 *
 * @param res  The result value to return
 */
void thrd_exit(int res);


/******************************************************************************
 * Condition functions
 *****************************************************************************/

/**
 * Initializes new condition variable
 *
 * @param cnd  Pointer to a variable to store condition variable
 *
 * @return 0 if success, otherwise errorcode
 */
int cnd_init(cnd_t *cnd);


/**
 * Unblocks one thread blocked on a condition variable
 *
 * @param cnd  Pointer to condition variable
 *
 * @return 0 if success, otherwise errorcode
 */
int cnd_signal(cnd_t *cnd);


/**
 * Unblocks all thrds blocked on a condition variable
 *
 * @param cnd  Pointer to condition variable
 *
 * @return 0 if success, otherwise errorcode
 */
int cnd_broadcast(cnd_t *cnd);


/**
 * Blocks on a condition variable
 *
 * @param cnd  Pointer to condition variable
 * @param lock  Lock mutex pointer
 *
 * @return 0 if success, otherwise errorcode
 */
int cnd_wait(cnd_t *cnd, struct lock *lock);


/**
 * Destroys the condition variable pointed to by cnd.
 * If there are thrds waiting on cnd, the behavior is undefined.
 *
 * @param cnd  pointer to the condition variable to destroy
 */
void cnd_destroy(cnd_t *cnd);

/* @TODO
 * - thrd_sleep
 * - thrd_yield
 * - cnd_timedwait
 */

#endif /* C11 threads */


/******************************************************************************
 * Extra
 *****************************************************************************/
/* int thrd_prio(enum thrd_prio prio) */
/* void thrd_print(struct re_printf *pf, void *unused); */
int thrd_create_name(thrd_t *thr, const char *name, thrd_start_t func,
		     void *arg);

