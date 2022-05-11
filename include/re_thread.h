/**
 * @file re_thread.h  Thread support
 *
 * Inspired by C11 thread support this provides a cross platform interfaces to
 * thread, mutex and condition handling (C11, POSIX and Windows Threads).
 *
 * Preferred order:
 *
 * - C11 threads (glibc>=2.28, musl, FreeBSD>=10)
 * - Windows Thread API
 * - POSIX PTHREAD (Linux/UNIX)
 *
 * Copyright (C) 2022 Sebastian Reimers
 */

#if defined(HAVE_THREADS)
#include <threads.h>

#else

#if defined(WIN32)

#include <windows.h>
#define ONCE_FLAG_INIT INIT_ONCE_STATIC_INIT
typedef INIT_ONCE once_flag;
typedef HANDLE thrd_t;
typedef CONDITION_VARIABLE cnd_t;
typedef CRITICAL_SECTION mtx_t;

#else

#include <pthread.h>
#include <time.h>
#define ONCE_FLAG_INIT PTHREAD_ONCE_INIT
typedef pthread_once_t once_flag;
typedef pthread_t thrd_t;
typedef pthread_cond_t cnd_t;
typedef pthread_mutex_t mtx_t;

#endif

enum { mtx_plain = 0, mtx_try = 1, mtx_timed = 2, mtx_recursive = 4 };

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
 * @param flag  Pointer to object initialized by ONCE_FLAG_INIT
 * @param func  The function to execute only once
 */
void call_once(once_flag *flag, void (*func)(void));


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
 * @param cnd   Pointer to condition variable
 * @param lock  Lock mutex pointer
 *
 * @return 0 if success, otherwise errorcode
 */
int cnd_wait(cnd_t *cnd, mtx_t *mtx);


/**
 * Destroys the condition variable pointed to by cnd.
 * If there are thrds waiting on cnd, the behavior is undefined.
 *
 * @param cnd  pointer to the condition variable to destroy
 */
void cnd_destroy(cnd_t *cnd);


/******************************************************************************
 * Mutex functions
 *****************************************************************************/

/**
 * Creates a new mutex object with type. The object pointed to by mutex is set
 * to an identifier of the newly created mutex.
 *
 * @param mtx   Pointer to the mutex to initialize
 * @param type  The type of the mutex
 *
 * @return thrd_success on success, otherwise thrd_error
 */
int mtx_init(mtx_t *mtx, int type);


/**
 * Blocks the current thread until the mutex pointed to by mutex is locked.
 * The behavior is undefined if the current thread has already locked the
 * mutex and the mutex is not recursive.
 *
 * @param mtx   Pointer to the mutex
 *
 * @return thrd_success on success, otherwise thrd_error
 */
int mtx_lock(mtx_t *mtx);


/**
 * Tries to lock the mutex pointed to by mutex without blocking.
 * Returns immediately if the mutex is already locked.
 *
 * @param mtx   Pointer to the mutex
 *
 * @return thrd_success on success, thrd_busy if alread locked,
 * otherwise thrd_error
 */
int mtx_trylock(mtx_t *mtx);


/**
 * Unlocks the mutex pointed to by mutex.
 *
 * @param mtx   Pointer to the mutex
 *
 * @return thrd_success on success, otherwise thrd_error
 */
int mtx_unlock(mtx_t *mtx);


#endif /* C11 threads fallback */


/******************************************************************************
 * Extra
 *****************************************************************************/
/* int thrd_prio(enum thrd_prio prio) */
/* void thrd_print(struct re_printf *pf, void *unused); */

/**
 * Creates a new thread with name
 *
 * @param thr   Pointer to new thread
 * @param name  Unique name for a thread
 * @param func  Function to execute
 * @param arg   Argument to pass to the function
 *
 * @return 0 if success, otherwise errorcode
 */
int thrd_create_name(thrd_t *thr, const char *name, thrd_start_t func,
		     void *arg);
