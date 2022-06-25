/**
 * @file main.c  Main polling routine
 *
 * Copyright (C) 2010 Creytiv.com
 * Copyright (C) 2020-2022 Sebastian Reimers
 */
#include <stdlib.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/types.h>
#undef _STRICT_ANSI
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/resource.h>
#endif
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#ifdef HAVE_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_POLL
#include <poll.h>
#endif
#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif
#ifdef HAVE_KQUEUE
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#undef LIST_INIT
#undef LIST_FOREACH
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_net.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_main.h>
#include <re_thread.h>
#include <re_btrace.h>
#include <re_atomic.h>
#include "main.h"


#define DEBUG_MODULE "main"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/** Main loop values */
enum {
	MAX_BLOCKING = 500,    /**< Maximum time spent in handler in [ms] */
#if defined (FD_SETSIZE)
	DEFAULT_MAXFDS = FD_SETSIZE
#else
	DEFAULT_MAXFDS = 128
#endif
};

/** File descriptor handler struct */
struct fhs {
	re_sock_t fd;        /**< File Descriptor                   */
	int flags;           /**< Polling flags (Read, Write, etc.) */
	fd_h* fh;            /**< Event handler                     */
	void* arg;           /**< Handler argument                  */
};

/** Polling loop data */
struct re {
	struct fhs *fhs;             /** File descriptor handler set        */
	int nfds;                    /**< Number of active file descriptors */
	int maxfds;                  /**< Maximum number of polling fds     */
	enum poll_method method;     /**< The current polling method        */
	bool update;                 /**< File descriptor set need updating */
	RE_ATOMIC bool polling;      /**< Is polling flag                   */
	int sig;                     /**< Last caught signal                */
	struct list tmrl;            /**< List of timers                    */

#ifdef HAVE_POLL
	struct pollfd *fds;          /**< Event set for poll()              */
#endif

#ifdef HAVE_EPOLL
	struct epoll_event *events;  /**< Event set for epoll()             */
	int epfd;                    /**< epoll control file descriptor     */
#endif

#ifdef HAVE_KQUEUE
	struct kevent *evlist;
	int kqfd;
#endif
	mtx_t *mutex;                /**< Mutex for thread synchronization  */
	mtx_t *mutexp;               /**< Pointer to active mutex           */
	thrd_t tid;                  /**< Thread id                         */
	RE_ATOMIC bool thread_enter; /**< Thread enter is called            */
};

static struct re *re_global = NULL;
static tss_t key;
static once_flag flag = ONCE_FLAG_INIT;

static void poll_close(struct re *re);


static void re_destructor(void *arg)
{
	struct re *re = arg;

	poll_close(re);
	mem_deref(re->mutex);
}


/** fallback destructor if thread gets destroyed before re_thread_close() */
static void thread_destructor(void *arg)
{
	struct re *re = arg;

	if (!re)
		return;

	mem_deref(re);
}


int re_alloc(struct re **rep)
{
	struct re *re;
	int err;

	if (!rep)
		return EINVAL;

	re = mem_zalloc(sizeof(struct re), re_destructor);
	if (!re)
		return ENOMEM;

	err = mtx_alloc(&re->mutex);
	if (err) {
		DEBUG_WARNING("thread_init: mtx_init error\n");
		goto out;
	}
	re->mutexp = re->mutex;

	list_init(&re->tmrl);
	re->tid = thrd_current();

#ifdef HAVE_EPOLL
	re->epfd = -1;
#endif

#ifdef HAVE_KQUEUE
	re->kqfd = -1;
#endif


out:
	if (err)
		mem_deref(re);
	else
		*rep = re;

	return err;
}


static void re_once(void)
{
	int err;

	err = tss_create(&key, thread_destructor);
	if (err) {
		DEBUG_WARNING("tss_create failed: %d\n", err);
		exit(err);
	}

}


/**
 * Get thread specific re pointer (fallback to re_global if called by non re
 * thread)
 *
 * @return re pointer on success, otherwise NULL if libre_init() or
 * re_thread_init() is missing
 */
static struct re *re_get(void)
{
	struct re *re;

	call_once(&flag, re_once);
	re = tss_get(key);
	if (!re)
		re = re_global;

	return re;
}


static inline void re_lock(struct re *re)
{
	int err;

	err = mtx_lock(re->mutexp);
	if (err)
		DEBUG_WARNING("re_lock: %m\n", err);
}


static inline void re_unlock(struct re *re)
{
	int err;

	err = mtx_unlock(re->mutexp);
	if (err)
		DEBUG_WARNING("re_unlock: %m\n", err);
}


/**
 * Performs a binary search for a file descriptor event handler by the given
 * fd
 *
 * @param re Poll state
 * @param fd File descriptor
 * @return Index to the found entry in re->fhs or to the entry before which
 *         the fd should have been
 */
static int bsearch_fd_handler(struct re *re, re_sock_t fd)
{
	struct fhs* b = re->fhs;
	int n = re->nfds;
	while (n > 0) {
		int i = n / 2;
		if (b[i].fd < fd) {
			++i;
			b += i;
			n -= i;
		}
		else
			n = i;
	}

	return (int)(b - re->fhs);
}

/**
 * Performs a binary search for a file descriptor event handler by the given
 * fd
 *
 * @param re Poll state
 * @param fd File descriptor
 * @return Index to the found entry in re->fhs or re->nfds if not found
 */
static inline int find_fd_handler(struct re *re, re_sock_t fd)
{
	int idx = bsearch_fd_handler(re, fd);
	if (idx < re->nfds && re->fhs[idx].fd == fd)
		return idx;
	return re->nfds;
}

/**
 * Inserts a new fd handler entry into the ordered list of handlers.
 * The function always reallocates the list so that \c fd_poll is able to
 * detect list modifications.
 *
 * @param re Poll state
 * @param fd File descriptor
 * @param flags Event flags
 * @param fh Event handler
 * @param arg Event handler state
 * @param pidx Returned index of the inserted entry in re->fhs.
 * @return 0 if successful, error code otherwise
 */
static int insert_fd_handler(struct re *re, re_sock_t fd, int flags, fd_h *fh,
							 void *arg, int* pidx)
{
	int idx = bsearch_fd_handler(re, fd);
	struct fhs* p = re->fhs + idx;
	if (idx >= re->nfds || p->fd != fd) {
		struct fhs* new_fhs = (struct fhs*)mem_zalloc(
			(re->nfds + 1) * sizeof(*re->fhs), NULL);
		if (!new_fhs)
			return ENOMEM;
		memcpy(new_fhs, re->fhs, idx * sizeof(*re->fhs));
		memcpy(new_fhs + idx + 1, p,
			(re->nfds - idx) * sizeof(*re->fhs));
		mem_deref(re->fhs);
		re->fhs = new_fhs;
		p = new_fhs + idx;

		++re->nfds;
		p->fd = fd;
	}

	p->flags = flags;
	p->fh = fh;
	p->arg = arg;
	*pidx = idx;

	return 0;
}

/**
 * Removes an fd handler from the ordered list of handlers.
 * The function always reallocates the list so that \c fd_poll is able to
 * detect list modifications. Note that this implies that the function may
 * potentially fail.
 *
 * @param re Poll state
 * @param fd File descriptor
 * @param pidx Returned index of the removed entry in re->fhs. Note that it
 *        may be equal to re->nfds upon return if the removed entry was at
 *        the end of the list.
 * @param found Returned flag that indicates whether the entry has been found.
 * @return 0 if successful, error code otherwise
 */
static int erase_fd_handler(struct re *re, re_sock_t fd, int *pidx,
							bool *found)
{
	int idx = find_fd_handler(re, fd);
	*pidx = idx;
	if (idx < re->nfds) {
		if (re->nfds > 1) {
			struct fhs* p = re->fhs + idx;
			struct fhs* new_fhs = (struct fhs*)mem_zalloc(
				(re->nfds - 1) * sizeof(*re->fhs), NULL);
			if (!new_fhs)
				return ENOMEM;
			--re->nfds;
			memcpy(new_fhs, re->fhs, idx * sizeof(*re->fhs));
			memcpy(new_fhs + idx, p + 1,
				(re->nfds - idx) * sizeof(*re->fhs));
			mem_deref(re->fhs);
			re->fhs = new_fhs;
		}
		else {
			re->fhs = mem_deref(re->fhs);
			re->nfds = 0;
		}
		*found = true;
	}
	else
		*found = false;

	return 0;
}

/**
 * Removes an fd handler at the specified position in the list. Does not
 * reallocate memory and should only be used as a way to roll back
 * \c insert_fd_handler in case of failure, in a single transaction.
 *
 * @param re Poll state
 * @param idx Fd handler index in the re->fhs list
 */
static void erase_fd_handler_no_realloc(struct re *re, int idx)
{
	struct fhs* p = re->fhs + idx;
	--re->nfds;
	memmove(p, p + 1, (re->nfds - idx) * sizeof(*re->fhs));
}


#if MAIN_DEBUG
/**
 * Call the application event handler
 *
 * @param re     Poll state
 * @param i	 File descriptor handler index
 * @param flags  Event flags
 */
static void fd_handler(struct re *re, int i, int flags)
{
	const uint64_t tick = tmr_jiffies();
	uint32_t diff;

	DEBUG_INFO("event on fd=%d index=%d (flags=0x%02x)...\n",
		   re->fhs[i].fd, i, flags);

	re->fhs[i].fh(flags, re->fhs[i].arg);

	diff = (uint32_t)(tmr_jiffies() - tick);

	if (diff > MAX_BLOCKING) {
		DEBUG_WARNING("long async blocking: %u>%u ms (h=%p arg=%p)\n",
			      diff, MAX_BLOCKING,
			      re->fhs[i].fh, re->fhs[i].arg);
	}
}
#endif


#ifdef HAVE_POLL
static inline void set_poll_events(int flags, struct pollfd *p)
{
	p->events = 0;
	if (flags & FD_READ)
		p->events |= POLLIN;
	if (flags & FD_WRITE)
		p->events |= POLLOUT;
	if (flags & FD_EXCEPT)
		p->events |= POLLERR;
}

static int create_poll_fds(struct re *re, struct pollfd** pfds)
{
	struct pollfd* new_fds = (struct pollfd*)mem_zalloc(
		re->nfds * sizeof(*re->fds), NULL);
	if (!new_fds)
		return ENOMEM;

	for (int i = 0; i < re->nfds; ++i) {
		new_fds[i].fd = re->fhs[i].fd;
		set_poll_events(re->fhs[i].flags, new_fds + i);
	}

	*pfds = new_fds;

	return 0;
}

static inline void reset_poll_fds(struct re *re)
{
	re->fds = mem_deref(re->fds);
}
#endif


#ifdef HAVE_EPOLL
static int set_epoll_fds(struct re *re, re_sock_t fd, int flags)
{
	struct epoll_event event;
	int err = 0;

	if (re->epfd < 0)
		return EBADFD;

	memset(&event, 0, sizeof(event));

	DEBUG_INFO("set_epoll_fds: fd=%d flags=0x%02x\n", fd, flags);

	if (flags) {
		event.data.fd = fd;

		if (flags & FD_READ)
			event.events |= EPOLLIN;
		if (flags & FD_WRITE)
			event.events |= EPOLLOUT;
		if (flags & FD_EXCEPT)
			event.events |= EPOLLERR;

		/* Try to add it first */
		if (-1 == epoll_ctl(re->epfd, EPOLL_CTL_ADD, fd, &event)) {

			/* If already exist then modify it */
			if (EEXIST == errno) {

				if (-1 == epoll_ctl(re->epfd, EPOLL_CTL_MOD,
						    fd, &event)) {
					err = errno;
					DEBUG_WARNING("epoll_ctl:"
						      " EPOLL_CTL_MOD:"
						      " fd=%d (%m)\n",
						      fd, err);
				}
			}
			else {
				err = errno;
				DEBUG_WARNING("epoll_ctl: EPOLL_CTL_ADD:"
					      " fd=%d (%m)\n",
					      fd, err);
			}
		}
	}
	else {
		if (-1 == epoll_ctl(re->epfd, EPOLL_CTL_DEL, fd, &event)) {
			err = errno;
			DEBUG_INFO("epoll_ctl: EPOLL_CTL_DEL: fd=%d (%m)\n",
				   fd, err);
		}
	}

	return err;
}
#endif


#ifdef HAVE_KQUEUE
static int set_kqueue_fds(struct re *re, re_sock_t fd, int flags)
{
	struct kevent kev[2];
	int r, n = 0;

	memset(kev, 0, sizeof(kev));

	/* always delete the events */
	EV_SET(&kev[0], fd, EVFILT_READ,  EV_DELETE, 0, 0, 0);
	EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
	kevent(re->kqfd, kev, 2, NULL, 0, NULL);

	memset(kev, 0, sizeof(kev));

	if (flags & FD_WRITE) {
		EV_SET(&kev[n], fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
		++n;
	}
	if (flags & FD_READ) {
		EV_SET(&kev[n], fd, EVFILT_READ, EV_ADD, 0, 0, 0);
		++n;
	}

	if (n) {
		r = kevent(re->kqfd, kev, n, NULL, 0, NULL);
		if (r < 0) {
			int err = errno;

			DEBUG_WARNING("set: [fd=%d, flags=%x] kevent: %m\n",
				      fd, flags, err);
			return err;
		}
	}

	return 0;
}
#endif


/**
 * Rebuild the file descriptor mapping table. This must be done whenever
 * the polling method is changed.
 */
static int rebuild_fds(struct re *re)
{
	int err = 0;

	DEBUG_INFO("rebuilding fds (nfds=%d)\n", re->nfds);

	/* Update fd sets */
	switch (re->method) {

#ifdef HAVE_POLL
	case METHOD_POLL:
		/* Just release the poll fd list, let fd_poll re-create it
		 * when needed */
		reset_poll_fds(re);
		break;
#endif
#ifdef HAVE_EPOLL
	case METHOD_EPOLL:
		for (int i = 0; i < re->nfds; ++i) {
			err = set_epoll_fds(re, i, re->fhs[i].flags);
			if (err)
				break;
		}
		break;
#endif

#ifdef HAVE_KQUEUE
	case METHOD_KQUEUE:
		for (int i = 0; i < re->nfds; ++i) {
			err = set_kqueue_fds(re, i, re->fhs[i].flags);
			if (err)
				break;
		}
		break;
#endif

	default:
		break;
	}

	return err;
}


static int poll_init(struct re *re)
{
	DEBUG_INFO("poll init (maxfds=%d)\n", re->maxfds);

	if (!re->maxfds) {
		DEBUG_WARNING("poll init: maxfds is 0\n");
		return EINVAL;
	}

	switch (re->method) {

#ifdef HAVE_EPOLL
	case METHOD_EPOLL:
		if (!re->events) {
			DEBUG_INFO("allocate %u bytes for epoll set\n",
				   re->maxfds * sizeof(*re->events));
			re->events = mem_zalloc(re->maxfds*sizeof(*re->events),
					      NULL);
			if (!re->events)
				return ENOMEM;
		}

		if (re->epfd < 0
		    && -1 == (re->epfd = epoll_create(re->maxfds))) {

			int err = errno;

			DEBUG_WARNING("epoll_create: %m (maxfds=%d)\n",
				      err, re->maxfds);
			return err;
		}
		DEBUG_INFO("init: epoll_create() epfd=%d\n", re->epfd);
		break;
#endif

#ifdef HAVE_KQUEUE
	case METHOD_KQUEUE:

		if (!re->evlist) {
			size_t sz = re->maxfds * sizeof(*re->evlist);
			re->evlist = mem_zalloc(sz, NULL);
			if (!re->evlist)
				return ENOMEM;
		}

		if (re->kqfd < 0) {
			re->kqfd = kqueue();
			if (re->kqfd < 0)
				return errno;
			DEBUG_INFO("kqueue: fd=%d\n", re->kqfd);
		}

		break;
#endif

	default:
		break;
	}
	return 0;
}


/** Free all resources */
static void poll_close(struct re *re)
{
	if (!re)
		return;

	DEBUG_INFO("poll close\n");

	re->fhs = mem_deref(re->fhs);
	re->nfds = 0;
	re->maxfds = 0;

#ifdef HAVE_POLL
	re->fds = mem_deref(re->fds);
#endif
#ifdef HAVE_EPOLL
	DEBUG_INFO("poll_close: epfd=%d\n", re->epfd);

	if (re->epfd >= 0) {
		(void)close(re->epfd);
		re->epfd = -1;
	}

	re->events = mem_deref(re->events);
#endif

#ifdef HAVE_KQUEUE
	if (re->kqfd >= 0) {
		close(re->kqfd);
		re->kqfd = -1;
	}

	re->evlist = mem_deref(re->evlist);
#endif
}


static int poll_setup(struct re *re)
{
	int err;

	err = fd_setsize(DEFAULT_MAXFDS);
	if (err)
		goto out;

	if (METHOD_NULL == re->method) {
		err = poll_method_set(poll_method_best());
		if (err)
			goto out;

		DEBUG_INFO("poll setup: poll method not set - set to `%s'\n",
			   poll_method_name(re->method));
	}

	err = poll_init(re);

 out:
	if (err)
		poll_close(re);

	return err;
}


/**
 * Listen for events on a file descriptor
 *
 * @param fd     File descriptor
 * @param flags  Wanted event flags
 * @param fh     Event handler
 * @param arg    Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int fd_listen(re_sock_t fd, int flags, fd_h *fh, void *arg)
{
	struct re *re = re_get();
	int err = 0;
	int i;

	if (!re) {
		DEBUG_WARNING("fd_listen: re not ready\n");
		return EINVAL;
	}

	DEBUG_INFO("fd_listen: fd=%d flags=0x%02x\n", fd, flags);

#ifndef RELEASE
	err = re_thread_check();
	if (err)
		return err;
#endif

	if (fd == BAD_SOCK) {
		DEBUG_WARNING("fd_listen: corrupt fd %d\n", fd);
		return EBADF;
	}

	if ((flags && !fh) || (!flags && fh)) {
		DEBUG_WARNING("fd_listen: both handler and and flags "
			"must be non-empty or both empty\n");
		return EINVAL;
	}

	if (flags) {
		/* Add a new fd */
		err = poll_setup(re);
		if (err)
			return err;

		if (re->method != METHOD_EPOLL && re->nfds >= re->maxfds) {
			DEBUG_WARNING("fd_listen: fd=%d flags=0x%02x"
				      " - Max %d fds limit reached\n",
				      fd, flags, re->maxfds);
			return EMFILE;
		}

		if (re->method == METHOD_SELECT && fd >= FD_SETSIZE) {
			DEBUG_WARNING("fd_listen: fd=%d flags=0x%02x"
				" - Poll method 'select' cannot be used "
				"with fds >= %d\n",
				fd, flags, (int)FD_SETSIZE);
			return EMFILE;
		}

		err = insert_fd_handler(re, fd, flags, fh, arg, &i);
		if (err)
			return err;
	}
	else {
		/* Remove fd */
		bool found = false;
		err = erase_fd_handler(re, fd, &i, &found);
		if (err)
			return err;
		if (!found)
			return 0;
	}

	switch (re->method) {

#ifdef HAVE_POLL
	case METHOD_POLL:
		/* Just release the poll fd list, let fd_poll re-create it
		 * when needed */
		reset_poll_fds(re);
		break;
#endif

#ifdef HAVE_EPOLL
	case METHOD_EPOLL:
		if (re->epfd < 0) {
			err = EBADFD;
			break;
		}
		err = set_epoll_fds(re, fd, flags);
		break;
#endif

#ifdef HAVE_KQUEUE
	case METHOD_KQUEUE:
		err = set_kqueue_fds(re, fd, flags);
		break;
#endif

	default:
		break;
	}

	if (err) {
		if (flags) {
			erase_fd_handler_no_realloc(re, i);
			DEBUG_WARNING("fd_listen: fd=%d flags=0x%02x (%m)\n",
				      fd, flags, err);
		}
	}

	return err;
}


/**
 * Stop listening for events on a file descriptor
 *
 * @param fd     File descriptor
 */
void fd_close(re_sock_t fd)
{
	(void)fd_listen(fd, 0, NULL, NULL);
}


/**
 * Polling loop
 *
 * @param re Poll state.
 *
 * @return 0 if success, otherwise errorcode
 */
static int fd_poll(struct re *re)
{
	const uint64_t to = tmr_next_timeout(&re->tmrl);
	struct fhs* const fhs = mem_ref(re->fhs);
	const int nfds = re->nfds;
	const enum poll_method method = re->method;
	int err = 0;
	int i, n, index;
	bool fhs_changed;
#ifdef HAVE_SELECT
	fd_set rfds, wfds, efds;
#endif
#ifdef HAVE_POLL
	struct pollfd* poll_fds = NULL;
#endif

	DEBUG_INFO("next timer: %llu ms\n", to);

	/* Wait for I/O */
	switch (method) {

#ifdef HAVE_POLL
	case METHOD_POLL:
		poll_fds = mem_ref(re->fds);
		if (!poll_fds) {
			err = create_poll_fds(re, &poll_fds);
			if (err)
				goto out;
			re->fds = mem_ref(poll_fds);
		}

		re_unlock(re);
		n = poll(poll_fds, nfds, to ? (int)to : -1);
		re_lock(re);
		break;
#endif
#ifdef HAVE_SELECT
	case METHOD_SELECT: {
		struct timeval tv;

		/* Clear and update fd sets */
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);

		for (i=0; i<nfds; ++i) {
			re_sock_t fd = fhs[i].fd;
			if (!fhs[i].fh)
				continue;

			if (fhs[i].flags & FD_READ)
				FD_SET(fd, &rfds);
			if (fhs[i].flags & FD_WRITE)
				FD_SET(fd, &wfds);
			if (fhs[i].flags & FD_EXCEPT)
				FD_SET(fd, &efds);
		}

#ifdef WIN32
		tv.tv_sec  = (long) to / 1000;
#else
		tv.tv_sec  = (time_t) to / 1000;
#endif
		tv.tv_usec = (uint32_t) (to % 1000) * 1000;
		re_unlock(re);
		n = select(nfds, &rfds, &wfds, &efds, to ? &tv : NULL);
		re_lock(re);
	}
		break;
#endif
#ifdef HAVE_EPOLL
	case METHOD_EPOLL:
		re_unlock(re);
		n = epoll_wait(re->epfd, re->events, re->maxfds,
			       to ? (int)to : -1);
		re_lock(re);
		break;
#endif

#ifdef HAVE_KQUEUE
	case METHOD_KQUEUE: {
		struct timespec timeout;

		timeout.tv_sec = (time_t) (to / 1000);
		timeout.tv_nsec = (to % 1000) * 1000000;

		re_unlock(re);
		n = kevent(re->kqfd, NULL, 0, re->evlist, re->maxfds,
			   to ? &timeout : NULL);
		re_lock(re);
		}
		break;
#endif

	default:
		(void)to;
		DEBUG_WARNING("no polling method set\n");
		err = EINVAL;
		goto out;
	}

	if (n < 0) {
		err = ERRNO_SOCK;
		goto out;
	}

	fhs_changed = fhs != re->fhs;

	/* Check for events */
	for (i=0; (n > 0) && (i < nfds); ++i) {
		re_sock_t fd;
		int flags = 0;

		switch (method) {

#ifdef HAVE_POLL
		case METHOD_POLL:
			fd = poll_fds[i].fd;
			index = fhs_changed ? find_fd_handler(re, fd) : i;
			if (poll_fds[i].revents & POLLIN)
				flags |= FD_READ;
			if (poll_fds[i].revents & POLLOUT)
				flags |= FD_WRITE;
			if (poll_fds[i].revents & (POLLERR|POLLHUP|POLLNVAL))
				flags |= FD_EXCEPT;
			if (poll_fds[i].revents & POLLNVAL) {
				DEBUG_WARNING("event: i=%d POLLNVAL"
					      " (fds.fd=%d,"
					      " fds.events=0x%02x)\n",
					      i, poll_fds[i].fd,
					      poll_fds[i].events);
			}
			/* Clear events */
			poll_fds[i].revents = 0;
			break;
#endif
#ifdef HAVE_SELECT
		case METHOD_SELECT:
			fd = re->fhs[i].fd;
			index = fhs_changed ? find_fd_handler(re, fd) : i;
			if (FD_ISSET(fd, &rfds))
				flags |= FD_READ;
			if (FD_ISSET(fd, &wfds))
				flags |= FD_WRITE;
			if (FD_ISSET(fd, &efds))
				flags |= FD_EXCEPT;
			break;
#endif
#ifdef HAVE_EPOLL
		case METHOD_EPOLL:
			fd = re->events[i].data.fd;
			index = find_fd_handler(re, fd);

			if (re->events[i].events & EPOLLIN)
				flags |= FD_READ;
			if (re->events[i].events & EPOLLOUT)
				flags |= FD_WRITE;
			if (re->events[i].events & (EPOLLERR|EPOLLHUP))
				flags |= FD_EXCEPT;

			if (!flags) {
				DEBUG_WARNING("epoll: no flags fd=%d\n", fd);
			}

			break;
#endif

#ifdef HAVE_KQUEUE
		case METHOD_KQUEUE: {

			struct kevent *kev = &re->evlist[i];

			fd = (int)kev->ident;
			index = find_fd_handler(re, fd);

			if (fd >= re->maxfds) {
				DEBUG_WARNING("large fd=%d\n", fd);
				break;
			}

			if (kev->filter == EVFILT_READ)
				flags |= FD_READ;
			else if (kev->filter == EVFILT_WRITE)
				flags |= FD_WRITE;
			else {
				DEBUG_WARNING("kqueue: unhandled "
					      "filter %x\n",
					      kev->filter);
			}

			if (kev->flags & EV_EOF) {
				flags |= FD_EXCEPT;
			}
			if (kev->flags & EV_ERROR) {
				DEBUG_WARNING("kqueue: EV_ERROR on fd %d\n",
					      fd);
			}

			if (!flags) {
				DEBUG_WARNING("kqueue: no flags fd=%d\n", fd);
			}
		}
			break;
#endif

		default:
			err = EINVAL;
			goto out;
		}

		if (!flags || index >= re->nfds)
			continue;

		if (re->fhs[index].fh) {
#if MAIN_DEBUG
			fd_handler(re, index, flags);
#else
			re->fhs[index].fh(flags, re->fhs[index].arg);
#endif
		}

		/* Check if polling method was changed */
		if (re->update) {
			re->update = false;
			err = 0;
			goto out;
		}

		--n;
	}

out:
#ifdef HAVE_POLL
	if (poll_fds)
		mem_deref(poll_fds);
#endif
	mem_deref(fhs);
	return err;
}


/**
 * Set the maximum number of file descriptors
 *
 * @note Only first call inits maxfds and fhs, so call after libre_init() and
 * before re_main() in custom applications.
 *
 * @param maxfds Max FDs. 0 to free and -1 for RLIMIT_NOFILE (Linux/Unix only)
 *
 *
 * @return 0 if success, otherwise errorcode
 */
int fd_setsize(int maxfds)
{
	struct re *re = re_get();

	if (!re) {
		DEBUG_WARNING("fd_setsize: re not ready\n");
		return EINVAL;
	}

	if (!maxfds) {
		fd_debug();
		poll_close(re);
		return 0;
	}

#ifdef WIN32
	if (maxfds < 0)
		return ENOSYS;
#else
	if (maxfds < 0) {
		struct rlimit limits;
		int err;

		err = getrlimit(RLIMIT_NOFILE, &limits);
		if (err) {
			DEBUG_WARNING("fd_setsize: error rlimit: %m\n", err);
			return err;
		}

		maxfds = (int)limits.rlim_cur;
	}
#endif

	if (!re->maxfds)
		re->maxfds = maxfds;

	return 0;
}


/**
 * Print all file descriptors in-use
 */
void fd_debug(void)
{
	const struct re *re = re_get();
	int i;

	if (!re) {
		DEBUG_WARNING("fd_debug: re not ready\n");
		return;
	}

	if (!re->fhs)
		return;

	for (i=0; i<re->nfds; i++) {

		if (!re->fhs[i].flags)
			continue;

		(void)re_fprintf(stderr,
				 "fd %d in use: flags=%x fh=%p arg=%p\n",
				 re->fhs[i].fd, re->fhs[i].flags,
				 re->fhs[i].fh, re->fhs[i].arg);
	}
}


#ifdef HAVE_SIGNAL
/* Thread-safe signal handling */
static void signal_handler(int sig)
{
	struct re *re = re_get();

	if (!re) {
		DEBUG_WARNING("signal_handler: re not ready\n");
		return;
	}

	(void)signal(sig, signal_handler);
	re->sig = sig;
}
#endif


/**
 * Main polling loop for async I/O events. This function will only return when
 * re_cancel() is called or an error occured.
 *
 * @param signalh Optional Signal handler
 *
 * @return 0 if success, otherwise errorcode
 */
int re_main(re_signal_h *signalh)
{
	struct re *re = re_get();
	int err;

	if (!re) {
		DEBUG_WARNING("re_main: re not ready\n");
		return EINVAL;
	}

#ifdef HAVE_SIGNAL
	if (signalh) {
		(void)signal(SIGINT, signal_handler);
		(void)signal(SIGALRM, signal_handler);
		(void)signal(SIGTERM, signal_handler);
	}
#endif

	if (re->polling) {
		DEBUG_WARNING("main loop already polling\n");
		return EALREADY;
	}

	err = poll_setup(re);
	if (err)
		goto out;

	DEBUG_INFO("Using async I/O polling method: `%s'\n",
		   poll_method_name(re->method));

	re->polling = true;

	re_lock(re);
	for (;;) {

		if (re->sig) {
			if (signalh)
				signalh(re->sig);

			re->sig = 0;
		}

		if (!re->polling) {
			err = 0;
			break;
		}


		err = fd_poll(re);
		if (err) {
			if (EINTR == err)
				continue;

#ifdef DARWIN
			/* NOTE: workaround for Darwin */
			if (EBADF == err)
				continue;

#endif
#ifdef WIN32
			if (WSAEINVAL == err) {
				tmr_poll(&re->tmrl);
				continue;
			}
#endif
			break;
		}

		tmr_poll(&re->tmrl);
	}
	re_unlock(re);

 out:
	re->polling = false;

	return err;
}


/**
 * Cancel the main polling loop
 */
void re_cancel(void)
{
	struct re *re = re_get();

	if (!re) {
		DEBUG_WARNING("re_cancel: re not ready\n");
		return;
	}

	re->polling = false;
}


/**
 * Debug the main polling loop
 *
 * @param pf     Print handler where debug output is printed to
 * @param unused Unused parameter
 *
 * @return 0 if success, otherwise errorcode
 */
int re_debug(struct re_printf *pf, void *unused)
{
	struct re *re = re_get();
	int err = 0;

	(void)unused;

	if (!re) {
		DEBUG_WARNING("re_debug: re not ready\n");
		return EINVAL;
	}

	err |= re_hprintf(pf, "re main loop:\n");
	err |= re_hprintf(pf, "  maxfds:  %d\n", re->maxfds);
	err |= re_hprintf(pf, "  nfds:    %d\n", re->nfds);
	err |= re_hprintf(pf, "  method:  %d (%s)\n", re->method,
			  poll_method_name(re->method));

	return err;
}


/**
 * Set async I/O polling method. This function can also be called while the
 * program is running.
 *
 * @param method New polling method
 *
 * @return 0 if success, otherwise errorcode
 */
int poll_method_set(enum poll_method method)
{
	struct re *re = re_get();
	int err;

	err = fd_setsize(DEFAULT_MAXFDS);
	if (err)
		return err;

	switch (method) {

#ifdef HAVE_POLL
	case METHOD_POLL:
		break;
#endif
#ifdef HAVE_SELECT
	case METHOD_SELECT:
		if (re->maxfds > (int)FD_SETSIZE) {
			DEBUG_WARNING("SELECT: maxfds > FD_SETSIZE\n");
			return EMFILE;
		}
		break;
#endif
#ifdef HAVE_EPOLL
	case METHOD_EPOLL:
		break;
#endif
#ifdef HAVE_KQUEUE
	case METHOD_KQUEUE:
		break;
#endif
	default:
		DEBUG_WARNING("poll method not supported: '%s'\n",
			      poll_method_name(method));
		return EINVAL;
	}

	re->method = method;
	re->update = true;

	DEBUG_INFO("Setting async I/O polling method to `%s'\n",
		   poll_method_name(re->method));

	err = poll_init(re);
	if (err)
		return err;

	return rebuild_fds(re);
}


/**
 * Add a worker thread for this thread
 *
 * @note: for main thread this is called by libre_init()
 *
 * @return 0 if success, otherwise errorcode
 */
int re_thread_init(void)
{
	struct re *re;
	int err;

	call_once(&flag, re_once);

	re = tss_get(key);
	if (re) {
		DEBUG_WARNING("thread_init: already added for thread\n");
		return EALREADY;
	}

	err = re_alloc(&re);
	if (err)
		return err;

	if (!re_global)
		re_global = re;

	err = tss_set(key, re);
	if (err)
		DEBUG_WARNING("thread_init: tss_set error\n");

	return err;
}


/**
 * Remove the worker thread for this thread
 */
void re_thread_close(void)
{
	struct re *re;

	call_once(&flag, re_once);

	re = tss_get(key);
	if (re) {
		if (re == re_global)
			re_global = NULL;
		mem_deref(re);
		tss_set(key, NULL);
	}
}


/**
 * Enter an 're' thread
 */
void re_thread_enter(void)
{
	struct re *re = re_get();

	if (!re) {
		DEBUG_WARNING("re_thread_enter: re not ready\n");
		return;
	}

	re_lock(re);

	/* set only for non-re threads */
	if (!thrd_equal(re->tid, thrd_current()))
		re->thread_enter = true;
}


/**
 * Leave an 're' thread
 */
void re_thread_leave(void)
{
	struct re *re = re_get();

	if (!re) {
		DEBUG_WARNING("re_thread_leave: re not ready\n");
		return;
	}

	re->thread_enter = false;
	re_unlock(re);
}


/**
 * Attach the current thread to re context
 */
int re_thread_attach(struct re *context)
{
	struct re *re;

	if (!context)
		return EINVAL;

	call_once(&flag, re_once);

	re = tss_get(key);
	if (re) {
		if (re != context)
			return EALREADY;
		return 0;
	}

	tss_set(key, context);

	return 0;
}


/**
 * Detach the current thread from re context
 */
void re_thread_detach(void)
{
	call_once(&flag, re_once);

	tss_set(key, NULL);
}


/**
 * Set an external mutex for this thread
 *
 * @param mutexp Pointer to external mutex, NULL to use internal
 */
void re_set_mutex(void *mutexp)
{
	struct re *re = re_get();

	if (!re) {
		DEBUG_WARNING("re_set_mutex: re not ready\n");
		return;
	}

	re->mutexp = mutexp ? mutexp : re->mutex;
}


/**
 * Check for NON-RE thread calls
 *
 * @return 0 if success, otherwise EPERM
 */
int re_thread_check(void)
{
	struct re *re = re_get();

	if (!re)
		return EINVAL;

	if (re->thread_enter)
		return 0;

	if (thrd_equal(re->tid, thrd_current()))
		return 0;

	DEBUG_WARNING("thread check: called from a NON-RE thread without "
		      "thread_enter()!\n");

#if DEBUG_LEVEL > 5
	struct btrace trace;
	btrace(&trace);
	DEBUG_INFO("%H", btrace_println, &trace);
#endif

	return EPERM;
}


/**
 * Get the timer-list for this thread
 *
 * @return Timer list
 *
 * @note only used by tmr module
 */
struct list *tmrl_get(void);
struct list *tmrl_get(void)
{
	struct re *re = re_get();

	if (!re) {
		DEBUG_WARNING("tmrl_get: re not ready\n");
		return NULL;
	}

	return &re->tmrl;
}
