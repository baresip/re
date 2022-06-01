/**
 * @file re_poll.h  Interface to external main polling
 *
 * Copyright (C) 2022 Commend.com - c.spielberger@commend.com
 */

#ifdef HAVE_SELECT
int re_prepare_select(int maxfds,
		fd_set *rfds, fd_set *wfds, fd_set *efds);
#endif
#ifdef HAVE_POLL
int re_prepare_poll(int maxfds, struct pollfd *fds);
#endif
#ifdef HAVE_EPOLL
int re_prepare_epoll(int maxfds, struct epoll_event *events, int epfd);
#endif
#ifdef HAVE_KQUEUE
int re_prepare_kqueue(int maxfds, struct kevent *evlist, int kqfd);
#endif
int re_process(int n);
uint64_t re_next_timeout(void);

