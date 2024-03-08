#include <sys/epoll.h>

#include <re.h>
#include "test.h"


int __wrap_epoll_create(int size);
int __real_epoll_create(int size);

int __wrap_epoll_create(int size)
{
	int ret;

	int err = wrap_return_int("epoll_create", &ret);

	return err ? __real_epoll_create(size) : ret;
}


int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int __real_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	int ret;

	int err = wrap_return_int("epoll_create", &ret);

	return err ? __real_epoll_ctl(epfd, op, fd, event) : ret;
}
