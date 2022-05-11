#include <re_types.h>
#include <re_mem.h>
#include <re_thread.h>


int thrd_create_name(thrd_t *thr, const char *name, thrd_start_t func,
		     void *arg)
{
	int err;
	(void)name; /* @TODO implement */

	if (!thr || !func)
		return EINVAL;

	err = thrd_create(thr, func, arg);

	return err;
}
