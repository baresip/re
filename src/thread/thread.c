#include <re_types.h>
#include <re_mem.h>
#include <re_thread.h>


static void mtx_destructor(void *data)
{
	mtx_t *mtx = data;

	mtx_destroy(mtx);
}


int mtx_alloc(mtx_t **mtx)
{
	mtx_t *m;
	int err;

	if (!mtx)
		return EINVAL;

	m = mem_alloc(sizeof(mtx_t), NULL);
	if (!m)
		return ENOMEM;

	err = mtx_init(m, mtx_plain);
	if (err == thrd_error) {
		err = EBUSY;
		goto out;
	}

	mem_destructor(m, mtx_destructor);

	*mtx = m;

out:
	if (err)
		mem_deref(m);

	return err;
}


int thrd_create_name(thrd_t *thr, const char *name, thrd_start_t func,
		     void *arg)
{
	(void)name; /* @TODO implement */

	if (!thr || !func)
		return thrd_error;

	return thrd_create(thr, func, arg);
}
