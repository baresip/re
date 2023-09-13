#include <re.h>
#include "test.h"

enum wrap_type {
	WRAP_INT,
	WRAP_DATA
};

struct wrap_entry {
	struct le le;
	char func[64];
	enum wrap_type type;
	union {
		int ret_int;
		void *ret_data;
	} u;
};

static struct list wrapl = LIST_INIT;


static void entry_destruct(void *arg)
{
	struct wrap_entry *e = arg;
	list_unlink(&e->le);
}


static struct wrap_entry *wrap_entry_alloc(const char *func)
{
	struct wrap_entry *e;

	e = mem_alloc(sizeof(struct wrap_entry), entry_destruct);
	if (!e)
		return NULL;

	str_ncpy(e->func, func, sizeof(e->func));

	list_append(&wrapl, &e->le, e);

	return e;
}


int wrap_will_return_int(const char *func, int ret)
{
	struct wrap_entry *e;

	if (!func)
		return EINVAL;

	e = wrap_entry_alloc(func);
	if (!e)
		return ENOMEM;

	e->type = WRAP_INT;
	e->u.ret_int = ret;

	return 0;
}


int wrap_will_return_data(const char *func, void *data)
{
	struct wrap_entry *e;

	if (!func)
		return EINVAL;

	e = wrap_entry_alloc(func);
	if (!e)
		return ENOMEM;

	e->type = WRAP_DATA;
	e->u.ret_data = data;

	return 0;
}


int wrap_return_int(const char *func, int *ret)
{
	struct le *le;

	if (!func)
		return EINVAL;

	LIST_FOREACH(&wrapl, le)
	{
		struct wrap_entry *e = le->data;

		if (e->type != WRAP_INT)
			continue;

		if (0 == str_casecmp(e->func, func)) {
			*ret = e->u.ret_int;
			mem_deref(e);
			return 0;
		}
	}

	return ENODATA;
}


void *wrap_return_data(const char *func)
{
	struct le *le;
	void *data;

	if (!func)
		return NULL;

	LIST_FOREACH(&wrapl, le)
	{
		struct wrap_entry *e = le->data;

		if (e->type != WRAP_DATA)
			continue;

		if (0 == str_casecmp(e->func, func)) {
			data = e->u.ret_data;
			mem_deref(e);
			return data;
		}
	}

	return NULL;
}
