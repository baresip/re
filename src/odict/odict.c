/**
 * @file odict.c  Ordered Dictionary
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include "re_types.h"
#include "re_fmt.h"
#include "re_mem.h"
#include "re_list.h"
#include "re_hash.h"
#include "re_odict.h"
#include "odict.h"
#include <math.h>
#include <float.h>


static void destructor(void *arg)
{
	struct odict *o = arg;

	hash_clear(o->ht);
	list_flush(&o->lst);
	mem_deref(o->ht);
}


int odict_alloc(struct odict **op, uint32_t hash_size)
{
	struct odict *o;
	int err;

	if (!op || !hash_size)
		return EINVAL;

	o = mem_zalloc(sizeof(*o), destructor);
	if (!o)
		return ENOMEM;

	err = hash_alloc(&o->ht, hash_valid_size(hash_size));
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(o);
	else
		*op = o;

	return err;
}


const struct odict_entry *odict_lookup(const struct odict *o, const char *key)
{
	struct le *le;

	if (!o || !key)
		return NULL;

	le = list_head(hash_list(o->ht, hash_fast_str(key)));

	while (le) {
		const struct odict_entry *e = le->data;

		if (!str_cmp(e->key, key))
			return e;

		le = le->next;
	}

	return NULL;
}


size_t odict_count(const struct odict *o, bool nested)
{
	struct le *le;
	size_t n = 0;

	if (!o)
		return 0;

	if (!nested)
		return list_count(&o->lst);

	for (le=o->lst.head; le; le=le->next) {

		const struct odict_entry *e = le->data;

		switch (e->type) {

		case ODICT_OBJECT:
		case ODICT_ARRAY:
			n += odict_count(e->u.odict, true);
			break;

		default:
			n += 1;  /* count all entries */
			break;
		}
	}

	return n;
}


int odict_debug(struct re_printf *pf, const struct odict *o)
{
	struct le *le;
	int err;

	if (!o)
		return 0;

	err = re_hprintf(pf, "{");

	for (le=o->lst.head; le; le=le->next) {

		const struct odict_entry *e = le->data;

		err |= re_hprintf(pf, " %H", odict_entry_debug, e);
	}

	err |= re_hprintf(pf, " }");

	return err;
}


static bool cmp_double(double a, double b)
{
	return fabs(a - b) < DBL_EPSILON;
}


bool odict_value_compare(const struct odict_entry *e1,
	const struct odict_entry *e2, bool ignore_order)
{
	if (!e1 || !e2)
		return false;

	if (odict_entry_type(e1) != odict_entry_type(e2))
		return false;

	switch (odict_entry_type(e1)) {

	case ODICT_OBJECT:
		return odict_compare(odict_entry_object(e1),
				     odict_entry_object(e2), ignore_order);

	case ODICT_ARRAY:
		return odict_compare(odict_entry_array(e1),
				     odict_entry_array(e2), ignore_order);

	case ODICT_INT:
		if (odict_entry_int(e1) == odict_entry_int(e2))
			return true;
		break;

	case ODICT_DOUBLE:
		if (cmp_double(odict_entry_dbl(e1), odict_entry_dbl(e2)))
			return true;
		break;

	case ODICT_STRING:
		if ( 0 == str_cmp(odict_entry_str(e1), odict_entry_str(e2)))
			return true;
		break;

	case ODICT_BOOL:
		if (odict_entry_boolean(e1) == odict_entry_boolean(e2))
			return true;
		break;

	case ODICT_NULL: /* no check */
		return true;

	default:
		return false;
	}

	return false;
}


/* return TRUE if equal */
bool odict_compare(const struct odict *dict1, const struct odict *dict2,
	bool ignore_order)
{
	struct le *le1, *le2;

	if (!dict1 || !dict2)
		return false;

	if (odict_count(dict1, true) != odict_count(dict2, true))
		return false;

	for (le1 = dict1->lst.head, le2 = dict2->lst.head;
	     le1 && le2;
	     le1 = le1->next, le2 = le2->next) {

		const struct odict_entry *e1 = le1->data;
		const struct odict_entry *e2;

		if (ignore_order)
			e2 = odict_lookup(dict2, odict_entry_key(e1));
		else
			e2 = le2->data;

		if (0 != str_cmp(odict_entry_key(e1), odict_entry_key(e2)))
			return false;

		if (!odict_value_compare(e1, e2, ignore_order))
			return false;
	}

	return true;  /* equal */
}
