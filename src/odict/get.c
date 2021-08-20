/**
 * @file get.c  Ordered Dictionary -- high level accessors
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


struct odict *odict_get_object(const struct odict *o, const char *key)
{
	const struct odict_entry *entry;

	if (!o || !key)
		return NULL;

	entry = odict_get_type(o, ODICT_OBJECT, key);
	if (!entry)
		return NULL;

	return entry->u.odict;
}


struct odict *odict_get_array(const struct odict *o, const char *key)
{
	const struct odict_entry *entry;

	if (!o || !key)
		return NULL;

	entry = odict_get_type(o, ODICT_ARRAY, key);
	if (!entry)
		return NULL;

	return entry->u.odict;
}


struct odict *odict_entry_object(const struct odict_entry *e)
{
	if (!e || e->type != ODICT_OBJECT )
		return NULL;

	return e->u.odict;
}

struct odict *odict_entry_array(const struct odict_entry *e)
{
	if (!e || e->type != ODICT_ARRAY)
		return NULL;

	return e->u.odict;
}


char *odict_entry_str(const struct odict_entry *e)
{
	if (!e || e->type != ODICT_STRING)
		return NULL;

	return e->u.str;
}


int64_t odict_entry_int(const struct odict_entry *e)
{
	if (!e || e->type != ODICT_INT)
		return 0;

	return e->u.integer;
}


double odict_entry_dbl(const struct odict_entry *e)
{
	if (!e || e->type != ODICT_DOUBLE)
		return 0.0;

	return e->u.dbl;
}


bool odict_entry_boolean(const struct odict_entry *e)
{
	if (!e || e->type != ODICT_BOOL)
		return false;

	return e->u.boolean;
}


enum odict_type odict_entry_type(const struct odict_entry *e)
{
	if (!e)
		return ODICT_ERR;

	return e->type;
}


const char *odict_entry_key(const struct odict_entry *e)
{
	if (!e)
		return NULL;

	return e->key;
}


const struct odict_entry *odict_get_type(const struct odict *o,
					 enum odict_type type, const char *key)
{
	const struct odict_entry *entry;

	if (!o || !key)
		return NULL;

	entry = odict_lookup(o, key);
	if (!entry)
		return NULL;

	if (entry->type != type)
		return NULL;

	return entry;
}


const char *odict_string(const struct odict *o, const char *key)
{
	const struct odict_entry *entry;

	entry = odict_get_type(o, ODICT_STRING, key);
	if (!entry)
		return NULL;

	return entry->u.str;
}


bool odict_get_number(const struct odict *o, uint64_t *num, const char *key)
{
	const struct odict_entry *entry;

	if (!o || !key)
		return false;

	entry = odict_lookup(o, key);
	if (!entry)
		return false;

	switch (entry->type) {

	case ODICT_DOUBLE:
		if (num)
			*num = (uint64_t)entry->u.dbl;
		break;

	case ODICT_INT:
		if (num)
			*num = entry->u.integer;
		break;

	default:
		return false;
	}

	return true;
}


bool odict_get_boolean(const struct odict *o, bool *value, const char *key)
{
	const struct odict_entry *entry;

	entry = odict_get_type(o, ODICT_BOOL, key);
	if (!entry)
		return false;

	if (value)
		*value = entry->u.boolean;

	return true;
}
