/**
 * @file json/encode.c  JSON encoder
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_odict.h>
#include <re_json.h>


static int encode_entry(struct re_printf *pf, const struct odict_entry *e)
{
	struct odict *o;
	struct le *le;
	int err;

	if (!e)
		return 0;

	switch (odict_entry_type(e)) {

	case ODICT_OBJECT:
		o = odict_entry_object(e);
		if (!o)
			return 0;

		err = re_hprintf(pf, "{");
		for (le = o->lst.head; le; le = le->next) {

			const struct odict_entry *oe = le->data;

			err |= re_hprintf(pf, "\"%H\":%H%s", utf8_encode,
					  odict_entry_key(oe), encode_entry,
					  oe, le->next ? "," : "");
		}
		err |= re_hprintf(pf, "}");
		break;

	case ODICT_ARRAY:
		o = odict_entry_array(e);
		if (!o)
			return 0;

		err = re_hprintf(pf, "[");

		for (le=o->lst.head; le; le=le->next) {

			const struct odict_entry *ae = le->data;

			err |= re_hprintf(pf, "%H%s",
					  encode_entry, ae,
					  le->next ? "," : "");
		}

		err |= re_hprintf(pf, "]");
		break;

	case ODICT_INT:
		err = re_hprintf(pf, "%lld", odict_entry_int(e));
		break;

	case ODICT_DOUBLE:
		err = re_hprintf(pf, "%f", odict_entry_dbl(e));
		break;

	case ODICT_STRING:
		err = re_hprintf(pf, "\"%H\"", utf8_encode,
				 odict_entry_str(e));
		break;

	case ODICT_BOOL:
		err = re_hprintf(pf, "%s",
				 odict_entry_boolean(e) ? "true" : "false");
		break;

	case ODICT_NULL:
		err = re_hprintf(pf, "null");
		break;

	default:
		re_fprintf(stderr, "json: unsupported type %d\n",
			   odict_entry_type(e));
		err = EINVAL;
	}

	return err;
}


int json_encode_odict(struct re_printf *pf, const struct odict *o)
{
	struct le *le;
	int err;

	if (!o)
		return 0;

	err = re_hprintf(pf, "{");
	for (le = o->lst.head; le; le = le->next) {

		const struct odict_entry *oe = le->data;

		err |= re_hprintf(pf, "\"%H\":%H%s", utf8_encode,
				  odict_entry_key(oe), encode_entry,
				  oe, le->next ? "," : "");
	}
	err |= re_hprintf(pf, "}");

	return err;
}


int json_encode_odict_full(struct re_printf *pf, const struct odict *o)
{
	struct le *le;
	int err;

	if (!o)
		return 0;

	le = o->lst.head;
	if (!le)
		return 0;

	struct odict_entry *oe = le->data;

	err = encode_entry(pf, oe);

	return err;
}
