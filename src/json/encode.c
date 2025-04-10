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
	struct odict *array;
	struct le *le;
	int err;

	if (!e)
		return 0;

	switch (odict_entry_type(e)) {

	case ODICT_OBJECT:
		err = json_encode_odict(pf, odict_entry_object(e));
		break;

	case ODICT_ARRAY:
		array = odict_entry_array(e);
		if (!array)
			return 0;

		err = re_hprintf(pf, "[");

		for (le=array->lst.head; le; le=le->next) {

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

enum odict_bracket {
	OB_Init = 0,
	OB_None,
	OB_Curly,
	OB_Square,
};

int json_encode_odict(struct re_printf *pf, const struct odict *o)
{
	struct le *le;
	int err = 0;
	enum odict_bracket b = OB_Init;

	if (!o)
		return 0;

	for (le=o->lst.head; le; le=le->next) {

		const struct odict_entry *e = le->data;

		if (b == OB_Init) {
			if (str_isset(odict_entry_key(e))) {
				err = re_hprintf(pf, "{");
				b = OB_Curly;
			}
			else if (odict_entry_array(e)) {
				err = re_hprintf(pf, "[");
				b = OB_Square;
			} else
				b = OB_None;
		}

		if (str_isset(odict_entry_key(e)))
			err |= re_hprintf(pf, "\"%H\":%H%s",
					utf8_encode, odict_entry_key(e),
					encode_entry, e,
					le->next ? "," : "");
		else
			err |= re_hprintf(pf, "%H%s",
					encode_entry, e,
					le->next ? "," : "");
	}

	if (b == OB_Curly)
		err |= re_hprintf(pf, "}");
	else if (b == OB_Square)
		err |= re_hprintf(pf, "]");
	else if (b == OB_Init)
		err |= re_hprintf(pf, "{}");

	return err;
}
