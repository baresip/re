/**
 * @file json.c Testcode for JSON parser
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */
#include <stdlib.h>
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "json"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

enum {
	DICT_BSIZE = 32,
	MAX_LEVELS =  8,
};

static int test_json_basic_parser(void)
{
	static const char *str =
		"{"
		"  \"name\"      : \"Herr Alfred\","
		"  \"height\"    : 1.86,"
		"  \"weight\"    : 90,"
		"  \"has_depth\" : false,"
		"  \"has_money\" : true,"
		"  \"array\"     : [1, 2, 3, \"x\", \"y\"],"
		"  \"negative\"  : -42,"
		"  \"negativef\" : -0.0042,"
		"  \"expo_pos\"  : 2.0E3,"
		"  \"expo_neg\"  : 2.0E-3,"
		"  \"foo\x1d\"   : \"foo\x1d\","
		"  \"object\"    : {"
		"    \"one\" : 1,"
		"    \"two\" : 2"
		"  }"
		"}";

	struct odict *dict = NULL, *sub;
	const struct odict_entry *o, *e;
	int err;

	err = json_decode_odict(&dict, DICT_BSIZE,
				str, strlen(str), MAX_LEVELS);
	if (err)
		goto out;

	TEST_EQUALS(12U, odict_count(dict, false));
	TEST_EQUALS(17U, odict_count(dict, true));

	o = odict_lookup(dict, "name");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_STRING, odict_entry_type(o));
	TEST_STRCMP("Herr Alfred", 11, odict_entry_str(o),
		    str_len(odict_entry_str(o)));

	o = odict_lookup(dict, "height");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_DOUBLE, odict_entry_type(o));
	TEST_ASSERT(odict_entry_dbl(o) > .0);

	o = odict_lookup(dict, "weight");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_INT, odict_entry_type(o));
	TEST_EQUALS(90, odict_entry_int(o));

	o = odict_lookup(dict, "has_depth");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_BOOL, odict_entry_type(o));
	TEST_ASSERT(!odict_entry_boolean(o));

	o = odict_lookup(dict, "has_money");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_BOOL, odict_entry_type(o));
	TEST_ASSERT(odict_entry_boolean(o));

	o = odict_lookup(dict, "array");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_ARRAY, odict_entry_type(o));
	TEST_EQUALS(5U, odict_count(odict_entry_array(o), false));
	e = odict_get_type(odict_entry_array(o), ODICT_INT, "0");
	TEST_EQUALS(1, odict_entry_int(e));
	e = odict_get_type(odict_entry_array(o), ODICT_INT, "1");
	TEST_EQUALS(2, odict_entry_int(e));
	e = odict_get_type(odict_entry_array(o), ODICT_INT, "2");
	TEST_EQUALS(3, odict_entry_int(e));

	o = odict_lookup(dict, "negative");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_INT, odict_entry_type(o));
	TEST_EQUALS(-42, odict_entry_int(o));

	o = odict_lookup(dict, "negativef");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_DOUBLE, odict_entry_type(o));
	TEST_ASSERT(odict_entry_dbl(o) < .0);

	o = odict_lookup(dict, "expo_pos");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_DOUBLE, odict_entry_type(o));
	TEST_ASSERT(odict_entry_dbl(o) > .0);

	o = odict_lookup(dict, "expo_neg");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_DOUBLE, odict_entry_type(o));
	TEST_ASSERT(odict_entry_dbl(o) > .0);

	o = odict_lookup(dict, "foo\x1d");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_STRING, odict_entry_type(o));
	TEST_STRCMP("foo\x1d", 4, odict_entry_str(o),
		    str_len(odict_entry_str(o)));

	/* object */
	o = odict_lookup(dict, "object");
	TEST_ASSERT(o != NULL);
	TEST_EQUALS(ODICT_OBJECT, odict_entry_type(o));
	sub = odict_entry_object(o);
	e = odict_lookup(sub, "one");
	TEST_ASSERT(e != NULL);
	TEST_EQUALS(ODICT_INT, odict_entry_type(e));
	TEST_EQUALS(1, odict_entry_int(e));
	e = odict_lookup(sub, "two");
	TEST_ASSERT(e != NULL);
	TEST_EQUALS(ODICT_INT, odict_entry_type(e));
	TEST_EQUALS(2, odict_entry_int(e));

	/* non-existing entry */
	o = odict_lookup(dict, "not-found");
	TEST_ASSERT(o == NULL);

 out:
	mem_deref(dict);
	return err;
}

static const struct test {
	unsigned num;
	unsigned num_total;
	unsigned full_num;
	unsigned full_num_total;
	char *str;
} testjson[] = {
	{
		0,
		0,
		1,
		0,
		"{}"
	},
	{
		1,
		1,
		1,
		1,
		"\"yyyyyyyyyy\""
	},
	{
		1,
		1,
		1,
		1,
		"42"
	},
	{
		1,
		1,
		1,
		1,
		"1.30142114406914976E17"
	},
	{
		1,
		1,
		1,
		1,
		"true"
	},
	{
		1,
		1,
		1,
		1,
		"{\"a\":1}"
	},
	{
		2,
		2,
		1,
		2,
		"{\"a\":1,\"b\":2}"
	},
	{
		5,
		5,
		1,
		5,
		"{"
		"  \"aaaaa\"  :  \"yyyyyyyyyy\","
		"  \"bbbbb\"  :  \"yyyyyyyyyy\","
		"  \"ccccc\"  :  \"yyyyyyyyyy\","
		"  \"ddddd\"  :  \"yyyyyyyyyy\","
		"  \"eeeee\"  :  \"yyyyyyyyyy\""
		"}"
	},
	{
		2,
		2,
		1,
		2,
		"{\"num\":42,\"str\":\"hei du\"}"
	},
	{
		6,
		6,
		1,
		6,
		"{"
		"  \"zero\"  : 0,"
		"  \"one\"   : 1,"
		"  \"false\" : 0,"
		"  \"true\"  : 1,"
		"  \"0\"     : false,"
		"  \"1\"     : true"
		"}"
	},

	/* arrays */
	{
		2,
		8,
		1,
		8,
		"{"
		"  \"array\" : [1,2,3,4,5],"
		"  \"arraz\" : [\"ole\", \"dole\", \"doffen\"]"
		"}"
	},

	{
		1,
		0,
		1,
		0,
		"{"
		"  \"empty_array\" : []"
		"}"
	},

	{
		1,
		1,
		1,
		1,
		"{"
		"  \"array_with_object\" : [ { \"key\" : 42 } ]"
		"}"
	},

	{
		1,
		3,
		1,
		3,
		"{"
		"  \"array_with_bool_and_null\" : ["
		"    true, false, null"
		"  ]"
		"}"
	},

	{
		1,
		30,
		1,
		30,
		"{"
		"  \"array\" : ["
		"     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,"
		"    10,11,12,13,14,15,16,17,18,19,"
		"    20,21,22,23,24,25,26,27,28,29"
		"  ]"
		"}"
	},

	/* simple array */
	{
		1,
		1,
		1,
		1,
		"[42]"
	},

	/* larger array */
	{
		3,
		3,
		1,
		3,
		"[42, 43, 44]"
	},

	/* simplest json, just an integer */
	{
		1,
		1,
		1,
		1,
		"43"
	},


	/* nested arrays */
	{
		1,
		4,
		1,
		4,
		"{"
		"   \"array\": ["
		"     1,"
		"     2,"
		"     ["
		"       \"[][][][\","
		"       \"][][][\""
		"     ]"
		"   ]"
		"}"
	},

	/* null */
	{
		1,
		1,
		1,
		1,
		"{"
		"   \"empty\": null"
		"}"
	},

	/* escaped string */
	{
		2,
		2,
		1,
		2,
		"{"
		"  \"string1\": \"\\\"\\/\\b\\f\\n\\r\\t\", "
		"  \"string2\": \"\\\"/\\b\\f\\n\\r\\t\""
		" }"
	},

	{
		2,
		2,
		1,
		2,
		"{"
		"    \"string\"  : \"\\r\\n\" , "
		"    \"boolean\" : true"
		"}"
	},

	{
		2,
		2,
		1,
		2,
		"{"
		"    \"string\"  : \"a\\r\\n\" , "
		"    \"null\"    : null"
		"}"
	},

	/* key with escaped string */
	{
		1,
		1,
		1,
		1,
		"{ \"\\\"\\b\\f\\n\\r\\t\":\"value\"}"
	},

	{
		2,
		3,
		1,
		3,
		"{"
		"  \"type\": \"object\","
		"  \"properties\": {"
		"    \"id\": {"
		"      \"description\": \"The unique identifier\","
		"      \"type\": \"integer\""
		"    }"
		"  }"
		"}"
	},

	{
		1,
		2,
		1,
		2,
		"{"
		"  \"a\": {"
		"    \"b\": {"
		"      \"c\": {"
		"        \"d\": {"
		"          \"e\": {"
		"            \"f\": {"
		"              \"string\": \"hei hei\","
		"              \"number\": 4242"
		"            }"
		"          }"
		"        }"
		"      }"
		"    }"
		"  }"
		"}"
	},

	/* unicode */
	{
		1,
		1,
		1,
		1,
		"{  \"\\u0001key\": \"val\\u0002\" }"
	},

	/* numbers */

	{
		2,
		2,
		1,
		2,
		"{  \"start\":  1372701600000,  "
		"   \"stop\":  -1372701600000  }"
	},

	{
		4,
		4,
		1,
		4,
		"{"
		"    \"a\":  1.30142114406914976E17, "
		"    \"b\":  1.7555215491128452E-19, "
		"    \"c\": -4.57371918053102129E18, "
		"    \"d\": -1.3014211440691497E-17  "
		"}"
	},

	/* array with objects (legal JSON) */
	{
		2,
		4,
		1,
		4,
		"["
		"  {"
		"    \"foo\" : 111,"
		"    \"bar\" : 111"
		"  },"
		"  {"
		"    \"foo\" : 222,"
		"    \"bar\" : 222"
		"  }"
		"]"
	}
};


/* verify a bunch of JSON messages */
static int test_json_verify_decode(void)
{
	struct odict *dict = NULL, *dict2 = NULL;
	struct mbuf *mb_enc = NULL;
	unsigned i;
	int err = 0;
	char *json = NULL;

	for (i=0; i<RE_ARRAY_SIZE(testjson); i++) {

		const struct test *t = &testjson[i];

		/* check with native JSON decoder */
		err = json_decode_odict(&dict, DICT_BSIZE,
					t->str, str_len(t->str), MAX_LEVELS);
		if (err)
			goto out;

		TEST_EQUALS(t->num,       odict_count(dict, false));
		TEST_EQUALS(t->num_total, odict_count(dict, true));

		mb_enc = mbuf_alloc(1024);
		if (!mb_enc) {
			err = ENOMEM;
			goto out;
		}

		/* verify that the JSON object can be encoded */
		err = mbuf_printf(mb_enc, "%H", json_encode_odict, dict);
		TEST_ERR(err);

		/* decode it again */
		err = json_decode_odict(&dict2, DICT_BSIZE,
					(void *)mb_enc->buf, mb_enc->end,
					MAX_LEVELS);
		if (err) {
			goto out;
		}

		TEST_ASSERT(odict_compare(dict, dict2, false));

		dict = mem_deref(dict);
		dict2 = mem_deref(dict2);
		mb_enc = mem_deref(mb_enc);
	}

 out:
	mem_deref(json);
	mem_deref(dict2);
	mem_deref(dict);
	mem_deref(mb_enc);

	return err;
}


/* verify a JSON messages with full decode */
static int test_json_verify_full_decode(void)
{
	struct odict *dict = NULL, *dict2 = NULL;
	struct mbuf *mb_enc = NULL;
	unsigned i;
	int err = 0;
	char *json = NULL;

	for (i=0; i<RE_ARRAY_SIZE(testjson); i++) {

		const struct test *t = &testjson[i];

		/* check with native JSON decoder */
		err = json_decode_odict_full(&dict, DICT_BSIZE,
			t->str, str_len(t->str), MAX_LEVELS);
		if (err)
			goto out;

		TEST_EQUALS(t->full_num,       odict_count(dict, false));
		TEST_EQUALS(t->full_num_total, odict_count(dict, true));

		mb_enc = mbuf_alloc(1024);
		if (!mb_enc) {
			err = ENOMEM;
			goto out;
		}

		/* verify that the JSON object can be encoded */
		err = mbuf_printf(mb_enc, "%H", json_encode_odict_full, dict);
		TEST_ERR(err);

		/* full json decode again */
		err = json_decode_odict_full(&dict2, DICT_BSIZE,
			(void *)mb_enc->buf, mb_enc->end,
			MAX_LEVELS);
		if (err)
			goto out;

		TEST_ASSERT(odict_compare(dict, dict2, false));

		/*mbuf_write_u8(mb_enc, 0);
		mbuf_set_pos(mb_enc, 0);
		err = mbuf_strdup(mb_enc, &json, mbuf_get_left(mb_enc));
		TEST_ERR(err);

		printf("t->str: %s, encoded: %s\n", t->str, json);
		TEST_ASSERT(!str_casecmp(t->str, json));
		json = mem_deref(json);*/

		dict = mem_deref(dict);
		dict2 = mem_deref(dict2);
		mb_enc = mem_deref(mb_enc);
	}

 out:
	mem_deref(json);
	mem_deref(dict2);
	mem_deref(dict);
	mem_deref(mb_enc);

	return err;
}


static int test_json_exponent(void)
{
	static const char *str =
		"{"
		"  \"exponents\" : [1e2, 1e-2, 9E18, -9E18]"
		"}";
	struct odict *dict = NULL;
	const struct odict_entry *arr, *e;
	static const double values[] = {
		100.0,
		0.01,
		9000000000000000000.0,
		-9000000000000000000.0,
	};
	struct le *le;
	unsigned i;
	int err;

	err = json_decode_odict(&dict, DICT_BSIZE,
				str, strlen(str), MAX_LEVELS);
	if (err)
		goto out;

	arr = odict_lookup(dict, "exponents");

	TEST_EQUALS(RE_ARRAY_SIZE(values),
		    odict_count(odict_entry_array(arr), false));

	for (le = list_head(&odict_entry_array(arr)->lst), i = 0; le;
	     le = le->next, ++i) {

		e = le->data;

		TEST_ASSERT(e != NULL);
		TEST_EQUALS(ODICT_DOUBLE, odict_entry_type(e));
		TEST_EQUALS( values[i], odict_entry_dbl(e));
	}

 out:
	mem_deref(dict);
	return err;
}


int test_json(void)
{
	int err = 0;

	err = test_json_exponent();
	TEST_ERR(err);

	err = test_json_basic_parser();
	TEST_ERR(err);

	err = test_json_verify_decode();
	TEST_ERR(err);

	err = test_json_verify_full_decode();
	TEST_ERR(err);

out:
	return err;
}


/* check a bunch of bad JSON messages, unparsable */
int test_json_bad(void)
{
	static const struct test {
		int err;
		char *str;
	} testv[] = {
		{
			EBADMSG,
			"}"
		},
		{
			EBADMSG,
			"{]"
		},
		{
			EBADMSG,
			"{[}"
		},
		{
			EBADMSG,
			"]"
		},

		/* boolean values */
		{
			EBADMSG,
			"{ \"short_true\" : t }"
		},
		{
			EBADMSG,
			"{ \"short_false\" : f }"
		},
		{
			EBADMSG,
			"{ \"short_null\" : n }"
		},
		{
			EBADMSG,
			"{ \"a\" : frue }"
		},
		{
			EBADMSG,
			"{ \"a\" : talse }"
		},

		/* string values */
		{
			EBADMSG,
			"{ \"invalid_unicode\" : \"\\u000g\" }"
		},

		/* corrupt data */
		{
			EBADMSG,
			"10t[3e9e66\"49\"[[72677:[f58{.fn}0{59\":8\"e}["
		},
		{
			EBADMSG,
			"1t34:{{:f{1.n{\"\"n8[0f7e}:53e6{7:28:{n{00:7"
		},
		{
			EBADMSG,
			"}3][ne5}.5n41ef96f99\":n47{9[n[1:0f5\"}985}{"
		},
		{
			EBADMSG,
			"}3][ne5}.5n41ef96f99\":n47{9[n[1:0f5\"}985}{"
		},
		{
			EBADMSG,
			"8n0}3:28e27}8]75:[:e47968e96n[:2f]n1:]n2[t"
		},

		{
			EBADMSG,
			"{"
		},
		{
			EBADMSG,
			"["
		},
		{
			EBADMSG,
			"{ \"broken_key }"
		},
		{
			EBADMSG,
			"{ \"key\" : \"broken_value }"
		},
		{
			0,
			"\"hei\""
		},
		{
			0,
			"123"
		},
	};
	struct odict *dict = NULL;
	unsigned i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct test *t = &testv[i];
		int e;

		/* check with native JSON decoder */
		e = json_decode_odict(&dict, DICT_BSIZE,
				      t->str, str_len(t->str), MAX_LEVELS);
		if (e == ENOMEM)
			break;
		TEST_EQUALS(t->err, e);

		if (e) {
			TEST_ASSERT(dict == NULL);
		}
		else {
			TEST_ASSERT(dict != NULL);
		}

		dict = mem_deref(dict);
	}

 out:
	mem_deref(dict);
	return err;
}


static int test_json_file_parse(const char *filename)
{
	struct mbuf *mb_ref = NULL, *mb_enc = NULL;
	struct odict *dict = NULL, *dict2 = NULL;
	char path[256];
	unsigned max_levels = 480;
	int err;

	mb_ref = mbuf_alloc(1024);
	mb_enc = mbuf_alloc(1024);
	if (!mb_ref || !mb_enc) {
		err = ENOMEM;
		goto out;
	}

	re_snprintf(path, sizeof(path), "%s/%s", test_datapath(), filename);

	err = test_load_file(mb_ref, path);
	if (err)
		goto out;

	err = json_decode_odict(&dict, DICT_BSIZE,
				(void *)mb_ref->buf, mb_ref->end,
				max_levels);
	if (err) {
		goto out;
	}

	TEST_ASSERT(dict != NULL);
	TEST_ASSERT(odict_count(dict, true) > 0);

#if 0
	re_printf("%s: JSON parsed OK (%zu elements)\n",
		  filename, odict_count(dict, true));
#endif

	/* verify that JSON object can be encoded */
	err = mbuf_printf(mb_enc, "%H", json_encode_odict, dict);
	TEST_ERR(err);

	/* decode it again */
	err = json_decode_odict(&dict2, DICT_BSIZE,
				(void *)mb_enc->buf, mb_enc->end, max_levels);
	if (err) {
		goto out;
	}

	TEST_ASSERT(odict_compare(dict, dict2, false));

 out:
	mem_deref(dict2);
	mem_deref(dict);
	mem_deref(mb_enc);
	mem_deref(mb_ref);
	return err;
}


int test_json_file(void)
{
	const char *files[] = {
		"fstab.json",
		"menu.json",
		"rfc7159.json",
		"webapp.json",
		"widget.json",
	};
	unsigned i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(files); i++) {
		err = test_json_file_parse(files[i]);
		if (err)
			return err;
	}

	return err;
}


int test_json_unicode(void)
{
	struct odict *dict=0, *dict2=0;
	static const char *key = "nul\x01key";
	char buf[1024];
	int err = 0;

	err = odict_alloc(&dict, 32);
	if (err)
		goto out;

	err = odict_entry_add(dict, key, ODICT_STRING, "foo\x1d");
	if (err)
		goto out;

	re_snprintf(buf, sizeof(buf), "%H", json_encode_odict, dict);

	err = json_decode_odict(&dict2, DICT_BSIZE,
				buf, str_len(buf), MAX_LEVELS);
	if (err)
		goto out;

	TEST_ASSERT(odict_compare(dict, dict2, false));

 out:
	mem_deref(dict2);
	mem_deref(dict);
	return err;
}


static int verify_array(const struct odict *arr, unsigned num)
{
	const struct odict_entry *e;
	struct le *le;
	char buf[32];
	unsigned i;
	int err = 0;

	for (i=0; i<num; i++) {

		re_snprintf(buf, sizeof(buf), "%u", i);

		e = odict_lookup(arr, buf);
		TEST_ASSERT(e != NULL);
	}

	for (le = arr->lst.head, i=0; le; le = le->next, ++i) {

		struct odict_entry *ae = le->data;
		unsigned key;

		key = atoi(odict_entry_key(ae));

		TEST_EQUALS(i, key);
	}

	/* should not exist */
	re_snprintf(buf, sizeof(buf), "%u", num);
	e = odict_lookup(arr, buf);
	TEST_ASSERT(e == NULL);

 out:
	return err;
}


int test_json_array(void)
{
	static const char *str =
		"{"
		"  \"array1\" : [0,1,2,3,4,5,6,7],"
		"  \"array2\" : [\"ole\",\"dole\",\"doffen\"],"
		"  \"array3\" : [ {\"x\":0}, {\"x\":0}, {\"x\":0} ],"
		"  \"object\" : {"
		"    \"array4\" : [0,1,2,3]"
		"  }"
		"}";

	struct odict *dict = NULL, *obj;
	int err;

	err = json_decode_odict(&dict, DICT_BSIZE,
				str, strlen(str), MAX_LEVELS);
	if (err)
		goto out;

	err |= verify_array(odict_get_array(dict, "array1"), 8);
	err |= verify_array(odict_get_array(dict, "array2"), 3);
	err |= verify_array(odict_get_array(dict, "array3"), 3);
	if (err)
		goto out;

	obj = odict_get_object(dict, "object");
	TEST_ASSERT(obj != NULL);
	err |= verify_array(odict_get_array(obj, "array4"), 4);
	if (err)
		goto out;

 out:
	mem_deref(dict);
	return err;
}
