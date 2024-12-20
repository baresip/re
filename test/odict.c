/**
 * @file odict.c Testcode for Ordered Dictionary
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "odict"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct dtest {
	const char *key;
	enum odict_type type;
	union {
		int64_t i;
		double d;
		char *s;
		bool b;
	} u;
};


static int compare(const struct dtest *test, const struct odict_entry *entry)
{
	int err = 0;

	TEST_ASSERT(entry != NULL);

	TEST_STRCMP(test->key, str_len(test->key),
		    odict_entry_key(entry), strlen(odict_entry_key(entry)));

	TEST_EQUALS(test->type, odict_entry_type(entry));

	switch (test->type) {

	case ODICT_INT:
		TEST_EQUALS(test->u.i, odict_entry_int(entry));
		break;

	case ODICT_BOOL:
		TEST_EQUALS(test->u.b, odict_entry_boolean(entry));
		break;

	case ODICT_DOUBLE:
		TEST_EQUALS(test->u.d, odict_entry_dbl(entry));
		break;

	case ODICT_STRING:
		TEST_STRCMP(test->u.s, str_len(test->u.s),
			    odict_entry_str(entry),
			    str_len(odict_entry_str(entry)));
		break;

	default:
		DEBUG_WARNING("cannot compare type %d\n", test->type);
		err = EINVAL;
		goto out;
	}

 out:
	return err;
}


int test_odict(void)
{
	static const struct dtest testv[] = {
		{"a",   ODICT_INT,     {.i = 42  }         },
		{"b",   ODICT_DOUBLE,  {.d = 3.14}         },
		{"c",   ODICT_STRING,  {.s = "rattarei"}   },
		{"d",   ODICT_BOOL,    {.b = true  }       },
		{"e",   ODICT_BOOL,    {.b = false  }       },

		{"ha73ofhjausdhkjquhriasjdhkaksjdkjqkjhwkjhqweaaaaaa",
		 ODICT_INT,     {.i = 617284773  }         },
		{"mkkpnaidhs747fusyudyaisdiayiakakakaakajdjiwi123456",
		 ODICT_INT,     {.i = 12345678  }         },
		{"lllalsidjjlalksjdlaksjdlkjasd",
		 ODICT_DOUBLE,  {.d = 123456.123456}         },
		{"8adhw6fjshdkhjaskjdhakdhaskhdkjh",
		 ODICT_DOUBLE,  {.d = -0.007}         },

		{"hafgsdudue6dhcgfjgieiwuehsdkjhsdjkhasdkjasdkjhasd",
		 ODICT_STRING,
		 {.s = "kasjdsuher7yw783897njxdvkhjskhdkhsdkhjsdkhjasdasd"}
		},
		{"liajsdoiausdoaudoaisudaoisdjalsijdalsidjalidjaslidj",
		 ODICT_STRING,
		 {.s = "bdjkhdiuasd7y78yw4y78ryuseyugfasygdasygdh"}
		},
	};
	struct odict *dict = NULL;
	size_t i;
	int err;

	TEST_ASSERT(odict_type_iscontainer(ODICT_OBJECT));
	TEST_ASSERT(odict_type_iscontainer(ODICT_ARRAY));
	TEST_ASSERT(odict_type_isreal(ODICT_INT));
	TEST_ASSERT(odict_type_isreal(ODICT_DOUBLE));
	TEST_ASSERT(odict_type_isreal(ODICT_STRING));
	TEST_ASSERT(odict_type_isreal(ODICT_BOOL));
	TEST_ASSERT(odict_type_isreal(ODICT_NULL));

	err = odict_alloc(&dict, 64);
	if (err)
		goto out;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct dtest *test = &testv[i];
		const struct odict_entry *entry = NULL;

		/* verify that this entry does not exist (based on key) */
		TEST_ASSERT(NULL == odict_lookup(dict, test->key));

		switch (test->type) {

		case ODICT_INT:
			err = odict_entry_add(dict, test->key,
					      test->type, test->u.i);
			break;

		case ODICT_BOOL:
			err = odict_entry_add(dict, test->key,
					      test->type, (int)test->u.b);
			break;

		case ODICT_DOUBLE:
			err = odict_entry_add(dict, test->key,
					      test->type, test->u.d);
			break;

		case ODICT_STRING:
			err = odict_entry_add(dict, test->key,
					      test->type, test->u.s);
			break;

		default:
			err = EINVAL;
			goto out;
			break;
		}
		if (err)
			goto out;

		/* verify that entry exist after adding */
		entry = odict_lookup(dict, test->key);
		TEST_ASSERT(entry != NULL);

		err = compare(test, entry);
		TEST_ERR(err);
	}

	/* verify size of dictionary, after adding all entries */
	TEST_EQUALS(RE_ARRAY_SIZE(testv), odict_count(dict, false));

	/* compare dictionary with itself */
	TEST_ASSERT(odict_compare(dict, dict, false));

	/* remove all entries */
	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct dtest *test = &testv[i];
		struct odict_entry *e;

		e = (struct odict_entry *)odict_lookup(dict, test->key);
		TEST_ASSERT(e != NULL);

		/* delete entry from dictionary */
		mem_deref(e);

		/* entry should not exist anymore */
		e = (struct odict_entry *)odict_lookup(dict, test->key);
		TEST_ASSERT(e == NULL);
	}

	/* verify size of dictionary, after removing all entries */
	TEST_EQUALS(0, odict_count(dict, false));

 out:
	mem_deref(dict);
	return err;
}


int test_odict_pl(void)
{
	struct odict *od = NULL;
	const struct odict_entry *e;
	int err;

	static struct pl pl=PL("liajsdoiausdoaudoaisudaoisdjal");

	err = odict_alloc(&od, 64);
	if (err)
		goto out;

	/* add pl */
	err = odict_pl_add(od, "pl1", &pl);
	TEST_ERR(err);

	e = odict_lookup(od, "pl1");
	TEST_ASSERT(e != NULL);

	TEST_STRCMP(pl.p, pl.l,
	     odict_entry_str(e), str_len(odict_entry_str(e)));

	mem_deref((struct odict_entry *) e);
	/* entry should not exist anymore */
	e = (struct odict_entry *)odict_lookup(od, "pl1");
	TEST_ASSERT(e == NULL);

 out:
	mem_deref(od);
	return err;
}


int test_odict_array(void)
{
	struct odict *arr = NULL;
	const struct odict_entry *e;
	int err;

	err = odict_alloc(&arr, 64);
	if (err)
		goto out;

	/* test an empty array */
	TEST_EQUALS(0, odict_count(arr, false));
	TEST_ASSERT(NULL == odict_lookup(arr, "0"));
	TEST_ASSERT(NULL == odict_lookup(arr, "255"));

	/* add some elements of variying types */
	err = odict_entry_add(arr, "0", ODICT_STRING, "hei");
	if (err)
		goto out;

	TEST_EQUALS(1, odict_count(arr, false));

	err  = odict_entry_add(arr, "1", ODICT_INT, 1LL);
	err |= odict_entry_add(arr, "2", ODICT_INT, 2LL);
	err |= odict_entry_add(arr, "3", ODICT_INT, 3LL);
	if (err)
		goto out;

	TEST_EQUALS(4, odict_count(arr, false));

	/* verify that elements are correct */
	e = odict_lookup(arr, "0");
	TEST_ASSERT(e != NULL);
	TEST_EQUALS(ODICT_STRING, odict_entry_type(e));
	TEST_STRCMP("hei", (size_t)3, odict_entry_str(e),
		    str_len(odict_entry_str(e)));

	e = odict_lookup(arr, "3");
	TEST_ASSERT(e != NULL);
	TEST_EQUALS(ODICT_INT, odict_entry_type(e));
	TEST_EQUALS(3LL, odict_entry_int(e));

#if 0
	re_printf("%H\n", odict_debug, arr);
#endif

 out:
	mem_deref(arr);
	return err;
}
