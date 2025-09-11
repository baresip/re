/**
 * @file conf.c  Testcode for Configuration module
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"

#define DEBUG_MODULE "test_conf"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_conf(void)
{
	static const char *cfg =
		"string_val\trattarei\n"
		"u32_val       42\n"
		"i32_val       -23\n"
		"float_val     1.5\n"
		"bool_val_1    true\n"
		"bool_val_2    Yes\n"
		"bool_val_3    1\n"
		"bool_val_4    false\n"
		;
	char str[256];
	struct conf *conf;
	struct pl pl;
	uint32_t u32;
	int32_t i32;
	double fl;
	int err;

	err = conf_alloc_buf(&conf, (uint8_t *)cfg, strlen(cfg));
	if (err)
		return err;

	err = conf_get_str(conf, "string_val", str, sizeof(str));
	TEST_ERR(err);
	if (strcmp(str, "rattarei"))
		goto badmsg;

	err = conf_get_u32(conf, "u32_val", &u32);
	TEST_ERR(err);
	TEST_EQUALS(42, u32);

	err = conf_get_i32(conf, "i32_val", &i32);
	TEST_ERR(err);
	TEST_EQUALS(-23, i32);

	err = conf_get_float(conf, "float_val", &fl);
	TEST_ERR(err);
	TEST_EQUALS(1.5, fl);

	bool val = false;

	err = conf_get_bool(conf, "bool_val_1", &val);
	TEST_ERR(err);
	ASSERT_TRUE(val);

	err = conf_get_bool(conf, "bool_val_2", &val);
	TEST_ERR(err);
	ASSERT_TRUE(val);

	err = conf_get_bool(conf, "bool_val_3", &val);
	TEST_ERR(err);
	ASSERT_TRUE(val);

	err = conf_get_bool(conf, "bool_val_4", &val);
	TEST_ERR(err);
	ASSERT_TRUE(!val);

	/* Non-existing parameters */
	if (0 == conf_get(conf, "rattarei", &pl))
		goto badmsg;

 out:
	mem_deref(conf);
	return err;

 badmsg:
	mem_deref(conf);
	return EBADMSG;
}
