/**
 * @file conf.c  Testcode for Configuration module
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


int test_conf(void)
{
	static const char *cfg =
		"string_val\trattarei\n"
		"u32_val       42\n";
	char str[256];
	struct conf *conf;
	struct pl pl;
	uint32_t u32;
	int err;

	err = conf_alloc_buf(&conf, (uint8_t *)cfg, strlen(cfg));
	if (err)
		return err;

	err = conf_get_str(conf, "string_val", str, sizeof(str));
	if (err)
		goto out;
	if (strcmp(str, "rattarei"))
		goto badmsg;

	err = conf_get_u32(conf, "u32_val", &u32);
	if (u32 != 42)
		goto badmsg;

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
