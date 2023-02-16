/**
 * @file dtmf.c Testcode for librem's DTMF module
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "test/dtmf"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void dtmf_dec_handler(char digit, void *arg)
{
	char *buf = arg;

	buf[str_len(buf)] = digit;
}


int test_dtmf(void)
{
#define SRATE 8000
	static const char digits[] = "2*A#7";
	char dbuf[256] = "";
	struct dtmf_dec *dec = NULL;
	struct mbuf *mb = NULL;
	size_t i;
	int err = 0;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err = dtmf_dec_alloc(&dec, SRATE, 1, dtmf_dec_handler, dbuf);
	if (err)
		goto out;

	/* generate audio samples with test digits */
	for (i=0; i<str_len(digits); i++) {
		err = autone_dtmf(mb, SRATE, digits[i]);
		if (err)
			goto out;
	}

	/* use the DTMF detector to decode digits */
	dtmf_dec_probe(dec, (void *)mb->buf, mb->end / 2);

	TEST_STRCMP(digits, str_len(digits), dbuf, str_len(dbuf));

 out:
	mem_deref(dec);
	mem_deref(mb);
	return err;
}
