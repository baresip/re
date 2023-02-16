/**
 * @file telev.c  Testcode for Telephone-event
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


int test_telev(void)
{
	static const char digits[] = "1234567890ABCD*#";
	struct telev *tlv = NULL;
	struct mbuf *mb;
	bool marker, expect_end = false;
	char digit;
	size_t i;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = telev_alloc(&tlv, 1);
	if (err)
		goto out;

	/* Encode all digits */
	for (i=0; i<strlen(digits) && !err; i++) {
		digit = telev_digit2code(digits[i]);
		err |= telev_send(tlv, digit, false);
		err |= telev_send(tlv, digit, true);
	}
	if (err)
		goto out;

	while (0 == telev_poll(tlv, &marker, mb))
		;

	/* Decode all digits */
	mb->pos = 0;
	i = 0;
	while (mbuf_get_left(mb) && i<strlen(digits)) {
		int event;
		bool end;

		if (telev_recv(tlv, mb, &event, &end))
			continue;

		digit = telev_code2digit(event);

		if (digits[i] != digit) {
			(void)re_fprintf(stderr, "telev: expect %c, got %c\n",
					 digits[i], digit);
			err = EBADMSG;
			break;
		}

		if (!expect_end != !end) {
			err = EBADMSG;
			break;
		}

		expect_end = !end;
		if (end)
			++i;
	}

	if (i != strlen(digits))
		err = EBADMSG;

 out:
	mem_deref(tlv);
	mem_deref(mb);
	return err;
}
