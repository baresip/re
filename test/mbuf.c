/**
 * @file mbuf.c Mbuffer Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_mbuf"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int test_mbuf_basic(void)
{
	struct mbuf mb;
	struct pl pl, hei = PL("hei"), foo = PL("foo");
	static const char *pattern = "mmmmmmmmm";
	char *str = NULL;
	int err;

	mbuf_init(&mb);

	/* write */
	err = mbuf_write_u8(&mb, 0x5a);
	if (err)
		goto out;
	err = mbuf_write_u16(&mb, 0x5a5a);
	if (err)
		goto out;
	err = mbuf_write_u32(&mb, 0x5a5a5a5a);
	if (err)
		goto out;
	err = mbuf_write_str(&mb, "hei foo");
	if (err)
		goto out;

	/* read */
	mb.pos = 0;
	if (0x5a != mbuf_read_u8(&mb)) {
		err = EINVAL;
		goto out;
	}
	if (0x5a5a != mbuf_read_u16(&mb)) {
		err = EINVAL;
		goto out;
	}
	if (0x5a5a5a5a != mbuf_read_u32(&mb)) {
		err = EINVAL;
		goto out;
	}
	pl.p = (char *)mbuf_buf(&mb);
	pl.l = 3;
	err = pl_cmp(&hei, &pl);
	if (err)
		goto out;

	mb.pos += 4;
	pl.p = (char *)mbuf_buf(&mb);
	pl.l = mbuf_get_left(&mb);
	err = pl_cmp(&foo, &pl);
	if (err)
		goto out;

	/* Test mbuf_strdup() */
	err = mbuf_strdup(&mb, &str, 3);
	if (err)
		goto out;
	err = pl_strcmp(&foo, str);
	TEST_ERR(err);

	mb.pos = mb.end = 0;
	err = mbuf_fill(&mb, 'm', 9);
	if (err)
		goto out;
	if (mb.pos != strlen(pattern) ||
	    mb.end != strlen(pattern) ||
	    0 != memcmp(mb.buf, pattern, 9)) {
		err = EBADMSG;
		goto out;
	}

	/* Test position and end */
	mbuf_set_posend(&mb, 2, 4);

	ASSERT_EQ(2, mbuf_pos(&mb));
	ASSERT_EQ(4, mbuf_end(&mb));

 out:
	mbuf_reset(&mb);
	mem_deref(str);

	return err;
}


static int test_mbuf_shift(void)
{
	static const uint8_t payload[10] = {0,1,2,3,4,5,6,7,8,9};
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(sizeof(payload));
	if (!mb)
		return ENOMEM;

	err = mbuf_write_mem(mb, payload, sizeof(payload));
	if (err)
		goto out;
	mb->pos = 0;

	/* inject a header in the front */
	err = mbuf_shift(mb, 64);
	if (err)
		goto out;

	TEST_EQUALS(64, mb->pos);
	TEST_EQUALS(64+10, mb->end);
	TEST_MEMCMP(payload, sizeof(payload),
		    mbuf_buf(mb), mbuf_get_left(mb));

	/* remove a header in the front */
	err = mbuf_shift(mb, -1);
	if (err)
		goto out;

	TEST_EQUALS(63, mb->pos);
	TEST_EQUALS(63+10, mb->end);
	TEST_MEMCMP(payload, sizeof(payload),
		    mbuf_buf(mb), mbuf_get_left(mb));

 out:
	mem_deref(mb);

	return err;
}


static int test_mbuf_ptr(void)
{
	struct mbuf *buf;
	int err;

	buf = mbuf_alloc(1 * sizeof(void *));
	if (!buf)
		return ENOMEM;

	err = mbuf_write_ptr(buf, (intptr_t)buf);

	buf->pos = 0;
	intptr_t p = mbuf_read_ptr(buf);

	TEST_EQUALS((intptr_t)buf, p);

out:
	mem_deref(buf);
	return err;
}


int test_mbuf(void)
{
	int err;

	err = test_mbuf_basic();
	TEST_ERR(err);

	err = test_mbuf_shift();
	TEST_ERR(err);

	err = test_mbuf_ptr();
	TEST_ERR(err);

out:
	return err;
}
