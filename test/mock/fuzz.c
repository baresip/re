/**
 * @file mock/fuzz.c Packet fuzzing
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mock/fuzz"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct fuzz {
	struct tcp_helper *th;
	struct tcp_conn *tc;
	size_t packet_count;
};


static void destructor(void *data)
{
	struct fuzz *fuzz = data;

	mem_deref(fuzz->th);
	mem_deref(fuzz->tc);
}


static void apply_fuzzing(struct fuzz *fuzz, struct mbuf *mb)
{
	const size_t len = mbuf_get_left(mb);
	size_t pos;
	bool flip;
	unsigned bit;

	if (len == 0)
		return;

	++fuzz->packet_count;

	pos = rand_u16() % len;
	bit = rand_u16() % 8;

	/* percent change of corrupt packet */
	flip = ((rand_u16() % 100) < 33);

	if (flip) {
		re_printf("### flipped bit on pos %zu\n", pos);

		/* flip a random bit */
		mbuf_buf(mb)[pos] ^= 1<<bit;
	}
}


static bool helper_send_handler(int *err, struct mbuf *mb, void *arg)
{
	struct fuzz *fuzz = arg;
	(void)err;

	apply_fuzzing(fuzz, mb);

	return false;
}


static bool helper_recv_handler(int *err, struct mbuf *mb, bool *estab,
				void *arg)
{
	struct fuzz *fuzz = arg;
	(void)err;
	(void)estab;

	apply_fuzzing(fuzz, mb);

	return false;
}


int fuzz_register_tcpconn(struct fuzz **fuzzp, struct tcp_conn *tc)
{
	struct fuzz *fuzz;
	int err;

	if (!fuzzp || !tc)
		return EINVAL;

	fuzz = mem_zalloc(sizeof(*fuzz), destructor);
	if (!fuzz)
		return ENOMEM;

	fuzz->tc = mem_ref(tc);

	err = tcp_register_helper(&fuzz->th, tc, -1000, NULL,
				  helper_send_handler,
				  helper_recv_handler, fuzz);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(fuzz);
	else
		*fuzzp = fuzz;

	return err;
}
