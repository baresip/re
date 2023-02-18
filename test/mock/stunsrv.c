/**
 * @file mock/stunsrv.c Mock STUN server
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mock/stunsrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	TCP_MAX_LENGTH = 2048,
};


static void process_msg(struct stunserver *stun,
			int proto, void *sock,
			const struct sa *src, const struct sa *dst,
			struct mbuf *mb)
{
	struct stun_msg *msg;
	bool fp = false;
	int err;
	(void)dst;

	stun->nrecv++;

	err = stun_msg_decode(&msg, mb, NULL);
	if (err)
		return;

#if 0
	stun_msg_dump(msg);
#endif

	TEST_EQUALS(0x0001, stun_msg_type(msg));
	TEST_EQUALS(STUN_CLASS_REQUEST, stun_msg_class(msg));
	TEST_EQUALS(STUN_METHOD_BINDING, stun_msg_method(msg));

	/* mirror FINGERPRINT attribute back in response */
	fp = NULL != stun_msg_attr(msg, STUN_ATTR_FINGERPRINT);
	if (fp) {
		TEST_EQUALS(0, stun_msg_chk_fingerprint(msg));
	}

	err = stun_reply(proto, sock, src,
			 0, msg, NULL, 0, fp, 2,
			 STUN_ATTR_MAPPED_ADDR, src,
			 STUN_ATTR_XOR_MAPPED_ADDR, src);

 out:
	if (err) {
		(void)stun_ereply(proto, sock, src, 0, msg, 400,
				  "Bad Request", NULL, 0, fp, 0);
	}

	mem_deref(msg);
}


static void stunserver_udp_recv(const struct sa *src, struct mbuf *mb,
				void *arg)
{
	struct stunserver *stun = arg;

	process_msg(stun, IPPROTO_UDP, stun->us, src, &stun->laddr, mb);
}


static void tcp_recv(struct mbuf *mb, void *arg)
{
	struct stunserver *stun = arg;
	int err = 0;

	if (stun->mb) {
		size_t pos;

		pos = stun->mb->pos;

		stun->mb->pos = stun->mb->end;

		err = mbuf_write_mem(stun->mb, mbuf_buf(mb),mbuf_get_left(mb));
		if (err) {
			goto out;
		}

		stun->mb->pos = pos;
	}
	else {
		stun->mb = mem_ref(mb);
	}

	for (;;) {

		size_t len, pos, end;
		uint16_t typ;

		if (mbuf_get_left(stun->mb) < 4)
			break;

		typ = ntohs(mbuf_read_u16(stun->mb));
		len = ntohs(mbuf_read_u16(stun->mb));

		if (len > TCP_MAX_LENGTH) {
			DEBUG_WARNING("tcp: bad length: %zu\n", len);
			err = EBADMSG;
			goto out;
		}

		if (typ < 0x4000)
			len += STUN_HEADER_SIZE;
		else if (typ < 0x8000)
			len += 4;
		else {
			DEBUG_WARNING("tcp: bad type: 0x%04x\n", typ);
			err = EBADMSG;
			goto out;
		}

		stun->mb->pos -= 4;

		if (mbuf_get_left(stun->mb) < len)
			break;

		pos = stun->mb->pos;
		end = stun->mb->end;

		stun->mb->end = pos + len;

		process_msg(stun, IPPROTO_TCP, stun->tc, &stun->paddr,
			    &stun->laddr_tcp, stun->mb);

		/* 4 byte alignment */
		while (len & 0x03)
			++len;

		stun->mb->pos = pos + len;
		stun->mb->end = end;

		if (stun->mb->pos >= stun->mb->end) {
			stun->mb = mem_deref(stun->mb);
			break;
		}
	}

 out:
	if (err) {
		stun->mb = mem_deref(stun->mb);
	}
}


static void tcp_close(int err, void *arg)
{
	struct stunserver *stun = arg;
	(void)err;

	stun->tc = mem_deref(stun->tc);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct stunserver *stun = arg;
	int err;

	/* max 1 TCP connection */
	TEST_ASSERT(stun->tc == NULL);
	err = tcp_accept(&stun->tc, stun->ts, NULL, tcp_recv, tcp_close, stun);
	if (err)
		goto out;

	stun->paddr = *peer;

 out:
	if (err) {
		/* save the error code */
		stun->err = err;

		tcp_reject(stun->ts);
	}
}


static void stunserver_destructor(void *arg)
{
	struct stunserver *stun = arg;

	mem_deref(stun->us);
	mem_deref(stun->mb);
	mem_deref(stun->tc);
	mem_deref(stun->ts);
}


/* Both UDP- and TCP-transport enabled by default */
int stunserver_alloc(struct stunserver **stunp)
{
	struct stunserver *stun;
	struct sa laddr;
	int err;

	if (!stunp)
		return EINVAL;

	stun = mem_zalloc(sizeof(*stun), stunserver_destructor);
	if (!stun)
		return ENOMEM;

	sa_set_str(&laddr, "127.0.0.1", 0);

	err = udp_listen(&stun->us, &laddr, stunserver_udp_recv, stun);
	if (err)
		goto out;

	err = udp_local_get(stun->us, &stun->laddr);
	if (err)
		goto out;

	err = tcp_listen(&stun->ts, &laddr, tcp_conn_handler, stun);
	if (err)
		goto out;

	err = tcp_local_get(stun->ts, &stun->laddr_tcp);
	if (err)
		goto out;

#if 0
	DEBUG_NOTICE("stunserver: udp=%J, tcp=%J\n",
		     &stun->laddr, &stun->laddr_tcp);
#endif

 out:
	if (err)
		mem_deref(stun);
	else
		*stunp = stun;

	return err;
}


const struct sa *stunserver_addr(const struct stunserver *stun, int proto)
{
	if (!stun)
		return NULL;

	switch (proto) {

	case IPPROTO_UDP: return &stun->laddr;
	case IPPROTO_TCP: return &stun->laddr_tcp;
	default: return NULL;
	}

	return NULL;
}
