/**
 * @file mock/turnsrv.c Mock TURN server
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "mock/turnsrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	TCP_MAX_LENGTH = 2048,
};


static struct channel *find_channel_numb(struct turnserver *tt, uint16_t nr)
{
	size_t i;

	if (!tt)
		return NULL;

	for (i=0; i<tt->chanc; i++) {

		if (tt->chanv[i].nr == nr)
			return &tt->chanv[i];
	}

	return NULL;
}


static struct channel *find_channel_peer(struct turnserver *tt,
					 const struct sa *peer)
{
	size_t i;

	if (!tt)
		return NULL;

	for (i=0; i<tt->chanc; i++) {

		if (sa_cmp(&tt->chanv[i].peer, peer, SA_ALL))
			return &tt->chanv[i];
	}

	return NULL;
}


static int add_permission(struct turnserver *tt, const struct sa *peer)
{
	int err = 0;

	TEST_ASSERT(tt->permc < RE_ARRAY_SIZE(tt->permv));
	tt->permv[tt->permc] = *peer;
	++tt->permc;
 out:
	return err;
}


static struct sa *find_permission(struct turnserver *tt,
				  const struct sa *peer)
{
	size_t i;

	if (!tt)
		return NULL;

	for (i=0; i<tt->permc; i++) {

		if (sa_cmp(&tt->permv[i], peer, SA_ADDR))
			return &tt->permv[i];
	}

	return NULL;
}


/* Receive packet on the "relayed" address -- relay to the client */
static void relay_udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct turnserver *turn = arg;
	struct channel *chan;
	int err = 0;

	++turn->n_recv;

	chan = find_channel_peer(turn, src);
	if (chan) {
		uint16_t len = (uint16_t)mbuf_get_left(mb);
		size_t start;

		if (mb->pos < 4) {
			DEBUG_WARNING("relay_udp_recv: mb pos < 4\n");
			return;
		}

		mb->pos -= 4;
		start = mb->pos;

		(void)mbuf_write_u16(mb, htons(chan->nr));
		(void)mbuf_write_u16(mb, htons(len));

		mb->pos = start;

		err = udp_send(turn->us, &turn->cli, mb);
	}
	else {
		err = stun_indication(IPPROTO_UDP, turn->us,
				      &turn->cli, 0, STUN_METHOD_DATA,
				      NULL, 0, false, 2,
				      STUN_ATTR_XOR_PEER_ADDR, src,
				      STUN_ATTR_DATA, mb);
	}

	if (err) {
		DEBUG_WARNING("relay_udp_recv: error %m\n", err);
	}
}


static void process_msg(struct turnserver *turn, int proto, void *sock,
			const struct sa *src, struct mbuf *mb)
{
	struct stun_msg *msg = NULL;
	struct sa laddr;
	int err = 0;

	if (stun_msg_decode(&msg, mb, NULL)) {

		uint16_t numb, len;
		struct channel *chan;

		if (!turn->us_relay)
			return;

		++turn->n_raw;

		numb = ntohs(mbuf_read_u16(mb));
		len  = ntohs(mbuf_read_u16(mb));

		if (mbuf_get_left(mb) < len) {
			DEBUG_WARNING("short length: %zu < %u\n",
				      mbuf_get_left(mb), len);
		}

		chan = find_channel_numb(turn, numb);
		if (!chan) {
			DEBUG_WARNING("channel not found: numb=%u\n", numb);
			return;
		}

		/* relay data from channel to peer */
		(void)udp_send(turn->us_relay, &chan->peer, mb);
		return;
	}

#if 0
	re_printf("process: %s:%p:%J %s\n",
		  net_proto2name(proto), sock, src,
		  stun_method_name(stun_msg_method(msg)));
#endif

	switch (stun_msg_method(msg)) {

	case STUN_METHOD_ALLOCATE:
		/* Max 1 allocation for now */
		++turn->n_allocate;

		if (turn->us_relay) {
			err = EALREADY;
			goto out;
		}

		turn->cli = *src;

		err = sa_set_str(&laddr, "127.0.0.1", 0);
		if (err)
			goto out;

		err = udp_listen(&turn->us_relay, &laddr,
				 relay_udp_recv, turn);
		if (err)
			goto out;

		err = udp_local_get(turn->us_relay, &turn->relay);
		if (err)
			goto out;

		udp_rxbuf_presz_set(turn->us_relay, 4);

		err = stun_reply(proto, sock, src, 0,
				 msg, NULL, 0, false,
				 2,
				 STUN_ATTR_XOR_MAPPED_ADDR, src,
				 STUN_ATTR_XOR_RELAY_ADDR, &turn->relay);
		break;

	case STUN_METHOD_CREATEPERM: {
		struct stun_attr *peer;

		++turn->n_createperm;

		peer = stun_msg_attr(msg, STUN_ATTR_XOR_PEER_ADDR);
		TEST_ASSERT(peer != NULL);

		add_permission(turn, &peer->v.xor_peer_addr);

		/* todo: install permissions and check them */
		err = stun_reply(proto, sock, src, 0,
				 msg, NULL, 0, false,
				 0);
	}
		break;

	case STUN_METHOD_CHANBIND: {
		struct stun_attr *chnr, *peer;

		++turn->n_chanbind;

		TEST_ASSERT(turn->us_relay != NULL);

		chnr = stun_msg_attr(msg, STUN_ATTR_CHANNEL_NUMBER);
		peer = stun_msg_attr(msg, STUN_ATTR_XOR_PEER_ADDR);
		if (!chnr || !peer) {
			DEBUG_WARNING("CHANBIND: missing chnr/peer attrib\n");
			goto out;
		}

		TEST_ASSERT(turn->chanc < RE_ARRAY_SIZE(turn->chanv));
		turn->chanv[turn->chanc].nr   = chnr->v.channel_number;
		turn->chanv[turn->chanc].peer = peer->v.xor_peer_addr;
		++turn->chanc;

		err = stun_reply(proto, sock, src, 0,
				 msg, NULL, 0, false,
				 0);
	}
		break;

	case STUN_METHOD_SEND: {
		struct stun_attr *peer, *data;

		++turn->n_send;

		TEST_ASSERT(turn->us_relay != NULL);

		peer = stun_msg_attr(msg, STUN_ATTR_XOR_PEER_ADDR);
		data = stun_msg_attr(msg, STUN_ATTR_DATA);

		if (!peer || !data) {
			DEBUG_WARNING("SEND: missing peer/data attrib\n");
			goto out;
		}

		/* check for valid Permission */
		if (!find_permission(turn, &peer->v.xor_peer_addr)) {
			DEBUG_NOTICE("no permission to peer %j\n",
				     &peer->v.xor_peer_addr);
			goto out;
		}

		err = udp_send(turn->us_relay, &peer->v.xor_peer_addr,
			       &data->v.data);
	}
		break;

	case STUN_METHOD_REFRESH: {
		uint32_t lifetime = 1; /* short test lifetime */
		err = stun_reply(proto, sock, src, 0, msg, NULL, 0, false, 1,
				 STUN_ATTR_LIFETIME, &lifetime);
	}
		break;

	default:
		DEBUG_WARNING("unknown STUN method: %s\n",
			      stun_method_name(stun_msg_method(msg)));
		err = EPROTO;
		break;
	}

	if (err)
		goto out;

 out:
	if (err && stun_msg_class(msg) == STUN_CLASS_REQUEST) {
		(void)stun_ereply(proto, sock, src, 0, msg,
				  500, "Server Error",
				  NULL, 0, false, 0);
	}

	mem_deref(msg);
}


/* Simulated TURN server */
static void srv_udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct turnserver *turn = arg;

	process_msg(turn, IPPROTO_UDP, turn->us, src, mb);
}


static void tcp_estab_handler(void *arg)
{
	struct turnserver *turn = arg;
	(void)turn;
}


static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
	struct turnserver *conn = arg;
	int err = 0;

	if (conn->mb) {
		size_t pos;

		pos = conn->mb->pos;

		conn->mb->pos = conn->mb->end;

		err = mbuf_write_mem(conn->mb, mbuf_buf(mb),mbuf_get_left(mb));
		if (err) {
			DEBUG_WARNING("tcp: buffer write error: %m\n", err);
			goto out;
		}

		conn->mb->pos = pos;
	}
	else {
		conn->mb = mem_ref(mb);
	}

	for (;;) {

		size_t len, pos, end;
		uint16_t typ;

		if (mbuf_get_left(conn->mb) < 4)
			break;

		typ = ntohs(mbuf_read_u16(conn->mb));
		len = ntohs(mbuf_read_u16(conn->mb));

		if (len > TCP_MAX_LENGTH) {
			re_printf("tcp: bad length: %zu\n", len);
			err = EBADMSG;
			goto out;
		}

		if (typ < 0x4000)
			len += STUN_HEADER_SIZE;
		else if (typ < 0x8000)
			len += 4;
		else {
			re_printf("tcp: bad type: 0x%04x\n", typ);
			err = EBADMSG;
			goto out;
		}

		conn->mb->pos -= 4;

		if (mbuf_get_left(conn->mb) < len)
			break;

		pos = conn->mb->pos;
		end = conn->mb->end;

		conn->mb->end = pos + len;

		process_msg(conn, IPPROTO_TCP, conn->tc, &conn->paddr,
			    conn->mb);

		/* 4 byte alignment */
		while (len & 0x03)
			++len;

		conn->mb->pos = pos + len;
		conn->mb->end = end;

		if (conn->mb->pos >= conn->mb->end) {
			conn->mb = mem_deref(conn->mb);
			break;
		}
	}

 out:
	if (err) {
		conn->mb = mem_deref(conn->mb);
	}
}


static void tcp_close_handler(int err, void *arg)
{
	struct turnserver *turn = arg;
	(void)err;

	turn->tc = mem_deref(turn->tc);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct turnserver *turn = arg;
	int err = 0;

	if (turn->tc) {
		tcp_reject(turn->ts);
	}
	else {
		err = tcp_accept(&turn->tc, turn->ts, tcp_estab_handler,
				 tcp_recv_handler, tcp_close_handler, turn);
		if (err)
			tcp_reject(turn->ts);

		turn->paddr = *peer;
	}
}


static void destructor(void *arg)
{
	struct turnserver *turn = arg;

	mem_deref(turn->us);
	mem_deref(turn->us_relay);
	mem_deref(turn->tc);
	mem_deref(turn->ts);
	mem_deref(turn->mb);
}


int turnserver_alloc(struct turnserver **turnp)
{
	struct turnserver *turn;
	struct sa laddr;
	int err = 0;

	if (!turnp)
		return EINVAL;

	turn = mem_zalloc(sizeof(*turn), destructor);
	if (!turn)
		return ENOMEM;

	err = sa_set_str(&laddr, "127.0.0.1", 0);
	if (err)
		goto out;

	err = udp_listen(&turn->us, &laddr, srv_udp_recv, turn);
	if (err)
		goto out;

	err = udp_local_get(turn->us, &turn->laddr);
	if (err)
		goto out;

	err = tcp_listen(&turn->ts, &laddr, tcp_conn_handler, turn);
	if (err)
		goto out;

	err = tcp_sock_local_get(turn->ts, &turn->laddr_tcp);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(turn);
	else
		*turnp = turn;

	return err;
}
