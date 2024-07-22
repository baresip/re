/**
 * @file payload.c  PCP payload encoding and decoding
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_pcp.h>
#include "pcp.h"


static int pcp_write_port(struct mbuf *mb, const struct sa *sa)
{
	uint16_t port_be;

	if (!mb || !sa)
		return EINVAL;

	switch (sa->u.sa.sa_family) {

	case AF_INET:
		port_be = sa->u.in.sin_port;
		break;

	case AF_INET6:
		port_be = sa->u.in6.sin6_port;
		break;

	default:
		return EAFNOSUPPORT;
	}

	return mbuf_write_u16(mb, port_be);
}


static int pcp_map_encode(struct mbuf *mb, const struct pcp_map *map)
{
	int err = 0;

	if (!mb || !map)
		return EINVAL;

	err |= mbuf_write_mem(mb, map->nonce, sizeof(map->nonce));
	err |= mbuf_write_u8(mb, map->proto);
	err |= mbuf_fill(mb, 0x00, 3);
	err |= mbuf_write_u16(mb, htons(map->int_port));
	err |= pcp_write_port(mb, &map->ext_addr);
	err |= pcp_ipaddr_encode(mb, &map->ext_addr);

	return err;
}


static int pcp_peer_encode(struct mbuf *mb, const struct pcp_peer *peer)
{
	int err;

	if (!mb || !peer)
		return EINVAL;

	/* Protocol MUST NOT be zero.
	 * Internal port MUST NOT be zero.
	 */
	if (!peer->map.proto || !peer->map.int_port)
		return EPROTO;

	/* note: the MAP and PEER opcodes are quite similar */
	err = pcp_map_encode(mb, &peer->map);
	if (err)
		return err;

	err  = pcp_write_port(mb, &peer->remote_addr);
	err |= mbuf_write_u16(mb, 0x0000);
	err |= pcp_ipaddr_encode(mb, &peer->remote_addr);

	return err;
}


int pcp_payload_encode(struct mbuf *mb, enum pcp_opcode opcode,
		       const union pcp_payload *pld)
{
	int err;

	if (!mb || !pld)
		return EINVAL;

	switch (opcode) {

	case PCP_MAP:
		err = pcp_map_encode(mb, &pld->map);
		break;

	case PCP_PEER:
		err = pcp_peer_encode(mb, &pld->peer);
		break;

	default:
		re_fprintf(stderr, "pcp: dont know how to encode payload"
			   " for opcode %d\n", opcode);
		err = EPROTO;
		break;
	}

	return err;
}
