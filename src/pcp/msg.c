/**
 * @file pcp/msg.c  PCP messages
 *
 * Copyright (C) 2010 - 2016 Alfred E. Heggestad
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_pcp.h>
#include "pcp.h"


static int pcp_map_decode(struct pcp_map *map, struct mbuf *mb)
{
	uint16_t port;
	int err;

	if (!map || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < PCP_MAP_SZ)
		return EBADMSG;

	(void)mbuf_read_mem(mb, map->nonce, sizeof(map->nonce));
	map->proto = mbuf_read_u8(mb); mbuf_advance(mb, 3);
	map->int_port = ntohs(mbuf_read_u16(mb));

	port = ntohs(mbuf_read_u16(mb));
	err = pcp_ipaddr_decode(mb, &map->ext_addr);
	sa_set_port(&map->ext_addr, port);

	return err;
}


static int pcp_peer_decode(struct pcp_peer *peer, struct mbuf *mb)
{
	uint16_t port;
	int err = 0;

	if (!peer || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < PCP_PEER_SZ)
		return EBADMSG;

	/* note: the MAP and PEER opcodes are quite similar */
	err = pcp_map_decode(&peer->map, mb);
	if (err)
		return err;

	port = ntohs(mbuf_read_u16(mb)); mbuf_advance(mb, 2);
	err |= pcp_ipaddr_decode(mb, &peer->remote_addr);
	sa_set_port(&peer->remote_addr, port);

	return err;
}


static void destructor(void *arg)
{
	struct pcp_msg *msg = arg;

	list_flush(&msg->optionl);
}


static int pcp_header_encode_request(struct mbuf *mb, enum pcp_opcode opcode,
			      uint32_t req_lifetime, const struct sa *int_addr)
{
	int err = 0;

	if (!mb || !int_addr)
		return EINVAL;

	err |= mbuf_write_u8(mb, PCP_VERSION);
	err |= mbuf_write_u8(mb, opcode);
	err |= mbuf_write_u16(mb, 0x0000);
	err |= mbuf_write_u32(mb, htonl(req_lifetime));
	err |= pcp_ipaddr_encode(mb, int_addr);

	return err;
}


static int pcp_header_decode(struct pcp_hdr *hdr, struct mbuf *mb)
{
	uint8_t b;

	if (!hdr || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < PCP_HDR_SZ)
		return EBADMSG;

	hdr->version = mbuf_read_u8(mb);

	if (hdr->version != PCP_VERSION) {
		(void)re_fprintf(stderr, "pcp: unknown version %u\n",
				 hdr->version);
		return EPROTO;
	}

	b            = mbuf_read_u8(mb);
	hdr->resp    = b>>7;
	hdr->opcode  = b & 0x7f;

	(void)mbuf_read_u8(mb);
	b = mbuf_read_u8(mb);

	if (hdr->resp)
		hdr->result = b;

	hdr->lifetime = ntohl(mbuf_read_u32(mb));

	if (hdr->resp) {
		hdr->epoch = ntohl(mbuf_read_u32(mb));
		mbuf_advance(mb, 12);
	}
	else { /* Request */
		(void)pcp_ipaddr_decode(mb, &hdr->cli_addr);
	}

	return 0;
}


int pcp_msg_req_vencode(struct mbuf *mb, enum pcp_opcode opcode,
			uint32_t lifetime, const struct sa *cli_addr,
			const void *payload, uint32_t optionc, va_list ap)
{
	uint32_t i;
	int err;

	if (!mb || !cli_addr)
		return EINVAL;

	err = pcp_header_encode_request(mb, opcode, lifetime, cli_addr);
	if (err)
		return err;

	if (payload) {
		err = pcp_payload_encode(mb, opcode, payload);
		if (err)
			return err;
	}

	/* encode options */
	for (i=0; i<optionc; i++) {

		enum pcp_option_code code = va_arg(ap, int);
		const void *v = va_arg(ap, const void *);

		if (!v)
			continue;

		err |= pcp_option_encode(mb, code, v);
	}

	return err;
}


int pcp_msg_req_encode(struct mbuf *mb, enum pcp_opcode opcode,
		       uint32_t lifetime, const struct sa *cli_addr,
		       const void *payload, uint32_t optionc, ...)
{
	va_list ap;
	int err;

	va_start(ap, optionc);
	err = pcp_msg_req_vencode(mb, opcode, lifetime, cli_addr,
				  payload, optionc, ap);
	va_end(ap);

	return err;
}


int pcp_msg_decode(struct pcp_msg **msgp, struct mbuf *mb)
{
	struct pcp_msg *msg;
	size_t len, pos;
	int err;

	if (!msgp || !mb)
		return EINVAL;

	len = mbuf_get_left(mb);
	if (len < PCP_MIN_PACKET || len > PCP_MAX_PACKET || len&3)
		return EBADMSG;

	msg = mem_zalloc(sizeof(*msg), destructor);
	if (!msg)
		return ENOMEM;

	pos = mb->pos;
	err = pcp_header_decode(&msg->hdr, mb);
	if (err)
		goto out;

	switch (msg->hdr.opcode) {

	case PCP_MAP:
		err = pcp_map_decode(&msg->pld.map, mb);
		break;

	case PCP_PEER:
		err = pcp_peer_decode(&msg->pld.peer, mb);
		break;

	default:
		break;
	}
	if (err)
		goto out;

	/* Decode PCP Options */
	while (mbuf_get_left(mb) >= 4) {

		struct pcp_option *opt;

		err = pcp_option_decode(&opt, mb);
		if (err)
			goto out;

		list_append(&msg->optionl, &opt->le, opt);
	}

 out:
	if (err) {
		mb->pos = pos;
		mem_deref(msg);
	}
	else
		*msgp = msg;

	return err;
}


struct pcp_option *pcp_msg_option(const struct pcp_msg *msg,
				  enum pcp_option_code code)
{
	struct le *le = msg ? list_head(&msg->optionl) : NULL;

	while (le) {
		struct pcp_option *opt = le->data;

		le = le->next;

		if (opt->code == code)
			return opt;
	}

	return NULL;
}


struct pcp_option *pcp_msg_option_apply(const struct pcp_msg *msg,
					pcp_option_h *h, void *arg)
{
	struct le *le = msg ? list_head(&msg->optionl) : NULL;

	while (le) {
		struct pcp_option *opt = le->data;

		le = le->next;

		if (h && h(opt, arg))
			return opt;
	}

	return NULL;
}


static bool option_print(const struct pcp_option *opt, void *arg)
{
	return 0 != pcp_option_print(arg, opt);
}


int pcp_msg_printhdr(struct re_printf *pf, const struct pcp_msg *msg)
{
	int err;

	if (!msg)
		return 0;

	err = re_hprintf(pf, "%s %s %usec",
			 msg->hdr.resp ? "Response" : "Request",
			 pcp_opcode_name(msg->hdr.opcode),
			 msg->hdr.lifetime);

	if (msg->hdr.resp) {
		err |= re_hprintf(pf, " result=%s, epoch_time=%u sec",
				  pcp_result_name(msg->hdr.result),
				  msg->hdr.epoch);
	}
	else {
		err |= re_hprintf(pf, " client_addr=%j", &msg->hdr.cli_addr);
	}

	return err;
}


static int pcp_map_print(struct re_printf *pf, const struct pcp_map *map)
{
	if (!map)
		return 0;

	return re_hprintf(pf,
			  " nonce    = %w\n protocol = %s\n"
			  " int_port = %u\n ext_addr = %J\n",
			  map->nonce, sizeof(map->nonce),
			  pcp_proto_name(map->proto),
			  map->int_port,
			  &map->ext_addr);
}


int pcp_msg_print(struct re_printf *pf, const struct pcp_msg *msg)
{
	int err;

	if (!msg)
		return 0;

	err  = pcp_msg_printhdr(pf, msg);
	err |= re_hprintf(pf, "\n");

	switch (msg->hdr.opcode) {

	case PCP_MAP:
		err |= pcp_map_print(pf, &msg->pld.map);
		break;

	case PCP_PEER:
		err |= pcp_map_print(pf, &msg->pld.peer.map);
		err |= re_hprintf(pf, " remote_peer = %J\n",
				  &msg->pld.peer.remote_addr);
		break;
	}

	if (err)
		return err;

	if (pcp_msg_option_apply(msg, option_print, pf))
		return ENOMEM;

	return 0;
}


/**
 * Get the payload from a PCP message
 *
 * @param msg PCP message
 *
 * @return either "struct pcp_map" or "struct pcp_peer"
 */
const void *pcp_msg_payload(const struct pcp_msg *msg)
{
	if (!msg)
		return NULL;

	switch (msg->hdr.opcode) {

	case PCP_MAP:  return &msg->pld.map;
	case PCP_PEER: return &msg->pld.peer;
	default:       return NULL;
	}
}
