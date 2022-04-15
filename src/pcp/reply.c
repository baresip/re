/**
 * @file pcp/reply.c  PCP reply
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_udp.h>
#include <re_pcp.h>
#include "pcp.h"


static int pcp_header_encode_response(struct mbuf *mb, enum pcp_opcode opcode,
				      enum pcp_result result,
				      uint32_t lifetime, uint32_t epoch_time)
{
	int err = 0;

	if (!mb)
		return EINVAL;

	err |= mbuf_write_u8(mb, PCP_VERSION);
	err |= mbuf_write_u8(mb, 1<<7 | opcode);
	err |= mbuf_write_u8(mb, 0x00);
	err |= mbuf_write_u8(mb, result);
	err |= mbuf_write_u32(mb, htonl(lifetime));
	err |= mbuf_write_u32(mb, htonl(epoch_time));
	err |= mbuf_fill(mb, 0x00, 12);

	return err;
}


/**
 * Send a PCP response message
 *
 * @param us         UDP Socket
 * @param dst        Destination network address
 * @param req        Buffer containing original PCP request (optional)
 * @param opcode     PCP opcode
 * @param result     PCP result for the response
 * @param lifetime   Lifetime in [seconds]
 * @param epoch_time Server Epoch-time
 * @param payload    PCP payload, e.g. struct pcp_map (optional)
 *
 * @return 0 if success, otherwise errorcode
 */
int pcp_reply(struct udp_sock *us, const struct sa *dst, struct mbuf *req,
	      enum pcp_opcode opcode, enum pcp_result result,
	      uint32_t lifetime, uint32_t epoch_time, const void *payload)
{
	struct mbuf *mb;
	size_t start;
	int err;

	if (!us || !dst)
		return EINVAL;

	if (req) {
		/* the complete Request must be included in the Response */
		mb = mem_ref(req);
	}
	else {
		mb = mbuf_alloc(128);
		if (!mb)
			return ENOMEM;
	}

	start = mb->pos;

	/* encode the response packet */
	err = pcp_header_encode_response(mb, opcode, result,
					 lifetime, epoch_time);
	if (err)
		goto out;

	if (payload) {
		err = pcp_payload_encode(mb, opcode, payload);
		if (err)
			goto out;
	}

	mb->pos = start;
	err = udp_send(us, dst, mb);

 out:
	mem_deref(mb);
	return err;
}
