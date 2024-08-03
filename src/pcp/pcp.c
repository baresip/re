/**
 * @file pcp/pcp.c  PCP protocol details
 *
 * Copyright (C) 2010 - 2016 Alfred E. Heggestad
 */
#include <string.h>
#include <re_types.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_pcp.h>
#include "pcp.h"


static const uint8_t pattern[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};


int pcp_ipaddr_encode(struct mbuf *mb, const struct sa *sa)
{
	int err = 0;

	if (!mb || !sa)
		return EINVAL;

	switch (sa_af(sa)) {

	case AF_INET:
		err |= mbuf_write_mem(mb, pattern, sizeof(pattern));
		err |= mbuf_write_mem(mb, (void *)&sa->u.in.sin_addr.s_addr,
				      4);
		break;

	case AF_INET6:
		err |= mbuf_write_mem(mb, sa->u.in6.sin6_addr.s6_addr, 16);
		break;

	default:
		err = EAFNOSUPPORT;
		break;
	}

	return err;
}


int pcp_ipaddr_decode(struct mbuf *mb, struct sa *sa)
{
	uint8_t *p;

	if (!mb || !sa)
		return EINVAL;

	if (mbuf_get_left(mb) < 16)
		return EBADMSG;

	p = mbuf_buf(mb);

	if (0 == memcmp(p, pattern, sizeof(pattern))) {

		sa_init(sa, AF_INET);
		memcpy(&sa->u.in.sin_addr, p + 12, 4);
	}
	else {
		sa_init(sa, AF_INET6);
		memcpy(sa->u.in6.sin6_addr.s6_addr, p, 16);
	}

	mb->pos += 16;

	return 0;
}


const char *pcp_result_name(enum pcp_result result)
{
	switch (result) {

	case PCP_SUCCESS:                 return "SUCCESS";
	case PCP_UNSUPP_VERSION:          return "UNSUPP_VERSION";
	case PCP_NOT_AUTHORIZED:          return "NOT_AUTHORIZED";
	case PCP_MALFORMED_REQUEST:       return "MALFORMED_REQUEST";
	case PCP_UNSUPP_OPCODE:           return "UNSUPP_OPCODE";
	case PCP_UNSUPP_OPTION:           return "UNSUPP_OPTION";
	case PCP_MALFORMED_OPTION:        return "MALFORMED_OPTION";
	case PCP_NETWORK_FAILURE:         return "NETWORK_FAILURE";
	case PCP_NO_RESOURCES:            return "NO_RESOURCES";
	case PCP_UNSUPP_PROTOCOL:         return "UNSUPP_PROTOCOL";
	case PCP_USER_EX_QUOTA:           return "USER_EX_QUOTA";
	case PCP_CANNOT_PROVIDE_EXTERNAL: return "CANNOT_PROVIDE_EXTERNAL";
	case PCP_ADDRESS_MISMATCH:        return "ADDRESS_MISMATCH";
	case PCP_EXCESSIVE_REMOTE_PEERS:  return "EXCESSIVE_REMOTE_PEERS";
	default: return "?";
	}
}


const char *pcp_opcode_name(enum pcp_opcode opcode)
{
	switch (opcode) {

	case PCP_ANNOUNCE: return "ANNOUNCE";
	case PCP_MAP:      return "MAP";
	case PCP_PEER:     return "PEER";
	default:           return "?";
	}
}


const char *pcp_proto_name(int proto)
{
	switch (proto) {

	case IPPROTO_UDP: return "UDP";
	case IPPROTO_TCP: return "TCP";
	default: return "?";
	}
}
