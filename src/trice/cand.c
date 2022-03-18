/**
 * @file cand.c  Common ICE Candidates
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_sys.h>
#include <re_stun.h>
#include <re_udp.h>
#include <re_tcp.h>
#include <re_ice.h>
#include <re_trice.h>
#include "trice.h"


const char *ice_tcptype_name(enum ice_tcptype tcptype)
{
	switch (tcptype) {

	case ICE_TCP_ACTIVE:  return "active";
	case ICE_TCP_PASSIVE: return "passive";
	case ICE_TCP_SO:      return "so";
	default: return "???";
	}
}


/*
   Local           Remote
   Candidate       Candidate
   ---------------------------
   tcp-so          tcp-so
   tcp-active      tcp-passive
   tcp-passive     tcp-active

 */
enum ice_tcptype ice_tcptype_reverse(enum ice_tcptype type)
{
	switch (type) {

	case ICE_TCP_SO:      return ICE_TCP_SO;
	case ICE_TCP_ACTIVE:  return ICE_TCP_PASSIVE;
	case ICE_TCP_PASSIVE: return ICE_TCP_ACTIVE;
	default:              return (enum ice_tcptype)-1;
	}
}


enum ice_cand_type ice_cand_type_base(enum ice_cand_type type)
{
	switch (type) {

	case ICE_CAND_TYPE_HOST:    return ICE_CAND_TYPE_HOST;
	case ICE_CAND_TYPE_SRFLX:   return ICE_CAND_TYPE_HOST;
	case ICE_CAND_TYPE_PRFLX:   return ICE_CAND_TYPE_HOST;
	case ICE_CAND_TYPE_RELAY:   return ICE_CAND_TYPE_RELAY;
	default: return type;
	}
}


int trice_cand_print(struct re_printf *pf, const struct ice_cand_attr *cand)
{
	int err = 0;

	if (!cand)
		return 0;

	err |= re_hprintf(pf, "%s|%s", ice_cand_type2name(cand->type),
			  net_proto2name(cand->proto));

	if (cand->proto == IPPROTO_TCP) {

		err |= re_hprintf(pf, ".%s", ice_tcptype_name(cand->tcptype));
	}

	err |= re_hprintf(pf, "|%J", &cand->addr);

	return err;
}
