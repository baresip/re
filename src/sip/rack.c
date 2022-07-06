/**
 * @file rack.c  SIP RAck decode (RFC 3262)
 *
 * Copyright (C) 2022 commend.com - m.fridrich@commend.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_uri.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_msg.h>
#include <re_sip.h>

/**
 * Decode a pointer-length string into a SIP RAck header
 *
 * @param rack SIP RAck header
 * @param pl   Pointer-length string
 *
 * @return 0 for success, otherwise errorcode
 */
int sip_rack_decode(struct sip_rack *rack, const struct pl *pl)
{
	struct pl rel_seq;
	struct pl cseq;
	int err;

	if (!rack || !pl)
		return EINVAL;

	err = re_regex(pl->p, pl->l,
		       "[0-9]+[ \t\r\n]+[0-9]+[ \t\r\n]+[^ \t\r\n]+",
		       &rel_seq, NULL, &cseq, NULL, &rack->met);
	if (err)
		return err;

	rack->rel_seq = pl_u32(&rel_seq);
	rack->cseq = pl_u32(&cseq);
	return 0;
}
