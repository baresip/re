/**
 * @file av1/pkt.c AV1 Packetizer
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re_types.h>
#include <re_mbuf.h>
#include <re_av1.h>


enum {
	HDR_SIZE = 1,
};


static void hdr_encode(uint8_t hdr[HDR_SIZE],
		       bool z, bool y, uint8_t w, bool n)
{
	hdr[0] = z<<7 | y<<6 | w<<4 | n<<3;
}


int av1_packetize(bool *newp, bool marker, uint64_t rtp_ts,
		  const uint8_t *buf, size_t len, size_t maxlen,
		  av1_packet_h *pkth, void *arg)
{
	uint8_t hdr[HDR_SIZE];
	bool start = true;
	uint8_t w = 0;  /* variable OBU count */
	int err = 0;

	if (!newp || !buf || !len || maxlen < (HDR_SIZE + 1) || !pkth)
		return EINVAL;

	maxlen -= sizeof(hdr);

	while (len > maxlen) {

		hdr_encode(hdr, !start, true, w, *newp);
		*newp = false;

		err |= pkth(false, rtp_ts, hdr, sizeof(hdr), buf, maxlen, arg);

		buf  += maxlen;
		len  -= maxlen;
		start = false;
	}

	hdr_encode(hdr, !start, false, w, *newp);
	*newp = false;

	err |= pkth(marker, rtp_ts, hdr, sizeof(hdr), buf, len, arg);

	return err;
}
