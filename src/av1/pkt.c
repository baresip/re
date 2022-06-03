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


/**
 * Packetize an AV1 bitstream with one or more OBUs
 *
 * @param newp    Pointer to new stream flag
 * @param marker  Set marker bit
 * @param rtp_ts  RTP timestamp
 * @param buf     Input buffer
 * @param len     Buffer length
 * @param maxlen  Maximum RTP packet size
 * @param pkth    Packet handler
 * @param arg     Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int av1_packetize(bool *newp, bool marker, uint64_t rtp_ts,
		  const uint8_t *buf, size_t len, size_t maxlen,
		  av1_packet_h *pkth, void *arg)
{
	uint8_t hdr[HDR_SIZE];
	bool cont = false;
	uint8_t w = 0;  /* variable OBU count */
	int err = 0;

	if (!newp || !buf || !len || maxlen < (HDR_SIZE + 1) || !pkth)
		return EINVAL;

	maxlen -= sizeof(hdr);

	while (len > maxlen) {

		hdr_encode(hdr, cont, true, w, *newp);
		*newp = false;

		err |= pkth(false, rtp_ts, hdr, sizeof(hdr), buf, maxlen, arg);

		buf  += maxlen;
		len  -= maxlen;
		cont = true;
	}

	hdr_encode(hdr, cont, false, w, *newp);
	*newp = false;

	err |= pkth(marker, rtp_ts, hdr, sizeof(hdr), buf, len, arg);

	return err;
}
