/**
 * @file avc/config.c Advanced Video Coding -- Configuration record
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_net.h>
#include <rem_avc.h>


#define AVC_CONFIG_VERSION 1
#define SPS_MASK 0xe0


int avc_config_encode(struct mbuf *mb, uint8_t profile_ind,
		      uint8_t profile_compat, uint8_t level_ind,
		      uint16_t sps_length, const uint8_t *sps,
		      uint16_t pps_length, const uint8_t *pps)
{
	int err;

	if (!mb || !sps || !pps)
		return EINVAL;

	err  = mbuf_write_u8(mb, AVC_CONFIG_VERSION);

	err |= mbuf_write_u8(mb, profile_ind);
	err |= mbuf_write_u8(mb, profile_compat);
	err |= mbuf_write_u8(mb, level_ind);

	err |= mbuf_write_u8(mb, 0xfc | (4-1));

	/* SPS */
	err |= mbuf_write_u8(mb, SPS_MASK | 1);
	err |= mbuf_write_u16(mb, htons(sps_length));
	err |= mbuf_write_mem(mb, sps, sps_length);

	/* PPS */
	err |= mbuf_write_u8(mb, 1);
	err |= mbuf_write_u16(mb, htons(pps_length));
	err |= mbuf_write_mem(mb, pps, pps_length);

	return err;
}


int avc_config_decode(struct avc_config *conf, struct mbuf *mb)
{
	uint8_t version, length_size, count;

	if (!conf || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < 5)
		return EBADMSG;

	version              = mbuf_read_u8(mb);
	conf->profile_ind    = mbuf_read_u8(mb);
	conf->profile_compat = mbuf_read_u8(mb);
	conf->level_ind      = mbuf_read_u8(mb);
	length_size          = mbuf_read_u8(mb) & 0x03;

	if (version != AVC_CONFIG_VERSION || length_size != 3)
		return EPROTO;

	/* SPS */
	if (mbuf_get_left(mb) < 3)
		return EBADMSG;

	count = mbuf_read_u8(mb) & 0x1f;
	conf->sps_len = ntohs(mbuf_read_u16(mb));

	if (count != 1 || conf->sps_len > sizeof(conf->sps))
		return EOVERFLOW;

	if (mbuf_get_left(mb) < conf->sps_len)
		return EBADMSG;

	mbuf_read_mem(mb, conf->sps, conf->sps_len);

	/* PPS */
	if (mbuf_get_left(mb) < 3)
		return EBADMSG;

	count = mbuf_read_u8(mb);
	conf->pps_len = ntohs(mbuf_read_u16(mb));

	if (count != 1 || conf->pps_len > sizeof(conf->pps))
		return EOVERFLOW;

	if (mbuf_get_left(mb) < conf->pps_len)
		return EBADMSG;

	mbuf_read_mem(mb, conf->pps, conf->pps_len);

	return 0;
}
