/**
 * @file aac.c Advanced Audio Coding
 *
 * Copyright (C) 2018 Creytiv.com
 */

#include <re_types.h>
#include <rem_aac.h>


/*
 * Ref https://wiki.multimedia.cx/index.php/MPEG-4_Audio
 */

enum {
	OBJECT_TYPE_AAC_LC = 2
};


static const unsigned aac_sample_rates[13] = {
	96000, 88200, 64000, 48000, 44100, 32000,
	24000, 22050, 16000, 12000, 11025, 8000, 7350
};


static const unsigned aac_channels[8] = {
	0, 1, 2, 3, 4, 5, 6, 8
};


/**
 * Decode an AAC header
 *
 * @param hdr Decoded AAC header
 * @param p   Packet to decode
 * @param len Packet length
 *
 * @return 0 if success, otherwise errorcode
 */
int aac_header_decode(struct aac_header *hdr, const uint8_t *p, size_t len)
{
	uint8_t object_type;
	uint8_t srate_index;
	uint8_t channel_index;

	if (!hdr || !p || len<2)
		return EINVAL;

	object_type = (p[0] >> 3) & 0x1f;

	if (object_type != OBJECT_TYPE_AAC_LC)
		return EBADMSG;

	srate_index  = (p[0] & 0x07) << 1;
	srate_index |= (p[1] & 0x80) >> 7;

	channel_index = (p[1] >> 3) & 0xf;

	if (srate_index >= ARRAY_SIZE(aac_sample_rates))
		return ENOTSUP;
	if (channel_index >= ARRAY_SIZE(aac_channels))
		return ENOTSUP;

	hdr->sample_rate = aac_sample_rates[srate_index];
	hdr->channels    = aac_channels[channel_index];
	hdr->frame_size  = ((p[1] >> 2) & 1) ? 960 : 1024;

	return 0;
}
