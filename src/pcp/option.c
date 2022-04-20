/**
 * @file option.c  PCP options
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


static void destructor(void *arg)
{
	struct pcp_option *opt = arg;

	list_unlink(&opt->le);

	switch (opt->code) {

	case PCP_OPTION_DESCRIPTION:
		mem_deref(opt->u.description);
		break;

	default:
		break;
	}
}


int pcp_option_encode(struct mbuf *mb, enum pcp_option_code code,
		      const void *v)
{
	const struct sa *sa = v;
	const struct pcp_option_filter *filt = v;
	size_t start, len;
	int err = 0;

	if (!mb)
		return EINVAL;

	mb->pos += 4;
	start = mb->pos;

	switch (code) {

	case PCP_OPTION_THIRD_PARTY:
		if (!sa)
			return EINVAL;
		err |= pcp_ipaddr_encode(mb, sa);
		break;

	case PCP_OPTION_PREFER_FAILURE:
		/* no payload */
		break;

	case PCP_OPTION_FILTER:
		if (!filt)
			return EINVAL;
		err |= mbuf_write_u8(mb, 0x00);
		err |= mbuf_write_u8(mb, filt->prefix_length);
		err |= mbuf_write_u16(mb, htons(sa_port(&filt->remote_peer)));
		err |= pcp_ipaddr_encode(mb, &filt->remote_peer);
		break;

	case PCP_OPTION_DESCRIPTION:
		if (!v)
			return EINVAL;
		err |= mbuf_write_str(mb, v);
		break;

	default:
		(void)re_fprintf(stderr,
				 "pcp: unsupported option %d\n", code);
		return EINVAL;
	}

	/* header */
	len = mb->pos - start;

	mb->pos = start - 4;
	err |= mbuf_write_u8(mb, code);
	err |= mbuf_write_u8(mb, 0x00);
	err |= mbuf_write_u16(mb, htons((uint16_t)len));
	mb->pos += len;

	/* padding */
	while ((mb->pos - start) & 0x03)
		err |= mbuf_write_u8(mb, 0x00);

	return err;
}


int pcp_option_decode(struct pcp_option **optp, struct mbuf *mb)
{
	struct pcp_option *opt;
	size_t start, len;
	uint16_t port;
	int err = 0;

	if (!optp || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < 4)
		return EBADMSG;

	opt = mem_zalloc(sizeof(*opt), destructor);
	if (!opt)
		return ENOMEM;

	opt->code = mbuf_read_u8(mb);
	(void)mbuf_read_u8(mb);
	len = ntohs(mbuf_read_u16(mb));

	if (mbuf_get_left(mb) < len)
		goto badmsg;

	start = mb->pos;

	switch (opt->code) {

	case PCP_OPTION_THIRD_PARTY:
		if (len < 16)
			goto badmsg;
		err = pcp_ipaddr_decode(mb, &opt->u.third_party);
		break;

	case PCP_OPTION_PREFER_FAILURE:
		/* no payload */
		break;

	case PCP_OPTION_FILTER:
		if (len < 20)
			goto badmsg;
		(void)mbuf_read_u8(mb);
		opt->u.filter.prefix_length = mbuf_read_u8(mb);
		port = ntohs(mbuf_read_u16(mb));
		err = pcp_ipaddr_decode(mb, &opt->u.filter.remote_peer);
		sa_set_port(&opt->u.filter.remote_peer, port);
		break;

	case PCP_OPTION_DESCRIPTION:
		err = mbuf_strdup(mb, &opt->u.description, len);
		break;

	default:
		mb->pos += len;

		(void)re_printf("pcp: ignore option code %d (len=%zu)\n",
				opt->code, len);
		break;
	}

	if (err)
		goto error;

	/* padding */
	while (((mb->pos - start) & 0x03) && mbuf_get_left(mb))
		++mb->pos;

	*optp = opt;

	return 0;

 badmsg:
	err = EBADMSG;
 error:
	mem_deref(opt);

	return err;
}


static const char *pcp_option_name(enum pcp_option_code code)
{
	switch (code) {

	case PCP_OPTION_THIRD_PARTY:    return "THIRD_PARTY";
	case PCP_OPTION_PREFER_FAILURE: return "PREFER_FAILURE";
	case PCP_OPTION_FILTER:         return "FILTER";
	case PCP_OPTION_DESCRIPTION:    return "DESCRIPTION";
	default: return "?";
	}
}


int pcp_option_print(struct re_printf *pf, const struct pcp_option *opt)
{
	int err;

	if (!opt)
		return 0;

	err = re_hprintf(pf, " %-25s", pcp_option_name(opt->code));

	switch (opt->code) {

	case PCP_OPTION_THIRD_PARTY:
		err |= re_hprintf(pf, "address=%j",
				  &opt->u.third_party);
		break;

	case PCP_OPTION_PREFER_FAILURE:
		break;

	case PCP_OPTION_FILTER:
		err |= re_hprintf(pf, "prefix_length=%u, remote_peer=%J",
				  opt->u.filter.prefix_length,
				  &opt->u.filter.remote_peer);
		break;

	case PCP_OPTION_DESCRIPTION:
		err |= re_hprintf(pf, "'%s'", opt->u.description);
		break;

	default:
		err |= re_hprintf(pf, "???");
		break;
	}

	err |= re_hprintf(pf, "\n");

	return err;
}
