/**
 * @file sdp.c  SDP helpers for T.140 Real-Time Text over RTP (RFC 4103)
 *
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_sdp.h>
#include <re_red.h>
#include <re_t140.h>
#include "t140.h"


/*
 * A text stream is offered as
 *
 *   m=text 11000 RTP/AVP 100 98
 *   a=rtpmap:100 red/1000
 *   a=fmtp:100 98/98/98
 *   a=rtpmap:98 t140/1000
 *   a=fmtp:98 cps=30
 *   a=sendrecv
 *
 * The fmtp of "red" lists the payload type of each generation, oldest
 * first, followed by the primary one. The NG9-1-1 RUE profile expects two
 * redundant generations, which is what conf.u.rtp.ngen defaults to in
 * practice.
 *
 * These helpers describe an RTP media line, so each of them refuses a
 * configuration that names another transport with EINVAL. The data channel
 * of RFC 8865 is described by a=dcmap and a=dcsa instead, which is what
 * t140_dc_sdp_encode() and t140_dc_sdp_decode() in dc.c are for.
 */


/**
 * Parse a "red" fmtp list and check that every generation resolves to the
 * expected payload type
 */
static bool red_list_check(const char *params, uint8_t pt)
{
	const char *p = params;
	unsigned n = 0;

	while (*p) {

		unsigned v = 0;
		unsigned d = 0;

		if (' ' == *p || '\t' == *p || '/' == *p) {
			++p;
			continue;
		}

		while (*p >= '0' && *p <= '9') {

			v = v * 10 + (unsigned)(*p++ - '0');

			if (++d > 3)
				return false;
		}

		if (!d || v != pt)
			return false;

		++n;
	}

	return n > 0;
}


/**
 * Encode the fmtp parameters of the "t140" format
 *
 * @param mb    Buffer to encode into
 * @param fmt   SDP format
 * @param offer True if the SDP is an offer
 * @param arg   Pointer to a struct t140_conf
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_fmtp_enc(struct mbuf *mb, const struct sdp_format *fmt,
		  bool offer, void *arg)
{
	const struct t140_conf *conf = arg;

	(void)offer;

	if (!mb || !fmt || !conf)
		return EINVAL;

	if (T140_TRANSPORT_RTP != conf->transport)
		return EINVAL;

	if (!conf->cps || T140_CPS == conf->cps)
		return 0;

	return mbuf_printf(mb, "a=fmtp:%s cps=%u\r\n", fmt->id, conf->cps);
}


/**
 * Compare the fmtp parameters of the "t140" format
 *
 * The character rate is a hint about what the far end is willing to
 * receive, never a reason to reject the format.
 *
 * @param lparams Local parameters
 * @param rparams Remote parameters
 * @param arg     Pointer to a struct t140_conf
 *
 * @return True if the formats are compatible
 */
bool t140_fmtp_cmp(const char *lparams, const char *rparams, void *arg)
{
	const struct t140_conf *conf = arg;

	(void)lparams;
	(void)rparams;

	if (conf && T140_TRANSPORT_RTP != conf->transport)
		return false;

	return true;
}


/**
 * Encode the fmtp parameters of the "red" format
 *
 * @param mb    Buffer to encode into
 * @param fmt   SDP format
 * @param offer True if the SDP is an offer
 * @param arg   Pointer to a struct t140_conf
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_red_fmtp_enc(struct mbuf *mb, const struct sdp_format *fmt,
		      bool offer, void *arg)
{
	const struct t140_conf *conf = arg;
	unsigned i;
	int err;

	(void)offer;

	if (!mb || !fmt || !conf)
		return EINVAL;

	if (T140_TRANSPORT_RTP != conf->transport)
		return EINVAL;

	err = mbuf_printf(mb, "a=fmtp:%s %u", fmt->id, conf->u.rtp.pt);

	for (i=0; i<conf->u.rtp.ngen; i++)
		err |= mbuf_printf(mb, "/%u", conf->u.rtp.pt);

	err |= mbuf_printf(mb, "\r\n");

	return err;
}


/**
 * Compare the fmtp parameters of the "red" format
 *
 * A "red" format is only usable if every generation it lists is the "t140"
 * format we negotiated; redundancy over a different codec is not something
 * this module can carry.
 *
 * @param lparams Local parameters
 * @param rparams Remote parameters
 * @param arg     Pointer to a struct t140_conf
 *
 * @return True if the formats are compatible
 */
bool t140_red_fmtp_cmp(const char *lparams, const char *rparams, void *arg)
{
	const struct t140_conf *conf = arg;

	(void)lparams;

	if (!conf || !str_isset(rparams))
		return false;

	if (T140_TRANSPORT_RTP != conf->transport)
		return false;

	return red_list_check(rparams, conf->u.rtp.pt);
}


/**
 * Add a text media line to an SDP session
 *
 * Both the "red" and the "t140" formats are registered, with "red" first
 * so that it is the preferred one. The configuration is copied, so the
 * caller may let its own go out of scope.
 *
 * @param mp    Pointer to allocated SDP media line (optional)
 * @param sess  SDP session
 * @param laddr Local address (optional)
 * @param conf  T.140 configuration
 *
 * @return 0 if success, otherwise errorcode
 */
int t140_sdp_media_add(struct sdp_media **mp, struct sdp_session *sess,
		       const struct sa *laddr, const struct t140_conf *conf)
{
	struct sdp_media *m = NULL;
	struct t140_conf *cp;
	char id[4];
	int err;

	if (!sess || !conf)
		return EINVAL;

	if (T140_TRANSPORT_RTP != conf->transport)
		return EINVAL;

	if (!conf->u.rtp.pt || conf->u.rtp.pt > 0x7f)
		return EINVAL;

	cp = mem_zalloc(sizeof(*cp), NULL);
	if (!cp)
		return ENOMEM;

	*cp = *conf;

	err = sdp_media_add(&m, sess, sdp_media_text,
			    laddr ? sa_port(laddr) : 0, sdp_proto_rtpavp);
	if (err)
		goto out;

	if (laddr)
		sdp_media_set_laddr(m, laddr);

	if (conf->u.rtp.pt_red && conf->u.rtp.ngen) {

		(void)re_snprintf(id, sizeof(id), "%u", conf->u.rtp.pt_red);

		err = sdp_format_add(NULL, m, false, id, t140_red_rtpfmt,
				     T140_SRATE, 1, t140_red_fmtp_enc,
				     t140_red_fmtp_cmp, cp, true, NULL);
		if (err)
			goto out;
	}

	(void)re_snprintf(id, sizeof(id), "%u", conf->u.rtp.pt);

	err = sdp_format_add(NULL, m, false, id, t140_rtpfmt, T140_SRATE, 1,
			     t140_fmtp_enc, t140_fmtp_cmp, cp, true, NULL);
	if (err)
		goto out;

 out:
	mem_deref(cp);

	if (err)
		mem_deref(m);
	else if (mp)
		*mp = m;

	return err;
}
