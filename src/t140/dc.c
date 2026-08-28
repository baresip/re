/**
 * @file dc.c  T.140 Real-Time Text over data channels (RFC 8865)
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
 * NOT IMPLEMENTED.
 *
 * RFC 8865 carries the same T.140 block stream as RFC 4103 does, but over
 * a WebRTC data channel with subprotocol "t140". Because SCTP over DTLS is
 * reliable and ordered, there is no redundancy and no timestamp on the
 * wire: the T140 blocks are written to the channel as they are.
 *
 * Everything above the transport is therefore already written and already
 * transport-neutral. t140_send() and its variants, t140_recv(),
 * t140_poll(), the handlers and the counters all work unchanged on a
 * session allocated with T140_TRANSPORT_DC; tx.c and rx.c already take the
 * branches that skip the redundancy, the timestamps and the loss marking.
 * That is why there is no separate constructor and no second set of
 * handlers: the transport is a parameter of t140_alloc(), which returns
 * ENOSYS for this one until the pieces below exist.
 *
 * What is missing is the transport and its signalling:
 *
 *   - libre has no SCTP and no data-channel stack. The binding is meant to
 *     stay transport-agnostic: the application owns the channel, writes
 *     what the send handler gives it, and feeds what arrives back through
 *     t140_recv() with only pkt->mb set. That way this can be built ahead
 *     of any SCTP work, and a native stack can slot in underneath later;
 *
 *   - the two functions below, which describe the channel in SDP.
 *
 * When implementing, RFC 8865 constrains the channel:
 *
 *   - it must be reliable and ordered. A "dcmap" that says otherwise, by
 *     carrying max-retr or max-time, is to be rejected;
 *   - one bidirectional channel carries one T.140 conversation both ways;
 *   - loss marking is not needed, but a channel that closes in the middle
 *     of a code point still has to emit U+FFFD, which is what
 *     t140_utf8_reset() and a trailing marker are for;
 *   - closing the channel ends the text conversation, not the session.
 *
 * The SDP shape to generate and parse is, per RFC 8864 and RFC 8865:
 *
 *   m=application 54111 UDP/DTLS/SCTP webrtc-datachannel
 *   a=sctp-port:5000
 *   a=dcmap:1 label="t140";subprotocol="t140";ordered=true
 *   a=dcsa:1 sendrecv
 *   a=dcsa:1 fmtp:t140 cps=30
 *   a=dcsa:1 lang:fr
 *
 * The exact "dcsa" grammar must be checked against RFC 8865 section 5
 * before this is written; the lines above are indicative.
 */


const char t140_dc_subproto[] = "t140";


/**
 * Encode the "dcmap" and "dcsa" attributes of a T.140 data channel
 *
 * @param mb        Buffer to encode into
 * @param stream_id Data channel stream identifier
 * @param conf      T.140 configuration, transport T140_TRANSPORT_DC
 * @param dir       Direction of the text stream
 *
 * @return EINVAL if the configuration names another transport, otherwise
 *         ENOSYS: this transport is not implemented
 */
int t140_dc_sdp_encode(struct mbuf *mb, uint16_t stream_id,
		       const struct t140_conf *conf, enum sdp_dir dir)
{
	(void)mb;
	(void)stream_id;
	(void)dir;

	if (!conf)
		return EINVAL;

	if (T140_TRANSPORT_DC != conf->transport)
		return EINVAL;

	return ENOSYS;
}


/**
 * Decode the "dcmap" and "dcsa" attributes of a T.140 data channel
 *
 * @param conf  T.140 configuration, set on return with transport
 *              T140_TRANSPORT_DC
 * @param dir   Direction of the text stream, set on return
 * @param dcmap Value of the "dcmap" attribute
 * @param dcsa  Value of the "dcsa" attributes
 *
 * @return EINVAL if the configuration names another transport, otherwise
 *         ENOSYS: this transport is not implemented
 */
int t140_dc_sdp_decode(struct t140_conf *conf, enum sdp_dir *dir,
		       const char *dcmap, const char *dcsa)
{
	(void)dir;
	(void)dcmap;
	(void)dcsa;

	if (!conf)
		return EINVAL;

	if (T140_TRANSPORT_DC != conf->transport)
		return EINVAL;

	return ENOSYS;
}
