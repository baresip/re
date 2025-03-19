/**
 * @file rtcp.c  Real-time Transport Control Protocol
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_rtp.h>
#include "rtcp.h"


static int rtcp_quick_send(struct rtp_sock *rs, enum rtcp_type type,
			   uint32_t count, ...)
{
	struct mbuf *mb;
	va_list ap;
	int err;

	mb = mbuf_alloc(32);
	if (!mb)
		return ENOMEM;

	mb->pos = RTCP_HEADROOM;

	err  = rtcp_make_sr(rs, mb);
	err |= rtcp_make_sdes_cname(rs, mb);
	if (err)
		goto out;

	va_start(ap, count);
	err = rtcp_vencode(mb, type, count, ap);
	va_end(ap);

	mb->pos = RTCP_HEADROOM;

	if (!err)
		err = rtcp_send(rs, mb);

	if (!err)
		rtcp_schedule_report(rs);

out:
	mem_deref(mb);

	return err;
}


/**
 * Send an RTCP Application-Defined (APP) packet
 *
 * @param rs   RTP Socket
 * @param name Ascii name (4 octets)
 * @param data Application-dependent data
 * @param len  Number of bytes of data
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_send_app(struct rtp_sock *rs, const char name[4],
		  const uint8_t *data, size_t len)
{
	return rtcp_quick_send(rs, RTCP_APP, 0, rtp_sess_ssrc(rs),
			       name, data, len);
}


/**
 * Send a Full INTRA-frame Request (FIR) packet
 *
 * @param rs   RTP Socket
 * @param ssrc Synchronization source identifier for the sender of this packet
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_send_fir(struct rtp_sock *rs, uint32_t ssrc)
{
	return rtcp_quick_send(rs, RTCP_FIR, 0, ssrc);
}


/**
 * Send an RTCP NACK packet
 *
 * @param rs   RTP Socket
 * @param fsn  First Sequence Number lost
 * @param blp  Bitmask of lost packets
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_send_nack(struct rtp_sock *rs, uint16_t fsn, uint16_t blp)
{
	return rtcp_quick_send(rs, RTCP_NACK, 0, rtp_sess_ssrc(rs), fsn, blp);
}


static int encode_gnack(struct mbuf *mb, void *arg)
{
	struct gnack *fci = arg;

	return rtcp_rtpfb_gnack_encode(mb, fci->pid, fci->blp);
}


/**
 * Send an RTCP Generic NACK packet (RFC 4585 6.2.1)
 *
 * @param rs   RTP Socket
 * @param ssrc SSRC of the target encoder
 * @param fsn  First Sequence Number lost
 * @param blp  Bitmask of lost packets
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_send_gnack(struct rtp_sock *rs, uint32_t ssrc, uint16_t fsn,
		    uint16_t blp)
{
	struct gnack fci = {fsn, blp};
	return rtcp_quick_send(rs, RTCP_RTPFB, RTCP_RTPFB_GNACK,
			       rtp_sess_ssrc(rs), ssrc, &encode_gnack,
			       &fci);
}


static int encode_twcc(struct mbuf *mb, void *arg)
{
	struct twcc *twcc = arg;

	return rtcp_rtpfb_twcc_encode(mb, twcc);
}


/**
 * Send an RTCP Transport-wide congestion control Feedback Message
 *
 * @param rs   RTP Socket
 * @param ssrc SSRC of the target encoder
 * @param twcc Transport-wide CC message
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_send_twcc(struct rtp_sock *rs, uint32_t ssrc, struct twcc *twcc)
{
	return rtcp_quick_send(rs, RTCP_RTPFB, RTCP_RTPFB_TWCC,
			       rtp_sess_ssrc(rs), ssrc, &encode_twcc, twcc);
}


/**
 * Send an RTCP Picture Loss Indication (PLI) packet
 *
 * @param rs      RTP Socket
 * @param fb_ssrc Feedback SSRC
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_send_pli(struct rtp_sock *rs, uint32_t fb_ssrc)
{
	return rtcp_quick_send(rs, RTCP_PSFB, RTCP_PSFB_PLI,
			       rtp_sess_ssrc(rs), fb_ssrc, NULL, NULL);
}


static int encode_fir_rfc5104_fci(struct mbuf *mb, void *arg)
{
	struct fir_rfc5104 *fci = arg;
	int err = mbuf_write_u32(mb, htonl(fci->ssrc));
	err |= mbuf_write_u8(mb, fci->seq_n);
	err |= mbuf_write_u8(mb, 0);
	err |= mbuf_write_u8(mb, 0);
	err |= mbuf_write_u8(mb, 0);
	return err;
}


/**
 * Send an RTCP Full INTRA-frame Request (FIR) packet according to RFC 5104
 *
 * @param rs       RTP Socket
 * @param ssrc     SSRC of the target encoder
 * @param fir_seqn FIR sequence number
 *
 * @return 0 for success, otherwise errorcode
 */
int rtcp_send_fir_rfc5104(struct rtp_sock *rs, uint32_t ssrc, uint8_t fir_seqn)
{
	struct fir_rfc5104 fci = { ssrc, fir_seqn };
	return rtcp_quick_send(rs, RTCP_PSFB, RTCP_PSFB_FIR,
			       rtp_sess_ssrc(rs), (uint32_t)0u,
			       &encode_fir_rfc5104_fci, &fci);
}


/**
 * Get the name of an RTCP type
 *
 * @param type RTCP type
 *
 * @return String with RTCP name
 */
const char *rtcp_type_name(enum rtcp_type type)
{
	switch (type) {

	case RTCP_FIR:   return "FIR";
	case RTCP_NACK:  return "NACK";
	case RTCP_SR:    return "SR";
	case RTCP_RR:    return "RR";
	case RTCP_SDES:  return "SDES";
	case RTCP_BYE:   return "BYE";
	case RTCP_APP:   return "APP";
	case RTCP_RTPFB: return "RTPFB";
	case RTCP_PSFB:  return "PSFB";
	case RTCP_XR:    return "XR";
	case RTCP_AVB:   return "AVB";
	default:         return "?";
	}
}


/**
 * Get the name of an RTCP SDES type
 *
 * @param sdes RTCP SDES type
 *
 * @return String with RTCP SDES name
 */
const char *rtcp_sdes_name(enum rtcp_sdes_type sdes)
{
	switch (sdes) {

	case RTCP_SDES_END:    return "END";
	case RTCP_SDES_CNAME:  return "CNAME";
	case RTCP_SDES_NAME:   return "NAME";
	case RTCP_SDES_EMAIL:  return "EMAIL";
	case RTCP_SDES_PHONE:  return "PHONE";
	case RTCP_SDES_LOC:    return "LOC";
	case RTCP_SDES_TOOL:   return "TOOL";
	case RTCP_SDES_NOTE:   return "NOTE";
	case RTCP_SDES_PRIV:   return "PRIV";
	default:               return "?";
	}
}


/**
 * Print an RTCP Message
 *
 * @param pf  Print handler for debug output
 * @param msg RTCP Message
 *
 * @return 0 if success, otherwise errorcode
 */
int rtcp_msg_print(struct re_printf *pf, const struct rtcp_msg *msg)
{
	size_t i, j;
	int err;

	if (!msg)
		return 0;

	err = re_hprintf(pf, "%8s pad=%d count=%-2d pt=%-3d len=%u ",
			 rtcp_type_name((enum rtcp_type)msg->hdr.pt),
			 msg->hdr.p,
			 msg->hdr.count, msg->hdr.pt, msg->hdr.length);
	if (err)
		return err;

	switch (msg->hdr.pt) {

	case RTCP_SR:
		err = re_hprintf(pf, "%08x %u %u %u %u %u",
				 msg->r.sr.ssrc,
				 msg->r.sr.ntp_sec,
				 msg->r.sr.ntp_frac,
				 msg->r.sr.rtp_ts,
				 msg->r.sr.psent,
				 msg->r.sr.osent);
		for (i=0; i<msg->hdr.count && !err; i++) {
			const struct rtcp_rr *rr = &msg->r.sr.rrv[i];
			err = re_hprintf(pf, " {%08x %u %d %u %u %u %u}",
					 rr->ssrc, rr->fraction, rr->lost,
					 rr->last_seq, rr->jitter,
					 rr->lsr, rr->dlsr);
		}
		break;

	case RTCP_RR:
		err = re_hprintf(pf, "%08x", msg->r.rr.ssrc);
		for (i=0; i<msg->hdr.count && !err; i++) {
			const struct rtcp_rr *rr = &msg->r.rr.rrv[i];
			err = re_hprintf(pf, " {0x%08x %u %d %u %u %u %u}",
					 rr->ssrc, rr->fraction, rr->lost,
					 rr->last_seq, rr->jitter,
					 rr->lsr, rr->dlsr);
		}
		break;

	case RTCP_SDES:
		for (i=0; i<msg->hdr.count; i++) {
			const struct rtcp_sdes *sdes = &msg->r.sdesv[i];

			err = re_hprintf(pf, " {0x%08x n=%u",
					 sdes->src, sdes->n);
			for (j=0; j<sdes->n && !err; j++) {
				const struct rtcp_sdes_item *item;
				item = &sdes->itemv[j];
				err = re_hprintf(pf, " <%s:%b>",
						 rtcp_sdes_name(item->type),
						 item->data,
						 (size_t)item->length);
			}
			err |= re_hprintf(pf, "}");
		}
		break;

	case RTCP_BYE:
		err = re_hprintf(pf, "%u srcs:", msg->hdr.count);
		for (i=0; i<msg->hdr.count && !err; i++) {
			err = re_hprintf(pf, " %08x",
					 msg->r.bye.srcv[i]);
		}
		err |= re_hprintf(pf, " '%s'", msg->r.bye.reason);
		break;

	case RTCP_APP:
		err = re_hprintf(pf, "src=%08x '%b' data=%zu",
				 msg->r.app.src,
				 msg->r.app.name, sizeof(msg->r.app.name),
				 msg->r.app.data_len);
		break;

	case RTCP_FIR:
		err = re_hprintf(pf, "ssrc=%08x", msg->r.fir.ssrc);
		break;

	case RTCP_NACK:
		err = re_hprintf(pf, "ssrc=%08x fsn=%04x blp=%04x",
				 msg->r.nack.ssrc, msg->r.nack.fsn,
				 msg->r.nack.blp);
		break;

	case RTCP_RTPFB:
		err = re_hprintf(pf, "pkt=%08x med=%08x n=%u",
				 msg->r.fb.ssrc_packet,
				 msg->r.fb.ssrc_media,
				 msg->r.fb.n);
		if (msg->hdr.count == RTCP_RTPFB_GNACK) {
			err |= re_hprintf(pf, " GNACK");
			for (i=0; i<msg->r.fb.n; i++) {
				err |= re_hprintf(pf, " {%04x %04x}",
						  msg->r.fb.fci.gnackv[i].pid,
						  msg->r.fb.fci.gnackv[i].blp);
			}
		}
		else if (msg->hdr.count == RTCP_RTPFB_TWCC) {
			const struct twcc *twcc = msg->r.fb.fci.twccv;

			err |= re_hprintf(pf,
					  " TWCC"
					  " base_seq=%u"
					  " pkt_status_count=%u"
					  " ref_time=%u"
					  " fb_pkt_count=%u"
					  ,
					  twcc->seq,
					  twcc->count,
					  twcc->reftime,
					  twcc->fbcount);
		}
		break;

	case RTCP_PSFB:
		err = re_hprintf(pf, "pkt=%08x med=%08x n=%u",
				 msg->r.fb.ssrc_packet,
				 msg->r.fb.ssrc_media,
				 msg->r.fb.n);
		if (msg->hdr.count == RTCP_PSFB_SLI) {
			err |= re_hprintf(pf, " SLI");
			for (i=0; i<msg->r.fb.n; i++) {
				err |= re_hprintf(pf, " {%04x %04x %02x}",
						  msg->r.fb.fci.sliv[i].first,
						  msg->r.fb.fci.sliv[i].number,
						  msg->r.fb.fci.sliv[i].picid);
			}
		}
		else if (msg->hdr.count == RTCP_PSFB_AFB) {
			err |= re_hprintf(pf, " AFB %u bytes",
					  msg->r.fb.n * 4);
		}
		else if (msg->hdr.count == RTCP_PSFB_FIR) {
			err |= re_hprintf(pf, " FIR (RFC5104)");
			for (i=0; i<msg->r.fb.n; i++) {
				err |= re_hprintf(pf,
						  " {ssrc=%08x seq_n=%02x}",
						  msg->r.fb.fci.firv[i].ssrc,
						  msg->r.fb.fci.firv[i].seq_n);
			}
		}
		break;

	default:
		err = re_hprintf(pf, "<len=%u>", msg->hdr.length);
		break;
	}

	err |= re_hprintf(pf, "\n");

	return err;
}


/**
 * Check if packet is RTCP packet, used for de-multiplexing
 *
 * @param mb Mbuffer with packet
 *
 * @return True if RTCP packet, otherwise false
 */
bool rtp_is_rtcp_packet(const struct mbuf *mb)
{
	uint8_t pt;

	if (mbuf_get_left(mb) < 2)
		return false;

	pt = mbuf_buf(mb)[1] & 0x7f;

	return rtp_pt_is_rtcp(pt);
}
