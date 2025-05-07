/**
 * @file rtcp.h  Internal interface to RTCP
 *
 * Copyright (C) 2010 Creytiv.com
 */


/** RTCP protocol values */
enum {
	RTCP_HDR_SIZE  =   4,  /**< Size of common RTCP header   */
	RTCP_SRC_SIZE  =   4,  /**< Size of Source field         */
	RTCP_SR_SIZE   =  20,  /**< Size of Sender Information   */
	RTCP_RR_SIZE   =  24,  /**< Size of Report Block         */
	RTCP_APP_SIZE  =   8,  /**< Size of Application packet   */
	RTCP_FIR_SIZE  =   4,  /**< Size of FIR packet           */
	RTCP_NACK_SIZE =   8,  /**< Size of NACK packet          */
	RTCP_FB_SIZE   =   8,  /**< Size of Feedback packets     */
	RTCP_MAX_SDES  = 255,  /**< Maximum text length for SDES */
	RTCP_HEADROOM  =   4,  /**< Headroom in RTCP packets     */
};


struct hash;


/** RTP Member */
struct rtp_member {
	struct le le;             /**< Hash-table element                  */
	struct rtp_source *s;     /**< RTP source state                    */
	uint32_t src;             /**< Source - used for hash-table lookup */
	int cum_lost;             /**< Cumulative number of packets lost   */
	uint32_t jit;             /**< Jitter in [us]                      */
	uint32_t rtt;             /**< Round-trip time in [us]             */
};


/* Member */
struct rtp_member *rtp_member_add(struct hash *ht, uint32_t src);
struct rtp_member *rtp_member_find(struct hash *ht, uint32_t src);


/* RR (Reception report) */
int rtcp_rr_alloc(struct rtcp_rr **rrp, size_t count);
int rtcp_rr_encode(struct mbuf *mb, const struct rtcp_rr *rr);
int rtcp_rr_decode(struct mbuf *mb, struct rtcp_rr *rr);

/* SR (Sender report) */
int rtcp_make_sr(const struct rtp_sock *rs, struct mbuf *mb);

/* SDES (Source Description) */
int rtcp_sdes_decode(struct mbuf *mb, struct rtcp_sdes *sdes);
int rtcp_make_sdes_cname(const struct rtp_sock *rs, struct mbuf *mb);

/* RTCP Feedback */
int rtcp_rtpfb_gnack_encode(struct mbuf *mb, uint16_t pid, uint16_t blp);
int rtcp_rtpfb_twcc_encode(struct mbuf *mb, struct twcc *twcc);
int rtcp_rtpfb_twcc_decode(struct mbuf *mb, struct twcc *msg, int n);
int rtcp_rtpfb_decode(struct mbuf *mb, struct rtcp_msg *msg);
int rtcp_psfb_decode(struct mbuf *mb, struct rtcp_msg *msg);

/** NTP Time */
struct timeval;
void unix2ntp(struct rtp_ntp_time *ntp, const struct timeval *tv);
void ntp_time_get(struct rtp_ntp_time *ntp, uint64_t* jfs_rt);
uint32_t ntp_compact(const struct rtp_ntp_time *ntp);
uint64_t ntp_compact2us(uint32_t ntpc);

/* RTP Socket */
struct rtcp_sess *rtp_rtcp_sess(const struct rtp_sock *rs);

/* RTCP message */
typedef int (rtcp_encode_h)(struct mbuf *mb, void *arg);

int rtcp_hdr_encode(struct mbuf *mb, uint8_t count, enum rtcp_type type,
		    uint16_t length);
int rtcp_hdr_decode(struct mbuf *mb, struct rtcp_hdr *hdr);
int rtcp_vencode(struct mbuf *mb, enum rtcp_type type, uint32_t count,
		 va_list ap);

/* RTCP Session */
struct rtcp_sess;

int  rtcp_sess_alloc(struct rtcp_sess **sessp, struct rtp_sock *rs);
int  rtcp_enable(struct rtcp_sess *sess, bool enabled, const char *cname);
int  rtcp_send(struct rtp_sock *rs, struct mbuf *mb);
void rtcp_handler(struct rtcp_sess *sess, struct rtcp_msg *msg);
void rtcp_sess_tx_rtp(struct rtcp_sess *sess, uint32_t ts, uint64_t jfs_rt,
		      size_t payload_size);
void rtcp_sess_rx_rtp(struct rtcp_sess *sess, struct rtp_header *hdr,
		      size_t payload_size, const struct sa *peer);
void rtcp_schedule_report(const struct rtp_sock *rs);
