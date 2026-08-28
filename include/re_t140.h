/**
 * @file re_t140.h  Interface to ITU-T T.140 Real-Time Text
 *
 * Copyright (C) 2026 Emmanuel BUU
 */

struct sa;
struct sdp_format;
struct sdp_media;
struct sdp_session;
struct rtp_header;


/*
 * ITU-T T.140 real-time text.
 *
 * One API serves both transports. The transport is chosen once, in the
 * configuration handed to t140_alloc(), and everything after that -
 * sending, receiving, the handlers, the counters - is the same whichever
 * one was chosen. An application that bridges one leg to another, which is
 * what a relay centre does, therefore holds two sessions of the same type
 * and cross-wires their handlers.
 *
 *   T140_TRANSPORT_RTP  RFC 4103, with RFC 2198 redundancy. Implemented.
 *
 *   T140_TRANSPORT_DC   RFC 8865, over a WebRTC data channel. NOT
 *                       IMPLEMENTED: t140_alloc() returns ENOSYS for it.
 *
 * Only two functions are specific to a transport, the SDP helpers, and
 * each returns EINVAL when handed a configuration for the other one.
 *
 *   struct t140_conf conf = {
 *           .transport = T140_TRANSPORT_RTP,
 *           .u.rtp     = {.pt = 98, .pt_red = 100, .ngen = 2},
 *   };
 *
 *   t140_alloc(&t, &conf, send_handler, recv_handler, arg);
 *   t140_start(t);
 *   t140_send(t, "bonjour", 7);
 */


/** T.140 protocol values */
enum {
	T140_SRATE      = 1000,  /**< RTP clock rate for t140 and red     */
	T140_PTIME      = 300,   /**< Default transmission interval [ms]  */
	T140_IDLE_PTIME = 10000, /**< Suggested keep-alive interval [ms]  */
	T140_CPS        = 30,    /**< Default max characters per second   */
	T140_MAX_PKTSZ  = 1000   /**< Max payload we will build [bytes]   */
};

/** T.140 control code points */
enum {
	T140_BS   = 0x0008,  /**< Backspace, erase one character     */
	T140_LF   = 0x000a,  /**< Line feed                          */
	T140_CR   = 0x000d,  /**< Carriage return                    */
	T140_ESC  = 0x001b,  /**< Escape, introduces a control code  */
	T140_BOM  = 0xfeff,  /**< Zero width no-break space          */
	T140_LS   = 0x2028,  /**< Preferred T.140 line separator     */
	T140_LOSS = 0xfffd   /**< Replacement char, marks lost text  */
};

/** Transport a T.140 session runs over */
enum t140_transport {
	T140_TRANSPORT_RTP = 0,  /**< RFC 4103, T.140 over RTP           */
	T140_TRANSPORT_DC        /**< RFC 8865, over a data channel      */
};

extern const char t140_rtpfmt[];      /**< "t140" */
extern const char t140_red_rtpfmt[];  /**< "red"  */
extern const char t140_dc_subproto[]; /**< "t140", data channel subproto */

struct t140;

/** Configuration of a T.140 session */
struct t140_conf {
	enum t140_transport transport;

	uint32_t ptime;   /**< Transmission interval [ms] (0 = T140_PTIME)  */
	uint16_t cps;     /**< Max characters per second (0 = T140_CPS)     */
	bool     bom;     /**< Emit U+FEFF at the start of the stream       */

	union {
		/** T140_TRANSPORT_RTP */
		struct {
			uint32_t idle;   /**< Keep-alive [ms], 0 = off     */
			uint8_t pt;      /**< Payload type of "t140"       */
			uint8_t pt_red;  /**< Payload type of "red", 0 = no
					      redundancy                 */
			uint8_t ngen;    /**< Redundant generations,
					      1..RED_MAX_GEN             */
			bool red_pad;    /**< Pad RED headers for legacy
					      peers                      */
		} rtp;

		/** T140_TRANSPORT_DC */
		struct {
			char lang[8];    /**< BCP 47 tag for a=dcsa lang   */
		} dc;
	} u;
};

/**
 * One packet, as it goes to or comes back from the transport
 *
 * The RTP fields are only meaningful on T140_TRANSPORT_RTP and are left at
 * zero otherwise. On the send side the sequence number is not set: it
 * belongs to the RTP session, which the application owns.
 */
struct t140_pkt {
	struct mbuf *mb;  /**< Payload: a RED payload or a bare T140 block */
	uint32_t ts;      /**< RTP timestamp                    (RTP only) */
	uint16_t seq;     /**< RTP sequence number, receive     (RTP only) */
	uint8_t  pt;      /**< RTP payload type                 (RTP only) */
	bool     marker;  /**< RTP marker bit                   (RTP only) */
};

/**
 * T.140 session counters
 *
 * The recovery, loss and duplicate counters only ever move on a transport
 * that can lose or reorder packets, so they stay at zero over a reliable
 * data channel.
 */
struct t140_stats {
	uint64_t tx_chars;      /**< Characters handed to the transport   */
	uint64_t tx_packets;    /**< Packets built                        */
	uint64_t rx_chars;      /**< Characters delivered                 */
	uint64_t rx_packets;    /**< Packets accepted                     */
	uint64_t rx_recovered;  /**< Characters recovered from redundancy */
	uint64_t rx_lost;       /**< U+FFFD loss markers inserted         */
	uint64_t rx_dup;        /**< Duplicate blocks discarded           */
};

/**
 * Called when a packet is ready for transmission
 *
 * On T140_TRANSPORT_RTP the read position of the buffer is at the start of
 * the payload, with RTP_HEADER_SIZE bytes of headroom in front of it, so
 * that the buffer can be handed to rtp_send() as it is.
 *
 * @param pkt Packet to transmit
 * @param arg Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
typedef int (t140_send_h)(const struct t140_pkt *pkt, void *arg);

/**
 * Called with received text
 *
 * The text is always valid UTF-8 and is never split in the middle of a
 * code point. Text lost in transmission is signalled inline as U+FFFD.
 *
 * @param txt Received text, UTF-8 encoded and not zero-terminated
 * @param len Length of the text in bytes
 * @param arg Handler argument
 */
typedef void (t140_recv_h)(const char *txt, size_t len, void *arg);


/* session */
int  t140_alloc(struct t140 **t140p, const struct t140_conf *conf,
		t140_send_h *sendh, t140_recv_h *recvh, void *arg);
int  t140_update(struct t140 *t, const struct t140_conf *conf);
int  t140_start(struct t140 *t);
void t140_stop(struct t140 *t);
void t140_set_dir(struct t140 *t, enum sdp_dir dir);
enum t140_transport t140_transport(const struct t140 *t);

/* tx */
int  t140_send(struct t140 *t, const char *utf8, size_t len);
int  t140_sendf(struct t140 *t, const char *fmt, ...);
int  t140_send_bs(struct t140 *t, unsigned count);
int  t140_send_nl(struct t140 *t);
int  t140_send_bom(struct t140 *t);
bool t140_is_empty(const struct t140 *t);

/* rx */
int  t140_recv(struct t140 *t, const struct t140_pkt *pkt);

/* manual clocking, alternative to the internal timer */
int  t140_poll(struct t140 *t, struct t140_pkt *pkt, struct mbuf *mb);

/* misc */
void t140_pkt_rtp(struct t140_pkt *pkt, const struct rtp_header *hdr,
		  struct mbuf *mb);
void t140_stats_get(const struct t140 *t, struct t140_stats *stats);
int  t140_debug(struct re_printf *pf, const struct t140 *t);


/*
 * SDP. These are the only entry points specific to a transport: each
 * returns EINVAL when the configuration it is handed names the other one.
 */

/* T140_TRANSPORT_RTP */
int  t140_fmtp_enc(struct mbuf *mb, const struct sdp_format *fmt,
		   bool offer, void *arg);
bool t140_fmtp_cmp(const char *lparams, const char *rparams, void *arg);
int  t140_red_fmtp_enc(struct mbuf *mb, const struct sdp_format *fmt,
		       bool offer, void *arg);
bool t140_red_fmtp_cmp(const char *lparams, const char *rparams, void *arg);
int  t140_sdp_media_add(struct sdp_media **mp, struct sdp_session *sess,
			const struct sa *laddr, const struct t140_conf *conf);

/* T140_TRANSPORT_DC -- NOT IMPLEMENTED, returns ENOSYS */
int  t140_dc_sdp_encode(struct mbuf *mb, uint16_t stream_id,
			const struct t140_conf *conf, enum sdp_dir dir);
int  t140_dc_sdp_decode(struct t140_conf *conf, enum sdp_dir *dir,
			const char *dcmap, const char *dcsa);
