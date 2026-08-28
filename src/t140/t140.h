/**
 * @file t140.h  Internal interface to ITU-T T.140 Real-Time Text
 *
 */


enum {
	T140_TXBUF_MAX = 8192,  /**< Max bytes queued for transmission  */
	T140_TSWIN     = 24,    /**< Delivered-timestamp window entries */
};


/** Incremental UTF-8 decoder state */
struct t140_utf8 {
	uint8_t buf[4];   /**< Bytes of the sequence being assembled  */
	uint8_t lo;       /**< Lowest legal value of the next byte    */
	uint8_t hi;       /**< Highest legal value of the next byte   */
	unsigned n;       /**< Bytes held so far                      */
	unsigned need;    /**< Total bytes of the sequence            */
};


/** Defines a T.140 session */
struct t140 {
	struct t140_conf conf;
	enum sdp_dir dir;

	/* tx */
	struct mbuf *txmb;    /**< Pending text, pos is the read cursor */
	struct tmr tmr;
	struct red *red;
	uint64_t jfs;         /**< Jiffies the clock was started at     */
	uint64_t tx_last;     /**< Jiffies of the last packet built     */
	uint32_t ts_base;     /**< Random RTP timestamp base            */
	uint32_t ts_last;     /**< Timestamp of the last packet built   */
	unsigned tx_tail;     /**< Redundancy-only packets still to go  */
	bool tx_idle;         /**< Nothing was sent on the last tick    */
	bool ts_valid;        /**< ts_last holds a timestamp            */

	/* rx */
	struct t140_utf8 dec;
	struct mbuf *rxmb;    /**< Scratch buffer for delivered text    */
	uint32_t tsv[T140_TSWIN];
	unsigned tsn;         /**< Next slot in the timestamp window    */
	unsigned tsc;         /**< Valid entries in the window          */
	uint16_t rx_seq;
	bool rx_seq_valid;
	bool rx_bom;          /**< A leading BOM is still to be dropped */

	t140_send_h *sendh;
	t140_recv_h *recvh;
	void *arg;

	struct t140_stats stats;
};


/* utf8.c */
unsigned t140_utf8_seqlen(uint8_t b);
int      t140_utf8_check(const uint8_t *buf, size_t len);
size_t   t140_utf8_take(const uint8_t *buf, size_t len, size_t maxbytes,
			unsigned maxchars, unsigned *charsp);
unsigned t140_utf8_chars(const uint8_t *buf, size_t len);
int      t140_utf8_encode(struct mbuf *mb, uint32_t cp);
int      t140_utf8_decode(struct t140_utf8 *d, struct mbuf *mb,
			  const uint8_t *buf, size_t len);
void     t140_utf8_reset(struct t140_utf8 *d);

/* tx.c */
int  t140_tx_alloc(struct t140 *t);
int  t140_tx_red_alloc(struct t140 *t);
int  t140_tx_build(struct t140 *t, struct t140_pkt *pkt, struct mbuf *mb);
int  t140_tx_queue(struct t140 *t, const uint8_t *buf, size_t len);
void t140_tx_tmr_start(struct t140 *t);

/* rx.c */
void t140_rx_reset(struct t140 *t);
