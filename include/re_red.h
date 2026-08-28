/**
 * @file re_red.h  Interface to RTP Redundant Payload (RFC 2198)
 *
 */


/** RED protocol values */
enum {
	RED_HDR_SIZE   = 4,     /**< Size of a non-final RED header block   */
	RED_MAX_GEN    = 3,     /**< Max redundant generations we encode    */
	RED_MAX_BLOCKS = 16,    /**< Max blocks we accept when decoding     */
	RED_MAX_LEN    = 1023,  /**< 10-bit block length field              */
	RED_MAX_TSOFF  = 16383  /**< 14-bit timestamp offset field          */
};

struct red;

/**
 * Called once per block found in a RED payload, oldest redundant block
 * first and the primary block last
 *
 * @param pt   Payload type of this block
 * @param ts   Absolute RTP timestamp of this block
 * @param buf  Block payload (may be NULL if len is zero)
 * @param len  Block length in bytes
 * @param arg  Handler argument
 */
typedef void (red_block_h)(uint8_t pt, uint32_t ts, const uint8_t *buf,
			   size_t len, void *arg);

int  red_alloc(struct red **redp, uint8_t pt, unsigned ngen);
void red_set_pad(struct red *red, bool pad);
int  red_encode(struct red *red, struct mbuf *mb, uint32_t ts,
		const uint8_t *buf, size_t len);
void red_flush(struct red *red);
unsigned red_gen_count(const struct red *red);

int  red_decode(struct mbuf *mb, uint32_t ts, red_block_h *blockh, void *arg);

int  red_debug(struct re_printf *pf, const struct red *red);
