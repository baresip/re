/**
 * @file re_trice.h  Interface to Interactive Connectivity Establishment (ICE)
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */


/** ICE Configuration */
struct trice_conf {
	bool debug;                    /**< Enable ICE debugging             */
	bool trace;                    /**< Enable tracing of Connectivity
					    checks                           */
	bool ansi;                     /**< Enable ANSI colors for debug
					   output                            */
	bool optimize_loopback_pairing;/**< Reduce candidate pairs when
					    using loopback addresses         */
};

struct trice;
struct ice_lcand;
struct ice_candpair;
struct stun_conf;


/**
 * Handler for receiving packets on candidate
 *
 * @param lcand Local candidate
 * @param proto Network protocol (UDP or TCP)
 * @param sock  Local socket (struct udp_sock or struct tcp_conn)
 * @param src   Source address
 * @param mb    Data packet
 * @param arg   Handler argument
 *
 * @return True if handled, False if not
 */
typedef bool (ice_cand_recv_h)(struct ice_lcand *lcand,
			       int proto, void *sock, const struct sa *src,
			       struct mbuf *mb, void *arg);


/** Local candidate */
struct ice_lcand {
	struct ice_cand_attr attr; /**< Base class (inheritance)           */
	struct le le;              /**< List element                       */
	struct sa base_addr;       /**< IP-address of "base" candidate     */
	struct udp_sock *us;       /**< UDP socket                         */
	struct udp_helper *uh;     /**< UDP helper to intercept packets    */
	struct tcp_sock *ts;       /**< TCP for simultaneous-open/passive  */
	char ifname[32];           /**< Network interface, for diagnostics */
	int layer;                 /**< Protocol layer                     */
	ice_cand_recv_h *recvh;    /**< Handler for receiving packets      */
	void *arg;                 /**< Handler argument                   */
	struct trice *icem;        /**< Pointer to parent                  */

	/** Packet statistics */
	struct {
		size_t n_tx;  /**< Number of packets sent */
		size_t n_rx;  /**< Number of packets received */
	} stats;
};

/** Remote candidate */
struct ice_rcand {
	struct ice_cand_attr attr;   /**< Base class (inheritance)           */
	struct le le;                /**< List element                       */
};


/** Defines a candidate pair */
struct ice_candpair {
	struct le le;                  /**< List element                   */
	struct ice_lcand *lcand;       /**< Local candidate                */
	struct ice_rcand *rcand;       /**< Remote candidate               */
	enum ice_candpair_state state; /**< Candidate pair state           */
	uint64_t pprio;                /**< Pair priority                  */
	bool valid;                    /**< Valid flag                     */
	bool nominated;                /**< Nominated flag                 */
	bool estab;                    /**< Pair is established            */
	bool trigged;                  /**< Pair was triggered             */
	int err;                       /**< Saved error code, if failed    */
	uint16_t scode;                /**< Saved STUN code, if failed     */
	struct tcp_conn *tc;           /**< TCP-connection used            */
	struct ice_tcpconn *conn;      /**< the ICE-TCP-connection used    */
};


/**
 * Handler for established candidate pair
 *
 * @param pair Which candidate pair was established
 * @param msg  STUN message
 * @param arg  Handler argument
 */
typedef void (trice_estab_h)(struct ice_candpair *pair,
			     const struct stun_msg *msg, void *arg);


/**
 * Handler for failed candidate pair
 *
 * @param err   Posix error code
 * @param scode STUN status code
 * @param pair  Candidate pair
 * @param arg   Handler argument
 */
typedef void (trice_failed_h)(int err, uint16_t scode,
			    struct ice_candpair *pair, void *arg);


int  trice_alloc(struct trice **icemp, const struct trice_conf *conf,
		 enum ice_role role, const char *lufrag, const char *lpwd);
int  trice_set_remote_ufrag(struct trice *icem, const char *rufrag);
int  trice_set_remote_pwd(struct trice *icem, const char *rpwd);
int  trice_set_role(struct trice *trice, enum ice_role role);
enum ice_role trice_local_role(const struct trice *icem);
int  trice_debug(struct re_printf *pf, const struct trice *icem);
struct trice_conf *trice_conf(struct trice *icem);


/* Candidates (common) */
int  trice_cand_print(struct re_printf *pf, const struct ice_cand_attr *cand);
enum ice_tcptype   ice_tcptype_reverse(enum ice_tcptype type);
const char        *ice_tcptype_name(enum ice_tcptype tcptype);
enum ice_cand_type ice_cand_type_base(enum ice_cand_type type);


/* Local candidates */
int trice_lcand_add(struct ice_lcand **lcandp, struct trice *icem,
		    unsigned compid, int proto, uint32_t prio,
		    const struct sa *addr, const struct sa *base_addr,
		    enum ice_cand_type type, const struct sa *rel_addr,
		    enum ice_tcptype tcptype,
		    void *sock, int layer);
struct list      *trice_lcandl(const struct trice *icem);
struct ice_lcand *trice_lcand_find(struct trice *icem,
				   enum ice_cand_type type,
				   unsigned compid, int proto,
				   const struct sa *addr);
struct ice_lcand *trice_lcand_find2(const struct trice *icem,
				    enum ice_cand_type type, int af);
void *trice_lcand_sock(struct trice *icem, const struct ice_lcand *lcand);
void trice_lcand_recv_packet(struct ice_lcand *lcand,
			     const struct sa *src, struct mbuf *mb);


/* Remote candidate */
struct list *trice_rcandl(const struct trice *icem);
int trice_rcand_add(struct ice_rcand **rcandp, struct trice *icem,
		    unsigned compid, const char *foundation, int proto,
		    uint32_t prio, const struct sa *addr,
		    enum ice_cand_type type, enum ice_tcptype tcptype);
struct ice_rcand *trice_rcand_find(struct trice *icem, unsigned compid,
				   int proto, const struct sa *addr);


/* ICE Candidate pairs */
struct list *trice_checkl(const struct trice *icem);
struct list *trice_validl(const struct trice *icem);
struct ice_candpair *trice_candpair_find_state(const struct list *lst,
					   enum ice_candpair_state state);
int  trice_candpair_debug(struct re_printf *pf, const struct ice_candpair *cp);
int  trice_candpairs_debug(struct re_printf *pf, bool ansi_output,
			   const struct list *list);


/* ICE checklist */
void trice_checklist_set_waiting(struct trice *icem);
int  trice_checklist_start(struct trice *icem, struct stun *stun,
			   uint32_t interval,
			   trice_estab_h *estabh, trice_failed_h *failh,
			   void *arg);
void trice_checklist_stop(struct trice *icem);
bool trice_checklist_isrunning(const struct trice *icem);
bool trice_checklist_iscompleted(const struct trice *icem);


/* ICE Conncheck */
int trice_conncheck_send(struct trice *icem, struct ice_candpair *pair,
			bool use_cand);

/* Port range */
int trice_set_port_range(struct trice *trice,
			 uint16_t min_port, uint16_t max_port);
