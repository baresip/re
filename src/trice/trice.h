/**
 * @file trice.h  Internal Interface to ICE
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */


struct ice_tcpconn;
struct ice_conncheck;


/**
 * Active Checklist. Only used by Full-ICE and Trickle-ICE
 */
struct ice_checklist {
	struct trice *icem;     /* parent */

	struct tmr tmr_pace;         /**< Timer for pacing STUN requests     */
	uint32_t interval;           /**< Interval in [ms]                   */
	struct stun *stun;           /**< STUN Transport                     */
	struct list conncheckl;
	bool is_running;             /**< Checklist is running               */

	/* callback handlers */
	trice_estab_h *estabh;
	trice_failed_h *failh;
	void *arg;
};


/**
 * Defines an ICE media-stream
 *
 * NOTE: We try to follow the Resource Acquisition Is Initialization (RAII)
 *       programming idiom, which means:
 *
 * - at any time is the number of local/remote candidates correct
 * - at any time is the checklist up to date (matching local/remote candidates)
 *
 */
struct trice {
	struct trice_conf conf;
	enum ice_role lrole;         /**< Local role                         */
	uint64_t tiebrk;             /**< Tie-break value for roleconflict   */

	/* stun/authentication */
	char *lufrag;                /**< Local Username fragment            */
	char *lpwd;                  /**< Local Password                     */
	char *rufrag;                /**< Remote Username fragment           */
	char *rpwd;                  /**< Remote Password                    */

	struct list lcandl;          /**< local candidates (add order)       */
	struct list rcandl;          /**< remote candidates (add order)      */
	struct list checkl;          /**< Check List of cand pairs (sorted)  */
	struct list validl;          /**< Valid List of cand pairs (sorted)  */
	struct list reqbufl;         /**< buffered incoming requests         */

	struct ice_checklist *checklist;

	struct list connl;           /**< TCP-connections for all components */

	/* Port range */
	struct {
		uint16_t min;
		uint16_t max;
	} ports;
};


/**
 * Holds an unhandled STUN request message that will be handled once
 * the role has been determined.
 */
struct trice_reqbuf {
	struct le le;                /**< list element                       */
	struct ice_lcand *lcand;     /**< corresponding local candidate      */
	void *sock;                  /**< request's socket                   */
	struct sa src;               /**< source address                     */
	struct stun_msg *req;        /**< buffered STUN request              */
	size_t presz;                /**< number of bytes in preamble        */
};


/* return TRUE if handled */
typedef bool (tcpconn_frame_h)(struct trice *icem,
			       struct tcp_conn *tc, struct sa *src,
			       struct mbuf *mb, void *arg);

/**
 * Defines a TCP-connection from local-address to remote-address
 *
 * - one TCP-connection can be shared by multiple candidate pairs
 *
 * - one TCP-connection is always created by the Local Candidate
 */
struct ice_tcpconn {
	struct trice *icem;      /* parent */
	struct le le;
	struct tcp_conn *tc;
	struct shim *shim;
	struct sa laddr;
	struct sa paddr;
	unsigned compid;
	int layer;
	bool active;
	bool estab;

	tcpconn_frame_h *frameh;
	void *arg;
};

struct ice_conncheck {
	struct le le;
	struct ice_candpair *pair;    /* pointer */
	struct stun_ctrans *ct_conn;
	struct trice *icem;           /* owner */
	bool use_cand;
	bool term;
};


/* cand */
int trice_add_lcandidate(struct ice_lcand **candp,
			 struct trice *icem, struct list *lst,
			 unsigned compid, char *foundation, int proto,
			 uint32_t prio, const struct sa *addr,
			 const struct sa *base_addr,
			 enum ice_cand_type type,
			 const struct sa *rel_addr,
			 enum ice_tcptype tcptype);
int trice_lcands_debug(struct re_printf *pf, const struct list *lst);
int trice_rcands_debug(struct re_printf *pf, const struct list *lst);


/* candpair */
int  trice_candpair_alloc(struct ice_candpair **cpp, struct trice *icem,
			 struct ice_lcand *lcand, struct ice_rcand *rcand);
void trice_candpair_prio_order(struct list *lst, bool controlling);
void trice_candpair_make_valid(struct trice *icem, struct ice_candpair *pair);
void trice_candpair_failed(struct ice_candpair *cp, int err, uint16_t scode);
void trice_candpair_set_state(struct ice_candpair *cp,
			     enum ice_candpair_state state);
bool trice_candpair_iscompleted(const struct ice_candpair *cp);
bool trice_candpair_cmp_fnd(const struct ice_candpair *cp1,
			   const struct ice_candpair *cp2);
struct ice_candpair *trice_candpair_find(const struct list *lst,
					const struct ice_lcand *lcand,
					const struct ice_rcand *rcand);
int  trice_candpair_with_local(struct trice *icem, struct ice_lcand *lcand);
int  trice_candpair_with_remote(struct trice *icem, struct ice_rcand *rcand);
const char    *trice_candpair_state2name(enum ice_candpair_state st);


/* STUN server */
int trice_stund_recv(struct trice *icem, struct ice_lcand *lcand,
		    void *sock, const struct sa *src,
		    struct stun_msg *req, size_t presz);
int trice_stund_recv_role_set(struct trice *icem, struct ice_lcand *lcand,
		    void *sock, const struct sa *src,
		    struct stun_msg *req, size_t presz);


/* ICE media */
void trice_switch_local_role(struct trice *ice);
void trice_printf(struct trice *icem, const char *fmt, ...);
void trice_tracef(struct trice *icem, int color, const char *fmt, ...);


/* ICE checklist */
int  trice_checklist_debug(struct re_printf *pf,
			   const struct ice_checklist *ic);
void trice_conncheck_schedule_check(struct trice *icem);
int  trice_checklist_update(struct trice *icem);
void trice_checklist_refresh(struct trice *icem);


/* ICE conncheck */
int trice_conncheck_stun_request(struct ice_checklist *ic,
			       struct ice_conncheck *cc,
			       struct ice_candpair *cp, void *sock,
			       bool cc_use_cand);
int trice_conncheck_trigged(struct trice *icem, struct ice_candpair *pair,
			   void *sock, bool use_cand);
int trice_conncheck_debug(struct re_printf *pf,
			  const struct ice_conncheck *cc);


/* TCP connections */


int trice_conn_alloc(struct list *connl, struct trice *icem, unsigned compid,
		   bool active, const struct sa *laddr, const struct sa *peer,
		   struct tcp_sock *ts, int layer,
		   tcpconn_frame_h *frameh, void *arg);
struct ice_tcpconn *trice_conn_find(struct list *connl, unsigned compid,
				  const struct sa *laddr,
				  const struct sa *peer);
int trice_conn_debug(struct re_printf *pf, const struct ice_tcpconn *conn);


bool trice_stun_process(struct trice *icem, struct ice_lcand *lcand,
		       int proto, void *sock, const struct sa *src,
		       struct mbuf *mb);
int trice_reqbuf_append(struct trice *icem, struct ice_lcand *lcand,
		    void *sock, const struct sa *src,
		    struct stun_msg *req, size_t presz);
