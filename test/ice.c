/**
 * @file ice.c ICE Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
/* Legacy ICE and Trickle ICE use the same candidate-pair struct tag.  Rename
 * the unused Trickle ICE tag in this white-box test before including the
 * classic ICE internals below. */
#define ice_candpair trice_ice_candpair
#include <re.h>
#undef ice_candpair
#include "../src/ice/ice.h"
#include "test.h"


#define DEBUG_MODULE "test_ice"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * Protocol testcode for 2 ICE agents. We setup 2 ICE agents A and B,
 * with only a basic host candidate. Gathering is done using a small
 * STUN Server running on localhost, SDP is exchanged with Offer/Answer.
 * Finally the connectivity checks are run and the result is verified.
 *
 *
 *                    .-------------.
 *                    | STUN Server |
 *                    '-------------'
 *              STUN /               \ STUN
 *                  /                 \
 *                 /                   \
 *  .-------------.                     .-------------.
 *  | ICE-Agent A |---------------------| ICE-Agent B |
 *  '-------------'     Connectivity    '-------------'
 *                         checks
 *
 */


struct attrs {
	struct attr {
		char name[16];
		char value[128];
	} attrv[16];
	unsigned attrc;
};

struct agent {
	struct icem *icem;
	struct udp_sock *us;
	struct sa laddr;
	struct attrs attr_s;
	struct attrs attr_m;
	struct ice_test *it;  /* parent */
	struct stunserver *stun;
	struct turnserver *turn;
	char name[16];
	uint8_t compid;
	bool offerer;
	bool use_turn;
	size_t n_cand;

	char lufrag[8];
	char lpwd[32];

	/* results: */
	bool gathering_ok;
	bool conncheck_ok;

	struct stun_ctrans *ct_gath;
};

struct ice_test {
	struct agent *a;
	struct agent *b;
	struct tmr tmr;
	int err;
};


struct shared_socket_test {
	struct udp_sock *us;
	struct udp_helper *capture;
	struct icem *old;
	struct icem *candidate;
	struct stun_ctrans *candidate_ct;
	struct sa local;
	struct sa old_peer;
	struct sa new_peer;
	struct sa third_peer;
	struct mbuf *sent;
	unsigned sends;
	unsigned receives;
	unsigned candidate_responses;
	int response_err;
};


static int shared_socket_send_capture(struct shared_socket_test *test,
				      const struct mbuf *mb)
{
	struct mbuf *copy;
	int err;

	copy = mbuf_alloc(mbuf_get_left(mb));
	if (!copy)
		return ENOMEM;

	err = mbuf_write_mem(copy, mbuf_buf(mb), mbuf_get_left(mb));
	if (err) {
		mem_deref(copy);
		return err;
	}
	copy->pos = 0;

	mem_deref(test->sent);
	test->sent = copy;
	++test->sends;
	return 0;
}


static bool shared_socket_send_handler(int *err, struct sa *dst,
				       struct mbuf *mb, void *arg)
{
	struct shared_socket_test *test = arg;
	(void)dst;

	*err = shared_socket_send_capture(test, mb);
	return true;
}


static void shared_socket_recv_handler(const struct sa *src,
				       struct mbuf *mb, void *arg)
{
	struct shared_socket_test *test = arg;
	(void)src;
	(void)mb;

	++test->receives;
}


static void shared_socket_response_handler(int err, uint16_t scode,
					   const char *reason,
					   const struct stun_msg *msg,
					   void *arg)
{
	struct shared_socket_test *test = arg;
	(void)reason;
	(void)msg;

	++test->candidate_responses;
	test->response_err = err ? err : (scode ? EPROTO : 0);
}


static int shared_socket_add_valid_peer(struct icem *icem,
					const struct sa *local,
					const struct sa *peer)
{
	struct ice_candpair *pair = NULL;
	struct ice_cand *lcand;
	struct ice_cand *rcand;
	struct pl foundation = PL("peer");
	int err;

	err = icem_lcand_add_base(icem, ICE_CAND_TYPE_HOST, ICE_COMPID_RTP,
				   0, "loopback", ICE_TRANSP_UDP, local);
	if (err)
		return err;

	err = icem_rcand_add(icem, ICE_CAND_TYPE_HOST, ICE_COMPID_RTP,
			      ice_cand_calc_prio(ICE_CAND_TYPE_HOST, 0,
					 ICE_COMPID_RTP),
			      peer, NULL, &foundation);
	if (err)
		return err;

	lcand = list_ledata(list_head(icem_lcandl(icem)));
	rcand = icem_cand_find(icem_rcandl(icem), ICE_COMPID_RTP, peer);
	if (!lcand || !rcand)
		return ENOENT;

	err = icem_candpair_alloc(&pair, icem, lcand, rcand);
	if (err)
		return err;

	icem_candpair_make_valid(pair);
	return 0;
}


static int shared_socket_icem_alloc(struct icem **icemp,
				    struct shared_socket_test *test,
				    int layer, uint64_t tiebrk,
				    const char *ufrag, const char *pwd,
				    const struct sa *peer)
{
	int err;

	err = icem_alloc(icemp, ICE_ROLE_CONTROLLED, IPPROTO_UDP, layer,
			 tiebrk, ufrag, pwd, NULL, NULL);
	if (err)
		return err;

	err = icem_comp_add(*icemp, ICE_COMPID_RTP, test->us);
	if (err)
		return err;
	err = icem_sdp_decode(*icemp, "ice-ufrag", "remote");
	if (err)
		return err;

	return shared_socket_add_valid_peer(*icemp, &test->local, peer);
}


static void shared_socket_test_destructor(void *arg)
{
	struct shared_socket_test *test = arg;

	mem_deref(test->candidate_ct);
	mem_deref(test->candidate);
	mem_deref(test->old);
	mem_deref(test->capture);
	mem_deref(test->sent);
	mem_deref(test->us);
}


static int shared_socket_test_alloc(struct shared_socket_test **testp)
{
	static const char old_pwd[] = "old-password-0123456789abcdef";
	static const char new_pwd[] = "new-password-0123456789abcdef";
	struct shared_socket_test *test;
	int err;

	test = mem_zalloc(sizeof(*test), shared_socket_test_destructor);
	if (!test)
		return ENOMEM;

	err = sa_set_str(&test->local, "127.0.0.1", 0);
	if (err)
		goto out;
	err = sa_set_str(&test->old_peer, "127.0.0.1", 41001);
	if (err)
		goto out;
	err = sa_set_str(&test->new_peer, "127.0.0.1", 41002);
	if (err)
		goto out;
	err = sa_set_str(&test->third_peer, "127.0.0.1", 41003);
	if (err)
		goto out;

	err = udp_listen(&test->us, &test->local,
			 shared_socket_recv_handler, test);
	if (err)
		goto out;
	err = udp_local_get(test->us, &test->local);
	if (err)
		goto out;

	err = shared_socket_icem_alloc(&test->old, test, 20, 1,
				       "old-ufrag", old_pwd,
				       &test->old_peer);
	if (err)
		goto out;
	err = shared_socket_icem_alloc(&test->candidate, test, 20, 2,
				       "new-ufrag", new_pwd,
				       &test->new_peer);
	if (err)
		goto out;

	/* Capture replies and requests without sending them to the network. */
	err = udp_register_helper(&test->capture, test->us, 100,
				  shared_socket_send_handler, NULL, test);
	if (err)
		goto out;

	icem_shared_socket_candidate(test->candidate, true);
	icem_shared_socket_route(test->old, true);
	icem_shared_socket_route(test->candidate, true);

out:
	if (err)
		mem_deref(test);
	else
		*testp = test;
	return err;
}


static int shared_socket_inject(struct shared_socket_test *test,
				const struct sa *src, struct mbuf *mb)
{
	if (!test || !src || !mb)
		return EINVAL;

	mb->pos = 0;
	udp_recv_packet(test->us, src, mb);
	return 0;
}


static int shared_socket_request(struct mbuf **mbp, const char *username,
				 const char *pwd)
{
	static const uint32_t priority = 0x6e0001ff;
	static const uint64_t controlling = 0x932ff9b151263b36ULL;
	uint8_t tid[STUN_TID_SIZE];
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(256);
	if (!mb)
		return ENOMEM;

	stun_generate_tid(tid);
	err = stun_msg_encode(mb, STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
			      tid, NULL, (const uint8_t *)pwd, strlen(pwd),
			      true, 0, 3,
			      STUN_ATTR_PRIORITY, &priority,
			      STUN_ATTR_CONTROLLING, &controlling,
			      STUN_ATTR_USERNAME, username);
	if (err)
		mem_deref(mb);
	else
		*mbp = mb;
	return err;
}


static void icetest_check_gatherings(struct ice_test *it);
static void icetest_check_connchecks(struct ice_test *it);


/*
 * Test tools
 */


static void complete_test(struct ice_test *it, int err)
{
	it->err = err;

#if 0
	re_printf("\n\x1b[32m%H\x1b[;m\n", icem_debug, it->a->icem);
	re_printf("\n\x1b[36m%H\x1b[;m\n", icem_debug, it->b->icem);
#endif

	re_cancel();
}


static bool find_debug_string(struct icem *icem, const char *str)
{
	char buf[1024];

	if (re_snprintf(buf, sizeof(buf), "%H", icem_debug, icem) < 0)
		return false;

	return 0 == re_regex(buf, strlen(buf), str);
}


static int attr_add(struct attrs *attrs, const char *name,
		    const char *value, ...)
{
	struct attr *attr = &attrs->attrv[attrs->attrc];
	va_list ap;
	int r, err = 0;

	TEST_ASSERT(attrs->attrc <= RE_ARRAY_SIZE(attrs->attrv));

	TEST_ASSERT(strlen(name) < sizeof(attr->name));
	str_ncpy(attr->name, name, sizeof(attr->name));

	if (value) {
		va_start(ap, value);
		r = re_vsnprintf(attr->value, sizeof(attr->value), value, ap);
		va_end(ap);
		TEST_ASSERT(r > 0);
	}

	attrs->attrc++;

 out:
	return err;
}


static const char *attr_find(const struct attrs *attrs, const char *name)
{
	unsigned i;

	if (!attrs || !name)
		return NULL;

	for (i=0; i<attrs->attrc; i++) {
		const struct attr *attr = &attrs->attrv[i];

		if (0 == str_casecmp(attr->name, name))
			return attr->value;
	}

	return NULL;
}


/*
 * ICE Agent
 */


static void agent_destructor(void *arg)
{
	struct agent *agent = arg;

	mem_deref(agent->icem);
	mem_deref(agent->us);
	mem_deref(agent->stun);
	mem_deref(agent->turn);
}


static struct agent *agent_other(struct agent *agent)
{
	if (agent->it->a == agent)
		return agent->it->b;
	else
		return agent->it->a;
}


static int agent_encode_sdp(struct agent *ag)
{
	struct le *le;
	int err = 0;

	for (le = icem_lcandl(ag->icem)->head; le; le = le->next) {

		struct cand *cand = le->data;

		err = attr_add(&ag->attr_m, "candidate", "%H",
			       ice_cand_encode, cand);
		if (err)
			break;
	}

	err |= attr_add(&ag->attr_m, "ice-ufrag", ag->lufrag);
	err |= attr_add(&ag->attr_m, "ice-pwd", ag->lpwd);

	return err;
}


static int agent_verify_outgoing_sdp(const struct agent *agent)
{
	const char *cand, *ufrag, *pwd;
	char buf[1024];
	int err = 0;

	if (re_snprintf(buf, sizeof(buf),
			"7f000001 %u UDP 2113929465 127.0.0.1 %u typ host",
			agent->compid, sa_port(&agent->laddr)) < 0) {
		return ENOMEM;
	}
	cand = attr_find(&agent->attr_m, "candidate");
	TEST_STRCMP(buf, str_len(buf), cand, str_len(cand));

	ufrag = attr_find(&agent->attr_m, "ice-ufrag");
	pwd   = attr_find(&agent->attr_m, "ice-pwd");
	TEST_STRCMP(agent->lufrag, str_len(agent->lufrag),
		    ufrag, str_len(ufrag));
	TEST_STRCMP(agent->lpwd, str_len(agent->lpwd),
		    pwd, str_len(pwd));

	TEST_ASSERT(NULL == attr_find(&agent->attr_s, "ice-lite"));

 out:
	return err;
}


static int agent_decode_sdp(struct agent *agent, struct agent *other)
{
	unsigned i;
	int err = 0;

	for (i=0; i<other->attr_s.attrc; i++) {
		struct attr *attr = &other->attr_s.attrv[i];
		err = ice_sdp_decode(agent->icem, attr->name, attr->value);
		if (err)
			return err;
	}

	for (i=0; i<other->attr_m.attrc; i++) {
		struct attr *attr = &other->attr_m.attrv[i];
		err = icem_sdp_decode(agent->icem, attr->name, attr->value);
		if (err)
			return err;
	}

	return err;
}


static int send_sdp(struct agent *agent)
{
	int err;

	/* verify ICE states */
	TEST_ASSERT(!icem_mismatch(agent->icem));

	/* after gathering is complete we expect:
	 *   1 local candidate
	 *   0 remote candidates
	 *   checklist and validlist is empty
	 */
	TEST_EQUALS(agent->n_cand, list_count(icem_lcandl(agent->icem)));
	TEST_EQUALS(0, list_count(icem_rcandl(agent->icem)));
	TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
	TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

	if (agent->use_turn) {
		/* verify that default candidate is the relayed address */
		TEST_SACMP(&agent->turn->relay,
			   icem_cand_default(agent->icem, agent->compid),
			   SA_ALL);
	}
	else {
		/* verify that default candidate is our local address */
		TEST_SACMP(&agent->laddr,
			   icem_cand_default(agent->icem, agent->compid),
			   SA_ALL);
	}

	/* we should not have selected candidate-pairs yet */
	TEST_ASSERT(!icem_selected_laddr(agent->icem, agent->compid));

	err = agent_encode_sdp(agent);
	TEST_ERR(err);

	err = agent_verify_outgoing_sdp(agent);
	TEST_ERR(err);

 out:
	return err;
}


static void agent_gather_handler(int err, uint16_t scode, const char *reason,
				 void *arg)
{
	struct agent *agent = arg;

	if (err)
		goto out;
	if (scode) {
		DEBUG_WARNING("gathering failed: %u %s\n", scode, reason);
		complete_test(agent->it, EPROTO);
		return;
	}

	/* Eliminate redundant local candidates */
	icem_cand_redund_elim(agent->icem);

	err = icem_comps_set_default_cand(agent->icem);
	if (err) {
		DEBUG_WARNING("ice: set default cands failed (%m)\n", err);
		goto out;
	}

	agent->gathering_ok = true;

	err = send_sdp(agent);
	if (err)
		goto out;

	icetest_check_gatherings(agent->it);

	return;

 out:
	complete_test(agent->it, err);
}


static void stun_resp_handler(int err, uint16_t scode, const char *reason,
			      const struct stun_msg *msg, void *arg)
{
	struct agent *ag = arg;
	struct stun_attr *attr;
	struct ice_cand *lcand;

	if (err || scode > 0) {
		DEBUG_WARNING("STUN Request failed: %m\n", err);
		goto out;
	}

	/* base candidate */
	lcand = icem_cand_find(icem_lcandl(ag->icem), ag->compid, NULL);
	if (!lcand)
		goto out;

	attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
	if (!attr)
		attr = stun_msg_attr(msg, STUN_ATTR_MAPPED_ADDR);
	if (!attr) {
		DEBUG_WARNING("no Mapped Address in Response\n");
		err = EPROTO;
		goto out;
	}

	err = icem_lcand_add(ag->icem, icem_lcand_base(lcand),
			     ICE_CAND_TYPE_SRFLX,
			     &attr->v.sa);

 out:
	agent_gather_handler(err, scode, reason, ag);
}


static int icem_gather_srflx(struct agent *ag, const struct sa *srv)
{
	int err;

	err = stun_request(&ag->ct_gath, icem_stun(ag->icem), IPPROTO_UDP,
			   ag->us, srv, 0,
			   STUN_METHOD_BINDING,
			   NULL, false, 0,
			   stun_resp_handler, ag, 1,
			   STUN_ATTR_SOFTWARE, stun_software);
	if (err)
		return err;

	return 0;
}


static void agent_connchk_handler(int err, bool update, void *arg)
{
	struct agent *agent = arg;
	struct agent *other = agent_other(agent);
	const struct sa *laddr, *raddr;

	if (err) {
		if (err != ENOMEM) {
			DEBUG_WARNING("%s: connectivity checks failed: %m\n",
				      agent->name, err);
		}

		complete_test(agent->it, err);
		return;
	}

	if (agent->offerer ^ update) {
		DEBUG_WARNING("error in update flag\n");
		complete_test(agent->it, EPROTO);
		return;
	}

	agent->conncheck_ok = true;

	/* verify ICE states */
	TEST_ASSERT(!icem_mismatch(agent->icem));

	/* after connectivity checks are complete we expect:
	 *   1 local candidate
	 *   1 remote candidates
	 */
	TEST_EQUALS(agent->n_cand, list_count(icem_lcandl(agent->icem)));
	TEST_EQUALS(other->n_cand, list_count(icem_rcandl(agent->icem)));
	TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
	TEST_EQUALS(agent->n_cand * other->n_cand,
		    list_count(icem_validl(agent->icem)));

	laddr = icem_selected_laddr(agent->icem, agent->compid);
	raddr = &agent_other(agent)->laddr;

	if (!sa_cmp(&agent->laddr, laddr, SA_ALL)) {
		DEBUG_WARNING("unexpected selected address: %J\n", laddr);
		complete_test(agent->it, EPROTO);
		return;
	}

	if (!icem_verify_support(agent->icem, agent->compid, raddr)) {
		complete_test(agent->it, EPROTO);
		return;
	}

#if 0
	(void)re_printf("Agent %s -- Selected address: local=%J  remote=%J\n",
			agent->name, laddr, raddr);
#endif

	icetest_check_connchecks(agent->it);

 out:
	if (err)
		complete_test(agent->it, err);
}


static int agent_alloc(struct agent **agentp, struct ice_test *it,
		       bool use_turn,
		       const char *name, uint8_t compid, bool offerer)
{
	struct agent *agent;
	enum ice_role lrole;
	uint64_t tiebrk;
	int err;

	agent = mem_zalloc(sizeof(*agent), agent_destructor);
	if (!agent)
		return ENOMEM;

	re_snprintf(agent->lufrag, sizeof(agent->lufrag),
		    "ufrag-%s", name);
	re_snprintf(agent->lpwd, sizeof(agent->lpwd),
		    "password-0123456789abcdef-%s", name);

	agent->use_turn = use_turn;
	agent->it = it;
	str_ncpy(agent->name, name, sizeof(agent->name));
	agent->compid = compid;
	agent->offerer = offerer;

	if (agent->use_turn) {
		err = turnserver_alloc(&agent->turn, "127.0.0.1");
		if (err)
			goto out;
	}
	else {
		err = stunserver_alloc(&agent->stun, "127.0.0.1");
		if (err)
			goto out;
	}

	err = sa_set_str(&agent->laddr, "127.0.0.1", 0);
	if (err)
		goto out;

	err = udp_listen(&agent->us, &agent->laddr, 0, 0);
	if (err)
		goto out;

	err = udp_local_get(agent->us, &agent->laddr);
	if (err)
		goto out;

	lrole = offerer ? ICE_ROLE_CONTROLLING : ICE_ROLE_CONTROLLED;
	tiebrk = offerer ? 2 : 1;

	err = icem_alloc(&agent->icem, lrole, IPPROTO_UDP, 0,
			 tiebrk, agent->lufrag, agent->lpwd,
			 agent_connchk_handler, agent);
	if (err)
		goto out;

#if 0
	icem_conf(agent->icem)->debug = true;
#endif

	if (offerer) {
		TEST_EQUALS(ICE_ROLE_CONTROLLING,
			    icem_local_role(agent->icem));
	}
	else {
		TEST_EQUALS(ICE_ROLE_CONTROLLED,
			    icem_local_role(agent->icem));
	}

	icem_set_name(agent->icem, name);

	err = icem_comp_add(agent->icem, compid, agent->us);
	if (err)
		goto out;

	err = icem_lcand_add_base(agent->icem, ICE_CAND_TYPE_HOST, compid, 0,
				  "eth0", ICE_TRANSP_UDP, &agent->laddr);
	TEST_ERR(err);

	++agent->n_cand;

	/* Start gathering now -- full mode only
	 *
	 * A lite implementation doesn't gather candidates;
	 * it includes only host candidates for any media stream.
	 */

	if (agent->use_turn) {

		re_printf("turn disabled\n");
	}
	else {
		err = icem_gather_srflx(agent,
					&agent->stun->laddr);
	}

	if (err)
		goto out;

 out:
	if (err)
		mem_deref(agent);
	else
		*agentp = agent;

	return err;
}


/*
 * ICE Test
 */


static int verify_after_sdp_exchange(struct agent *agent)
{
	struct agent *other = agent_other(agent);
	int err = 0;

	/* verify remote mode (after SDP exchange) */
	TEST_ASSERT(find_debug_string(agent->icem,
				      "remote_mode=Full"));

	/* verify ICE states */
	TEST_ASSERT(!icem_mismatch(agent->icem));

	/* after SDP was exchanged, we expect:
	 *   1 local candidate
	 *   1 remote candidates
	 *   checklist and validlist is empty
	 */
	TEST_EQUALS(agent->n_cand, list_count(icem_lcandl(agent->icem)));
	TEST_EQUALS(other->n_cand, list_count(icem_rcandl(agent->icem)));
	TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
	TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

	if (agent->use_turn) {
		/* verify that default candidate is the relayed address */
		TEST_SACMP(&agent->turn->relay,
			   icem_cand_default(agent->icem, agent->compid),
			   SA_ALL);
	}
	else {
		/* verify that default candidate is our local address */
		TEST_SACMP(&agent->laddr,
			   icem_cand_default(agent->icem, agent->compid),
			   SA_ALL);
	}

	/* we should not have selected candidate-pairs yet */
	TEST_ASSERT(!icem_selected_laddr(agent->icem, agent->compid));

 out:
	if (err) {
		DEBUG_WARNING("agent %s failed\n", agent->name);
	}
	return err;
}


static int agent_start(struct agent *agent)
{
	struct agent *other = agent_other(agent);
	int err = 0;

	/* verify that check-list is empty before we start */
	TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
	TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

	err = icem_conncheck_start(agent->icem);
	if (err)
		return err;

	TEST_EQUALS(agent->n_cand * other->n_cand,
		    list_count(icem_checkl(agent->icem)));

	TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

 out:
	return err;
}


static int agent_verify_completed(struct agent *agent)
{
	struct agent *other = agent_other(agent);
	uint32_t validc;
	int err = 0;

	TEST_ASSERT(agent->gathering_ok);
	TEST_ASSERT(agent->conncheck_ok);

	TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
	validc = list_count(icem_validl(agent->icem));

	TEST_EQUALS(agent->n_cand * other->n_cand, validc);

	/* verify state of STUN/TURN server */
	if (agent->use_turn) {
		TEST_ASSERT(agent->turn->n_allocate >= 1);
		TEST_ASSERT(agent->turn->n_chanbind >= 1);
	}
	else {
		TEST_ASSERT(agent->stun->nrecv >= 1);
	}

 out:
	return err;
}


static void icetest_check_gatherings(struct ice_test *it)
{
	int err;

	if (!it->a->gathering_ok)
		return;
	if (!it->b->gathering_ok)
		return;

	/* both gatherings are complete
	 * exchange SDP and start conncheck
	 */

	err = agent_decode_sdp(it->a, it->b);
	if (err)
		goto out;
	err = agent_decode_sdp(it->b, it->a);
	if (err)
		goto out;

	err = verify_after_sdp_exchange(it->a);
	if (err)
		goto error;
	err = verify_after_sdp_exchange(it->b);
	if (err)
		goto error;

	err  = agent_start(it->a);
	if (err)
		goto out;
	err = agent_start(it->b);
	if (err)
		goto out;

	return;

 out:
 error:
	complete_test(it, err);
}


static void tmr_handler(void *arg)
{
	struct ice_test *it = arg;

#if 0
	re_printf("\n\x1b[32m%H\x1b[;m\n", icem_debug, it->a->icem);
	re_printf("\n\x1b[36m%H\x1b[;m\n", icem_debug, it->b->icem);
#endif

	complete_test(it, 0);
}


static void icetest_check_connchecks(struct ice_test *it)
{
	if (!it->a->conncheck_ok)
		return;
	if (!it->b->conncheck_ok)
		return;

	/* start an async timer to let the socket traffic complete */
	tmr_start(&it->tmr, 1, tmr_handler, it);
}


static void icetest_destructor(void *arg)
{
	struct ice_test *it = arg;

	tmr_cancel(&it->tmr);
	mem_deref(it->b);
	mem_deref(it->a);
}


static int icetest_alloc(struct ice_test **itp,
			 bool turn_a,
			 bool turn_b)
{
	struct ice_test *it;
	int err;

	it = mem_zalloc(sizeof(*it), icetest_destructor);
	if (!it)
		return ENOMEM;

	err = agent_alloc(&it->a, it, turn_a, "A", 7, true);
	if (err)
		goto out;

	err = agent_alloc(&it->b, it, turn_b, "B", 7, false);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(it);
	else
		*itp = it;

	return err;
}


static int _test_ice_loop(bool turn_a,
			  bool turn_b)
{
	struct ice_test *it = NULL;
	int err;

	err = icetest_alloc(&it, turn_a, turn_b);
	if (err)
		goto out;

	err = re_main_timeout(300);
	if (err)
		goto out;

	/* read back global errorcode */
	if (it->err) {
		err = it->err;
		goto out;
	}

	/* now verify all results after test was finished */
	err  = agent_verify_completed(it->a);
	err |= agent_verify_completed(it->b);
	if (err)
		goto out;

 out:
	mem_deref(it);

	return err;
}


/* also verify that these symbols are exported */
static int test_ice_basic_candidate(void)
{
	static const enum ice_cand_type typev[4] = {
		ICE_CAND_TYPE_HOST,
		ICE_CAND_TYPE_SRFLX,
		ICE_CAND_TYPE_PRFLX,
		ICE_CAND_TYPE_RELAY
	};
	unsigned i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(typev); i++) {

		const char *name;
		enum ice_cand_type type;

		name = ice_cand_type2name(typev[i]);
		TEST_ASSERT(str_isset(name));

		type = ice_cand_name2type(name);
		TEST_EQUALS(typev[i], type);
	}

 out:
	return err;
}


static int test_ice_cand_prio(void)
{
	int err = 0;

	TEST_EQUALS(0x7e0000ff, ice_cand_calc_prio(ICE_CAND_TYPE_HOST,  0, 1));
	TEST_EQUALS(0x640004ff, ice_cand_calc_prio(ICE_CAND_TYPE_SRFLX, 4, 1));
	TEST_EQUALS(0x6e0000fe, ice_cand_calc_prio(ICE_CAND_TYPE_PRFLX, 0, 2));
	TEST_EQUALS(0x000004fe, ice_cand_calc_prio(ICE_CAND_TYPE_RELAY, 4, 2));
 out:
	return err;
}


static const char *testv[] = {
"1 1 UDP 2130706431 10.0.1.1 5000 typ host",
"1 2 UDP 2130706431 10.0.1.1 5001 typ host",
"2 1 UDP 1694498815 192.0.2.3 5000 typ srflx raddr 10.0.1.1 rport 8998",
"2 2 UDP 1694498815 192.0.2.3 5001 typ srflx raddr 10.0.1.1 rport 8998",

"1 1 TCP 2128609279 10.0.1.1 9 typ host tcptype active",
"2 1 TCP 2124414975 10.0.1.1 8998 typ host tcptype passive",
"3 1 TCP 2120220671 10.0.1.1 8999 typ host tcptype so",
"4 1 TCP 1688207359 192.0.2.3 9 typ srflx raddr"
  " 10.0.1.1 rport 9 tcptype active",
"5 1 TCP 1684013055 192.0.2.3 45664 typ srflx raddr"
  " 10.0.1.1 rport 8998 tcptype passive",
"6 1 TCP 1692401663 192.0.2.3 45687 typ srflx raddr"
  " 10.0.1.1 rport 8999 tcptype so",

"H76f0ae12 1 UDP 2130706431 fda8:de2d:e95f:4811::1 6054 typ host",

"3113280040 1 UDP 2122255103 2001:aaaa:5ef5:79fb:1847:2c0d:a230:23ab 53329"
  " typ host",

};


static int test_ice_cand_attribute(void)
{
	unsigned i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		struct ice_cand_attr cand;
		char buf[256];
		int n;

		err = ice_cand_attr_decode(&cand, testv[i]);
		TEST_ERR(err);

		/* sanity-check of decoded attribute */
		TEST_ASSERT(str_isset(cand.foundation));
		TEST_ASSERT(1 <= cand.compid && cand.compid <= 2);
		TEST_ASSERT(cand.proto == IPPROTO_UDP ||
			    cand.proto == IPPROTO_TCP);
		TEST_ASSERT(cand.prio > 0);
		TEST_ASSERT(sa_isset(&cand.addr, SA_ALL));

		n = re_snprintf(buf, sizeof(buf), "%H",
				ice_cand_attr_encode, &cand);
		if (n < 0)
			return ENOMEM;

		TEST_STRCMP(testv[i], strlen(testv[i]), buf, (unsigned)n);
	}

 out:
	return err;
}


static int test_ice_shared_socket_stun_request(void)
{
	static const char new_pwd[] = "new-password-0123456789abcdef";
	struct shared_socket_test *test = NULL;
	struct stun_msg *response = NULL;
	struct mbuf *request = NULL;
	unsigned receives;
	int err;

	err = shared_socket_test_alloc(&test);
	TEST_ERR(err);

	/* The old helper sees this first, but only the matching local ufrag may
	 * authenticate and answer it. */
	err = shared_socket_request(&request, "new-ufrag:remote", new_pwd);
	TEST_ERR(err);
	err = shared_socket_inject(test, &test->new_peer, request);
	TEST_ERR(err);
	TEST_EQUALS(1, test->sends);
	TEST_EQUALS(0, test->receives);
	TEST_ASSERT(test->sent != NULL);
	err = stun_msg_decode(&response, test->sent, NULL);
	TEST_ERR(err);
	TEST_EQUALS(STUN_METHOD_BINDING, stun_msg_method(response));
	TEST_EQUALS(STUN_CLASS_SUCCESS_RESP, stun_msg_class(response));

	mem_deref(response);
	response = NULL;
	mem_deref(request);
	request = NULL;

	/* No generation owns this ufrag, so every ICE helper must fall through
	 * without manufacturing an authentication error. */
	receives = test->receives;
	err = shared_socket_request(&request, "unknown:remote", new_pwd);
	TEST_ERR(err);
	err = shared_socket_inject(test, &test->third_peer, request);
	TEST_ERR(err);
	TEST_EQUALS(1, test->sends);
	TEST_EQUALS(receives + 1, test->receives);

	mem_deref(request);
	request = NULL;

	/* Matching a provisional generation's local ufrag is insufficient when
	 * the peer still sends with its active generation.  The pair of ufrags
	 * identifies the generation, so this must route without a stale 401. */
	receives = test->receives;
	err = shared_socket_request(&request, "new-ufrag:stale-remote",
				    new_pwd);
	TEST_ERR(err);
	err = shared_socket_inject(test, &test->old_peer, request);
	TEST_ERR(err);
	TEST_EQUALS(1, test->sends);
	TEST_EQUALS(receives + 1, test->receives);

out:
	mem_deref(response);
	mem_deref(request);
	mem_deref(test);
	return err;
}


static int test_ice_single_socket_stun_request(void)
{
	static const char old_pwd[] = "old-password-0123456789abcdef";
	struct shared_socket_test *test = NULL;
	struct stun_attr *error_code;
	struct stun_msg *response = NULL;
	struct mbuf *request = NULL;
	int err;

	err = shared_socket_test_alloc(&test);
	TEST_ERR(err);
	test->candidate = mem_deref(test->candidate);
	icem_shared_socket_route(test->old, false);
	err = shared_socket_request(&request, "unknown:remote", old_pwd);
	TEST_ERR(err);
	err = shared_socket_inject(test, &test->third_peer, request);
	TEST_ERR(err);
	TEST_EQUALS(1, test->sends);
	TEST_EQUALS(0, test->receives);
	TEST_ASSERT(test->sent != NULL);
	err = stun_msg_decode(&response, test->sent, NULL);
	TEST_ERR(err);
	TEST_EQUALS(STUN_METHOD_BINDING, stun_msg_method(response));
	TEST_EQUALS(STUN_CLASS_ERROR_RESP, stun_msg_class(response));
	error_code = stun_msg_attr(response, STUN_ATTR_ERR_CODE);
	TEST_ASSERT(error_code != NULL);
	TEST_EQUALS(401, error_code->v.err_code.code);

out:
	mem_deref(response);
	mem_deref(request);
	mem_deref(test);
	return err;
}


static int test_ice_retired_socket_stun_request(void)
{
	static const char old_pwd[] = "old-password-0123456789abcdef";
	struct shared_socket_test *test = NULL;
	struct mbuf *request = NULL;
	unsigned receives;
	int err;

	err = shared_socket_test_alloc(&test);
	TEST_ERR(err);

	/* A retired generation may still share the live UDP helper chain.  Even
	 * a request matching its former local ufrag must continue to the active
	 * generation instead of producing a stale-remote-ufrag 401 response. */
	icem_shared_socket_candidate(test->old, true);
	icem_shared_socket_retired(test->old, true);
	receives = test->receives;
	err = shared_socket_request(&request, "old-ufrag:stale-remote", old_pwd);
	TEST_ERR(err);
	err = shared_socket_inject(test, &test->old_peer, request);
	TEST_ERR(err);
	TEST_EQUALS(0, test->sends);
	TEST_EQUALS(receives + 1, test->receives);

out:
	mem_deref(request);
	mem_deref(test);
	return err;
}


static int test_ice_shared_socket_stun_response(void)
{
	struct shared_socket_test *test = NULL;
	struct stun_msg *outgoing = NULL;
	struct mbuf *response = NULL;
	uint8_t tid[STUN_TID_SIZE];
	unsigned receives;
	int err;

	err = shared_socket_test_alloc(&test);
	TEST_ERR(err);

	/* Register a transaction only on the candidate generation.  The response
	 * reaches the old helper first and must continue until its TID owner. */
	err = stun_request(&test->candidate_ct, icem_stun(test->candidate),
			   IPPROTO_UDP, test->us, &test->new_peer, 0,
			   STUN_METHOD_BINDING, NULL, 0, true,
			   shared_socket_response_handler, test, 0);
	TEST_ERR(err);
	TEST_EQUALS(1, test->sends);
	TEST_ASSERT(test->sent != NULL);
	err = stun_msg_decode(&outgoing, test->sent, NULL);
	TEST_ERR(err);
	memcpy(tid, stun_msg_tid(outgoing), sizeof(tid));

	response = mbuf_alloc(128);
	if (!response) {
		err = ENOMEM;
		goto out;
	}
	err = stun_msg_encode(response, STUN_METHOD_BINDING,
			      STUN_CLASS_SUCCESS_RESP, tid, NULL,
			      NULL, 0, true, 0, 0);
	TEST_ERR(err);
	receives = test->receives;
	err = shared_socket_inject(test, &test->new_peer, response);
	TEST_ERR(err);
	TEST_EQUALS(1, test->candidate_responses);
	err = test->response_err;
	TEST_ERR(err);
	TEST_EQUALS(receives, test->receives);

out:
	mem_deref(outgoing);
	mem_deref(response);
	mem_deref(test);
	return err;
}


static int test_ice_shared_socket_publication(void)
{
	struct shared_socket_test *test = NULL;
	struct mbuf *packet = NULL;
	unsigned receives;
	int err;

	err = shared_socket_test_alloc(&test);
	TEST_ERR(err);
	packet = mbuf_alloc(4);
	if (!packet) {
		err = ENOMEM;
		goto out;
	}
	err = mbuf_write_str(packet, "DTLS");
	TEST_ERR(err);

	/* Prepared candidate is provisional.  It must not consume an old-path
	 * authenticated packet, while the active strict generation still drops an
	 * unauthenticated packet from a third source. */
	receives = test->receives;
	err = shared_socket_inject(test, &test->old_peer, packet);
	TEST_ERR(err);
	TEST_EQUALS(receives + 1, test->receives);
	receives = test->receives;
	err = shared_socket_inject(test, &test->third_peer, packet);
	TEST_ERR(err);
	TEST_EQUALS(receives, test->receives);

	/* Publish candidate strict and make old dormant.  Only the candidate's
	 * authenticated path is now admitted to the application. */
	icem_shared_socket_candidate(test->old, true);
	icem_shared_socket_retired(test->old, true);
	icem_shared_socket_candidate(test->candidate, false);
	receives = test->receives;
	err = shared_socket_inject(test, &test->new_peer, packet);
	TEST_ERR(err);
	TEST_EQUALS(receives + 1, test->receives);
	receives = test->receives;
	err = shared_socket_inject(test, &test->old_peer, packet);
	TEST_ERR(err);
	TEST_EQUALS(receives, test->receives);

	/* Rollback restores the old strict generation and candidate provisional
	 * state without changing the shared socket or either valid list. */
	icem_shared_socket_candidate(test->candidate, true);
	icem_shared_socket_retired(test->candidate, true);
	icem_shared_socket_candidate(test->old, false);
	icem_shared_socket_retired(test->old, false);
	receives = test->receives;
	err = shared_socket_inject(test, &test->old_peer, packet);
	TEST_ERR(err);
	TEST_EQUALS(receives + 1, test->receives);
	receives = test->receives;
	err = shared_socket_inject(test, &test->new_peer, packet);
	TEST_ERR(err);
	TEST_EQUALS(receives, test->receives);

out:
	mem_deref(packet);
	mem_deref(test);
	return err;
}


int test_ice_shared_socket(void)
{
	int err;

	/* Reply generation is intentionally void at the UDP helper boundary, so
	 * an injected allocator failure cannot be reported to this white-box test. */
	if (test_mode == TEST_MEMORY)
		return ESKIPPED;

	err = test_ice_shared_socket_stun_request();
	TEST_ERR(err);
	err = test_ice_single_socket_stun_request();
	TEST_ERR(err);
	err = test_ice_retired_socket_stun_request();
	TEST_ERR(err);
	err = test_ice_shared_socket_stun_response();
	TEST_ERR(err);
	err = test_ice_shared_socket_publication();
	TEST_ERR(err);

out:
	return err;
}


int test_ice_cand(void)
{
	int err = 0;

	err = test_ice_basic_candidate();
	TEST_ERR(err);

	err = test_ice_cand_prio();
	TEST_ERR(err);

	err = test_ice_cand_attribute();
	TEST_ERR(err);

out:
	return err;
}


int test_ice_loop(void)
{
	return _test_ice_loop(false, false);
}
