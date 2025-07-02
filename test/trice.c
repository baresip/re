/**
 * @file trice.c Trickle-ICE Testcode
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_trice"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define DEBUG 0
#define COMPID 1


struct fixture {
	struct trice *icem;
	struct sa laddr;
	bool controlling;
	char lufrag[8];
	char lpwd[24];
	char rufrag[8];
	char rpwd[24];

	struct trice *icem2;

	/* result: */
	int err;

	unsigned n_expected_estabh;
	bool cancel_on_both;

	/* counters: */
	unsigned n_estabh;
	unsigned n_failh;
	unsigned n_estabh2;
	unsigned n_failh2;

	/* NAT */
	struct nat *nat;
	struct nat *nat2;
};


/*
 * Helper macros
 */


#define FIXTURE_INIT				\
	struct fixture _f, *f = &_f;		\
	int err = fixture_init(f);		\
	if (err)				\
		goto out;			\


/* todo: 'addr' used as 'base_addr' (hack) */
#define ADD_LOCAL_SRFLX_CANDIDATE(proto, prio, addr)			\
									\
	do {								\
		struct ice_lcand *_lcand;				\
									\
		err = trice_lcand_add(&_lcand, f->icem,	\
				      COMPID, (proto),			\
				      (prio), (addr), (addr),		\
				      ICE_CAND_TYPE_SRFLX, (addr),	\
				      0, NULL, 0);			\
		if (err) goto out;					\
		TEST_ASSERT(_lcand != NULL);				\
									\
	} while (0);

#define add_local_udp_candidate_use(addr) \
						   \
	do {								\
		struct ice_lcand *_lcand;				\
		uint32_t _prio;						\
									\
		_prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, 0, 1);	\
									\
		err = trice_lcand_add(&_lcand, f->icem, 1,	\
				      IPPROTO_UDP, _prio,		\
				      addr, NULL,			\
				      ICE_CAND_TYPE_HOST, NULL,		\
				      0, NULL, 0);			\
		if (err) goto out;					\
		TEST_ASSERT(_lcand != NULL);				\
									\
	} while (0);

#define add_local_tcp_candidate_use(addr, tcptype) \
						   \
	do {								\
		struct ice_lcand *_lcand;				\
		uint32_t _prio;						\
									\
		_prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, 0, 1);	\
									\
		err = trice_lcand_add(&_lcand, f->icem, 1,	\
				      IPPROTO_TCP, _prio,		\
				      addr, NULL,			\
				      ICE_CAND_TYPE_HOST, NULL,		\
				      tcptype, NULL, 0);		\
		if (err) goto out;					\
		TEST_ASSERT(_lcand != NULL);				\
									\
	} while (0);


#define add_local_tcp_candidate_use2(addr, tcptype) \
						   \
	do {								\
		struct ice_lcand *_lcand;				\
		uint32_t _prio;						\
									\
		_prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, 0, 1);	\
									\
		err = trice_lcand_add(&_lcand, f->icem2, 1,	\
				      IPPROTO_TCP, _prio,		\
				      addr, NULL,			\
				      ICE_CAND_TYPE_HOST, NULL,		\
				      tcptype, NULL, 0);		\
		if (err) goto out;					\
		TEST_ASSERT(_lcand != NULL);				\
									\
	} while (0);


#define ADD_REMOTE_HOST_CANDIDATE(addr)					\
									\
	do {								\
		uint32_t _prio;						\
									\
		_prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, 0, 1);	\
									\
		err = trice_rcand_add(NULL, f->icem,		\
					      1, "FND",			\
					      IPPROTO_UDP,		\
					      _prio,			\
					      addr,			\
					      ICE_CAND_TYPE_HOST, 0);	\
		if (err) goto out;					\
									\
	} while (0);

#define CHECKLIST_START(fix)					\
	err = trice_checklist_start((fix)->icem, NULL, 1,	\
				   ice_estab_handler,		\
				   ice_failed_handler, (fix));	\
	TEST_ERR(err);						\


static void fixture_abort(struct fixture *f, int err);


static bool verify_sorted(const struct list *pairl)
{
	struct le *le;
	uint64_t pprio = 0;

	if (!pairl)
		return false;

	for (le = list_head(pairl); le; le = le->next) {

		struct ice_candpair *pair = le->data;

		if (!pprio) {
			pprio = pair->pprio;
			continue;
		}

		if (pair->pprio > pprio) {
			DEBUG_WARNING("unsorted list: %llu > %llu\n",
				      pair->pprio, pprio);
			return false;
		}
	}

	return true;
}


static bool are_both_established(const struct fixture *f)
{
	if (!f)
		return false;
	return f->n_estabh > 0 && f->n_estabh2 > 0;
}


static void ice_estab_handler(struct ice_candpair *pair,
			      const struct stun_msg *msg, void *arg)
{
	struct fixture *f = arg;
	int err = 0;

	++f->n_estabh;

	/* TODO: save candidate-pairs, and compare in the test */

	TEST_ASSERT(msg != NULL);
	TEST_ASSERT(pair != NULL);
	TEST_ASSERT(pair->lcand != NULL);
	TEST_ASSERT(pair->rcand != NULL);
	TEST_ASSERT(pair->valid);
	TEST_EQUALS(ICE_CANDPAIR_SUCCEEDED, pair->state);
	TEST_ERR(pair->err);
	TEST_EQUALS(0, pair->scode);

	TEST_ASSERT((ICE_CAND_TYPE_HOST == pair->rcand->attr.type) ||
		    (ICE_CAND_TYPE_PRFLX == pair->rcand->attr.type));

	/* exit criteria */
	if (f->n_expected_estabh && f->n_estabh >= f->n_expected_estabh) {
		fixture_abort(f, 0);
	}

	if (f->cancel_on_both && are_both_established(f)) {
		fixture_abort(f, 0);
	}

 out:
	if (err)
		fixture_abort(f, err);
}


static void ice_failed_handler(int err, uint16_t scode,
			       struct ice_candpair *pair, void *arg)
{
	struct fixture *f = arg;
	(void)err;
	(void)scode;
	(void)pair;

	++f->n_failh;

	if (trice_checklist_iscompleted(f->icem)) {
		re_cancel();
	}
}


static void ice_estab_handler2(struct ice_candpair *pair,
			       const struct stun_msg *msg, void *arg)
{
	struct fixture *f = arg;
	(void)pair;
	(void)msg;

	++f->n_estabh2;

	if (f->cancel_on_both && are_both_established(f)) {
		fixture_abort(f, 0);
	}
}


static void ice_failed_handler2(int err, uint16_t scode,
				struct ice_candpair *pair, void *arg)
{
	struct fixture *f = arg;
	(void)err;
	(void)scode;
	(void)pair;

	re_printf("  ~ ice2 closed (%m)\n", err);

	++f->n_failh2;

#if 0
	re_cancel();
#endif
}


static int fixture_init(struct fixture *f)
{
	const struct trice_conf conf = {
		.debug = DEBUG
	};
	int err;

	if (!f)
		return EINVAL;

	memset(f, 0, sizeof(*f));

	f->controlling = true;

	rand_str(f->lufrag, sizeof(f->lufrag));
	rand_str(f->lpwd, sizeof(f->lpwd));
	rand_str(f->rufrag, sizeof(f->rufrag));
	rand_str(f->rpwd, sizeof(f->rpwd));

	err = trice_alloc(&f->icem, &conf,
		  f->controlling ? ICE_ROLE_CONTROLLING : ICE_ROLE_CONTROLLED,
			  f->lufrag, f->lpwd);
	TEST_ERR(err);

	TEST_ASSERT(f->icem != NULL);

	err = trice_set_remote_ufrag(f->icem, f->rufrag);
	TEST_ERR(err);

	err = trice_set_remote_pwd(f->icem, f->rpwd);
	TEST_ERR(err);

	err = sa_set_str(&f->laddr, "127.0.0.1", 0);
	TEST_ERR(err);

 out:
	return err;
}


static void fixture_close(struct fixture *f)
{
	if (!f)
		return;

	f->nat = mem_deref(f->nat);
	f->nat2 = mem_deref(f->nat2);

	f->icem2 = mem_deref(f->icem2);
	f->icem = mem_deref(f->icem);
}


static void fixture_abort(struct fixture *f, int err)
{
	f->err = err;
	re_cancel();
}


/* ... TEST CASES ... */


static int candidate_local_udp(void)
{
	struct ice_lcand *lcand;
	FIXTURE_INIT;

	err = trice_lcand_add(&lcand, f->icem, 1, IPPROTO_UDP,
			      1234, &f->laddr, NULL,
			      ICE_CAND_TYPE_HOST, NULL, 0, NULL, 0);
	if (err)
		goto out;

	/* verify the new local candidate */
	TEST_ASSERT(lcand != NULL);
	TEST_ASSERT(str_isset(lcand->attr.foundation));
	TEST_EQUALS(1, lcand->attr.compid);
	TEST_EQUALS(IPPROTO_UDP, lcand->attr.proto);
	TEST_EQUALS(1234, lcand->attr.prio);
	TEST_SACMP(&f->laddr, &lcand->attr.addr, SA_ADDR);
	TEST_ASSERT(sa_isset(&lcand->attr.addr, SA_PORT));
	TEST_EQUALS(ICE_CAND_TYPE_HOST, lcand->attr.type);

	TEST_ASSERT(list_contains(trice_lcandl(f->icem), &lcand->le));
	TEST_ASSERT(lcand->icem == f->icem);
	TEST_ASSERT(lcand->us != NULL);
	TEST_ASSERT(lcand->uh != NULL);
	TEST_ASSERT(lcand->ts == NULL);

 out:
	fixture_close(f);
	return err;
}


static int candidate_local_tcp(enum ice_tcptype tcptype)
{
	struct ice_lcand *lcand;
	FIXTURE_INIT;

	err = trice_lcand_add(&lcand, f->icem, 1, IPPROTO_TCP,
			      1234, &f->laddr, NULL,
			      ICE_CAND_TYPE_HOST, NULL, tcptype, NULL, 0);
	if (err)
		goto out;

	/* verify the new local candidate */
	TEST_ASSERT(lcand != NULL);
	TEST_ASSERT(str_isset(lcand->attr.foundation));
	TEST_EQUALS(1, lcand->attr.compid);
	TEST_EQUALS(IPPROTO_TCP, lcand->attr.proto);
	TEST_EQUALS(1234, lcand->attr.prio);
	TEST_SACMP(&f->laddr, &lcand->attr.addr, SA_ADDR);
	if (tcptype == ICE_TCP_ACTIVE) {
		TEST_ASSERT(!sa_isset(&lcand->attr.addr, SA_PORT));
	}
	else {
		TEST_ASSERT(sa_isset(&lcand->attr.addr, SA_PORT));
	}
	TEST_EQUALS(ICE_CAND_TYPE_HOST, lcand->attr.type);

	TEST_ASSERT(list_contains(trice_lcandl(f->icem), &lcand->le));
	TEST_ASSERT(lcand->icem == f->icem);
	TEST_ASSERT(lcand->us == NULL);
	TEST_ASSERT(lcand->uh == NULL);
	if (tcptype == ICE_TCP_ACTIVE) {
		TEST_ASSERT(lcand->ts == NULL);
	}
	else {
		TEST_ASSERT(lcand->ts != NULL);
	}

 out:
	fixture_close(f);
	return err;
}


static int candidate_add_5_local(int proto)
{
	int i;
	FIXTURE_INIT;

	for (i=0; i<5; i++) {
		struct sa addr;
		char buf[64];

		re_snprintf(buf, sizeof(buf), "10.0.0.%u", i+1);

		sa_set_str(&addr, buf, 1000+i);

		ADD_LOCAL_SRFLX_CANDIDATE(proto, 0, &addr)
	}

	TEST_EQUALS(5, list_count(trice_lcandl(f->icem)));
	TEST_EQUALS(0, list_count(trice_rcandl(f->icem)));
	TEST_EQUALS(0, list_count(trice_checkl(f->icem)));
	TEST_EQUALS(0, list_count(trice_validl(f->icem)));

	TEST_EQUALS(0, f->n_estabh);

 out:
	fixture_close(f);
	return err;
}


static int candidate_find_local_candidate(void)
{
	struct sa addr;
	struct ice_lcand *cand;
	FIXTURE_INIT;

	sa_set_str(&addr, "1.2.3.4", 1234);

	/* should not exist now */
	cand = trice_lcand_find(f->icem, -1, 1, IPPROTO_UDP, &addr);
	TEST_ASSERT(cand == NULL);

	ADD_LOCAL_SRFLX_CANDIDATE(IPPROTO_UDP, 0x7e0000ff, &addr);

	cand = trice_lcand_find(f->icem, -1, 1, IPPROTO_UDP, &addr);
	TEST_ASSERT(cand != NULL);

	TEST_EQUALS(ICE_CAND_TYPE_SRFLX, cand->attr.type);
	TEST_EQUALS(0x7e0000ff, cand->attr.prio);
	TEST_ASSERT(str_isset(cand->attr.foundation));
	TEST_EQUALS(1, cand->attr.compid);
	TEST_SACMP(&addr, &cand->attr.addr, SA_ALL);
	TEST_EQUALS(IPPROTO_UDP, cand->attr.proto);

 out:
	fixture_close(f);
	return err;
}


static int candidate_add_5_remote_candidates(void)
{
	int i;
	FIXTURE_INIT;

	for (i=0; i<5; i++) {
		struct sa addr;
		char buf[64];

		re_snprintf(buf, sizeof(buf), "10.0.0.%u", i+1);

		sa_set_str(&addr, buf, 1234);

		ADD_REMOTE_HOST_CANDIDATE(&addr);
	}

	TEST_EQUALS(0, list_count(trice_lcandl(f->icem)));
	TEST_EQUALS(5, list_count(trice_rcandl(f->icem)));
	TEST_EQUALS(0, list_count(trice_checkl(f->icem)));
	TEST_EQUALS(0, list_count(trice_validl(f->icem)));

	TEST_EQUALS(0, f->n_estabh);

 out:
	fixture_close(f);
	return err;
}


static int candidate_find_remote_candidate(void)
{
	struct sa addr;
	struct ice_rcand *cand;
	FIXTURE_INIT;

	sa_set_str(&addr, "1.2.3.4", 1234);

	/* should not exist now */
	cand = trice_rcand_find(f->icem, 1, IPPROTO_UDP, &addr);
	TEST_ASSERT(cand == NULL);

	ADD_REMOTE_HOST_CANDIDATE(&addr);

	cand = trice_rcand_find(f->icem, 1, IPPROTO_UDP, &addr);
	TEST_ASSERT(cand != NULL);

	TEST_EQUALS(ICE_CAND_TYPE_HOST, cand->attr.type);
	TEST_EQUALS(0x7e0000ff, cand->attr.prio);
	TEST_ASSERT(str_isset(cand->attr.foundation));
	TEST_EQUALS(1, cand->attr.compid);
	TEST_SACMP(&addr, &cand->attr.addr, SA_ALL);
	TEST_EQUALS(IPPROTO_UDP, cand->attr.proto);

 out:
	fixture_close(f);
	return err;
}


static int candidate_add_2_local_and_2_remote_candidates(void)
{
	struct sa laddr, raddr;
	int i;
	FIXTURE_INIT;

	sa_set_str(&laddr, "10.0.0.1", 0);
	sa_set_str(&raddr, "10.0.0.2", 0);

	for (i=0; i<2; i++) {

		sa_set_port(&laddr, 10000+i);
		sa_set_port(&raddr, 20000+i);

		ADD_LOCAL_SRFLX_CANDIDATE(IPPROTO_UDP, 1234, &laddr)

		ADD_REMOTE_HOST_CANDIDATE(&raddr);
	}

	TEST_EQUALS(2, list_count(trice_lcandl(f->icem)));
	TEST_EQUALS(2, list_count(trice_rcandl(f->icem)));
	TEST_EQUALS(4, list_count(trice_checkl(f->icem)));
	TEST_EQUALS(0, list_count(trice_validl(f->icem)));

	TEST_EQUALS(0, f->n_estabh);

	TEST_ASSERT(verify_sorted(trice_checkl(f->icem)));

 out:
	fixture_close(f);
	return err;
}


static int candidate_2_local_duplicates(int proto,
					uint32_t prio1, uint32_t prio2)
{
	struct sa laddr;
	struct ice_lcand *lcand;
	FIXTURE_INIT;

	sa_set_str(&laddr, "10.0.0.3", 1002);

	TEST_EQUALS(0, list_count(trice_lcandl(f->icem)));

	/* add one with Low Priority */
	ADD_LOCAL_SRFLX_CANDIDATE(proto, prio1, &laddr);

	TEST_EQUALS(1, list_count(trice_lcandl(f->icem)));

	/* add one with High Priority */
	ADD_LOCAL_SRFLX_CANDIDATE(proto, prio2, &laddr);

	TEST_EQUALS(1, list_count(trice_lcandl(f->icem)));

	/* verify that local candidate has the HIGH prio */
	lcand = trice_lcand_find(f->icem, -1, 1, proto, &laddr);
	TEST_ASSERT(lcand != NULL);
	TEST_EQUALS(max(prio1, prio2), lcand->attr.prio);

 out:
	fixture_close(f);
	return err;
}


static int candidate_local_host_and_srflx_with_base(void)
{
	struct fixture f;
	struct sa laddr, srflx;
	struct ice_lcand *lcand;
	int err = 0;

	err = fixture_init(&f);
	if (err)
		goto out;

	sa_set_str(&laddr, "127.0.0.1", 0);
	sa_set_str(&srflx, "46.45.1.1", 1002);

	err = trice_lcand_add(&lcand, f.icem, COMPID, IPPROTO_UDP,
			      1234, &laddr, NULL,
			      ICE_CAND_TYPE_HOST, NULL, 0, NULL, 0);
	TEST_ERR(err);
	TEST_ASSERT(lcand != NULL);

	laddr = lcand->attr.addr;

	err = trice_lcand_add(NULL, f.icem, COMPID, IPPROTO_UDP,
			      1234, &srflx, &laddr,
			      ICE_CAND_TYPE_SRFLX, &laddr, 0, NULL, 0);
	TEST_ERR(err);

	TEST_EQUALS(2, list_count(trice_lcandl(f.icem)));

	/* verify */
	lcand = trice_lcand_find(f.icem, ICE_CAND_TYPE_HOST, COMPID,
				 IPPROTO_UDP, &lcand->attr.addr);
	TEST_ASSERT(lcand != NULL);
	TEST_EQUALS(ICE_CAND_TYPE_HOST, lcand->attr.type);
	TEST_SACMP(&laddr, &lcand->attr.addr, SA_ALL);

	lcand = trice_lcand_find(f.icem, ICE_CAND_TYPE_SRFLX, COMPID,
				 IPPROTO_UDP, &srflx);
	TEST_ASSERT(lcand != NULL);
	TEST_EQUALS(ICE_CAND_TYPE_SRFLX, lcand->attr.type);
	TEST_SACMP(&srflx, &lcand->attr.addr, SA_ALL);
	TEST_SACMP(&laddr, &lcand->base_addr, SA_ALL);

 out:
	fixture_close(&f);
	return err;
}


/* 4.1.3.  Eliminating Redundant Candidates */
static int candidate_verify_redundant_with_public_ip(void)
{
	struct sa laddr, raddr;
	struct ice_lcand *lcand;
	uint32_t prio;
	FIXTURE_INIT;

	sa_set_str(&laddr, "127.0.0.1", 0);
	sa_set_str(&raddr, "10.0.0.4", 1002);

	prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, 0, COMPID);
	err = trice_lcand_add(&lcand, f->icem, COMPID, IPPROTO_UDP,
			      prio, &laddr, NULL,
			      ICE_CAND_TYPE_HOST, NULL, 0,
			      NULL, 0);
	TEST_ERR(err);
	TEST_ASSERT(lcand != NULL);

	laddr = lcand->attr.addr;

	prio = ice_cand_calc_prio(ICE_CAND_TYPE_SRFLX, 0, COMPID);
	err = trice_lcand_add(NULL, f->icem, COMPID, IPPROTO_UDP,
			      prio,
			      &lcand->attr.addr, &lcand->attr.addr,
			      ICE_CAND_TYPE_SRFLX,
			      &lcand->attr.addr,
			      0, NULL, 0);
	TEST_ERR(err);

	ADD_REMOTE_HOST_CANDIDATE(&raddr);

	TEST_EQUALS(1, list_count(trice_lcandl(f->icem)));
	TEST_EQUALS(1, list_count(trice_rcandl(f->icem)));
	TEST_EQUALS(1, list_count(trice_checkl(f->icem)));
	TEST_EQUALS(0, list_count(trice_validl(f->icem)));

	/* verify the local candidate */
	lcand = list_ledata(list_head(trice_lcandl(f->icem)));
	TEST_EQUALS(ICE_CAND_TYPE_HOST, lcand->attr.type);
	TEST_SACMP(&laddr, &lcand->attr.addr, SA_ALL);

 out:
	fixture_close(f);
	return err;
}


/* ... testcases for candidate pairs ... */


static int candpair_add_1_local_and_1_remote_candidate_and_create_pair(void)
{
	struct sa addr;
	FIXTURE_INIT;

	sa_set_str(&addr, "10.0.0.5", 1000);

	ADD_LOCAL_SRFLX_CANDIDATE(IPPROTO_UDP, 1234, &addr);

	ADD_REMOTE_HOST_CANDIDATE(&addr);

	/* the checklist is formated automatically */

	TEST_EQUALS(1, list_count(trice_lcandl(f->icem)));
	TEST_EQUALS(1, list_count(trice_rcandl(f->icem)));
	TEST_EQUALS(1, list_count(trice_checkl(f->icem)));
	TEST_EQUALS(0, list_count(trice_validl(f->icem)));

	TEST_EQUALS(0, f->n_estabh);

 out:
	fixture_close(f);
	return err;
}


static int candpair_combine_ipv4_ipv6_udp_tcp(void)
{
	struct sa addr, addr6;
	FIXTURE_INIT;

	sa_set_str(&addr, "10.0.0.6", 1000);
	sa_set_str(&addr6, "::1", 6000);

	err |= trice_lcand_add(0, f->icem, 1, IPPROTO_UDP, 1234,
			       &addr, &addr, ICE_CAND_TYPE_SRFLX, &addr, 0,
			       NULL, 0);
	err |= trice_lcand_add(0, f->icem, 1, IPPROTO_TCP, 1234,
			       &addr, &addr, ICE_CAND_TYPE_SRFLX, &addr,
			       ICE_TCP_ACTIVE,
			       NULL, 0);
	err |= trice_lcand_add(0, f->icem, 1, IPPROTO_UDP, 1234,
			       &addr6, &addr6, ICE_CAND_TYPE_SRFLX, &addr6,
			       0, NULL, 0);
	err |= trice_lcand_add(0, f->icem, 1, IPPROTO_TCP, 1234,
			       &addr6, &addr6, ICE_CAND_TYPE_SRFLX, &addr6,
			       ICE_TCP_ACTIVE,
			       NULL, 0);
	TEST_ERR(err);

	ADD_REMOTE_HOST_CANDIDATE(&addr);
	err |= trice_rcand_add(NULL, f->icem, 1,
					 "FND", IPPROTO_TCP, 1234,
					 &addr, ICE_CAND_TYPE_HOST,
					 ICE_TCP_PASSIVE);
	if (err) goto out;

	ADD_REMOTE_HOST_CANDIDATE(&addr6);
	err |= trice_rcand_add(NULL, f->icem, 1,
					 "FND", IPPROTO_TCP, 1234,
					 &addr6, ICE_CAND_TYPE_HOST,
					 ICE_TCP_PASSIVE);
	if (err) goto out;

	TEST_EQUALS(4, list_count(trice_lcandl(f->icem)));
	TEST_EQUALS(4, list_count(trice_rcandl(f->icem)));
	TEST_EQUALS(4, list_count(trice_checkl(f->icem)));
	TEST_EQUALS(0, list_count(trice_validl(f->icem)));

	TEST_EQUALS(0, f->n_estabh);
	TEST_EQUALS(0, f->n_failh);

 out:
	fixture_close(f);
	return err;
}


static int candpair_add_many_verify_sorted(void)
{
	struct fixture f;
	struct sa laddr, raddr;
	int i, err = 0;

	err = fixture_init(&f);
	if (err)
		goto out;

	sa_set_str(&laddr, "10.0.0.7", 0);
	sa_set_str(&raddr, "10.0.0.8", 0);

	for (i=0; i<4; i++) {

		uint8_t compid = 1 + i%2;

		sa_set_port(&laddr, 10000+i);
		sa_set_port(&raddr, 20000+i);

		err = trice_lcand_add(0, f.icem, compid, IPPROTO_UDP,
				      i*1000, &laddr, &laddr,
				      ICE_CAND_TYPE_SRFLX, &laddr, 0,
				      NULL, 0);
		TEST_ERR(err);

		err = trice_rcand_add(0, f.icem, compid, "FND",
				      IPPROTO_UDP, i*2000,
				      &raddr, ICE_CAND_TYPE_HOST, 0);
		TEST_ERR(err);
	}

	TEST_EQUALS(4, list_count(trice_lcandl(f.icem)));
	TEST_EQUALS(4, list_count(trice_rcandl(f.icem)));
	TEST_EQUALS(8, list_count(trice_checkl(f.icem)));
	TEST_EQUALS(0, list_count(trice_validl(f.icem)));

	TEST_ASSERT(verify_sorted(trice_checkl(f.icem)));

 out:
	fixture_close(&f);
	return err;
}


static int candpair_test_pruning(void)
{
	struct sa srflx_addr, remote_addr;
	struct ice_lcand *lcand;
	uint32_t prio;
	FIXTURE_INIT;

	err |= sa_set_str(&srflx_addr, "95.1.2.3", 50000);
	err |= sa_set_str(&remote_addr, "10.0.0.9", 10000);
	TEST_ERR(err);

	prio = ice_cand_calc_prio(ICE_CAND_TYPE_SRFLX, 0, COMPID);

	add_local_udp_candidate_use(&f->laddr);

	lcand = trice_lcand_find(f->icem, -1, COMPID,
				 IPPROTO_UDP, NULL);
	TEST_ASSERT(lcand != NULL);

	err = trice_lcand_add(&lcand, f->icem, COMPID, IPPROTO_UDP,
			      prio, &srflx_addr, &lcand->attr.addr,
			      ICE_CAND_TYPE_SRFLX, &lcand->attr.addr,
			      0, NULL, 0);
	TEST_ERR(err);
	TEST_ASSERT(lcand != NULL);

	ADD_REMOTE_HOST_CANDIDATE(&remote_addr);

	/* verify that SRFLX candpair was pruned
	 */
	TEST_EQUALS(2, list_count(trice_lcandl(f->icem)));
	TEST_EQUALS(1, list_count(trice_rcandl(f->icem)));
	TEST_EQUALS(1, list_count(trice_checkl(f->icem)));
	TEST_EQUALS(0, list_count(trice_validl(f->icem)));

 out:
	fixture_close(f);
	return err;
}


static int checklist_verify_states(void)
{
	struct fixture f;
	int err = 0;

	err = fixture_init(&f);
	if (err)
		goto out;

	TEST_EQUALS(false, trice_checklist_isrunning(f.icem));

	/* Start -- Running */
	CHECKLIST_START(&f);
	TEST_EQUALS(true, trice_checklist_isrunning(f.icem));

	/* Stop */
	trice_checklist_stop(f.icem);
	TEST_EQUALS(false, trice_checklist_isrunning(f.icem));

 out:
	fixture_close(&f);
	return err;
}


static int exchange_candidates(struct trice *dst, const struct trice *src)
{
	struct le *le;
	int err = 0;

	for (le = list_head(trice_lcandl(src)); le; le = le->next) {

		struct ice_cand_attr *cand = le->data;

		err = trice_rcand_add(NULL, dst, cand->compid,
				      cand->foundation, cand->proto,
				      cand->prio, &cand->addr,
				      cand->type, cand->tcptype);
		if (err)
			return err;
	}

	return err;
}


static int checklist_tcp_simple(enum ice_tcptype tcptype)
{
	struct le *le;
	char *buf = NULL;
	FIXTURE_INIT;

#if 0
	trice_conf(f.icem)->debug = true;
	trice_conf(f.icem)->trace = true;
#endif

	err = trice_alloc(&f->icem2, NULL,
		  !f->controlling ? ICE_ROLE_CONTROLLING : ICE_ROLE_CONTROLLED,
			  f->rufrag, f->rpwd);
	TEST_ERR(err);

	err |= trice_set_remote_ufrag(f->icem2, f->lufrag);
	err |= trice_set_remote_pwd(f->icem2, f->lpwd);
	TEST_ERR(err);

	add_local_tcp_candidate_use(&f->laddr, tcptype);
	add_local_tcp_candidate_use2(&f->laddr, ice_tcptype_reverse(tcptype));

	err  = exchange_candidates(f->icem, f->icem2);
	err |= exchange_candidates(f->icem2, f->icem);
	TEST_ERR(err);

	CHECKLIST_START(f);

	err = trice_checklist_start(f->icem2, NULL, 1,
				   ice_estab_handler2, ice_failed_handler2, f);
	TEST_ERR(err);

	f->n_expected_estabh = 1;

	err = re_main_timeout(1000);
	if (err)
		goto out;

	TEST_ERR(f->err);

	err = re_sdprintf(&buf, "%H", trice_debug, f->icem);
	TEST_ERR(err);
	ASSERT_TRUE(str_isset(buf));

	TEST_ASSERT(f->n_estabh > 0);

	TEST_ASSERT(list_count(trice_lcandl(f->icem)) >= 1);
	TEST_ASSERT(list_count(trice_rcandl(f->icem)) >= 1);
	TEST_EQUALS(1, list_count(trice_validl(f->icem)));

	for (le = list_head(trice_validl(f->icem)); le; le = le->next) {
		struct ice_candpair *pair = le->data;
		struct ice_lcand *lcand = pair->lcand;

		TEST_ASSERT(pair->valid);

		TEST_EQUALS(ICE_CANDPAIR_SUCCEEDED, pair->state);
		TEST_EQUALS(0, pair->err);
		TEST_EQUALS(0, pair->scode);

		TEST_EQUALS(IPPROTO_TCP, lcand->attr.proto);
		TEST_EQUALS(tcptype, lcand->attr.tcptype);

		TEST_EQUALS(IPPROTO_TCP, pair->rcand->attr.proto);
		TEST_EQUALS(ice_tcptype_reverse(tcptype),
			    pair->rcand->attr.tcptype);
	}

 out:
	fixture_close(f);
	mem_deref(buf);
	return err;
}


int test_trice_cand(void)
{
	int err = 0;

	err |= candidate_local_udp();
	err |= candidate_local_tcp(ICE_TCP_ACTIVE);
	err |= candidate_local_tcp(ICE_TCP_PASSIVE);
	err |= candidate_local_tcp(ICE_TCP_SO);
	err |= candidate_add_5_local(IPPROTO_UDP);
	err |= candidate_add_5_local(IPPROTO_TCP);
	err |= candidate_find_local_candidate();
	err |= candidate_add_5_remote_candidates();
	err |= candidate_find_remote_candidate();
	err |= candidate_add_2_local_and_2_remote_candidates();
	err |= candidate_2_local_duplicates(IPPROTO_UDP, 100, 200);
	err |= candidate_2_local_duplicates(IPPROTO_UDP, 200, 100);
#if 0
	err |= candidate_2_local_duplicates(IPPROTO_TCP, 100, 200);
#endif
	err |= candidate_local_host_and_srflx_with_base();
	err |= candidate_verify_redundant_with_public_ip();

	return err;
}


int test_trice_candpair(void)
{
	int err = 0;

	err |= candpair_add_1_local_and_1_remote_candidate_and_create_pair();
	err |= candpair_combine_ipv4_ipv6_udp_tcp();
	err |= candpair_add_many_verify_sorted();
	err |= candpair_test_pruning();

	return err;
}


int test_trice_checklist(void)
{
	int err = 0;

	err |= checklist_verify_states();
	TEST_ERR(err);
	err |= checklist_tcp_simple(ICE_TCP_ACTIVE);
	TEST_ERR(err);
	err |= checklist_tcp_simple(ICE_TCP_PASSIVE);
	TEST_ERR(err);

out:
	return err;
}


static int checklist_udp_loop(bool fw_a, bool fw_b)
{
	struct ice_lcand *lcand, *lcand2;
	struct sa laddr2;
	uint32_t prio;
	char *buf = NULL;
	FIXTURE_INIT;

#if 0
	trice_conf(f->icem)->debug = true;
	trice_conf(f->icem)->trace = true;
#endif

	sa_set_str(&laddr2, "127.0.0.1", 0);

	err = trice_alloc(&f->icem2, NULL,
		  !f->controlling ? ICE_ROLE_CONTROLLING : ICE_ROLE_CONTROLLED,
			  f->rufrag, f->rpwd);
	TEST_ERR(err);

	err |= trice_set_remote_ufrag(f->icem2, f->lufrag);
	err |= trice_set_remote_pwd(f->icem2, f->lpwd);
	TEST_ERR(err);

	/* add local HOST candidates */

	add_local_udp_candidate_use(&f->laddr);

	lcand = trice_lcand_find2(f->icem,
				  ICE_CAND_TYPE_HOST, AF_INET);
	TEST_ASSERT(lcand != NULL);

	/* install NAT/Firewall */
	if (fw_a) {
		err = nat_alloc(&f->nat, NAT_FIREWALL, lcand->us, NULL);
		if (err) {
			re_printf("nat failed\n");
			goto out;
		}
	}

	prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, 0, COMPID);
	err = trice_lcand_add(&lcand2, f->icem2, COMPID, IPPROTO_UDP,
			      prio, &laddr2, NULL,
			      ICE_CAND_TYPE_HOST, NULL, 0, NULL, 0);
	if (err)
		goto out;

	/* install NAT/Firewall */
	if (fw_b) {
		err = nat_alloc(&f->nat2, NAT_FIREWALL, lcand2->us, NULL);
		if (err) {
			re_printf("nat failed\n");
			goto out;
		}
	}

	err  = exchange_candidates(f->icem, f->icem2);
	err |= exchange_candidates(f->icem2, f->icem);
	TEST_ERR(err);

	f->cancel_on_both = true;

	CHECKLIST_START(f);

	/* NOTE: slow checklist */
	err = trice_checklist_start(f->icem2, NULL, 10,
				   ice_estab_handler2, ice_failed_handler2, f);
	TEST_ERR(err);

	err = re_main_timeout(2000);
	if (err)
		goto out;

	TEST_ERR(f->err);

	err = re_sdprintf(&buf, "%H", trice_debug, f->icem);
	TEST_ERR(err);
	ASSERT_TRUE(str_isset(buf));

	TEST_ASSERT(f->n_estabh > 0);

	TEST_ASSERT(list_count(trice_lcandl(f->icem)) >= 1);
	TEST_ASSERT(list_count(trice_rcandl(f->icem)) >= 1);
	TEST_EQUALS(1, list_count(trice_validl(f->icem)));

	if (fw_a) {
		TEST_ASSERT(f->nat->bindingc >= 1);
	}

 out:
	fixture_close(f);
	mem_deref(buf);
	return err;
}


int test_trice_loop(void)
{
	int err = 0;

	err = checklist_udp_loop(0, 0);
	TEST_ERR(err);

	err = checklist_udp_loop(0, 1);
	TEST_ERR(err);

	err = checklist_udp_loop(1, 0);
	TEST_ERR(err);

	err = checklist_udp_loop(1, 1);
	TEST_ERR(err);

out:
	return err;
}
