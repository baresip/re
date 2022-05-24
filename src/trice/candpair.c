/**
 * @file candpair.c  ICE Candidate Pairs
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_udp.h>
#include <re_stun.h>
#include <re_ice.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "candpair"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * generic routines to operate on "struct ice_candpair"
 * (for both checkl and validl)
 */


/*
 * g = controlling agent
 * d = controlled agent

 pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

 */
static uint64_t ice_calc_pair_prio(uint32_t g, uint32_t d)
{
	const uint64_t m = min(g, d);
	const uint64_t x = max(g, d);

	return (m<<32) + 2*x + (g>d?1:0);
}


static void candpair_destructor(void *arg)
{
	struct ice_candpair *cp = arg;

	list_unlink(&cp->le);
	mem_deref(cp->lcand);
	mem_deref(cp->rcand);
	mem_deref(cp->tc);

	mem_deref(cp->conn);
}


static bool sort_handler(struct le *le1, struct le *le2, void *arg)
{
	const struct ice_candpair *cp1 = le1->data, *cp2 = le2->data;
	(void)arg;

	return cp1->pprio >= cp2->pprio;
}


static void candpair_set_pprio(struct ice_candpair *cp, bool controlling)
{
	uint32_t g, d;

	if (controlling) {
		g = cp->lcand->attr.prio;
		d = cp->rcand->attr.prio;
	}
	else {
		g = cp->rcand->attr.prio;
		d = cp->lcand->attr.prio;
	}

	cp->pprio = ice_calc_pair_prio(g, d);
}


/**
 * Add candidate pair to list, sorted by pair priority (highest is first)
 */
static void list_add_sorted(struct list *list, struct ice_candpair *cp)
{
	struct le *le;

	/* find our slot */
	for (le = list_tail(list); le; le = le->prev) {
		struct ice_candpair *cp0 = le->data;

		if (cp->pprio < cp0->pprio) {
			list_insert_after(list, le, &cp->le, cp);
			return;
		}
	}

	list_prepend(list, &cp->le, cp);
}


int trice_candpair_alloc(struct ice_candpair **cpp, struct trice *icem,
			struct ice_lcand *lcand, struct ice_rcand *rcand)
{
	struct ice_candpair *cp;

	if (!icem || !lcand || !rcand)
		return EINVAL;

	if (icem->lrole == ICE_ROLE_UNKNOWN) {
		DEBUG_WARNING("trice_candpair_alloc: invalid local role!\n");
		return EINVAL;
	}

	cp = mem_zalloc(sizeof(*cp), candpair_destructor);
	if (!cp)
		return ENOMEM;

	cp->lcand = mem_ref(lcand);
	cp->rcand = mem_ref(rcand);
	cp->state = ICE_CANDPAIR_FROZEN;

	candpair_set_pprio(cp, icem->lrole == ICE_ROLE_CONTROLLING);

	list_add_sorted(&icem->checkl, cp);

	if (cpp)
		*cpp = cp;

	return 0;
}


/* Computing Pair Priority and Ordering Pairs */
void trice_candpair_prio_order(struct list *lst, bool controlling)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {
		struct ice_candpair *cp = le->data;

		candpair_set_pprio(cp, controlling);
	}

	list_sort(lst, sort_handler, NULL);
}


void trice_candpair_make_valid(struct trice *icem, struct ice_candpair *pair)
{
	if (!icem || !pair)
		return;

	if (pair->state == ICE_CANDPAIR_FAILED) {
		DEBUG_WARNING("make_valid: pair already FAILED [%H]\n",
			      trice_candpair_debug, pair);
	}

	pair->err = 0;
	pair->scode = 0;
	pair->valid = true;

	trice_candpair_set_state(pair, ICE_CANDPAIR_SUCCEEDED);

	list_unlink(&pair->le);
	list_add_sorted(&icem->validl, pair);
}


void trice_candpair_failed(struct ice_candpair *cp, int err, uint16_t scode)
{
	if (!cp)
		return;

	if (cp->state == ICE_CANDPAIR_SUCCEEDED) {
		DEBUG_WARNING("set_failed(%m): pair already SUCCEEDED [%H]\n",
			      err, trice_candpair_debug, cp);
	}

	cp->err = err;
	cp->scode = scode;
	cp->valid = false;

	cp->conn = mem_deref(cp->conn);

	trice_candpair_set_state(cp, ICE_CANDPAIR_FAILED);
}


void trice_candpair_set_state(struct ice_candpair *pair,
			     enum ice_candpair_state state)
{
	if (!pair)
		return;
	if (pair->state == state)
		return;

	if (trice_candpair_iscompleted(pair)) {
		DEBUG_WARNING("set_state(%s): pair is already completed"
			      " [%H]\n",
			      trice_candpair_state2name(state),
			      trice_candpair_debug, pair);
	}

#if 0
	trice_printf(pair->lcand->icem,
		    "%H new state \"%s\"\n",
		    trice_candpair_debug, pair,
		    trice_candpair_state2name(state));
#endif

	pair->state = state;
}


bool trice_candpair_iscompleted(const struct ice_candpair *cp)
{
	if (!cp)
		return false;

	return cp->state == ICE_CANDPAIR_FAILED ||
		cp->state == ICE_CANDPAIR_SUCCEEDED;
}


/**
 * Find the highest-priority candidate-pair in a given list, with
 * optional match parameters
 *
 * @param lst    List of candidate pairs
 * @param lcand  Local candidate (optional)
 * @param rcand  Remote candidate (optional)
 *
 * @return Matching candidate pair if found, otherwise NULL
 *
 * note: assume list is sorted by priority
 */
struct ice_candpair *trice_candpair_find(const struct list *lst,
					const struct ice_lcand *lcand,
					const struct ice_rcand *rcand)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {

		struct ice_candpair *cp = le->data;

		if (!cp->lcand || !cp->rcand) {
			DEBUG_WARNING("corrupt candpair %p\n", cp);
			continue;
		}

		if (lcand && cp->lcand != lcand)
			continue;

		if (rcand && cp->rcand != rcand)
			continue;

		return cp;
	}

	return NULL;
}


/* find the first pair with a given state */
struct ice_candpair *trice_candpair_find_state(const struct list *lst,
					      enum ice_candpair_state state)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {

		struct ice_candpair *cp = le->data;

		if (cp->state != state)
			continue;

		return cp;
	}

	return NULL;
}


bool trice_candpair_cmp_fnd(const struct ice_candpair *cp1,
			   const struct ice_candpair *cp2)
{
	if (!cp1 || !cp2)
		return false;

	return 0 == strcmp(cp1->lcand->attr.foundation,
			   cp2->lcand->attr.foundation) &&
		0 == strcmp(cp1->rcand->attr.foundation,
			    cp2->rcand->attr.foundation);
}


/*  RFC 6544 -- 6.2. Forming the Check Lists

   Local           Remote
   Candidate       Candidate
   ---------------------------
   tcp-so          tcp-so
   tcp-active      tcp-passive
   tcp-passive     tcp-active

 */
static bool tcptype_match(enum ice_tcptype loc, enum ice_tcptype rem)
{
	if (loc == ICE_TCP_SO      && rem == ICE_TCP_SO)      return true;
	if (loc == ICE_TCP_ACTIVE  && rem == ICE_TCP_PASSIVE) return true;
	if (loc == ICE_TCP_PASSIVE && rem == ICE_TCP_ACTIVE)  return true;

	return false;
}


/* Replace server reflexive candidates by its base */
static const struct sa *cand_srflx_addr(const struct ice_lcand *cand)
{
	if (ICE_CAND_TYPE_SRFLX == cand->attr.type)
		return &cand->base_addr;
	else
		return &cand->attr.addr;
}


static struct ice_candpair *find_same_base_list(const struct list *lst,
						const struct ice_lcand *lcand,
						const struct ice_rcand *rcand)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {

		struct ice_candpair *cp = le->data;

		if (cp->lcand->attr.compid == lcand->attr.compid
		    &&
		    cp->lcand->attr.proto == lcand->attr.proto
		    &&
		    sa_cmp(cand_srflx_addr(cp->lcand),
			   cand_srflx_addr(lcand), SA_ALL)
		    &&
		    sa_cmp(&cp->rcand->attr.addr,
			   &rcand->attr.addr, SA_ALL)) {

			return cp;
		}
	}

	return NULL;
}


/* look in both check-list and valid-list */
static struct ice_candpair *find_same_base(struct trice *icem,
					   const struct ice_lcand *lcand,
					   const struct ice_rcand *rcand)
{
	struct ice_candpair *cp;

	cp = find_same_base_list(&icem->checkl, lcand, rcand);
	if (cp)
		return cp;

	cp = find_same_base_list(&icem->validl, lcand, rcand);
	if (cp)
		return cp;

	return NULL;
}


/* Pair a local candidate with a remote candidate */
static int create_pair(struct trice *icem, struct ice_lcand *lcand,
		       struct ice_rcand *rcand)
{
	struct ice_candpair *cpx;

	if (lcand->attr.compid != rcand->attr.compid ||
	    lcand->attr.proto != rcand->attr.proto ||
	    sa_af(&lcand->attr.addr) != sa_af(&rcand->attr.addr)) {
		return 0;
	}

	/*
	 * IPv6 link-local: only pair with IPv6 link-local addresses
	 * see: RFC5245bis, section 6.1.2.2
	 */
	if (sa_af(&lcand->attr.addr) == AF_INET6 &&
	    sa_is_linklocal(&lcand->attr.addr) !=
	    sa_is_linklocal(&rcand->attr.addr)) {
		return 0;
	}

	/* loopback pairing optimization: only pair with loopback addresses */
	if (icem->conf.optimize_loopback_pairing &&
	    sa_is_loopback(&lcand->attr.addr) !=
	    sa_is_loopback(&rcand->attr.addr)) {
		return 0;
	}

	cpx = find_same_base(icem, lcand, rcand);
	if (cpx) {
		trice_printf(icem,
				"with: pair with same"
				" base already exist"
				" (%H)\n",
				trice_candpair_debug, cpx);

		return 0;
	}

	if (lcand->attr.proto == IPPROTO_TCP) {
		if (!tcptype_match(lcand->attr.tcptype,
				   rcand->attr.tcptype))
			return 0;
	}

	/* add sorted */
	return trice_candpair_alloc(NULL, icem, lcand, rcand);
}


/* Pair a candidate with all other candidates of the opposite kind */
int trice_candpair_with_local(struct trice *icem, struct ice_lcand *lcand)
{
	struct list *lst = &icem->rcandl;
	struct le *le;
	int err = 0;

	if (icem->lrole == ICE_ROLE_UNKNOWN) {
		DEBUG_WARNING("trice_candpair_with_local: invalid local role!"
					  "\n");
		return EINVAL;
	}

	for (le = list_head(lst); le; le = le->next) {

		struct ice_rcand *rcand = le->data;

		err = create_pair(icem, lcand, rcand);
		if (err)
			goto out;
	}

 out:
	return err;
}


/* Pair a candidate with all other candidates of the opposite kind */
int trice_candpair_with_remote(struct trice *icem, struct ice_rcand *rcand)
{
	struct list *lst = &icem->lcandl;
	struct le *le;
	int err = 0;

	if (icem->lrole == ICE_ROLE_UNKNOWN) {
		DEBUG_WARNING("trice_candpair_with_remote: invalid local role!"
					  "\n");
		return EINVAL;
	}

	for (le = list_head(lst); le; le = le->next) {

		struct ice_lcand *lcand = le->data;

		err = create_pair(icem, lcand, rcand);
		if (err)
			goto out;
	}

 out:
	return err;
}


int trice_candpair_debug(struct re_printf *pf, const struct ice_candpair *cp)
{
	int err;

	if (!cp)
		return 0;

	err = re_hprintf(pf, "{comp=%u} %10s {%c%c%c%c} %28H <---> %28H",
			 cp->lcand->attr.compid,
			 trice_candpair_state2name(cp->state),
			 cp->valid ? 'V' : ' ',
			 cp->nominated ? 'N' : ' ',
			 cp->estab ? 'E' : ' ',
			 cp->trigged ? 'T' : ' ',
			 trice_cand_print, cp->lcand,
			 trice_cand_print, cp->rcand);

	if (cp->err)
		err |= re_hprintf(pf, " (%m)", cp->err);

	if (cp->scode)
		err |= re_hprintf(pf, " [%u]", cp->scode);

	return err;
}


int trice_candpairs_debug(struct re_printf *pf, bool ansi_output,
			  const struct list *list)
{
	struct le *le;
	int err;

	if (!list)
		return 0;

	err = re_hprintf(pf, " (%u)\n", list_count(list));

	for (le = list->head; le && !err; le = le->next) {

		const struct ice_candpair *cp = le->data;
		bool ansi = false;

		if (ansi_output) {
			if (cp->state == ICE_CANDPAIR_SUCCEEDED) {
				err |= re_hprintf(pf, "\x1b[32m");
				ansi = true;
			}
			else if (cp->err || cp->scode) {
				err |= re_hprintf(pf, "\x1b[31m");
				ansi = true;
			}
		}

		err |= re_hprintf(pf, "    %H\n",
				 trice_candpair_debug, cp);

		if (ansi)
			err |= re_hprintf(pf, "\x1b[;m");
	}

	return err;
}


const char *trice_candpair_state2name(enum ice_candpair_state st)
{
	switch (st) {

	case ICE_CANDPAIR_FROZEN:     return "Frozen";
	case ICE_CANDPAIR_WAITING:    return "Waiting";
	case ICE_CANDPAIR_INPROGRESS: return "InProgress";
	case ICE_CANDPAIR_SUCCEEDED:  return "Succeeded";
	case ICE_CANDPAIR_FAILED:     return "Failed";
	default:                      return "???";
	}
}
