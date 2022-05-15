/**
 * @file chklist.c  ICE Checklist
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
#include <re_stun.h>
#include <re_ice.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "checklist"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void destructor(void *arg)
{
	struct ice_checklist *ic = arg;

	tmr_cancel(&ic->tmr_pace);
	list_flush(&ic->conncheckl);  /* flush before stun deref */
	mem_deref(ic->stun);
}


static void pace_timeout(void *arg)
{
	struct ice_checklist *ic = arg;
	struct trice *icem = (struct trice *)ic->icem;

	tmr_start(&ic->tmr_pace, ic->interval,
		  pace_timeout, ic);

	trice_conncheck_schedule_check(icem);

	trice_checklist_update(icem);
}


int trice_checklist_start(struct trice *icem, struct stun *stun,
			  uint32_t interval,
			  trice_estab_h *estabh, trice_failed_h *failh,
			  void *arg)
{
	struct ice_checklist *ic;
	int err = 0;

	if (!icem)
		return EINVAL;

	if (icem->lrole == ICE_ROLE_UNKNOWN) {
		DEBUG_WARNING("trice_checklist_start: missing local role!\n");
		return EINVAL;
	}

	if (icem->checklist) {
		ic = icem->checklist;

		if (!tmr_isrunning(&ic->tmr_pace)) {
			tmr_start(&ic->tmr_pace, 1, pace_timeout, ic);
		}
		return 0;
	}

	/* The password is equal to the password provided by the peer */
	if (!str_isset(icem->rpwd)) {
		DEBUG_WARNING("start: remote password not set\n");
		return EINVAL;
	}

	ic = mem_zalloc(sizeof(*ic), destructor);
	if (!ic)
		return ENOMEM;

	if (stun) {
		ic->stun = mem_ref(stun);
	}
	else {
		err = stun_alloc(&ic->stun, NULL, NULL, NULL);
		if (err)
			goto out;

		/* Update STUN Transport */
		stun_conf(ic->stun)->rto = 100;
		stun_conf(ic->stun)->rc = 4;

	}

	tmr_init(&ic->tmr_pace);

	ic->interval = interval;
	ic->icem = icem;
	ic->estabh = estabh;
	ic->failh  = failh;
	ic->arg    = arg;

	ic->is_running = true;
	tmr_start(&ic->tmr_pace, 0, pace_timeout, ic);

	icem->checklist = ic;

 out:
	if (err)
		mem_deref(ic);

	return err;
}


void trice_checklist_stop(struct trice *icem)
{
	struct ice_checklist *ic;

	if (!icem || !icem->checklist)
		return;

	ic = icem->checklist;

	ic->is_running = false;
	tmr_cancel(&ic->tmr_pace);
}


/* If all of the pairs in the check list are now either in the Failed or
   Succeeded state:
 */
bool trice_checklist_iscompleted(const struct trice *icem)
{
	struct le *le;

	if (!icem)
		return false;

	for (le = icem->checkl.head; le; le = le->next) {

		const struct ice_candpair *cp = le->data;

		if (!trice_candpair_iscompleted(cp))
			return false;
	}

	return true;
}


/*
 * Scheduling Checks
 */
void trice_conncheck_schedule_check(struct trice *icem)
{
	struct ice_candpair *pair;
	bool use_cand;
	int err = 0;

	if (!icem)
		return;

	use_cand = false;

	/* Find the highest priority pair in that check list that is in the
	   Waiting state. */
	pair = trice_candpair_find_state(&icem->checkl, ICE_CANDPAIR_WAITING);
	if (pair) {
		err = trice_conncheck_send(icem, pair,
					  use_cand);
		if (err)
			trice_candpair_failed(pair, err, 0);
		return;
	}

	/* If there is no such pair: */

	/* Find the highest priority pair in that check list that is in
	   the Frozen state. */
	pair = trice_candpair_find_state(&icem->checkl, ICE_CANDPAIR_FROZEN);
	if (pair) { /* If there is such a pair: */

		/* Unfreeze the pair.
		   Perform a check for that pair, causing its state to
		   transition to In-Progress. */
		err = trice_conncheck_send(icem, pair,
					  use_cand);
		if (err)
			trice_candpair_failed(pair, err, 0);
		return;
	}

	/* If there is no such pair: */

	/* Terminate the timer for that check list. */
}


/*
 * Computing States
 */
void trice_checklist_set_waiting(struct trice *icem)
{
	struct le *le, *le2;

	if (!icem)
		return;

	if (icem->lrole == ICE_ROLE_UNKNOWN) {
		DEBUG_WARNING("trice_checklist_set_waiting: invalid local"
					  "role!\n");
		return;
	}

	/*
	For all pairs with the same foundation, it sets the state of
	the pair with the lowest component ID to Waiting.  If there is
	more than one such pair, the one with the highest priority is
	used.
	*/

	for (le = icem->checkl.head; le; le = le->next) {

		struct ice_candpair *cp = le->data;

		for (le2 = icem->checkl.head; le2; le2 = le2->next) {

			struct ice_candpair *cp2 = le2->data;

			if (!trice_candpair_cmp_fnd(cp, cp2))
				continue;

			if (cp2->lcand->attr.compid < cp->lcand->attr.compid &&
			    cp2->pprio > cp->pprio)
				cp = cp2;
		}

		if (cp->state == ICE_CANDPAIR_FROZEN)
			trice_candpair_set_state(cp, ICE_CANDPAIR_WAITING);
	}
}


int trice_checklist_update(struct trice *icem)
{
	struct ice_checklist *ic;

	if (!icem)
		return EINVAL;

	ic = icem->checklist;
	if (!ic)
		return ENOSYS;

	if (trice_checklist_iscompleted(icem)) {
		tmr_cancel(&ic->tmr_pace);

		trice_printf(icem, "ICE checklist is complete"
			     " (checkl=%u, valid=%u)\n",
			     list_count(&icem->checkl),
			     list_count(&icem->validl));
	}

	return 0;
}


void trice_checklist_refresh(struct trice *icem)
{
	struct ice_checklist *ic;

	if (!icem || !icem->checklist)
		return;

	ic = icem->checklist;

	tmr_start(&ic->tmr_pace, ic->interval, pace_timeout, ic);
}


bool trice_checklist_isrunning(const struct trice *icem)
{
	struct ice_checklist *ic;

	if (!icem || !icem->checklist)
		return false;

	ic = icem->checklist;

	return ic->is_running;
}


int trice_checklist_debug(struct re_printf *pf, const struct ice_checklist *ic)
{
	struct le *le;
	int err = 0;

	if (!ic)
		return 0;

	err |= re_hprintf(pf, " Checklist: %s, interval=%ums\n",
		  tmr_isrunning(&ic->tmr_pace) ? "Running" : "Not-Running",
			  ic->interval);
	err |= re_hprintf(pf, " Pending connchecks: %u\n",
			  list_count(&ic->conncheckl));
	for (le = ic->conncheckl.head; le; le = le->next) {
		struct ice_conncheck *cc = le->data;

		err |= re_hprintf(pf, " ...%H\n", trice_conncheck_debug, cc);
	}

	err |= stun_debug(pf, ic->stun);

	return err;
}
