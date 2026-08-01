/**
 * @file sdp/session.c  SDP Session
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_sdp.h>
#include <re_sys.h>
#include "sdp.h"


enum media_list {
	MEDIA_LIST_LOCAL,
	MEDIA_LIST_NEGOTIATED,
};


struct sdp_format_state {
	struct le le;
	struct sdp_format *fmt;
	char *id;
	char *params;
	char *rparams;
	char *name;
	void *data;
	sdp_fmtp_enc_h *ench;
	sdp_fmtp_cmp_h *cmph;
	int pt;
	uint32_t srate;
	uint8_t ch;
	bool ref;
	bool sup;
};


struct sdp_media_state {
	struct le le;
	struct sdp_media *media;
	struct list lattrl;
	struct list rattrl;
	struct list lfmtl;
	struct list rfmtl;
	struct sa laddr;
	struct sa raddr;
	struct sa laddr_rtcp;
	struct sa raddr_rtcp;
	int32_t lbwv[SDP_BANDWIDTH_MAX];
	int32_t rbwv[SDP_BANDWIDTH_MAX];
	char *name;
	char *proto;
	char *protov[RE_ARRAY_SIZE(((struct sdp_media *)0)->protov)];
	char *uproto;
	sdp_media_enc_h *ench;
	void *arg;
	enum sdp_dir ldir;
	enum sdp_dir rdir;
	enum media_list media_list;
	int dynpt;
	bool fmt_ignore;
	bool disabled;
};


struct sdp_session_state {
	struct sdp_session *sess;
	struct list lattrl;
	struct list rattrl;
	struct list medial;
	struct sa laddr;
	struct sa raddr;
	int32_t lbwv[SDP_BANDWIDTH_MAX];
	int32_t rbwv[SDP_BANDWIDTH_MAX];
	uint32_t id;
	uint32_t ver;
	enum sdp_dir rdir;
};


static void format_state_destructor(void *arg)
{
	struct sdp_format_state *state = arg;

	list_unlink(&state->le);
	mem_deref(state->fmt);
	mem_deref(state->id);
	mem_deref(state->params);
	mem_deref(state->rparams);
	mem_deref(state->name);
	if (state->ref)
		mem_deref(state->data);
}


static void media_state_destructor(void *arg)
{
	struct sdp_media_state *state = arg;

	list_unlink(&state->le);
	list_flush(&state->lattrl);
	list_flush(&state->rattrl);
	list_flush(&state->lfmtl);
	list_flush(&state->rfmtl);
	mem_deref(state->media);
	mem_deref(state->name);
	mem_deref(state->proto);
	for (size_t i = 0; i < RE_ARRAY_SIZE(state->protov); ++i)
		mem_deref(state->protov[i]);
	mem_deref(state->uproto);
}


static void session_state_destructor(void *arg)
{
	struct sdp_session_state *state = arg;

	list_flush(&state->lattrl);
	list_flush(&state->rattrl);
	list_flush(&state->medial);
	mem_deref(state->sess);
}


static int format_state_save(struct list *states, struct sdp_format *fmt)
{
	struct sdp_format_state *state;

	state = mem_zalloc(sizeof(*state), format_state_destructor);
	if (!state)
		return ENOMEM;

	state->fmt = mem_ref(fmt);
	state->id = mem_ref(fmt->id);
	state->params = mem_ref(fmt->params);
	state->rparams = mem_ref(fmt->rparams);
	state->name = mem_ref(fmt->name);
	state->ench = fmt->ench;
	state->cmph = fmt->cmph;
	state->data = fmt->ref ? mem_ref(fmt->data) : fmt->data;
	state->ref = fmt->ref;
	state->sup = fmt->sup;
	state->pt = fmt->pt;
	state->srate = fmt->srate;
	state->ch = fmt->ch;
	list_append(states, &state->le, state);
	return 0;
}


static int format_list_save(struct list *states, const struct list *formats)
{
	struct le *le;
	int err;

	for (le = list_head(formats); le; le = le->next) {
		err = format_state_save(states, le->data);
		if (err)
			return err;
	}
	return 0;
}


static int media_state_save(struct sdp_session_state *session_state,
			    struct sdp_media *media,
			    enum media_list media_list)
{
	struct sdp_media_state *state;
	int err;

	state = mem_zalloc(sizeof(*state), media_state_destructor);
	if (!state)
		return ENOMEM;

	state->media = mem_ref(media);
	state->name = mem_ref(media->name);
	state->proto = mem_ref(media->proto);
	for (size_t i = 0; i < RE_ARRAY_SIZE(state->protov); ++i)
		state->protov[i] = mem_ref(media->protov[i]);
	state->uproto = mem_ref(media->uproto);
	state->laddr = media->laddr;
	state->raddr = media->raddr;
	state->laddr_rtcp = media->laddr_rtcp;
	state->raddr_rtcp = media->raddr_rtcp;
	memcpy(state->lbwv, media->lbwv, sizeof(state->lbwv));
	memcpy(state->rbwv, media->rbwv, sizeof(state->rbwv));
	state->ench = media->ench;
	state->arg = media->arg;
	state->ldir = media->ldir;
	state->rdir = media->rdir;
	state->media_list = media_list;
	state->dynpt = media->dynpt;
	state->fmt_ignore = media->fmt_ignore;
	state->disabled = media->disabled;

	err = sdp_attr_clone(&state->lattrl, &media->lattrl);
	if (!err)
		err = sdp_attr_clone(&state->rattrl, &media->rattrl);
	if (!err)
		err = format_list_save(&state->lfmtl, &media->lfmtl);
	if (!err)
		err = format_list_save(&state->rfmtl, &media->rfmtl);
	if (err) {
		mem_deref(state);
		return err;
	}

	list_append(&session_state->medial, &state->le, state);
	return 0;
}


static int media_list_save(struct sdp_session_state *state,
			   const struct list *medial,
			   enum media_list media_list)
{
	struct le *le;
	int err;

	for (le = list_head(medial); le; le = le->next) {
		err = media_state_save(state, le->data, media_list);
		if (err)
			return err;
	}
	return 0;
}


/**
 * Save the complete mutable state of an SDP session.
 *
 * The returned state retains the original media and format objects so a
 * rollback preserves their pointer identity.  Dereference the state to
 * commit changes, or pass it to sdp_session_state_restore() for an
 * allocation-free rollback.
 *
 * @param statep Pointer to allocated session state
 * @param sess   SDP session to save
 *
 * @return 0 if successful, otherwise errorcode
 */
int sdp_session_state_save(struct sdp_session_state **statep,
			   struct sdp_session *sess)
{
	struct sdp_session_state *state;
	int err;

	if (!statep || !sess)
		return EINVAL;

	state = mem_zalloc(sizeof(*state), session_state_destructor);
	if (!state)
		return ENOMEM;

	state->sess = mem_ref(sess);
	state->laddr = sess->laddr;
	state->raddr = sess->raddr;
	memcpy(state->lbwv, sess->lbwv, sizeof(state->lbwv));
	memcpy(state->rbwv, sess->rbwv, sizeof(state->rbwv));
	state->id = sess->id;
	state->ver = sess->ver;
	state->rdir = sess->rdir;

	err = sdp_attr_clone(&state->lattrl, &sess->lattrl);
	if (!err)
		err = sdp_attr_clone(&state->rattrl, &sess->rattrl);
	if (!err)
		err = media_list_save(state, &sess->lmedial,
				      MEDIA_LIST_LOCAL);
	if (!err)
		err = media_list_save(state, &sess->medial,
				      MEDIA_LIST_NEGOTIATED);
	if (err) {
		mem_deref(state);
		return err;
	}

	*statep = state;
	return 0;
}


static void format_state_restore(struct list *formats,
				 struct sdp_format_state *state)
{
	struct sdp_format *fmt = state->fmt;

	fmt->id = mem_deref(fmt->id);
	fmt->params = mem_deref(fmt->params);
	fmt->rparams = mem_deref(fmt->rparams);
	fmt->name = mem_deref(fmt->name);
	if (fmt->ref)
		fmt->data = mem_deref(fmt->data);

	fmt->id = state->id;
	state->id = NULL;
	fmt->params = state->params;
	state->params = NULL;
	fmt->rparams = state->rparams;
	state->rparams = NULL;
	fmt->name = state->name;
	state->name = NULL;
	fmt->ench = state->ench;
	fmt->cmph = state->cmph;
	fmt->data = state->data;
	state->data = NULL;
	fmt->ref = state->ref;
	state->ref = false;
	fmt->sup = state->sup;
	fmt->pt = state->pt;
	fmt->srate = state->srate;
	fmt->ch = state->ch;

	list_append(formats, &fmt->le, fmt);
	state->fmt = NULL;
}


static void format_list_restore(struct list *formats, struct list *states)
{
	list_flush(formats);
	while (states->head) {
		struct sdp_format_state *state = states->head->data;

		format_state_restore(formats, state);
		mem_deref(state);
	}
}


static void media_state_restore(struct sdp_session *sess,
				struct sdp_media_state *state)
{
	struct sdp_media *media = state->media;
	struct list *medial = state->media_list == MEDIA_LIST_LOCAL
				    ? &sess->lmedial : &sess->medial;

	format_list_restore(&media->lfmtl, &state->lfmtl);
	format_list_restore(&media->rfmtl, &state->rfmtl);
	list_flush(&media->lattrl);
	list_flush(&media->rattrl);
	while (state->lattrl.head)
		list_move(state->lattrl.head, &media->lattrl);
	while (state->rattrl.head)
		list_move(state->rattrl.head, &media->rattrl);

	media->name = mem_deref(media->name);
	media->proto = mem_deref(media->proto);
	for (size_t i = 0; i < RE_ARRAY_SIZE(media->protov); ++i)
		media->protov[i] = mem_deref(media->protov[i]);
	media->uproto = mem_deref(media->uproto);

	media->name = state->name;
	state->name = NULL;
	media->proto = state->proto;
	state->proto = NULL;
	for (size_t i = 0; i < RE_ARRAY_SIZE(media->protov); ++i) {
		media->protov[i] = state->protov[i];
		state->protov[i] = NULL;
	}
	media->uproto = state->uproto;
	state->uproto = NULL;
	media->laddr = state->laddr;
	media->raddr = state->raddr;
	media->laddr_rtcp = state->laddr_rtcp;
	media->raddr_rtcp = state->raddr_rtcp;
	memcpy(media->lbwv, state->lbwv, sizeof(media->lbwv));
	memcpy(media->rbwv, state->rbwv, sizeof(media->rbwv));
	media->ench = state->ench;
	media->arg = state->arg;
	media->ldir = state->ldir;
	media->rdir = state->rdir;
	media->dynpt = state->dynpt;
	media->fmt_ignore = state->fmt_ignore;
	media->disabled = state->disabled;

	list_append(medial, &media->le, media);
	state->media = NULL;
}


/**
 * Restore a saved SDP session state without allocating.
 *
 * The state is consumed. Passing NULL is safe.
 *
 * @param state Session state to restore
 */
void sdp_session_state_restore(struct sdp_session_state *state)
{
	struct sdp_session *sess;

	if (!state)
		return;

	sess = state->sess;
	list_flush(&sess->lmedial);
	list_flush(&sess->medial);
	list_flush(&sess->lattrl);
	list_flush(&sess->rattrl);
	while (state->lattrl.head)
		list_move(state->lattrl.head, &sess->lattrl);
	while (state->rattrl.head)
		list_move(state->rattrl.head, &sess->rattrl);

	sess->laddr = state->laddr;
	sess->raddr = state->raddr;
	memcpy(sess->lbwv, state->lbwv, sizeof(sess->lbwv));
	memcpy(sess->rbwv, state->rbwv, sizeof(sess->rbwv));
	sess->id = state->id;
	sess->ver = state->ver;
	sess->rdir = state->rdir;

	while (state->medial.head) {
		struct sdp_media_state *media_state =
			state->medial.head->data;

		media_state_restore(sess, media_state);
		mem_deref(media_state);
	}

	mem_deref(state);
}


static void destructor(void *arg)
{
	struct sdp_session *sess = arg;

	list_flush(&sess->lmedial);
	list_flush(&sess->medial);
	list_flush(&sess->rattrl);
	list_flush(&sess->lattrl);
}


/**
 * Allocate a new SDP Session
 *
 * @param sessp Pointer to allocated SDP Session object
 * @param laddr Local network address
 *
 * @return 0 if success, otherwise errorcode
 */
int sdp_session_alloc(struct sdp_session **sessp, const struct sa *laddr)
{
	struct sdp_session *sess;
	int i;

	if (!sessp || !laddr)
		return EINVAL;

	sess = mem_zalloc(sizeof(*sess), destructor);
	if (!sess)
		return ENOMEM;

	sess->laddr = *laddr;
	sess->id    = rand_u32();
	sess->ver   = rand_u32() & 0x7fffffff;
	sess->rdir  = SDP_SENDRECV;

	sa_init(&sess->raddr, AF_INET);

	for (i=0; i<SDP_BANDWIDTH_MAX; i++) {
		sess->lbwv[i] = -1;
		sess->rbwv[i] = -1;
	}

	*sessp = sess;

	return 0;
}


/**
 * Reset the remote side of an SDP Session
 *
 * @param sess SDP Session
 */
void sdp_session_rreset(struct sdp_session *sess)
{
	int i;

	if (!sess)
		return;

	sa_init(&sess->raddr, AF_INET);

	list_flush(&sess->rattrl);

	sess->rdir = SDP_SENDRECV;

	for (i=0; i<SDP_BANDWIDTH_MAX; i++)
		sess->rbwv[i] = -1;
}


/**
 * Set the local network address of an SDP Session
 *
 * @param sess  SDP Session
 * @param laddr Local network address
 */
void sdp_session_set_laddr(struct sdp_session *sess, const struct sa *laddr)
{
	if (!sess || !laddr)
		return;

	sess->laddr = *laddr;
}


/**
 * Get the local network address of an SDP Session
 *
 * @param sess  SDP Session
 * @return Local network address
 */
const struct sa *sdp_session_laddr(struct sdp_session *sess)
{
	return sess ? &sess->laddr : NULL;
}


/**
 * Set the local bandwidth of an SDP Session
 *
 * @param sess SDP Session
 * @param type Bandwidth type
 * @param bw   Bandwidth value
 */
void sdp_session_set_lbandwidth(struct sdp_session *sess,
				enum sdp_bandwidth type, int32_t bw)
{
	if (!sess || type < SDP_BANDWIDTH_MIN || type >= SDP_BANDWIDTH_MAX)
		return;

	sess->lbwv[type] = bw;
}


/**
 * Set a local attribute of an SDP Session
 *
 * @param sess    SDP Session
 * @param replace True to replace any existing attributes, false to append
 * @param name    Attribute name
 * @param value   Formatted attribute value
 *
 * @return 0 if success, otherwise errorcode
 */
int sdp_session_set_lattr(struct sdp_session *sess, bool replace,
			  const char *name, const char *value, ...)
{
	va_list ap;
	int err;

	if (!sess || !name)
		return EINVAL;

	if (replace)
		sdp_attr_del(&sess->lattrl, name);

	va_start(ap, value);
	err = sdp_attr_addv(&sess->lattrl, name, value, ap);
	va_end(ap);

	return err;
}


/**
 * Delete a local attribute of an SDP Session
 *
 * @param sess SDP Session
 * @param name Attribute name
 */
void sdp_session_del_lattr(struct sdp_session *sess, const char *name)
{
	if (!sess || !name)
		return;

	sdp_attr_del(&sess->lattrl, name);
}


/**
 * Get the local bandwidth of an SDP Session
 *
 * @param sess SDP Session
 * @param type Bandwidth type
 *
 * @return Bandwidth value
 */
int32_t sdp_session_lbandwidth(const struct sdp_session *sess,
			       enum sdp_bandwidth type)
{
	if (!sess || type < SDP_BANDWIDTH_MIN || type >= SDP_BANDWIDTH_MAX)
		return 0;

	return sess->lbwv[type];
}


/**
 * Get the remote bandwidth of an SDP Session
 *
 * @param sess SDP Session
 * @param type Bandwidth type
 *
 * @return Bandwidth value
 */
int32_t sdp_session_rbandwidth(const struct sdp_session *sess,
				enum sdp_bandwidth type)
{
	if (!sess || type < SDP_BANDWIDTH_MIN || type >= SDP_BANDWIDTH_MAX)
		return 0;

	return sess->rbwv[type];
}


/**
 * Get a remote attribute of an SDP Session
 *
 * @param sess SDP Session
 * @param name Attribute name
 *
 * @return Attribute value if exist, NULL if not exist
 */
const char *sdp_session_rattr(const struct sdp_session *sess, const char *name)
{
	if (!sess || !name)
		return NULL;

	return sdp_attr_apply(&sess->rattrl, name, NULL, NULL);
}


/**
 * Apply a function handler to all matching local attributes
 *
 * @param sess  SDP Session
 * @param name  Attribute name
 * @param attrh Attribute handler
 * @param arg   Handler argument
 *
 * @return Attribute value if match
 */
const char *sdp_session_lattr_apply(const struct sdp_session *sess,
				    const char *name,
				    sdp_attr_h *attrh, void *arg)
{
	if (!sess)
		return NULL;

	return sdp_attr_apply(&sess->lattrl, name, attrh, arg);
}


/**
 * Apply a function handler of all matching remote attributes
 *
 * @param sess  SDP Session
 * @param name  Attribute name
 * @param attrh Attribute handler
 * @param arg   Handler argument
 *
 * @return Attribute value if match
 */
const char *sdp_session_rattr_apply(const struct sdp_session *sess,
				    const char *name,
				    sdp_attr_h *attrh, void *arg)
{
	if (!sess)
		return NULL;

	return sdp_attr_apply(&sess->rattrl, name, attrh, arg);
}


/**
 * Get the list of media-lines from an SDP Session
 *
 * @param sess  SDP Session
 * @param local True for local, False for remote
 *
 * @return List of media-lines
 */
const struct list *sdp_session_medial(const struct sdp_session *sess,
				      bool local)
{
	if (!sess)
		return NULL;

	return local ? &sess->lmedial : &sess->medial;
}


/**
 * Print SDP Session debug information
 *
 * @param pf   Print function for output
 * @param sess SDP Session
 *
 * @return 0 if success, otherwise errorcode
 */
int sdp_session_debug(struct re_printf *pf, const struct sdp_session *sess)
{
	struct le *le;
	int err;

	if (!sess)
		return 0;

	err = re_hprintf(pf, "SDP session\n");

	err |= re_hprintf(pf, "  local attributes:\n");

	for (le=sess->lattrl.head; le; le=le->next)
		err |= re_hprintf(pf, "    %H\n", sdp_attr_debug, le->data);

	err |= re_hprintf(pf, "  remote attributes:\n");
	err |= re_hprintf(pf, "  remote direction: %s\n",
			sdp_dir_name(sess->rdir));

	for (le=sess->rattrl.head; le; le=le->next)
		err |= re_hprintf(pf, "    %H\n", sdp_attr_debug, le->data);

	err |= re_hprintf(pf, "session media:\n");

	for (le=sess->medial.head; le; le=le->next)
		err |= sdp_media_debug(pf, le->data);

	err |= re_hprintf(pf, "local media:\n");

	for (le=sess->lmedial.head; le; le=le->next)
		err |= sdp_media_debug(pf, le->data);

	return err;
}
