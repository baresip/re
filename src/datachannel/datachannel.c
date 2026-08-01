/**
 * @file datachannel.c WebRTC data-channel transport
 *
 * Copyright (C) 2026 The baresip project
 */

#if !defined(WIN32) && !defined(_WIN32)
#include <arpa/inet.h>
#endif
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <re.h>
#include <re_datachannel.h>
#include <usrsctp.h>
#include "datachannel.h"

enum {
	/* RFC 8261 section 5 recommends at most 1200 when DF control is not
	 * available.  AF_CONN emits SCTP into caller-owned DTLS, so usrsctp
	 * cannot perform network-layer PMTU discovery itself. */
	SCTP_SAFE_PATH_MTU = 1200
};

static unsigned transport_count;
static bool stack_initialized;
static struct tmr stack_timer;
static struct list retired_addresses;
static struct list transports;
static uint64_t last_tick;
static once_flag stack_once = ONCE_FLAG_INIT;
static mtx_t stack_mtx;
static int stack_mtx_err;
static thrd_t stack_owner;
static bool stack_owner_set;
static unsigned stack_call_depth;
static bool stack_finish_pending;
static bool stack_finishing;

int dc_request_stream_reset(struct dc_transport *dt, uint16_t id,
			    uint16_t flags);
static int drain_stream_resets(struct dc_transport *dt);
static int drain_output(struct dc_transport *dt);
static void reset_destructor(void *arg);
static void reusable_destructor(void *arg);
static void close_retired_addresses(void);
static int drain_channel(struct dc_channel *dc);
static void clear_send_queue(struct dc_channel *dc);
static void clear_inbound_queue(struct dc_channel *dc);
static int enqueue_record(struct dc_channel *dc, uint32_t ppid,
			  const uint8_t *buf, size_t len);
static int drain_transport(struct dc_transport *dt);
static int drain_inbound(struct dc_channel *dc);
static int assign_pending(struct dc_transport *dt, bool terminal);
static void consume_packet_errors(void);
static void drain_pending_resets(void);
static void clear_partial(struct dc_transport *dt, uint16_t id);
static int deliver_message(struct dc_transport *dt, uint16_t id,
			   uint32_t ppid, const uint8_t *buf, size_t len);
static int channel_alloc(struct dc_channel **dcp, struct dc_transport *dt,
			 const char *label,
			 const struct dc_channel_config *config, bool remote);
static struct dc_reusable_id *reset_state(struct dc_transport *dt,
					   uint16_t id, bool create);
static int claim_stream_id(struct dc_transport *dt, uint16_t id,
			   struct dc_reusable_id **reservationp);
static void update_reusable_ids(struct dc_transport *dt);
static int close_protocol_channel(struct dc_transport *dt, uint16_t id,
				  int err);
static bool stack_finish(void);


static void stack_lock_init(void)
{
	stack_mtx_err = mtx_init(&stack_mtx, mtx_plain) == thrd_success
			      ? 0 : EIO;
}


static bool stack_is_owner(void)
{
	bool owner;

	call_once(&stack_once, stack_lock_init);
	if (stack_mtx_err)
		return false;
	mtx_lock(&stack_mtx);
	owner = stack_owner_set &&
		thrd_equal(stack_owner, thrd_current());
	mtx_unlock(&stack_mtx);
	return owner;
}


static void stack_call_enter(void)
{
	++stack_call_depth;
}


static void stack_call_leave(void)
{
	if (!stack_call_depth)
		return;
	--stack_call_depth;
	if (!stack_call_depth && stack_finish_pending && !stack_finishing &&
	    !transport_count) {
		stack_finish_pending = false;
		close_retired_addresses();
		(void)stack_finish();
	}
}


struct dc_address {
	struct le le;
	struct dc_transport *transport;
	struct socket *socket;
	bool registered;
	bool close_started;
	bool reap;
};


static void close_retired_addresses(void)
{
	for (struct le *le = retired_addresses.head; le;) {
		struct dc_address *address = le->data;
		struct le *next = le->next;

		if (address->reap) {
			list_unlink(&address->le);
			free(address);
			le = next;
			continue;
		}
		if (address->socket && !address->close_started) {
			const struct linger linger = {
				.l_onoff = 1,
				.l_linger = 0,
			};

			(void)usrsctp_setsockopt(address->socket, SOL_SOCKET,
						 SO_LINGER, &linger,
						 sizeof(linger));
			address->close_started = true;
			usrsctp_close(address->socket);
		}
		le = next;
	}
}

static void free_retired_addresses(void)
{
	while (retired_addresses.head) {
		struct dc_address *address = retired_addresses.head->data;

		list_unlink(&address->le);
		free(address);
	}
}

static bool stack_finish(void)
{
	unsigned i;

	if (transport_count)
		return false;
	if (stack_call_depth || stack_finishing) {
		stack_finish_pending = true;
		return false;
	}
	stack_finishing = true;

	for (i = 0; i < 1000; ++i) {
		if (!usrsctp_finish()) {
			stack_initialized = false;
			stack_finish_pending = false;
			stack_finishing = false;
			tmr_cancel(&stack_timer);
			free_retired_addresses();
			mtx_lock(&stack_mtx);
			stack_owner_set = false;
			mtx_unlock(&stack_mtx);
			return true;
		}
		usrsctp_handle_timers(10);
	}

	stack_finishing = false;
	stack_finish_pending = true;
	return false;
}


static void timer_handler(void *arg)
{
	uint64_t now = tmr_jiffies();
	uint64_t elapsed = now - last_tick;

	last_tick = now;
	close_retired_addresses();
	stack_call_enter();
	usrsctp_handle_timers((uint32_t)MIN(elapsed, (uint64_t)UINT32_MAX));
	stack_call_leave();
	drain_pending_resets();
	consume_packet_errors();
	if (!transport_count)
		(void)stack_finish();
	if (transport_count || stack_initialized)
		tmr_start(&stack_timer, 10, timer_handler, NULL);
	(void)arg;
}


static int packet_output(void *addr, void *buf, size_t len,
			 uint8_t tos, uint8_t set_df)
{
	struct dc_address *address = addr;
	struct dc_transport *dt = address ? address->transport : NULL;
	struct dc_outbound *packet;

	if (!dt || dt->closing)
		return ECANCELED;

	packet = mem_zalloc(sizeof(*packet), NULL);
	if (!packet) {
		if (!dt->packet_error)
			dt->packet_error = ENOMEM;
		return ENOMEM;
	}
	packet->mb = mbuf_alloc(len);
	if (!packet->mb) {
		mem_deref(packet);
		if (!dt->packet_error)
			dt->packet_error = ENOMEM;
		return ENOMEM;
	}
	{
		int err = mbuf_write_mem(packet->mb, buf, len);

		if (err) {
			mem_deref(packet->mb);
			mem_deref(packet);
			if (!dt->packet_error)
				dt->packet_error = err;
			return err;
		}
	}
	packet->mb->pos = 0;
	list_append(&dt->outbound_packets, &packet->le, packet);

	(void)tos;
	(void)set_df;
	return 0;
}


static int drain_output(struct dc_transport *dt)
{
	int result = 0;

	if (dt->draining_output)
		return 0;

	mem_ref(dt);
	dt->draining_output = true;
	while (dt->outbound_packets.head && !dt->closing) {
		struct dc_outbound *packet =
			dt->outbound_packets.head->data;
		int err;

		list_unlink(&packet->le);
		++dt->packet_callback_depth;
		err = dt->packeth(packet->mb, dt->arg);
		--dt->packet_callback_depth;
		mem_deref(packet->mb);
		mem_deref(packet);
		if (err) {
			result = err;
			break;
		}
		err = drain_stream_resets(dt);
		if (err) {
			result = err;
			break;
		}
	}
	dt->draining_output = false;
	if (result && !dt->packet_error)
		dt->packet_error = result;
	mem_deref(dt);
	return result;
}


static int stack_acquire(void)
{
	thrd_t current = thrd_current();

	call_once(&stack_once, stack_lock_init);
	if (stack_mtx_err)
		return stack_mtx_err;
	mtx_lock(&stack_mtx);
	if (stack_owner_set && !thrd_equal(stack_owner, current)) {
		mtx_unlock(&stack_mtx);
		return EBUSY;
	}
	if (!stack_owner_set) {
		stack_owner = current;
		stack_owner_set = true;
	}
	mtx_unlock(&stack_mtx);

	if (!stack_initialized) {
		usrsctp_init_nothreads(0, packet_output, NULL);
		stack_initialized = true;
		tmr_init(&stack_timer);
	}
	if (!tmr_isrunning(&stack_timer)) {
		last_tick = tmr_jiffies();
		tmr_start(&stack_timer, 10, timer_handler, NULL);
	}

	++transport_count;
	return 0;
}


static void stack_release(void)
{
	if (!transport_count)
		return;

	--transport_count;
	if (!transport_count) {
		close_retired_addresses();
		(void)stack_finish();
	}
}


bool dc_utf8_valid(const uint8_t *buf, size_t len, bool reject_nul)
{
	size_t i = 0;

	while (i < len) {
		uint32_t cp;
		size_t n;
		uint8_t c = buf[i];

		if (c < 0x80) {
			if (reject_nul && !c)
				return false;
			++i;
			continue;
		}
		if ((c & 0xe0) == 0xc0) {
			cp = c & 0x1f;
			n = 2;
			if (cp < 2)
				return false;
		}
		else if ((c & 0xf0) == 0xe0) {
			cp = c & 0x0f;
			n = 3;
		}
		else if ((c & 0xf8) == 0xf0) {
			cp = c & 0x07;
			n = 4;
		}
		else {
			return false;
		}
		if (i + n > len)
			return false;
		for (size_t j = 1; j < n; ++j) {
			if ((buf[i + j] & 0xc0) != 0x80)
				return false;
			cp = (cp << 6) | (buf[i + j] & 0x3f);
		}
		if ((n == 3 && cp < 0x800) ||
		    (n == 4 && cp < 0x10000) ||
		    (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff)
			return false;
		i += n;
	}

	return true;
}


struct dc_channel *dc_channel_find(struct dc_transport *dt, uint16_t id)
{
	for (struct le *le = dt->channels.head; le; le = le->next) {
		struct dc_channel *dc = le->data;
		if (dc->id == (int)id)
			return dc;
	}

	return NULL;
}


void dc_channel_set_state(struct dc_channel *dc, enum dc_state state, int err)
{
	bool defer_open;

	if (!dc || state <= dc->state)
		return;
	defer_open = state == DC_STATE_OPEN && dc->open_pending;
	dc->state = state;
	if (state == DC_STATE_CLOSED) {
		/* Stream ownership belongs to the association ledger, not to the
		 * lifetime of the application-facing channel object.  A caller may
		 * retain a closed object indefinitely without blocking a stream whose
		 * bilateral reset has completed. */
		list_unlink(&dc->le);
		dc->ack_pending = false;
		dc->open_pending = false;
		clear_send_queue(dc);
		clear_inbound_queue(dc);
		if (dc->id >= 0)
			clear_partial(dc->transport, (uint16_t)dc->id);
	}
	if (!defer_open && dc->transport->stateh) {
		mem_ref(dc);
		dc->transport->stateh(dc, state, err, dc->transport->arg);
		mem_deref(dc);
	}
}


static void notify_channel_state(struct dc_channel *dc, enum dc_state state,
				 int err)
{
	struct dc_transport *dt;

	if (!dc || !dc->transport->stateh)
		return;

	dt = mem_ref(dc->transport);
	mem_ref(dc);
	dt->stateh(dc, state, err, dt->arg);
	mem_deref(dc);
	mem_deref(dt);
}


static void deferred_open_handler(void *arg)
{
	struct dc_channel *dc = arg;

	mem_ref(dc);
	if (dc->state == DC_STATE_OPEN) {
		notify_channel_state(dc, DC_STATE_OPEN, 0);
		dc->open_pending = false;
		if (dc->state == DC_STATE_OPEN)
			(void)drain_inbound(dc);
	}
	else {
		dc->open_pending = false;
	}
	mem_deref(dc);
}


static void channel_destructor(void *arg)
{
	struct dc_channel *dc = arg;

	tmr_cancel(&dc->open_tmr);
	list_unlink(&dc->le);
	clear_send_queue(dc);
	clear_inbound_queue(dc);
	mem_deref(dc->inbound);
	mem_deref(dc->reservation);
	mem_deref(dc->label);
	mem_deref(dc->protocol);
	mem_deref(dc->transport);
}


void dc_sctp_send_params(struct sctp_sendv_spa *spa,
			 const struct dc_channel *dc, uint32_t ppid)
{
	memset(spa, 0, sizeof(*spa));
	spa->sendv_sndinfo.snd_sid = (uint16_t)dc->id;
	spa->sendv_sndinfo.snd_flags = SCTP_EOR;
	spa->sendv_sndinfo.snd_ppid = htonl(ppid);
	spa->sendv_flags = SCTP_SEND_SNDINFO_VALID;

	/* RFC 8832 section 5: DCEP control is ordered and reliable. */
	if (ppid == PPID_DCEP)
		return;

	if (!dc->ordered)
		spa->sendv_sndinfo.snd_flags |= SCTP_UNORDERED;

	switch (dc->reliability) {
	case DC_RELIABILITY_RETRANSMITS:
		spa->sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
		spa->sendv_prinfo.pr_value = dc->reliability_value;
		spa->sendv_flags |= SCTP_SEND_PRINFO_VALID;
		break;
	case DC_RELIABILITY_LIFETIME:
		spa->sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
		spa->sendv_prinfo.pr_value = dc->reliability_value;
		spa->sendv_flags |= SCTP_SEND_PRINFO_VALID;
		break;
	default:
		break;
	}
}


static int send_raw(struct dc_channel *dc, uint32_t ppid,
		    const uint8_t *buf, size_t len, size_t *accepted)
{
	enum { SCTP_SEND_OVERHEAD = 512 };
	struct sctp_sendv_spa spa;
	struct sockaddr_conn remote;
	struct dc_transport *dt = dc->transport;
	ssize_t sent;

	if (len > dt->send_free ||
	    SCTP_SEND_OVERHEAD > dt->send_free - len)
		return EAGAIN;

	dc_sctp_send_params(&spa, dc, ppid);

	memset(&remote, 0, sizeof(remote));
	remote.sconn_family = AF_CONN;
	remote.sconn_port = htons(dc->transport->config.remote_port);
	remote.sconn_addr = dc->transport->address;

	errno = 0;
	sent = usrsctp_sendv(dc->transport->socket, buf, len,
			    (struct sockaddr *)&remote, 1, &spa,
			    sizeof(spa), SCTP_SENDV_SPA, 0);
	if (drain_output(dt))
		return dt->packet_error ? dt->packet_error : EIO;
	if (!dt->packet_callback_depth) {
		int err = drain_stream_resets(dt);

		if (err)
			return err;
	}
	if (accepted)
		*accepted = 0;
	if (sent < 0)
		return errno ? errno : EIO;
	if (!sent)
		return EAGAIN;
	if ((size_t)sent != len)
		return EIO;
	if (accepted)
		*accepted = (size_t)sent;
	dt->send_free -= MIN(dt->send_free,
			     (size_t)sent + SCTP_SEND_OVERHEAD);
	if (dc->transport->packet_error) {
		int err = dc->transport->packet_error;
		dc->transport->packet_error = 0;
		return err;
	}

	return 0;
}


static void message_destructor(void *arg)
{
	struct dc_message *message = arg;

	list_unlink(&message->le);
}


static void clear_send_queue(struct dc_channel *dc)
{
	while (dc->sendq.head) {
		struct dc_message *message = dc->sendq.head->data;
		size_t app_remaining =
			message->len > message->offset
				? message->len - message->offset : 0;
		dc->buffered_amount -= app_remaining;
		dc->transport->queued_amount -=
			message->allocation_cost;
		list_unlink(&message->le);
		mem_deref(message);
	}
}


static int enqueue_message(struct dc_channel *dc, uint32_t ppid,
			   const uint8_t *buf, size_t len, bool application)
{
	struct dc_message *message;
	struct dc_transport *dt;
	size_t cost = MAX(len, (size_t)1);
	size_t allocation_cost;
	int err;

	if (cost > SIZE_MAX - sizeof(*message))
		return EAGAIN;
	allocation_cost = sizeof(*message) + cost;
	if (allocation_cost > dc->transport->queue_limit -
		   dc->transport->queued_amount)
		return EAGAIN;

	message = mem_zalloc(sizeof(*message) + cost, message_destructor);
	if (!message)
		return ENOMEM;
	message->len = application ? len : 0;
	message->cost = cost;
	message->allocation_cost = allocation_cost;
	message->ppid = ppid;
	if (len)
		memcpy(message->data, buf, len);
	else
		message->data[0] = 0;

	list_append(&dc->sendq, &message->le, message);
	dc->buffered_amount += message->len;
	dc->transport->queued_amount += allocation_cost;
	dt = mem_ref(dc->transport);
	err = drain_channel(dc);
	if (err)
		dc_transport_fail(dt, err);
	mem_deref(dt);
	return err;
}


static int enqueue_record(struct dc_channel *dc, uint32_t ppid,
			  const uint8_t *buf, size_t len)
{
	return enqueue_message(dc, ppid, buf, len, false);
}


static int drain_channel(struct dc_channel *dc)
{
	struct dc_transport *dt = dc->transport;
	int result = 0;

	if (dc->draining)
		return 0;

	mem_ref(dc);
	dc->draining = true;
	while (dc->sendq.head) {
		struct dc_message *message = mem_ref(dc->sendq.head->data);
		size_t remaining = message->cost - message->offset;
		size_t accepted = 0;
		size_t app_accepted;
		size_t app_remaining;
		size_t before = dc->buffered_amount;
		int err = send_raw(dc, message->ppid,
				   message->data + message->offset,
				   remaining, &accepted);

		if (err == EAGAIN || err == EWOULDBLOCK)
			goto stop;
		if (err) {
			result = err;
			goto stop;
		}
		if (!message->le.list)
			goto next;

		app_remaining = message->len > message->offset
				      ? message->len - message->offset : 0;
		app_accepted = MIN(accepted, app_remaining);
		dc->buffered_amount -= app_accepted;
		message->offset += accepted;
		if (message->offset == message->cost) {
			list_unlink(&message->le);
			dt->queued_amount -= message->allocation_cost;
			mem_deref(message);
		}

		if (before > dt->config.send_low_water &&
		    dc->buffered_amount <= dt->config.send_low_water &&
		    dt->buffered_lowh) {
			dt->buffered_lowh(dc, dt->arg);
		}
	next:
		mem_deref(message);
		continue;
	stop:
		mem_deref(message);
		break;
	}

	dc->draining = false;
	mem_deref(dc);
	return result;
}


static int drain_transport(struct dc_transport *dt)
{
	struct dc_channel *dc = dt->channels.head
				      ? mem_ref(dt->channels.head->data) : NULL;

	while (dc) {
		struct dc_channel *next = dc->le.next
					 ? mem_ref(dc->le.next->data) : NULL;
		int err;

		err = drain_channel(dc);
		mem_deref(dc);
		if (err) {
			mem_deref(next);
			return err;
		}
		dc = next;
	}

	return 0;
}


static int send_callback(struct socket *socket, uint32_t free_bytes, void *arg)
{
	struct dc_address *address = arg;
	struct dc_transport *dt = address ? address->transport : NULL;
	int err;

	if (!dt)
		return 0;

	mem_ref(dt);
	dt->send_free = free_bytes;
	err = drain_transport(dt);
	if (!err && dt->association_up)
		err = assign_pending(dt, true);
	if (err == EAGAIN || err == EWOULDBLOCK)
		err = 0;
	if (err)
		dc_transport_fail(dt, err);
	mem_deref(dt);

	(void)socket;
	(void)free_bytes;
	return 1;
}


int dc_send_record(struct dc_channel *dc, uint32_t ppid,
		   const uint8_t *buf, size_t len)
{
	return enqueue_record(dc, ppid, buf, len);
}


static uint8_t channel_type(const struct dc_channel *dc)
{
	uint8_t type;

	switch (dc->reliability) {
	case DC_RELIABILITY_RETRANSMITS: type = 0x01; break;
	case DC_RELIABILITY_LIFETIME:    type = 0x02; break;
	default:                         type = 0x00; break;
	}

	return dc->ordered ? type : (uint8_t)(type | 0x80);
}


static int send_open(struct dc_channel *dc)
{
	struct mbuf *mb;
	size_t label_len = str_len(dc->label);
	size_t protocol_len = str_len(dc->protocol);
	int err;

	mb = mbuf_alloc(12 + label_len + protocol_len);
	if (!mb)
		return ENOMEM;

	err  = mbuf_write_u8(mb, DCEP_OPEN);
	err |= mbuf_write_u8(mb, channel_type(dc));
	err |= mbuf_write_u16(mb, htons(dc->priority));
	err |= mbuf_write_u32(mb, htonl(dc->reliability_value));
	err |= mbuf_write_u16(mb, htons((uint16_t)label_len));
	err |= mbuf_write_u16(mb, htons((uint16_t)protocol_len));
	err |= mbuf_write_mem(mb, (const uint8_t *)dc->label, label_len);
	err |= mbuf_write_mem(mb, (const uint8_t *)dc->protocol, protocol_len);
	if (!err)
		err = enqueue_record(dc, PPID_DCEP, mb->buf, mb->end);
	mem_deref(mb);
	return err;
}


static int send_ack(struct dc_channel *dc)
{
	const uint8_t ack = DCEP_ACK;

	return enqueue_record(dc, PPID_DCEP, &ack, sizeof(ack));
}


static int allocate_stream_id(struct dc_transport *dt, uint16_t stream_limit,
			      uint16_t *idp,
			      struct dc_reusable_id **reservationp)
{
	struct dc_reusable_id *reusable = NULL;
	uint32_t parity = dt->role == DC_ROLE_CLIENT ? 0U : 1U;
	int err;

	while (dt->next_id < stream_limit) {
		uint16_t id = (uint16_t)dt->next_id;
		struct dc_reusable_id *state;

		dt->next_id += 2;
		state = reset_state(dt, id, false);
		if (state && !state->available)
			continue;
		err = claim_stream_id(dt, id, reservationp);
		if (err)
			return err;
		*idp = id;
		return 0;
	}

	for (struct le *le = dt->reusable_ids.head; le; le = le->next) {
		struct dc_reusable_id *candidate = le->data;
		uint16_t complete = SCTP_STREAM_RESET_INCOMING_SSN |
				    SCTP_STREAM_RESET_OUTGOING_SSN;

		if ((candidate->flags & complete) == complete &&
		    candidate->available &&
		    candidate->id < stream_limit &&
		    (candidate->id & 1U) == parity &&
		    !dc_channel_find(dt, candidate->id)) {
			reusable = candidate;
			break;
		}
	}
	if (!reusable)
		return ENOSPC;

	*idp = reusable->id;
	return claim_stream_id(dt, reusable->id, reservationp);
}


static struct dc_reusable_id *reset_state(struct dc_transport *dt,
					   uint16_t id, bool create)
{
	struct dc_reusable_id *reusable;

	for (struct le *le = dt->reusable_ids.head; le; le = le->next) {
		reusable = le->data;
		if (reusable->id == id)
			return reusable;
	}
	if (!create)
		return NULL;

	reusable = mem_zalloc(sizeof(*reusable), reusable_destructor);
	if (!reusable)
		return NULL;
	reusable->id = id;
	list_append(&dt->reusable_ids, &reusable->le, reusable);
	return reusable;
}


static int claim_stream_id(struct dc_transport *dt, uint16_t id,
			   struct dc_reusable_id **reservationp)
{
	struct dc_reusable_id *state = reset_state(dt, id, false);

	/* An existing unavailable entry can represent either a live channel or
	 * an unknown stream whose protocol-error reset is still in flight.  In
	 * both cases the SCTP stream must remain quarantined until both reset
	 * directions complete. */
	if (state && !state->available)
		return EADDRINUSE;
	if (!state) {
		if (reservationp && *reservationp) {
			state = *reservationp;
			*reservationp = NULL;
			state->id = id;
			list_append(&dt->reusable_ids, &state->le, state);
		}
		else {
			state = reset_state(dt, id, true);
			if (!state)
				return ENOMEM;
		}
	}
	state->used = true;
	state->available = false;
	state->flags = 0;
	state->requested_flags = 0;
	return 0;
}


static void update_reusable_ids(struct dc_transport *dt)
{
	const uint16_t complete = SCTP_STREAM_RESET_INCOMING_SSN |
				  SCTP_STREAM_RESET_OUTGOING_SSN;

	for (struct le *le = dt->reusable_ids.head; le; le = le->next) {
		struct dc_reusable_id *reusable = le->data;
		bool pending = false;

		for (struct le *reset_le = dt->resets.head; reset_le;
		     reset_le = reset_le->next) {
			const struct dc_reset *reset = reset_le->data;

			if (reset->id == reusable->id) {
				pending = true;
				break;
			}
		}
		if (!pending && (reusable->flags & complete) == complete)
			reusable->available = true;
	}
}


static int assign_pending(struct dc_transport *dt, bool terminal)
{
	struct dc_channel *dc = dt->channels.head
				      ? mem_ref(dt->channels.head->data) : NULL;
	uint16_t stream_limit = MIN(dt->outbound_streams,
				    dt->inbound_streams);

	while (dc) {
		struct dc_channel *next = dc->le.next
					 ? mem_ref(dc->le.next->data) : NULL;
		int err;

		if (dc->ack_pending && dc->state == DC_STATE_OPEN) {
			err = send_ack(dc);
			if (err) {
				mem_deref(dc);
				mem_deref(next);
				return err;
			}
			dc->ack_pending = false;
		}
		if (dc->remote || dc->negotiated ||
		    dc->state != DC_STATE_CONNECTING || dc->open_sent)
			goto next;
		if (dc->id < 0) {
			uint16_t id;

			while (dt->next_id < stream_limit &&
			       dc_channel_find(dt, (uint16_t)dt->next_id))
				dt->next_id += 2;
			err = allocate_stream_id(dt, stream_limit, &id,
						 &dc->reservation);
			if (err) {
				if (!terminal) {
					mem_deref(dc);
					mem_deref(next);
					return err;
				}
				dc_channel_set_state(dc, DC_STATE_CLOSED,
						     err);
				goto next;
			}
			dc->id = (int)id;
			dc->reservation = mem_deref(dc->reservation);
		}
		err = send_open(dc);
		if (err) {
			mem_deref(dc);
			mem_deref(next);
			return err;
		}
		dc->open_sent = true;

	next:
		mem_deref(dc);
		dc = next;
	}

	return 0;
}


static void association_ready(struct dc_transport *dt,
			      sctp_assoc_t assoc_id,
			      uint16_t outbound_streams,
			      uint16_t inbound_streams)
{
	struct dc_channel *dc;
	uint16_t stream_limit;

	if (dt->closing)
		return;

	dt->outbound_streams = outbound_streams;
	dt->inbound_streams = inbound_streams;
	dt->assoc_id = assoc_id;
	stream_limit = MIN(outbound_streams, inbound_streams);
	dt->association_up = true;

	for (;;) {
		dc = NULL;
		for (struct le *le = dt->channels.head; le; le = le->next) {
			struct dc_channel *candidate = le->data;

			if (candidate->negotiated &&
			    candidate->state == DC_STATE_CONNECTING) {
				dc = mem_ref(candidate);
				break;
			}
		}
		if (!dc)
			break;

		if (dc->id >= stream_limit)
			dc_channel_set_state(dc, DC_STATE_CLOSED, ENOSPC);
		else
			dc_channel_set_state(dc, DC_STATE_OPEN, 0);
		mem_deref(dc);
	}
}


void dc_handle_notification(struct dc_transport *dt,
			    const union sctp_notification *notification,
			    size_t len)
{
	if (len < sizeof(notification->sn_header))
		return;

	switch (notification->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		if (len < sizeof(notification->sn_assoc_change))
			return;
		switch (notification->sn_assoc_change.sac_state) {
		case SCTP_COMM_UP:
		case SCTP_RESTART:
			association_ready(
				dt,
				notification->sn_assoc_change.sac_assoc_id,
				notification->sn_assoc_change.sac_outbound_streams,
				notification->sn_assoc_change.sac_inbound_streams);
			break;
		case SCTP_COMM_LOST:
		case SCTP_CANT_STR_ASSOC:
		case SCTP_SHUTDOWN_COMP:
			dt->association_up = false;
			dc_transport_fail(dt, ECONNRESET);
			break;
		default:
			break;
		}
		break;
	case SCTP_SHUTDOWN_EVENT:
		dt->association_up = false;
		dc_transport_fail(dt, ECONNRESET);
		break;
	case SCTP_STREAM_RESET_EVENT: {
		const struct sctp_stream_reset_event *event =
			&notification->sn_strreset_event;
		size_t offset = offsetof(struct sctp_stream_reset_event,
					 strreset_stream_list);
		size_t count;
		const uint16_t complete =
			SCTP_STREAM_RESET_INCOMING_SSN |
			SCTP_STREAM_RESET_OUTGOING_SSN;

		if (len < offset)
			return;
		count = (len - offset) / sizeof(uint16_t);
		if (event->strreset_flags &
		    (SCTP_STREAM_RESET_DENIED | SCTP_STREAM_RESET_FAILED)) {
			if (!count) {
				dc_transport_fail(dt, EIO);
				return;
			}
			for (size_t i = 0; i < count; ++i) {
				uint16_t id = event->strreset_stream_list[i];
				struct dc_channel *dc = dc_channel_find(dt, id);
				struct dc_reusable_id *reusable =
					reset_state(dt, id, false);

				for (struct le *le = dt->resets.head; le;) {
					struct dc_reset *reset = le->data;
					struct le *next = le->next;

					if (reset->id == id)
						mem_deref(reset);
					le = next;
				}
				if (reusable) {
					reusable->requested_flags = 0;
					reusable->available = false;
				}
				if (dc && dc->state == DC_STATE_CLOSING) {
					mem_ref(dc);
					dc_channel_set_state(dc,
							     DC_STATE_CLOSED,
							     EIO);
					mem_deref(dc);
				}
			}
			return;
		}

		for (size_t i = 0; i < count; ++i) {
			struct dc_reusable_id *reusable;
			struct dc_channel *dc =
				dc_channel_find(
					dt, event->strreset_stream_list[i]);

			reusable = reset_state(
				dt, event->strreset_stream_list[i], true);
			if (!reusable) {
				dc_transport_fail(dt, ENOMEM);
				return;
			}
			reusable->flags |= event->strreset_flags;
			reusable->available = false;
			if (event->strreset_flags &
			    SCTP_STREAM_RESET_OUTGOING_SSN) {
				for (struct le *le = dt->resets.head; le;
				     le = le->next) {
					struct dc_reset *reset = le->data;

					if (reset->sent &&
					    reset->id ==
						    event->strreset_stream_list[i]) {
						mem_deref(reset);
						break;
					}
				}
			}
			if (dc) {
				int err = 0;

				mem_ref(dc);
				if (event->strreset_flags &
				    SCTP_STREAM_RESET_INCOMING_SSN &&
				    !(reusable->requested_flags &
				      SCTP_STREAM_RESET_OUTGOING))
					err = dc_request_stream_reset(
						dt, (uint16_t)dc->id,
						SCTP_STREAM_RESET_OUTGOING);
				if (err) {
					mem_deref(dc);
					dc_transport_fail(dt, err);
					return;
				}
				dc_channel_set_state(dc, DC_STATE_CLOSING, 0);
				if ((reusable->flags & complete) == complete)
					dc_channel_set_state(
						dc, DC_STATE_CLOSED, 0);
				mem_deref(dc);
			}
		}
		update_reusable_ids(dt);
		break;
	}
	case SCTP_PARTIAL_DELIVERY_EVENT: {
		const struct sctp_pdapi_event *event =
			&notification->sn_pdapi_event;

		if (len < sizeof(*event))
			return;
		if (event->pdapi_indication == SCTP_PARTIAL_DELIVERY_ABORTED &&
		    event->pdapi_stream <= UINT16_MAX)
			clear_partial(dt, (uint16_t)event->pdapi_stream);
		break;
	}
	case SCTP_SEND_FAILED_EVENT: {
		const struct sctp_send_failed_event *event =
			&notification->sn_send_failed_event;
		struct dc_channel *dc;

		if (len < sizeof(*event))
			return;
		dc = dc_channel_find(dt, event->ssfe_info.snd_sid);
		if (dc && dc->reliability == DC_RELIABLE) {
			mem_ref(dc);
			dc_channel_set_state(dc, DC_STATE_CLOSING, EIO);
			dc_channel_set_state(dc, DC_STATE_CLOSED, EIO);
			mem_deref(dc);
		}
		break;
	}
	default:
		break;
	}
}


static int dcep_open(struct dc_transport *dt, uint16_t id,
		     const uint8_t *buf, size_t len)
{
	struct dc_channel_config config;
	struct dc_channel *dc;
	uint32_t reliability;
	uint16_t priority;
	uint16_t label_len;
	uint16_t protocol_len;
	uint8_t base_type;
	bool ordered;
	int err;

	if (len < 12 || buf[0] != DCEP_OPEN || dc_channel_find(dt, id) ||
	    id >= MIN(dt->outbound_streams, dt->inbound_streams) ||
	    (id & 1) == (dt->role == DC_ROLE_CLIENT ? 0 : 1))
		return EPROTO;

	ordered = !(buf[1] & 0x80);
	base_type = buf[1] & 0x7f;
	memcpy(&priority, buf + 2, sizeof(priority));
	memcpy(&reliability, buf + 4, sizeof(reliability));
	memcpy(&label_len, buf + 8, sizeof(label_len));
	memcpy(&protocol_len, buf + 10, sizeof(protocol_len));
	priority = ntohs(priority);
	reliability = ntohl(reliability);
	label_len = ntohs(label_len);
	protocol_len = ntohs(protocol_len);
	/* aiortc and other deployed RFC 8832 implementations encode the
	 * historical DCEP default as zero.  Our constrained equal-share profile
	 * gives every accepted channel the RFC 8864 default weight, so normalize
	 * that wire value before enforcing the supported-priority boundary. */
	if (!priority)
		priority = DC_PRIORITY_DEFAULT;

	if ((size_t)label_len + protocol_len != len - 12 ||
	    !dc_utf8_valid(buf + 12, label_len, true) ||
	    !dc_utf8_valid(buf + 12 + label_len, protocol_len, true))
		return EPROTO;

	memset(&config, 0, sizeof(config));
	config.ordered = ordered;
	config.priority = priority;
	config.reliability_value = reliability;
	config.id = id;
	config.negotiated = true;
	switch (base_type) {
	case 0x00:
		config.reliability = DC_RELIABLE;
		/* RFC 8832 defines this word as unused for reliable channel types. */
		config.reliability_value = 0;
		break;
	case 0x01: config.reliability = DC_RELIABILITY_RETRANSMITS; break;
	case 0x02: config.reliability = DC_RELIABILITY_LIFETIME; break;
	default: return EPROTO;
	}

	char *label = mem_alloc((size_t)label_len + 1, NULL);
	char *protocol = mem_alloc((size_t)protocol_len + 1, NULL);
	if (!label || !protocol) {
		mem_deref(label);
		mem_deref(protocol);
		return ENOMEM;
	}
	memcpy(label, buf + 12, label_len);
	label[label_len] = '\0';
	memcpy(protocol, buf + 12 + label_len, protocol_len);
	protocol[protocol_len] = '\0';
	config.protocol = protocol;

	err = channel_alloc(&dc, dt, label, &config, true);
	mem_deref(label);
	mem_deref(protocol);
	if (err)
		return err == EADDRINUSE ? EPROTO : err;

	dc->negotiated = false;
	/* ACK output may synchronously feed the peer, which may immediately send
	 * user data back.  Guard the channel before any packet can escape so its
	 * messages cannot be published before channelh. */
	dc->dispatching = true;
	err = send_ack(dc);
	if (err == EAGAIN || err == EWOULDBLOCK) {
		dc->ack_pending = true;
		err = 0;
	}
	if (!err && dt->channelh) {
		mem_ref(dc);
		dt->channelh(dc, dt->arg);
		if (dc->state == DC_STATE_OPEN)
			notify_channel_state(dc, DC_STATE_OPEN, 0);
		mem_deref(dc);
	}
	dc->dispatching = false;
	if (!err && dt->channelh) {
		mem_ref(dc);
		if (dc->state == DC_STATE_OPEN)
			err = drain_inbound(dc);
		mem_deref(dc);
	}
	mem_deref(dc);
	return err;
}


static size_t inbound_budget(const struct dc_transport *dt)
{
	size_t overhead = sizeof(struct dc_partial) + sizeof(struct mbuf);

	return overhead > SIZE_MAX - dt->config.receive_limit
		     ? SIZE_MAX : dt->config.receive_limit + overhead;
}


static void inbound_destructor(void *arg)
{
	struct dc_inbound *inbound = arg;

	list_unlink(&inbound->le);
	if (inbound->transport)
		inbound->transport->inbound_amount -= inbound->cost;
}


static int queue_inbound(struct dc_channel *dc, uint32_t ppid,
			 const uint8_t *buf, size_t len)
{
	struct dc_transport *dt = dc->transport;
	struct dc_inbound *inbound;
	size_t data_cost = MAX(len, (size_t)1);
	size_t cost;
	size_t budget = inbound_budget(dt);

	if (data_cost > SIZE_MAX - sizeof(*inbound))
		return ENOBUFS;
	cost = sizeof(*inbound) + data_cost;
	if (dt->inbound_amount > budget ||
	    cost > budget - dt->inbound_amount)
		return ENOBUFS;

	inbound = mem_zalloc(sizeof(*inbound) + data_cost,
			     inbound_destructor);
	if (!inbound)
		return ENOMEM;
	inbound->transport = dt;
	inbound->len = len;
	inbound->cost = cost;
	inbound->ppid = ppid;
	if (len)
		memcpy(inbound->data, buf, len);
	list_append(&dc->inboundq, &inbound->le, inbound);
	dt->inbound_amount += cost;
	return 0;
}


static void notify_message(struct dc_channel *dc, enum dc_message_type type,
			   const uint8_t *buf, size_t len)
{
	struct dc_transport *dt = mem_ref(dc->transport);

	mem_ref(dc);
	if (dt->messageh)
		dt->messageh(dc, type, buf, len, dt->arg);
	mem_deref(dc);
	mem_deref(dt);
}


static int close_protocol_channel(struct dc_transport *dt, uint16_t id,
				  int err)
{
	struct dc_channel *dc = dc_channel_find(dt, id);
	int reset_err = 0;

	if (dc) {
		mem_ref(dc);
		dc_channel_set_state(dc, DC_STATE_CLOSING, err);
	}
	if (dt->socket && dt->association_up)
		reset_err = dc_request_stream_reset(
			dt, id, SCTP_STREAM_RESET_OUTGOING);
	if (dc && (reset_err || !dt->socket || !dt->association_up))
		dc_channel_set_state(dc, DC_STATE_CLOSED,
			reset_err ? reset_err : err);
	mem_deref(dc);
	return reset_err ? reset_err : EPROTO;
}


static int deliver_message(struct dc_transport *dt, uint16_t id,
			   uint32_t ppid, const uint8_t *buf, size_t len)
{
	struct dc_channel *dc = dc_channel_find(dt, id);
	enum dc_message_type type;

	switch (ppid) {
	case PPID_TEXT:
	case PPID_TEXT_EMPTY:
		type = DC_MESSAGE_TEXT;
		if (ppid == PPID_TEXT_EMPTY)
			len = 0;
		if (!dc_utf8_valid(buf, len, false)) {
			++dt->invalid_text;
			return EPROTO;
		}
		break;
	case PPID_BINARY:
	case PPID_BINARY_EMPTY:
		type = DC_MESSAGE_BINARY;
		if (ppid == PPID_BINARY_EMPTY)
			len = 0;
		break;
	default:
		return EPROTO;
	}
	if (!dc)
		return EPROTO;

	/* RFC 8832 permits user messages to overtake the reliable DCEP ACK on
	 * unordered channels.  Retain them only for a known locally-created
	 * stream whose OPEN has actually been sent, then publish after OPEN. */
	if (dc->state == DC_STATE_CONNECTING && !dc->remote &&
	    !dc->negotiated && dc->open_sent)
		return queue_inbound(dc, ppid, buf, len);
	if (dc->state != DC_STATE_OPEN)
		return 0;

	if (dc->dispatching || dc->draining_inbound || dc->open_pending)
		return queue_inbound(dc, ppid, buf, len);

	notify_message(dc, type, buf, len);
	return 0;
}


static int drain_inbound(struct dc_channel *dc)
{
	int err = 0;

	mem_ref(dc);
	dc->draining_inbound = true;
	while (dc->inboundq.head && dc->state == DC_STATE_OPEN) {
		struct dc_inbound *inbound = dc->inboundq.head->data;
		enum dc_message_type type =
			inbound->ppid == PPID_TEXT ||
			inbound->ppid == PPID_TEXT_EMPTY
				? DC_MESSAGE_TEXT : DC_MESSAGE_BINARY;

		list_unlink(&inbound->le);
		notify_message(dc, type, inbound->data, inbound->len);
		mem_deref(inbound);
	}
	dc->draining_inbound = false;
	if (dc->state != DC_STATE_OPEN)
		clear_inbound_queue(dc);
	mem_deref(dc);
	return err;
}


static void partial_destructor(void *arg)
{
	struct dc_partial *partial = arg;

	list_unlink(&partial->le);
	if (partial->transport)
		partial->transport->inbound_amount -= partial->cost;
	mem_deref(partial->mb);
}


static void clear_inbound_queue(struct dc_channel *dc)
{
	list_flush(&dc->inboundq);
}


static struct dc_partial *partial_find(struct dc_transport *dt, uint16_t id)
{
	for (struct le *le = dt->partials.head; le; le = le->next) {
		struct dc_partial *partial = le->data;
		if (partial->id == id)
			return partial;
	}

	return NULL;
}


static void clear_partial(struct dc_transport *dt, uint16_t id)
{
	mem_deref(partial_find(dt, id));
}


static void detach_partial(struct dc_partial *partial)
{
	if (!partial || !partial->le.list)
		return;

	list_unlink(&partial->le);
	mem_deref(partial);
}


int dc_receive_record(struct dc_transport *dt, uint16_t id,
		      uint32_t ppid, const uint8_t *buf, size_t len,
		      bool complete)
{
	struct dc_partial *partial = partial_find(dt, id);
	const uint8_t *record = buf;
	size_t record_len = len;
	int err = 0;

	if (partial)
		mem_ref(partial);
	if (partial && partial->ppid != ppid) {
		detach_partial(partial);
		mem_deref(partial);
		return close_protocol_channel(dt, id, EPROTO);
	}
	if (partial || !complete) {
		if (!partial) {
			size_t base_cost = sizeof(*partial) +
					   sizeof(struct mbuf);
			size_t capacity = MAX(len, (size_t)1);
			size_t budget = inbound_budget(dt);
			size_t cost;

			if (len > dt->config.receive_limit)
				return EMSGSIZE;
			if (capacity > SIZE_MAX - base_cost)
				return ENOBUFS;
			cost = base_cost + capacity;
			if (dt->inbound_amount > budget ||
			    cost > budget - dt->inbound_amount)
				return ENOBUFS;
			partial = mem_zalloc(sizeof(*partial),
					     partial_destructor);
			if (!partial)
				return ENOMEM;
			partial->mb = mbuf_alloc(capacity);
			if (!partial->mb) {
				mem_deref(partial);
				return ENOMEM;
			}
			partial->transport = dt;
			partial->cost = cost;
			partial->id = id;
			partial->ppid = ppid;
			list_append(&dt->partials, &partial->le, partial);
			dt->inbound_amount += cost;
			mem_ref(partial);
		}
		if (len > dt->config.receive_limit ||
		    partial->mb->end > dt->config.receive_limit - len) {
			detach_partial(partial);
			mem_deref(partial);
			return EMSGSIZE;
		}
		if (partial->mb->end + len > partial->mb->size) {
			size_t new_size = partial->mb->end + len;
			size_t growth = new_size - partial->mb->size;
			size_t budget = inbound_budget(dt);

			if (dt->inbound_amount > budget ||
			    growth > budget - dt->inbound_amount) {
				detach_partial(partial);
				mem_deref(partial);
				return ENOBUFS;
			}
			err = mbuf_resize(partial->mb, new_size);
			if (err) {
				detach_partial(partial);
				mem_deref(partial);
				return err;
			}
			partial->cost += growth;
			dt->inbound_amount += growth;
		}
		err = len ? mbuf_write_mem(partial->mb, buf, len) : 0;
		if (err) {
			detach_partial(partial);
			mem_deref(partial);
			return err;
		}
		if (!complete) {
			mem_deref(partial);
			return 0;
		}
		record = partial->mb->buf;
		record_len = partial->mb->end;
		detach_partial(partial);
	}
	else if (len > dt->config.receive_limit) {
		return EMSGSIZE;
	}

	if (ppid == PPID_DCEP) {
		if (record_len == 1 && record[0] == DCEP_ACK) {
			struct dc_channel *dc = dc_channel_find(dt, id);
			if (dc && dc->state == DC_STATE_CONNECTING) {
				mem_ref(dc);
				dc_channel_set_state(dc, DC_STATE_OPEN, 0);
				if (dc->state == DC_STATE_OPEN && !dc->open_pending)
					err = drain_inbound(dc);
				mem_deref(dc);
			}
		}
		else {
			err = dcep_open(dt, id, record, record_len);
		}
	}
	else {
		err = deliver_message(dt, id, ppid, record, record_len);
	}
	if (err == EPROTO)
		err = close_protocol_channel(dt, id, EPROTO);

	mem_deref(partial);
	return err;
}


static int receive_callback(struct socket *socket, union sctp_sockstore addr,
			    void *data, size_t len, struct sctp_rcvinfo rcv,
			    int flags, void *arg)
{
	struct dc_address *address = arg;
	struct dc_transport *dt = address ? address->transport : NULL;
	uint32_t ppid = ntohl(rcv.rcv_ppid);

	if (!dt) {
		if (!data && address) {
			address->socket = NULL;
			if (address->registered) {
				usrsctp_deregister_address(address);
				address->registered = false;
			}
			address->reap = true;
		}
		free(data);
		return 1;
	}

	mem_ref(dt);
	if (!data) {
		dt->socket = NULL;
		dt->association_up = false;
		if (dt->registered) {
			usrsctp_deregister_address(dt->address);
			dt->registered = false;
			dt->address->registered = false;
		}
		dt->address->socket = NULL;
		dt->address->reap = true;
		if (!dt->closing)
			dc_transport_fail(dt, ECONNRESET);
		mem_deref(dt);
		return 1;
	}

	if (flags & MSG_NOTIFICATION) {
		dc_handle_notification(dt, data, len);
	}
	else {
		int receive_err = dc_receive_record(dt, rcv.rcv_sid, ppid,
						    data, len,
						    !!(flags & MSG_EOR));
		if (receive_err == EPROTO) {
			int reset_err = dc_request_stream_reset(
				dt, rcv.rcv_sid,
				SCTP_STREAM_RESET_OUTGOING);
			if (reset_err)
				dc_transport_fail(dt, reset_err);
		}
		if (receive_err == ENOMEM) {
			/* usrsctp's receive callback cannot return an application error.
			 * Preserve process resource exhaustion for dc_transport_input(),
			 * or for the stack timer's deferred error consumer.
			 */
			if (!dt->packet_error)
				dt->packet_error = receive_err;
		}
		else if (receive_err == EMSGSIZE || receive_err == ENOBUFS) {
			struct dc_channel *dc =
				dc_channel_find(dt, rcv.rcv_sid);
			int reset_err;
			if (dc) {
				mem_ref(dc);
				dc_channel_set_state(dc, DC_STATE_CLOSING,
						     receive_err);
				dc_channel_set_state(dc, DC_STATE_CLOSED,
						     receive_err);
				mem_deref(dc);
			}
			reset_err = dc_request_stream_reset(
				dt, rcv.rcv_sid,
				SCTP_STREAM_RESET_OUTGOING);
			if (reset_err)
				dc_transport_fail(dt, reset_err);
		}
	}

	free(data);
	mem_deref(dt);
	(void)socket;
	(void)addr;
	return 1;
}


static int socket_option(struct socket *socket, int option,
			 const void *value, socklen_t len)
{
	if (usrsctp_setsockopt(socket, IPPROTO_SCTP, option, value, len) < 0)
		return errno ? errno : EIO;
	return 0;
}


static int socket_option_level(struct socket *socket, int level, int option,
			       const void *value, socklen_t len)
{
	if (usrsctp_setsockopt(socket, level, option, value, len) < 0)
		return errno ? errno : EIO;
	return 0;
}


static void reset_destructor(void *arg)
{
	struct dc_reset *reset = arg;

	list_unlink(&reset->le);
}


static void reusable_destructor(void *arg)
{
	struct dc_reusable_id *reusable = arg;

	list_unlink(&reusable->le);
}


int dc_request_stream_reset(struct dc_transport *dt, uint16_t id,
			    uint16_t flags)
{
	struct dc_reusable_id *reusable;
	struct dc_reset *reset;

	reusable = reset_state(dt, id, true);
	if (!reusable)
		return ENOMEM;
	flags &= (uint16_t)~reusable->requested_flags;
	if (!flags)
		return 0;
	for (struct le *le = dt->resets.head; le; le = le->next) {
		struct dc_reset *pending = le->data;

		if (pending->id == id) {
			pending->flags |= flags;
			reusable->requested_flags |= flags;
			return 0;
		}
	}

	reset = mem_zalloc(sizeof(*reset), reset_destructor);
	if (!reset)
		return ENOMEM;
	reset->id = id;
	reset->flags = flags;
	list_append(&dt->resets, &reset->le, reset);
	reusable->requested_flags |= flags;

	return dt->input_depth || dt->packet_callback_depth
		       ? 0 : drain_stream_resets(dt);
}


static int drain_stream_resets(struct dc_transport *dt)
{
	struct sctp_reset_streams *reset;
	size_t len = sizeof(*reset) + sizeof(uint16_t);
	int err = 0;

	while (dt->resets.head && dt->socket) {
		struct dc_reset *pending = dt->resets.head->data;

		if (pending->sent)
			break;
		reset = mem_zalloc(len, NULL);
		if (!reset)
			return ENOMEM;
		reset->srs_assoc_id = dt->assoc_id;
		reset->srs_flags = pending->flags;
		reset->srs_number_streams = 1;
		reset->srs_stream_list[0] = pending->id;
		err = socket_option(dt->socket, SCTP_RESET_STREAMS, reset,
				    (socklen_t)len);
		mem_deref(reset);
		if (err == EALREADY) {
			err = 0;
			break;
		}
		if (err)
			break;
		pending->sent = true;
		break;
	}

	return err;
}


static void consume_packet_errors(void)
{
	struct dc_transport *dt = transports.head
				      ? mem_ref(transports.head->data) : NULL;

	while (dt) {
		struct dc_transport *next = dt->global_le.next
					 ? mem_ref(dt->global_le.next->data)
					 : NULL;

		if (dt->packet_error && !dt->closing) {
			int err = dt->packet_error;

			dt->packet_error = 0;
			dc_transport_fail(dt, err);
		}
		mem_deref(dt);
		dt = next;
	}
}


static void drain_pending_resets(void)
{
	struct dc_transport *dt = transports.head
				      ? mem_ref(transports.head->data) : NULL;

	while (dt) {
		struct dc_transport *next = dt->global_le.next
					 ? mem_ref(dt->global_le.next->data)
					 : NULL;

		if (!dt->closing && !dt->packet_callback_depth) {
			int err = drain_stream_resets(dt);

			if (!err)
				err = drain_output(dt);
			if (err)
				dc_transport_fail(dt, err);
		}
		mem_deref(dt);
		dt = next;
	}
}


static void transport_destructor(void *arg)
{
	struct dc_transport *dt = arg;

	dt->closing = true;
	list_unlink(&dt->global_le);
	list_flush(&dt->partials);
	list_flush(&dt->resets);
	list_flush(&dt->reusable_ids);
	while (dt->outbound_packets.head) {
		struct dc_outbound *packet =
			dt->outbound_packets.head->data;

		list_unlink(&packet->le);
		mem_deref(packet->mb);
		mem_deref(packet);
	}
	if (dt->address)
		dt->address->transport = NULL;
	if (dt->address) {
		if (dt->stack_acquired)
			list_append(&retired_addresses, &dt->address->le,
				    dt->address);
		else
			free(dt->address);
		dt->address = NULL;
	}
	if (dt->stack_acquired)
		stack_release();
}


int dc_transport_alloc(struct dc_transport **dtp,
		       const struct dc_transport_config *config,
		       dc_packet_h *packeth, dc_channel_h *channelh,
		       dc_message_h *messageh, dc_state_h *stateh,
		       dc_buffered_low_h *buffered_lowh,
		       dc_transport_close_h *closeh, void *arg)
{
	struct dc_transport *dt;
	struct sockaddr_conn local;
	struct sctp_assoc_value reset;
	struct sctp_initmsg init;
	struct sctp_event event;
	struct sctp_paddrparams peer;
	struct sctp_assocparams assoc;
	struct sctp_rtoinfo rto;
	struct sctp_assoc_value scheduler;
	const int one = 1;
	uint32_t partial_delivery_point;
	int send_buffer;
	const uint16_t events[] = {
		SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_EVENT,
		SCTP_STREAM_RESET_EVENT, SCTP_SEND_FAILED_EVENT,
		SCTP_PARTIAL_DELIVERY_EVENT
	};
	int err;

	if (!dtp || !config || !packeth || !config->local_port ||
	    !config->remote_port || !config->outbound_streams ||
	    !config->inbound_streams || !config->receive_limit ||
	    !config->send_limit ||
	    config->send_limit > SIZE_MAX - sizeof(struct dc_message) ||
	    sizeof(struct dc_message) + config->send_limit >
		    config->send_high_water / 2 ||
	    config->send_low_water > config->send_high_water ||
	    !config->heartbeat_interval_ms || !config->rto_max_ms ||
	    !config->max_retransmissions)
		return EINVAL;

	dt = mem_zalloc(sizeof(*dt), transport_destructor);
	if (!dt)
		return ENOMEM;

	dt->config = *config;
	dt->outbound_streams = config->outbound_streams;
	dt->inbound_streams = config->inbound_streams;
	dt->queue_limit = config->send_high_water / 2;
	dt->packeth = packeth;
	dt->channelh = channelh;
	dt->messageh = messageh;
	dt->stateh = stateh;
	dt->buffered_lowh = buffered_lowh;
	dt->closeh = closeh;
	dt->arg = arg;
	dt->address = calloc(1, sizeof(*dt->address));
	if (!dt->address) {
		mem_deref(dt);
		return ENOMEM;
	}
	dt->address->transport = dt;

	err = stack_acquire();
	if (err)
		goto out;
	dt->stack_acquired = true;

	usrsctp_register_address(dt->address);
	dt->registered = true;
	dt->address->registered = true;
	dt->socket = usrsctp_socket(
		AF_CONN, SOCK_SEQPACKET, IPPROTO_SCTP, receive_callback,
		send_callback,
		dt->queue_limit / 2 > UINT32_MAX
			? UINT32_MAX
			: (uint32_t)(dt->queue_limit / 2),
		dt->address);
	if (!dt->socket) {
		err = errno ? errno : EIO;
		usrsctp_deregister_address(dt->address);
		dt->registered = false;
		dt->address->registered = false;
		dt->address->reap = true;
		goto out;
	}
	dt->address->socket = dt->socket;

	err = usrsctp_set_non_blocking(dt->socket, 1) < 0
		      ? (errno ? errno : EIO) : 0;
	err |= socket_option(dt->socket, SCTP_NODELAY, &one, sizeof(one));
	err |= socket_option(dt->socket, SCTP_RECVRCVINFO, &one, sizeof(one));
	err |= socket_option(dt->socket, SCTP_EXPLICIT_EOR, &one, sizeof(one));
#if defined(DC_USRSCTP_FAIR_BANDWIDTH)
	/* This is an equal-share constrained profile: every channel keeps the
	 * scheduler's identical default share.  Non-default DCEP priorities are
	 * rejected because this backend cannot set RFC 8260 stream weights.
	 */
	memset(&scheduler, 0, sizeof(scheduler));
	scheduler.assoc_id = SCTP_FUTURE_ASSOC;
	scheduler.assoc_value = SCTP_SS_FAIR_BANDWITH;
	err |= socket_option(dt->socket, SCTP_PLUGGABLE_SS, &scheduler,
			     sizeof(scheduler));
#else
	(void)scheduler;
#endif
#if defined(DC_USRSCTP_INTERLEAVING)
	{
		const uint32_t fragment_interleave = 2;
		struct sctp_assoc_value interleaving = {
			.assoc_id = SCTP_FUTURE_ASSOC,
			.assoc_value = 1
		};

		err |= socket_option(dt->socket, SCTP_FRAGMENT_INTERLEAVE,
				     &fragment_interleave,
				     sizeof(fragment_interleave));
		err |= socket_option(dt->socket, SCTP_INTERLEAVING_SUPPORTED,
				     &interleaving, sizeof(interleaving));
	}
#endif
	partial_delivery_point =
		(uint32_t)MIN(config->receive_limit, (size_t)1024);
	err |= socket_option(dt->socket, SCTP_PARTIAL_DELIVERY_POINT,
			     &partial_delivery_point,
			     sizeof(partial_delivery_point));
	send_buffer = dt->queue_limit > INT_MAX
			    ? INT_MAX : (int)dt->queue_limit;
	err |= socket_option_level(dt->socket, SOL_SOCKET, SO_SNDBUF,
				   &send_buffer, sizeof(send_buffer));
	dt->send_free = (size_t)send_buffer;

	memset(&reset, 0, sizeof(reset));
	reset.assoc_id = SCTP_ALL_ASSOC;
	reset.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ |
			    SCTP_ENABLE_CHANGE_ASSOC_REQ;
	err |= socket_option(dt->socket, SCTP_ENABLE_STREAM_RESET,
			     &reset, sizeof(reset));

	memset(&init, 0, sizeof(init));
	init.sinit_num_ostreams = config->outbound_streams;
	init.sinit_max_instreams = config->inbound_streams;
	err |= socket_option(dt->socket, SCTP_INITMSG, &init, sizeof(init));

	memset(&peer, 0, sizeof(peer));
	peer.spp_assoc_id = SCTP_FUTURE_ASSOC;
	peer.spp_hbinterval = config->heartbeat_interval_ms;
	peer.spp_pathmaxrxt = config->max_retransmissions;
	peer.spp_pathmtu = SCTP_SAFE_PATH_MTU;
	peer.spp_flags = SPP_HB_ENABLE | SPP_PMTUD_DISABLE;
	err |= socket_option(dt->socket, SCTP_PEER_ADDR_PARAMS,
			     &peer, sizeof(peer));

	memset(&assoc, 0, sizeof(assoc));
	assoc.sasoc_assoc_id = SCTP_FUTURE_ASSOC;
	assoc.sasoc_asocmaxrxt = config->max_retransmissions;
	err |= socket_option(dt->socket, SCTP_ASSOCINFO,
			     &assoc, sizeof(assoc));

	memset(&rto, 0, sizeof(rto));
	rto.srto_assoc_id = SCTP_FUTURE_ASSOC;
	rto.srto_initial = MIN(config->rto_max_ms, 1000U);
	rto.srto_min = MIN(config->rto_max_ms, 1000U);
	rto.srto_max = config->rto_max_ms;
	err |= socket_option(dt->socket, SCTP_RTOINFO, &rto, sizeof(rto));

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (size_t i = 0; i < RE_ARRAY_SIZE(events); ++i) {
		event.se_type = events[i];
		err |= socket_option(dt->socket, SCTP_EVENT,
				     &event, sizeof(event));
	}
	if (err)
		goto out;

	memset(&local, 0, sizeof(local));
	local.sconn_family = AF_CONN;
	local.sconn_port = htons(config->local_port);
	local.sconn_addr = dt->address;
	if (usrsctp_bind(dt->socket, (struct sockaddr *)&local,
			 sizeof(local)) < 0) {
		err = errno ? errno : EIO;
		goto out;
	}

out:
	if (err)
		mem_deref(dt);
	else {
		list_append(&transports, &dt->global_le, dt);
		*dtp = dt;
	}
	return err;
}


int dc_transport_start(struct dc_transport *dt, enum dc_role local_role)
{
	struct sockaddr_conn remote;
	int err = 0;

	if (!dt || (local_role != DC_ROLE_CLIENT &&
		    local_role != DC_ROLE_SERVER))
		return EINVAL;
	if (!stack_is_owner())
		return EPERM;
	if (dt->started)
		return EALREADY;

	mem_ref(dt);
	dt->started = true;
	dt->role = local_role;
	dt->next_id = local_role == DC_ROLE_CLIENT ? 0 : 1;

	memset(&remote, 0, sizeof(remote));
	remote.sconn_family = AF_CONN;
	remote.sconn_port = htons(dt->config.remote_port);
	remote.sconn_addr = dt->address;
	if (usrsctp_connect(dt->socket, (struct sockaddr *)&remote,
			    sizeof(remote)) < 0 &&
	    errno != EINPROGRESS && errno != EWOULDBLOCK)
		err = errno ? errno : EIO;
	if (!err)
		err = drain_output(dt);
	if (!err)
		err = drain_stream_resets(dt);
	if (dt->packet_error) {
		err = dt->packet_error;
		dt->packet_error = 0;
		dc_transport_fail(dt, err);
	}
	if (err && !dt->closing)
		dc_transport_fail(dt, err);

	mem_deref(dt);
	return err;
}


int dc_transport_input(struct dc_transport *dt, struct mbuf *packet)
{
	int result = 0;

	if (!dt || !packet)
		return EINVAL;
	if (!stack_is_owner())
		return EPERM;
	if (!dt->started || dt->closing)
		return ENOTCONN;

	mem_ref(dt);
	++dt->input_depth;
	usrsctp_conninput(dt->address, mbuf_buf(packet),
			  mbuf_get_left(packet), 0);
	--dt->input_depth;
	if (!dt->input_depth)
		result = drain_output(dt);
	if (!result && !dt->input_depth)
		result = drain_stream_resets(dt);
	if (result) {
		dc_transport_fail(dt, result);
		goto out;
	}
	if (dt->packet_error) {
		int err = dt->packet_error;
		dt->packet_error = 0;
		dc_transport_fail(dt, err);
		result = err;
		goto out;
	}
	if (dt->association_up) {
		int err = assign_pending(dt, true);
		if (err && err != EAGAIN) {
			dc_transport_fail(dt, err);
			result = err;
			goto out;
		}
	}
	if (!dt->closing) {
		int err = drain_transport(dt);
		if (err) {
			dc_transport_fail(dt, err);
			result = err;
			goto out;
		}
	}

out:
	if (!result && !dt->closing)
		update_reusable_ids(dt);
	mem_deref(dt);
	return result;
}


void dc_transport_fail(struct dc_transport *dt, int err)
{
	struct dc_channel *dc;
	dc_transport_close_h *closeh;
	void *arg;

	if (!dt || dt->closing)
		return;

	mem_ref(dt);
	dt->closing = true;
	dt->association_up = false;
	for (;;) {
		dc = NULL;
		for (struct le *le = dt->channels.head; le; le = le->next) {
			struct dc_channel *candidate = le->data;

			if (candidate->state != DC_STATE_CLOSED) {
				dc = mem_ref(candidate);
				break;
			}
		}
		if (!dc)
			break;

		dc_channel_set_state(dc, DC_STATE_CLOSED,
				     err > 0 ? err : ECONNRESET);
		mem_deref(dc);
	}
	closeh = dt->close_notified ? NULL : dt->closeh;
	arg = dt->arg;
	dt->close_notified = true;
	if (closeh)
		closeh(err > 0 ? err : ECONNRESET, arg);
	mem_deref(dt);
}


int dc_transport_close(struct dc_transport *dt, int err)
{
	if (!dt)
		return EINVAL;
	if (!stack_is_owner())
		return EPERM;

	mem_ref(dt);
	dt->closeh = NULL;
	dc_transport_fail(dt, err > 0 ? err : ECANCELED);
	if (dt->socket)
		(void)usrsctp_shutdown(dt->socket, SHUT_RDWR);
	mem_deref(dt);
	return 0;
}


bool dc_transport_association_ready(const struct dc_transport *dt)
{
	return dt && dt->association_up && !dt->closing;
}


uint64_t dc_transport_invalid_text_count(const struct dc_transport *dt)
{
	return dt ? dt->invalid_text : 0;
}


static int channel_alloc(struct dc_channel **dcp, struct dc_transport *dt,
			 const char *label,
			 const struct dc_channel_config *config, bool remote)
{
	struct dc_channel *dc;
	uint16_t stream_limit;
	size_t metadata_limit;
	int err = 0;

	stream_limit = dt ? MIN(dt->outbound_streams,
				dt->inbound_streams) : 0;
	metadata_limit = dt ? (remote ? dt->config.receive_limit
				      : dt->config.send_limit) : 0;
	if (!dcp || !dt || !label || !config || !config->protocol)
		return EINVAL;
	/* Priority is checked before allocation, SID reservation, or publication.
	 * The backend can schedule equal shares, but cannot apply RFC 8260 weights.
	 */
	if (config->priority != DC_PRIORITY_DEFAULT)
		return remote ? EPROTO : ENOTSUP;
	if (dt->closing ||
	    !dc_utf8_valid((const uint8_t *)label, str_len(label), true) ||
	    !dc_utf8_valid((const uint8_t *)config->protocol,
			   str_len(config->protocol), true) ||
	    config->reliability > DC_RELIABILITY_LIFETIME ||
	    (config->reliability == DC_RELIABLE &&
	     config->reliability_value) ||
	    (config->negotiated &&
	     (config->id < 0 || config->id >= stream_limit)) ||
	    (!config->negotiated && config->id >= 0))
		return EINVAL;
	if (str_len(label) > UINT16_MAX ||
	    str_len(config->protocol) > UINT16_MAX ||
	    str_len(label) + str_len(config->protocol) >
		    metadata_limit - MIN(metadata_limit, (size_t)12))
		return EMSGSIZE;
	if (config->negotiated &&
	    dc_channel_find(dt, (uint16_t)config->id))
		return EADDRINUSE;
	if (config->negotiated) {
		struct dc_reusable_id *state =
			reset_state(dt, (uint16_t)config->id, false);

		if (state && !state->available)
			return EADDRINUSE;
	}

	dc = mem_zalloc(sizeof(*dc), channel_destructor);
	if (!dc)
		return ENOMEM;
	if (!config->negotiated) {
		dc->reservation = mem_zalloc(sizeof(*dc->reservation),
					      reusable_destructor);
		if (!dc->reservation) {
			mem_deref(dc);
			return ENOMEM;
		}
	}

	tmr_init(&dc->open_tmr);
	dc->transport = mem_ref(dt);
	dc->state = DC_STATE_CONNECTING;
	dc->reliability = config->reliability;
	dc->reliability_value = config->reliability_value;
	dc->priority = config->priority;
	dc->ordered = config->ordered;
	dc->negotiated = config->negotiated;
	dc->remote = remote;
	dc->id = config->negotiated ? config->id : -1;
	dc->open_pending = !remote && !config->negotiated;
	err = str_dup(&dc->label, label);
	err |= str_dup(&dc->protocol, config->protocol);
	if (!err && dc->id >= 0)
		err = claim_stream_id(dt, (uint16_t)dc->id, NULL);
	if (err)
		goto out;

	list_append(&dt->channels, &dc->le, dc);
	if (dt->association_up) {
		if (dc->negotiated) {
			dc->state = DC_STATE_OPEN;
			if (!remote) {
				dc->open_pending = true;
				tmr_start(&dc->open_tmr, 0,
					  deferred_open_handler, dc);
			}
		}
		else {
			err = assign_pending(dt, false);
			if (err)
				goto out;
			if (dc->state == DC_STATE_OPEN)
				tmr_start(&dc->open_tmr, 0,
					  deferred_open_handler, dc);
			else
				dc->open_pending = false;
		}
	}
	else if (!dc->negotiated)
		dc->open_pending = false;

out:
	if (err)
		mem_deref(dc);
	else {
		*dcp = dc;
	}
	return err;
}


int dc_channel_create(struct dc_channel **dcp, struct dc_transport *dt,
		      const char *label,
		      const struct dc_channel_config *config)
{
	if (dt && !stack_is_owner())
		return EPERM;
	return channel_alloc(dcp, dt, label, config, false);
}


int dc_channel_send(struct dc_channel *dc, enum dc_message_type type,
		    const uint8_t *buf, size_t len)
{
	uint32_t ppid;

	if (!dc || (!buf && len) ||
	    (type != DC_MESSAGE_TEXT && type != DC_MESSAGE_BINARY))
		return EINVAL;
	if (!stack_is_owner())
		return EPERM;
	if (dc->state != DC_STATE_OPEN)
		return ENOTCONN;
	if (len > dc->transport->config.send_limit)
		return EMSGSIZE;
	if (type == DC_MESSAGE_TEXT &&
	    !dc_utf8_valid(buf, len, false))
		return EILSEQ;

	ppid = type == DC_MESSAGE_TEXT
		     ? (len ? PPID_TEXT : PPID_TEXT_EMPTY)
		     : (len ? PPID_BINARY : PPID_BINARY_EMPTY);
	return enqueue_message(dc, ppid, buf, len, true);
}


int dc_channel_close(struct dc_channel *dc)
{
	int err = 0;
	bool reset_pending = false;

	if (!dc)
		return EINVAL;
	if (!stack_is_owner())
		return EPERM;
	if (dc->state == DC_STATE_CLOSED)
		return 0;

	mem_ref(dc);
	dc_channel_set_state(dc, DC_STATE_CLOSING, 0);
	if (dc->id >= 0 && dc->transport->socket &&
	    dc->transport->association_up) {
		err = dc_request_stream_reset(
			dc->transport, (uint16_t)dc->id,
			SCTP_STREAM_RESET_OUTGOING);
		if (err)
			goto out;
		reset_pending = true;
	}
	if (!reset_pending)
		dc_channel_set_state(dc, DC_STATE_CLOSED, 0);

out:
	if (err)
		dc_channel_set_state(dc, DC_STATE_CLOSED, err);
	mem_deref(dc);
	return err;
}


const char *dc_channel_label(const struct dc_channel *dc)
{
	return dc ? dc->label : NULL;
}


const char *dc_channel_protocol(const struct dc_channel *dc)
{
	return dc ? dc->protocol : NULL;
}


int dc_channel_id(const struct dc_channel *dc)
{
	return dc ? dc->id : -1;
}


enum dc_state dc_channel_state(const struct dc_channel *dc)
{
	return dc ? dc->state : DC_STATE_CLOSED;
}


size_t dc_channel_buffered_amount(const struct dc_channel *dc)
{
	return dc ? dc->buffered_amount : 0;
}
