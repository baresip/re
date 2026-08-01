/**
 * @file datachannel.c WebRTC data-channel tests
 *
 * Copyright (C) 2026 The baresip project
 */

#include <string.h>
#include <re.h>
#include <re_datachannel.h>
#include "../src/datachannel/datachannel.h"
#include "test.h"

#define DEBUG_MODULE "datachannel"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

struct endpoint {
	struct endpoint *peer;
	struct list packets;
	struct dc_transport *transport;
	struct dc_channel *local;
	struct dc_channel *local2;
	struct dc_channel *local3;
	struct dc_channel *local4;
	struct dc_channel *local5;
	struct dc_channel *pre_ack_source;
	struct dc_channel *pre_ack_remote;
	struct dc_channel *reliable_remote;
	struct dc_channel *negotiated;
	struct dc_channel *late_negotiated;
	struct dc_channel *drain_source;
	struct dc_channel *fragment_source;
	struct dc_channel *fragment_remote;
	struct dc_channel *ack_source;
	struct dc_channel *release_on_open;
	struct dc_channel *release_on_low;
	struct dc_channel *release_other_on_close;
	struct dc_channel *close_on_packet;
	struct dc_channel *remote;
	unsigned opened;
	unsigned messages;
	unsigned buffered_low;
	unsigned pressure_received;
	unsigned late_count;
	unsigned drop_packets;
	unsigned dropped_packets;
	unsigned closing;
	unsigned closed;
	int close_error;
	unsigned transport_closed;
	int transport_close_error;
	int output_error;
	bool incoming_seen;
	bool incoming_order_error;
	bool creating_channel;
	bool create_callback_error;
	bool fragment_close_done;
	bool fragment_read_error;
	bool echoed;
	bool empty_echoed;
	bool negotiated_echoed;
	bool reorder;
	bool reorder_tail;
	bool release_local_on_close;
	bool release_all_on_transport_close;
	bool server_side;
	bool drop_all;
	bool synchronous;
	bool expect_recovery;
	bool recovery_seen;
	bool recovery_error;
	bool pre_ack_open_seen;
	bool pre_ack_message_ok;
	bool send_on_open;
	int send_on_open_error;
	uint8_t late_sequence[2];
};

struct packet {
	struct le le;
	struct mbuf *mb;
};

static once_flag datachannel_test_once = ONCE_FLAG_INIT;
static mtx_t datachannel_test_mtx;


static void datachannel_test_lock_init(void)
{
	(void)mtx_init(&datachannel_test_mtx, mtx_plain);
}


static int packet_handler(struct mbuf *packet, void *arg)
{
	struct endpoint *ep = arg;
	struct packet *queued;

	if (ep->close_on_packet) {
		struct dc_channel *dc = ep->close_on_packet;

		ep->close_on_packet = NULL;
		(void)dc_channel_close(dc);
	}
	if (ep->output_error)
		return ep->output_error;
	if (!ep->peer || !ep->peer->transport)
		return ENOTCONN;
	if (ep->drop_all || ep->drop_packets) {
		if (ep->drop_packets)
			--ep->drop_packets;
		++ep->dropped_packets;
		return 0;
	}

	queued = mem_zalloc(sizeof(*queued), NULL);
	if (!queued)
		return ENOMEM;
	queued->mb = mbuf_alloc(mbuf_get_left(packet));
	if (!queued->mb) {
		mem_deref(queued);
		return ENOMEM;
	}
	(void)mbuf_write_mem(queued->mb, mbuf_buf(packet),
			     mbuf_get_left(packet));
	queued->mb->pos = 0;
	if (ep->synchronous) {
		int err = dc_transport_input(ep->peer->transport, queued->mb);

		if (err == ENOTCONN) {
			list_append(&ep->peer->packets, &queued->le, queued);
			return 0;
		}
		mem_deref(queued->mb);
		mem_deref(queued);
		return err;
	}
	list_append(&ep->peer->packets, &queued->le, queued);
	return 0;
}


static int pump(struct endpoint *ep)
{
	struct le *le = ep->packets.head;
	struct packet *packet;
	int err;

	if (ep->reorder && ep->packets.head != ep->packets.tail) {
		ep->reorder_tail = !ep->reorder_tail;
		if (ep->reorder_tail)
			le = ep->packets.tail;
	}
	packet = list_ledata(le);
	if (!packet)
		return 0;
	list_unlink(&packet->le);
	err = dc_transport_input(ep->transport, packet->mb);
	mem_deref(packet->mb);
	mem_deref(packet);
	return err;
}


static int pump_pair(struct endpoint *a, struct endpoint *b)
{
	int err = pump(a);
	if (err == ENOTCONN && (a->close_error || b->close_error))
		err = a->close_error ? a->close_error : b->close_error;
	if (!err)
		err = pump(b);
	if (err == ENOTCONN && (a->close_error || b->close_error))
		err = a->close_error ? a->close_error : b->close_error;
	return err;
}


static void flush_packets(struct endpoint *ep)
{
	while (ep->packets.head) {
		struct packet *packet = ep->packets.head->data;
		list_unlink(&packet->le);
		mem_deref(packet->mb);
		mem_deref(packet);
	}
}


static void channel_handler(struct dc_channel *channel, void *arg)
{
	struct endpoint *ep = arg;

	ep->incoming_seen = true;
	if (!str_cmp(dc_channel_label(channel), "callback-close")) {
		(void)dc_channel_close(channel);
		++ep->opened;
		return;
	}
	if (!str_cmp(dc_channel_label(channel), "fragment-close")) {
		mem_deref(ep->fragment_remote);
		ep->fragment_remote = mem_ref(channel);
		++ep->opened;
		return;
	}
	if (!str_cmp(dc_channel_label(channel), "pre-ack-reorder")) {
		mem_deref(ep->pre_ack_remote);
		ep->pre_ack_remote = mem_ref(channel);
		++ep->opened;
		return;
	}
	if (!str_cmp(dc_channel_label(channel), "reliable")) {
		mem_deref(ep->reliable_remote);
		ep->reliable_remote = mem_ref(channel);
		++ep->opened;
		return;
	}
	mem_deref(ep->remote);
	ep->remote = mem_ref(channel);
	++ep->opened;
}


static void message_handler(struct dc_channel *channel,
			    enum dc_message_type type,
			    const uint8_t *buf, size_t len, void *arg)
{
	struct endpoint *ep = arg;
	const uint8_t expected[] = {0, 1, 2, 0xff};

	++ep->messages;
	if (!str_cmp(dc_channel_label(channel), "synchronous-publication")) {
		if (!ep->incoming_seen)
			ep->incoming_order_error = true;
		return;
	}
	if (channel == ep->pre_ack_source) {
		ep->pre_ack_message_ok = ep->pre_ack_open_seen &&
			type == DC_MESSAGE_BINARY && len == 1 && buf &&
			buf[0] == 0x5a;
		return;
	}
	if (channel == ep->late_negotiated && type == DC_MESSAGE_BINARY &&
	    len == 1 && ep->late_count < RE_ARRAY_SIZE(ep->late_sequence)) {
		ep->late_sequence[ep->late_count++] = buf[0];
		return;
	}
	if (!str_cmp(dc_channel_label(channel), "fragment-close")) {
		if (len != 16384 || !buf || buf[0] != 0x5a ||
		    buf[len - 1] != 0x5a)
			ep->fragment_read_error = true;
		(void)dc_channel_close(channel);
		if (len != 16384 || !buf || buf[0] != 0x5a ||
		    buf[len - 1] != 0x5a)
			ep->fragment_read_error = true;
		ep->fragment_close_done = true;
		return;
	}
	if (ep->expect_recovery &&
	    !str_cmp(dc_channel_label(channel), "loss-lifetime")) {
		if (type == DC_MESSAGE_BINARY && len == sizeof(expected) &&
		    !memcmp(buf, expected, len))
			ep->recovery_seen = true;
		else
			ep->recovery_error = true;
		return;
	}
	if (ep->local == channel && type == DC_MESSAGE_BINARY &&
	    len == sizeof(expected) && !memcmp(buf, expected, len)) {
		ep->echoed = true;
	}
	else if (ep->local2 == channel && type == DC_MESSAGE_TEXT && !len) {
		ep->empty_echoed = true;
	}
	else if (ep->negotiated == channel && type == DC_MESSAGE_TEXT &&
		 len == 10 && !memcmp(buf, "negotiated", len)) {
		if (ep->server_side)
			(void)dc_channel_send(ep->negotiated, type, buf, len);
		else
			ep->negotiated_echoed = true;
	}
	else if (!str_cmp(dc_channel_label(channel), "loopback") &&
		 type == DC_MESSAGE_BINARY &&
		 len == 8192) {
		++ep->pressure_received;
	}
	else if (ep->remote == channel && len <= 4) {
		(void)dc_channel_send(channel, type, buf, len);
	}
}


static void buffered_low_handler(struct dc_channel *channel, void *arg)
{
	struct endpoint *ep = arg;

	++ep->buffered_low;
	if (ep->release_on_low)
		ep->release_on_low = mem_deref(ep->release_on_low);
	(void)channel;
}


static void state_handler(struct dc_channel *channel,
			  enum dc_state state, int err, void *arg)
{
	struct endpoint *ep = arg;

	if (state == DC_STATE_OPEN) {
		if (channel == ep->pre_ack_source)
			ep->pre_ack_open_seen = true;
		if (ep->creating_channel)
			ep->create_callback_error = true;
		if (ep->server_side &&
		    !str_cmp(dc_channel_label(channel), "loopback") &&
		    !ep->incoming_seen)
			ep->incoming_order_error = true;
		++ep->opened;
		if (ep->send_on_open &&
		    !str_cmp(dc_channel_label(channel),
			     "synchronous-publication")) {
			const uint8_t byte = 0x5a;

			ep->send_on_open = false;
			ep->send_on_open_error = dc_channel_send(
				channel, DC_MESSAGE_BINARY, &byte, sizeof(byte));
		}
		if (ep->release_on_open == channel)
			ep->release_on_open =
				mem_deref(ep->release_on_open);
	}
	else if (state == DC_STATE_CLOSING) {
		++ep->closing;
	}
	else if (state == DC_STATE_CLOSED) {
		++ep->closed;
		ep->close_error = err;
		if (ep->release_other_on_close &&
		    ep->release_other_on_close != channel) {
			struct dc_channel *other = ep->release_other_on_close;

			ep->release_other_on_close = NULL;
			if (ep->local2 == other)
				ep->local2 = NULL;
			mem_deref(other);
		}
		if (ep->release_local_on_close && ep->local == channel) {
			ep->release_local_on_close = false;
			ep->local = mem_deref(ep->local);
		}
	}
	(void)channel;
	(void)err;
}

static void transport_failure_handler(int err, void *arg)
{
	struct endpoint *ep = arg;

	++ep->transport_closed;
	ep->transport_close_error = err;
	if (ep->release_all_on_transport_close) {
		ep->release_all_on_transport_close = false;
		ep->local = mem_deref(ep->local);
		ep->local2 = mem_deref(ep->local2);
		ep->remote = mem_deref(ep->remote);
		ep->negotiated = mem_deref(ep->negotiated);
		ep->transport = mem_deref(ep->transport);
	}
}


static int alloc_transport_limits(struct endpoint *ep, uint16_t local_port,
				  uint16_t remote_port,
				  uint16_t outbound_streams,
				  uint16_t inbound_streams)
{
	struct dc_transport_config config = {
		.local_port = local_port,
		.remote_port = remote_port,
		.receive_limit = 16384,
		.send_limit = 16384,
		.send_high_water = 65536,
		.send_low_water = 1024,
		.heartbeat_interval_ms = 30000,
		.rto_max_ms = 60000,
		.max_retransmissions = 10
	};

	config.outbound_streams = outbound_streams;
	config.inbound_streams = inbound_streams;
	return dc_transport_alloc(&ep->transport, &config, packet_handler,
				  channel_handler, message_handler,
				  state_handler, buffered_low_handler,
				  transport_failure_handler, ep);
}


static int alloc_transport_policy(struct endpoint *ep, uint16_t local_port,
				  uint16_t remote_port, size_t receive_limit,
				  size_t send_limit)
{
	const struct dc_transport_config config = {
		.local_port = local_port,
		.remote_port = remote_port,
		.outbound_streams = 32,
		.inbound_streams = 32,
		.receive_limit = receive_limit,
		.send_limit = send_limit,
		.send_high_water = 65536,
		.send_low_water = 1024,
		.heartbeat_interval_ms = 30000,
		.rto_max_ms = 60000,
		.max_retransmissions = 10
	};

	return dc_transport_alloc(&ep->transport, &config, packet_handler,
				  channel_handler, message_handler,
				  state_handler, buffered_low_handler,
				  transport_failure_handler, ep);
}


static int alloc_transport(struct endpoint *ep, uint16_t local_port,
			   uint16_t remote_port)
{
	return alloc_transport_limits(ep, local_port, remote_port, 32, 32);
}

static int alloc_liveness_transport(struct endpoint *ep, uint16_t port)
{
	const struct dc_transport_config config = {
		.local_port = port,
		.remote_port = port,
		.outbound_streams = 32,
		.inbound_streams = 32,
		.receive_limit = 16384,
		.send_limit = 16384,
		.send_high_water = 65536,
		.send_low_water = 1024,
		.heartbeat_interval_ms = 50,
		.rto_max_ms = 50,
		.max_retransmissions = 2
	};

	return dc_transport_alloc(&ep->transport, &config, packet_handler,
				  channel_handler, message_handler,
				  state_handler, buffered_low_handler,
				  transport_failure_handler, ep);
}


struct cross_thread_alloc {
	struct endpoint endpoint;
	int err;
};


static int cross_thread_alloc_handler(void *arg)
{
	struct cross_thread_alloc *cross = arg;

	cross->err = alloc_transport(&cross->endpoint, 5008, 5008);
	return 0;
}


static int test_dcep_send_params(void)
{
	struct dc_channel channel = {
		.id = 2,
		.reliability = DC_RELIABILITY_RETRANSMITS,
		.reliability_value = 0,
		.ordered = false
	};
	struct sctp_sendv_spa spa;
	int err = 0;

	dc_sctp_send_params(&spa, &channel, PPID_DCEP);
	TEST_EQUALS(2, spa.sendv_sndinfo.snd_sid);
	TEST_EQUALS(PPID_DCEP, ntohl(spa.sendv_sndinfo.snd_ppid));
	TEST_EQUALS(SCTP_EOR, spa.sendv_sndinfo.snd_flags);
	TEST_EQUALS(SCTP_SEND_SNDINFO_VALID, spa.sendv_flags);

	dc_sctp_send_params(&spa, &channel, PPID_BINARY);
	TEST_ASSERT(spa.sendv_sndinfo.snd_flags & SCTP_UNORDERED);
	TEST_ASSERT(spa.sendv_flags & SCTP_SEND_PRINFO_VALID);
	TEST_EQUALS(SCTP_PR_SCTP_RTX, spa.sendv_prinfo.pr_policy);
	TEST_EQUALS(0, spa.sendv_prinfo.pr_value);

	channel.reliability = DC_RELIABILITY_LIFETIME;
	channel.reliability_value = 100;
	dc_sctp_send_params(&spa, &channel, PPID_DCEP);
	TEST_EQUALS(SCTP_EOR, spa.sendv_sndinfo.snd_flags);
	TEST_EQUALS(SCTP_SEND_SNDINFO_VALID, spa.sendv_flags);

	dc_sctp_send_params(&spa, &channel, PPID_BINARY);
	TEST_ASSERT(spa.sendv_sndinfo.snd_flags & SCTP_UNORDERED);
	TEST_ASSERT(spa.sendv_flags & SCTP_SEND_PRINFO_VALID);
	TEST_EQUALS(SCTP_PR_SCTP_TTL, spa.sendv_prinfo.pr_policy);
	TEST_EQUALS(100, spa.sendv_prinfo.pr_value);

out:
	return err;
}


static int test_safe_path_mtu(const struct dc_transport *transport)
{
	struct sctp_paddrparams peer = {0};
	socklen_t len = sizeof(peer);
	int err = 0;

	peer.spp_assoc_id = SCTP_FUTURE_ASSOC;
	TEST_EQUALS(0, usrsctp_getsockopt(transport->socket, IPPROTO_SCTP,
					 SCTP_PEER_ADDR_PARAMS, &peer, &len));
	TEST_EQUALS(sizeof(peer), len);
	TEST_ASSERT(peer.spp_flags & SPP_PMTUD_DISABLE);
	TEST_ASSERT(!(peer.spp_flags & SPP_PMTUD_ENABLE));
	TEST_EQUALS(1200, peer.spp_pathmtu);
#if defined(DC_USRSCTP_FAIR_BANDWIDTH)
	{
		struct sctp_assoc_value scheduler = {
			.assoc_id = SCTP_FUTURE_ASSOC
		};

		len = sizeof(scheduler);
		TEST_EQUALS(0, usrsctp_getsockopt(transport->socket,
				IPPROTO_SCTP, SCTP_PLUGGABLE_SS,
				&scheduler, &len));
		TEST_EQUALS(SCTP_SS_FAIR_BANDWITH, scheduler.assoc_value);
	}
#endif

out:
	return err;
}


int test_datachannel(void)
{
	struct endpoint client = {0};
	struct endpoint server = {0};
	struct endpoint failed = {0};
	struct endpoint narrow = {0};
	struct endpoint wide = {0};
	struct endpoint retry_client = {0};
	struct endpoint retry_server = {0};
	struct endpoint lifecycle_client = {0};
	struct endpoint lifecycle_server = {0};
	struct endpoint liveness_client = {0};
	struct endpoint liveness_server = {0};
	struct endpoint sync_client = {0};
	struct endpoint sync_server = {0};
	struct endpoint reset_alloc_client = {0};
	struct endpoint reset_alloc_server = {0};
	struct endpoint reset_oom = {0};
	struct endpoint reset_failed = {0};
	struct endpoint timer_release_client = {0};
	struct endpoint timer_release_server = {0};
	struct endpoint association_lost = {0};
	struct endpoint association_shutdown = {0};
	struct endpoint terminal_close = {0};
	struct cross_thread_alloc cross = {0};
	thrd_t cross_thread;
	struct dc_channel *preclosed = NULL;
	struct dc_channel *reused_negotiated = NULL;
	struct dc_channel *bad_ppid = NULL;
	struct dc_channel *bad_text = NULL;
	const struct dc_channel_config config = {
		.protocol = "binary-test",
		.priority = 256,
		.reliability = DC_RELIABLE,
		.id = -1,
		.ordered = true
	};
	const uint8_t payload[] = {0, 1, 2, 0xff};
	const uint8_t invalid_text[] = {0xc0, 0x80};
	struct dc_channel_config partial = config;
	struct dc_channel_config negotiated = config;
	struct dc_channel_config asymmetric = config;
	uint8_t oversized[16385] = {0};
	uint8_t pressure[8192] = {0};
	char *large_label = NULL;
	unsigned accepted = 0;
	unsigned closed_before;
	unsigned closing_before;
	unsigned dropped_before;
	unsigned messages_before;
	unsigned opened_before;
	uint64_t deadline;
	int err;

	call_once(&datachannel_test_once, datachannel_test_lock_init);
	mtx_lock(&datachannel_test_mtx);
	err = test_dcep_send_params();
	TEST_ERR(err);

	client.peer = &server;
	server.peer = &client;
	server.server_side = true;
	narrow.peer = &wide;
	wide.peer = &narrow;
	retry_client.peer = &retry_server;
	retry_server.peer = &retry_client;
	lifecycle_client.peer = &lifecycle_server;
	lifecycle_server.peer = &lifecycle_client;
	liveness_client.peer = &liveness_server;
	liveness_server.peer = &liveness_client;
	liveness_server.server_side = true;
	sync_client.peer = &sync_server;
	sync_server.peer = &sync_client;
	sync_client.synchronous = true;
	sync_server.synchronous = true;
	sync_server.server_side = true;
	reset_alloc_client.peer = &reset_alloc_server;
	reset_alloc_server.peer = &reset_alloc_client;
	reset_alloc_client.synchronous = true;
	reset_alloc_server.synchronous = true;
	reset_alloc_server.server_side = true;
	timer_release_client.peer = &timer_release_server;
	timer_release_server.peer = &timer_release_client;
	timer_release_server.server_side = true;

	err = alloc_liveness_transport(&timer_release_server, 5010);
	TEST_ERR(err);
	err = alloc_liveness_transport(&timer_release_client, 5010);
	TEST_ERR(err);
	err = dc_channel_create(&timer_release_client.local,
				timer_release_client.transport,
				"timer-final-release", &config);
	TEST_ERR(err);
	err = dc_transport_start(timer_release_server.transport,
				 DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(timer_release_client.transport,
				 DC_ROLE_CLIENT);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(timer_release_client.local) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&timer_release_client, &timer_release_server);
		TEST_ERR(err);
		if (test_mode == TEST_MEMORY) {
			err = re_main_timeout(10);
			if (err == ETIMEDOUT)
				err = 0;
			TEST_ERR(err);
		}
		else {
			sys_msleep(10);
		}
	}
	/* OPEN encoding/queueing is driven by the asynchronous SCTP association
	 * callback.  Preserve its exact allocator failure for the OOM harness
	 * instead of turning it into a later state-timeout assertion. */
	if (timer_release_client.transport_close_error == ENOMEM ||
	    timer_release_server.transport_close_error == ENOMEM ||
	    timer_release_client.close_error == ENOMEM ||
	    timer_release_server.close_error == ENOMEM) {
		err = ENOMEM;
		goto out;
	}
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(timer_release_client.local));
	timer_release_client.drop_all = true;
	timer_release_server.drop_all = true;
	flush_packets(&timer_release_client);
	flush_packets(&timer_release_server);
	timer_release_client.release_all_on_transport_close = true;
	timer_release_server.release_all_on_transport_close = true;
	deadline = tmr_jiffies() + 1000;
	while ((!timer_release_client.transport_closed ||
		!timer_release_server.transport_closed) &&
	       tmr_jiffies() < deadline) {
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS(1, (int)timer_release_client.transport_closed);
	TEST_EQUALS(1, (int)timer_release_server.transport_closed);
	TEST_ASSERT(timer_release_client.transport == NULL);
	TEST_ASSERT(timer_release_server.transport == NULL);

	err = alloc_transport(&reset_oom, 5006, 5006);
	TEST_ERR(err);
	err = test_safe_path_mtu(reset_oom.transport);
	TEST_ERR(err);
	/* A non-default local priority is rejected before the output pointer,
	 * channel list, or persistent SID ledger can be mutated. */
	{
		struct dc_channel_config unsupported = config;
		struct dc_channel *unchanged = (struct dc_channel *)(uintptr_t)1;
		size_t channels = list_count(&reset_oom.transport->channels);
		size_t reusable = list_count(&reset_oom.transport->reusable_ids);

		unsupported.priority = DC_PRIORITY_DEFAULT / 2;
		err = dc_channel_create(&unchanged, reset_oom.transport,
					"unsupported-priority", &unsupported);
		TEST_EQUALS(ENOTSUP, err);
		TEST_ASSERT(unchanged == (struct dc_channel *)(uintptr_t)1);
		TEST_EQUALS(channels,
			    list_count(&reset_oom.transport->channels));
		TEST_EQUALS(reusable,
			    list_count(&reset_oom.transport->reusable_ids));
		unsupported.negotiated = true;
		unsupported.id = 26;
		err = dc_channel_create(&unchanged, reset_oom.transport,
					"unsupported-negotiated-priority",
					&unsupported);
		TEST_EQUALS(ENOTSUP, err);
		TEST_ASSERT(unchanged == (struct dc_channel *)(uintptr_t)1);
		TEST_EQUALS(channels,
			    list_count(&reset_oom.transport->channels));
		TEST_EQUALS(reusable,
			    list_count(&reset_oom.transport->reusable_ids));
		err = 0;
	}

	err = alloc_transport(&association_lost, 5011, 5011);
	TEST_ERR(err);
	{
		union sctp_notification notification = {0};

		notification.sn_assoc_change.sac_type = SCTP_ASSOC_CHANGE;
		notification.sn_assoc_change.sac_length =
			sizeof(notification.sn_assoc_change);
		notification.sn_assoc_change.sac_state = SCTP_COMM_UP;
		notification.sn_assoc_change.sac_assoc_id = 1;
		notification.sn_assoc_change.sac_outbound_streams = 32;
		notification.sn_assoc_change.sac_inbound_streams = 32;
		dc_handle_notification(association_lost.transport, &notification,
				       sizeof(notification.sn_assoc_change));
		TEST_ASSERT(dc_transport_association_ready(
			association_lost.transport));

		notification.sn_assoc_change.sac_state = SCTP_COMM_LOST;
		dc_handle_notification(association_lost.transport, &notification,
				       sizeof(notification.sn_assoc_change));
	}
	TEST_ASSERT(!dc_transport_association_ready(association_lost.transport));
	TEST_EQUALS(1, (int)association_lost.transport_closed);
	TEST_EQUALS(ECONNRESET, association_lost.transport_close_error);

	err = alloc_transport(&association_shutdown, 5012, 5012);
	TEST_ERR(err);
	association_shutdown.transport->association_up = true;
	{
		union sctp_notification notification = {0};

		notification.sn_shutdown_event.sse_type = SCTP_SHUTDOWN_EVENT;
		notification.sn_shutdown_event.sse_length =
			sizeof(notification.sn_shutdown_event);
		dc_handle_notification(association_shutdown.transport, &notification,
				       sizeof(notification.sn_shutdown_event));
	}
	TEST_ASSERT(!dc_transport_association_ready(
		association_shutdown.transport));
	TEST_EQUALS(1, (int)association_shutdown.transport_closed);

	err = alloc_transport(&terminal_close, 5013, 5013);
	TEST_ERR(err);
	terminal_close.transport->association_up = true;
	err = dc_transport_close(terminal_close.transport, ECANCELED);
	TEST_ERR(err);
	TEST_ASSERT(!dc_transport_association_ready(terminal_close.transport));
	TEST_EQUALS(thrd_success,
		    thrd_create(&cross_thread, cross_thread_alloc_handler,
				&cross));
	TEST_EQUALS(thrd_success, thrd_join(cross_thread, NULL));
	TEST_EQUALS(EBUSY, cross.err);
	TEST_ASSERT(cross.endpoint.transport == NULL);
	++reset_oom.transport->input_depth;
	if (test_mode != TEST_MEMORY) {
		struct memstat stat;

		err = mem_get_stat(&stat);
		TEST_ERR(err);
		mem_threshold_set((ssize_t)stat.blocks_cur + 1);
		err = dc_request_stream_reset(
			reset_oom.transport, 14,
			SCTP_STREAM_RESET_OUTGOING_SSN);
		mem_threshold_set(-1);
		TEST_EQUALS(ENOMEM, err);
		TEST_EQUALS(0,
			    (int)list_count(&reset_oom.transport->resets));
	}
	if (!reset_oom.transport->reusable_ids.head)
		goto out;
	TEST_EQUALS(1, (int)list_count(&reset_oom.transport->reusable_ids));
	{
		struct dc_reusable_id *state =
			reset_oom.transport->reusable_ids.head->data;

		TEST_EQUALS(0, state->requested_flags);
	}
	err = dc_request_stream_reset(
		reset_oom.transport, 14, SCTP_STREAM_RESET_OUTGOING_SSN);
	TEST_ERR(err);
	TEST_EQUALS(1, (int)list_count(&reset_oom.transport->resets));
	{
		struct dc_reusable_id *state =
			reset_oom.transport->reusable_ids.head->data;

		TEST_EQUALS(SCTP_STREAM_RESET_OUTGOING_SSN,
			    state->requested_flags);
	}
	--reset_oom.transport->input_depth;

	/* Unsupported PPIDs and malformed UTF-8 are per-channel protocol errors,
	 * not silently dropped messages.  On this deliberately unassociated
	 * fixture the close completes immediately; on a live association the same
	 * path requests the bilateral stream reset. */
	{
		struct dc_channel_config bad_config = config;
		unsigned messages = reset_oom.messages;

		bad_config.negotiated = true;
		bad_config.id = 20;
		err = dc_channel_create(&bad_ppid, reset_oom.transport,
					"bad-ppid", &bad_config);
		TEST_ERR(err);
		bad_config.id = 22;
		err = dc_channel_create(&bad_text, reset_oom.transport,
					"bad-text", &bad_config);
		TEST_ERR(err);
		dc_channel_set_state(bad_ppid, DC_STATE_OPEN, 0);
		dc_channel_set_state(bad_text, DC_STATE_OPEN, 0);
		err = dc_receive_record(reset_oom.transport, 20, 0xdead,
					payload, sizeof(payload), true);
		TEST_EQUALS(EPROTO, err);
		TEST_EQUALS(DC_STATE_CLOSED, dc_channel_state(bad_ppid));
		err = 0;
		{
			uint64_t invalid_before = dc_transport_invalid_text_count(
				reset_oom.transport);

			err = dc_receive_record(reset_oom.transport, 22,
					PPID_TEXT, invalid_text,
					sizeof(invalid_text), true);
			TEST_EQUALS(EPROTO, err);
			TEST_EQUALS(invalid_before + 1,
				dc_transport_invalid_text_count(
					reset_oom.transport));
		}
		TEST_EQUALS(DC_STATE_CLOSED, dc_channel_state(bad_text));
		TEST_EQUALS((int)messages, (int)reset_oom.messages);
		err = 0;

		/* A negotiated SID remains owned after CLOSED even if its old object
		 * is retained.  One reset direction is insufficient; only the second
		 * direction makes the ledger entry claimable by a new object. */
		bad_config.id = 24;
		err = dc_channel_create(&reused_negotiated,
					reset_oom.transport, "bilateral-old",
					&bad_config);
		TEST_ERR(err);
		dc_channel_set_state(reused_negotiated, DC_STATE_CLOSED, 0);
		{
			union sctp_notification notification = {0};
			struct dc_channel *replacement = NULL;

			notification.sn_strreset_event.strreset_type =
				SCTP_STREAM_RESET_EVENT;
			notification.sn_strreset_event.strreset_length =
				sizeof(struct sctp_stream_reset_event) +
				sizeof(uint16_t);
			notification.sn_strreset_event.strreset_stream_list[0] = 24;
			notification.sn_strreset_event.strreset_flags =
				SCTP_STREAM_RESET_INCOMING_SSN;
			dc_handle_notification(reset_oom.transport, &notification,
				notification.sn_strreset_event.strreset_length);
			err = dc_channel_create(&replacement, reset_oom.transport,
					"one-sided", &bad_config);
			TEST_EQUALS(EADDRINUSE, err);
			TEST_ASSERT(replacement == NULL);
			err = 0;
			notification.sn_strreset_event.strreset_flags =
				SCTP_STREAM_RESET_OUTGOING_SSN;
			dc_handle_notification(reset_oom.transport, &notification,
				notification.sn_strreset_event.strreset_length);
			err = dc_channel_create(&replacement, reset_oom.transport,
					"bilateral-complete", &bad_config);
			TEST_ERR(err);
			TEST_EQUALS(24, dc_channel_id(replacement));
			TEST_ASSERT(replacement != reused_negotiated);
			mem_deref(replacement);
		}
	}

	err = alloc_transport(&reset_failed, 5009, 5009);
	TEST_ERR(err);
	negotiated.negotiated = true;
	negotiated.id = 2;
	err = dc_channel_create(&reset_failed.local, reset_failed.transport,
				"reset-failed", &negotiated);
	TEST_ERR(err);
	negotiated.id = 4;
	err = dc_channel_create(&reset_failed.local2, reset_failed.transport,
				"reset-unrelated", &negotiated);
	TEST_ERR(err);
	dc_channel_set_state(reset_failed.local, DC_STATE_CLOSING, 0);
	dc_channel_set_state(reset_failed.local2, DC_STATE_CLOSING, 0);
	++reset_failed.transport->input_depth;
	err = dc_request_stream_reset(reset_failed.transport, 2,
				      SCTP_STREAM_RESET_OUTGOING);
	TEST_ERR(err);
	err = dc_request_stream_reset(reset_failed.transport, 4,
				      SCTP_STREAM_RESET_OUTGOING);
	TEST_ERR(err);
	--reset_failed.transport->input_depth;
	reset_failed.release_other_on_close = reset_failed.local2;
	{
		union sctp_notification notification = {0};

		notification.sn_strreset_event.strreset_type =
			SCTP_STREAM_RESET_EVENT;
		notification.sn_strreset_event.strreset_flags =
			SCTP_STREAM_RESET_FAILED;
		notification.sn_strreset_event.strreset_length =
			sizeof(struct sctp_stream_reset_event) + sizeof(uint16_t);
		notification.sn_strreset_event.strreset_stream_list[0] = 2;
		dc_handle_notification(
			reset_failed.transport, &notification,
			notification.sn_strreset_event.strreset_length);
	}
	TEST_EQUALS(DC_STATE_CLOSED,
		    dc_channel_state(reset_failed.local));
	TEST_EQUALS(EIO, reset_failed.close_error);
	TEST_ASSERT(reset_failed.local2 == NULL);
	TEST_EQUALS(1, (int)list_count(&reset_failed.transport->resets));
	TEST_EQUALS(4, ((struct dc_reset *)
			reset_failed.transport->resets.head->data)->id);

	{
		struct dc_transport_config boundary = {
			.local_port = 5004,
			.remote_port = 5004,
			.outbound_streams = 2,
			.inbound_streams = 2,
			.receive_limit = 16384,
			.send_limit = 16384,
			.send_high_water = 32768,
			.send_low_water = 1024,
			.heartbeat_interval_ms = 30000,
			.rto_max_ms = 60000,
			.max_retransmissions = 10
		};

		err = dc_transport_alloc(&lifecycle_client.transport, &boundary,
					 packet_handler, channel_handler,
					 message_handler, state_handler,
					 buffered_low_handler,
					 NULL,
					 &lifecycle_client);
		TEST_EQUALS(EINVAL, err);
	}

	err = alloc_transport(&server, 5000, 5000);
	TEST_ERR(err);
	err = alloc_transport(&client, 5000, 5000);
	TEST_ERR(err);
	err = dc_channel_create(&client.local, client.transport, "loopback",
				&config);
	TEST_ERR(err);
	err = dc_channel_create(&server.local, server.transport,
				"loopback-server", &config);
	TEST_ERR(err);
	negotiated.negotiated = true;
	negotiated.id = 6;
	err = dc_channel_create(&client.negotiated, client.transport,
				"negotiated", &negotiated);
	TEST_ERR(err);
	err = dc_channel_create(&server.negotiated, server.transport,
				"negotiated", &negotiated);
	TEST_ERR(err);
	negotiated.id = 8;
	err = dc_channel_create(&client.release_on_open, client.transport,
				"release-on-open", &negotiated);
	TEST_ERR(err);
	negotiated.id = 12;
	err = dc_channel_create(&preclosed, client.transport,
				"pre-association-close", &negotiated);
	TEST_ERR(err);
	err = dc_channel_close(preclosed);
	TEST_ERR(err);
	TEST_EQUALS(DC_STATE_CLOSED, dc_channel_state(preclosed));
	preclosed = mem_deref(preclosed);
	TEST_EQUALS(-1, dc_channel_id(client.local));
	TEST_EQUALS(-1, dc_channel_id(server.local));
	TEST_ASSERT(!dc_transport_association_ready(NULL));
	TEST_ASSERT(!dc_transport_association_ready(server.transport));
	TEST_ASSERT(!dc_transport_association_ready(client.transport));

	err = dc_transport_start(server.transport, DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(client.transport, DC_ROLE_CLIENT);
	TEST_ERR(err);
	/* Both endpoints are started before either packet queue is pumped.  This
	 * is the simultaneous-start case: neither side may report the association
	 * ready merely because its local SCTP socket has started. */
	TEST_ASSERT(!dc_transport_association_ready(server.transport));
	TEST_ASSERT(!dc_transport_association_ready(client.transport));

	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(client.local) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	if (dc_channel_state(client.local) != DC_STATE_OPEN)
		(void)re_fprintf(stderr, "datachannel closed: %m\n",
				 client.close_error);
	if (client.close_error) {
		err = client.close_error;
		goto out;
	}
	if (server.close_error) {
		err = server.close_error;
		goto out;
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(client.local));
	TEST_ASSERT(dc_transport_association_ready(server.transport));
	TEST_ASSERT(dc_transport_association_ready(client.transport));
	TEST_ASSERT(!(dc_channel_id(client.local) & 1));
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(server.local));
	TEST_ASSERT(dc_channel_id(server.local) & 1);
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(client.negotiated));
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(server.negotiated));
	TEST_ASSERT(client.release_on_open == NULL);
	TEST_ASSERT(server.remote != NULL);
	TEST_STRCMP("loopback", 8, dc_channel_label(server.remote), 8);
	TEST_STRCMP("binary-test", 11,
		    dc_channel_protocol(server.remote), 11);
	TEST_ASSERT(server.incoming_seen);
	TEST_ASSERT(!server.incoming_order_error);

	closing_before = client.closing;
	closed_before = client.closed;
	err = dc_channel_close(client.negotiated);
	TEST_ERR(err);
	TEST_EQUALS((int)closing_before + 1, (int)client.closing);
	TEST_EQUALS((int)closed_before, (int)client.closed);
	TEST_EQUALS(DC_STATE_CLOSING,
		    dc_channel_state(client.negotiated));
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(client.negotiated) != DC_STATE_CLOSED &&
	       tmr_jiffies() < deadline) {
		do {
			err = pump_pair(&client, &server);
			TEST_ERR(err);
		} while ((client.packets.head || server.packets.head) &&
			 tmr_jiffies() < deadline);
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS(DC_STATE_CLOSED,
		    dc_channel_state(client.negotiated));
	TEST_EQUALS((int)closed_before + 1, (int)client.closed);
	negotiated.id = 10;
	opened_before = client.opened;
	client.creating_channel = true;
	err = dc_channel_create(&client.late_negotiated, client.transport,
				"late-negotiated", &negotiated);
	client.creating_channel = false;
	TEST_ERR(err);
	err = dc_channel_create(&server.late_negotiated, server.transport,
				"late-negotiated", &negotiated);
	TEST_ERR(err);
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(client.late_negotiated));
	TEST_EQUALS((int)opened_before, (int)client.opened);
	TEST_ASSERT(!client.create_callback_error);
	messages_before = client.messages;
	{
		const uint8_t first = 1;
		const uint8_t second = 2;

		err = dc_channel_send(server.late_negotiated, DC_MESSAGE_BINARY,
				      &first, sizeof(first));
		TEST_ERR(err);
		err = dc_channel_send(server.late_negotiated, DC_MESSAGE_BINARY,
				      &second, sizeof(second));
	}
	TEST_ERR(err);
	while (client.packets.head) {
		err = pump(&client);
		TEST_ERR(err);
	}
	TEST_EQUALS((int)messages_before, (int)client.messages);
	deadline = tmr_jiffies() + 100;
	while (client.opened == opened_before &&
	       tmr_jiffies() < deadline) {
		err = re_main_timeout(1);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS((int)opened_before + 1, (int)client.opened);
	TEST_EQUALS((int)messages_before + 2, (int)client.messages);
	TEST_EQUALS(2, (int)client.late_count);
	TEST_EQUALS(1, client.late_sequence[0]);
	TEST_EQUALS(2, client.late_sequence[1]);

	err = dc_channel_send(client.local, DC_MESSAGE_BINARY,
			      payload, sizeof(payload));
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (!client.echoed && tmr_jiffies() < deadline)
	{
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_ASSERT(client.echoed);
	TEST_EQUALS(0, (int)dc_channel_buffered_amount(client.local));
	err = dc_channel_send(client.local, DC_MESSAGE_BINARY,
			      oversized, sizeof(oversized));
	TEST_EQUALS(EMSGSIZE, err);
	err = dc_channel_send(client.local, DC_MESSAGE_TEXT,
			      invalid_text, sizeof(invalid_text));
	TEST_EQUALS(EILSEQ, err);
	err = 0;

	err = dc_channel_create(&client.fragment_source, client.transport,
				"fragment-close", &config);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(client.fragment_source) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(client.fragment_source));
	memset(oversized, 0x5a, sizeof(oversized) - 1);
	err = dc_channel_send(client.fragment_source, DC_MESSAGE_BINARY,
			      oversized, sizeof(oversized) - 1);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (!server.fragment_close_done && tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_ASSERT(server.fragment_close_done);
	TEST_ASSERT(!server.fragment_read_error);

	for (;;) {
		err = dc_channel_send(client.local, DC_MESSAGE_BINARY,
				      pressure, sizeof(pressure));
		if (err == EAGAIN)
			break;
		TEST_ERR(err);
		++accepted;
		TEST_ASSERT(accepted < 64);
	}
	TEST_ASSERT(accepted > 0);
	TEST_ASSERT(dc_channel_buffered_amount(client.local) > 0);
	err = dc_channel_create(&server.ack_source, server.transport,
				"ack-pressure", &config);
	TEST_ERR(err);
	client.reorder = true;
	server.reorder = true;
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_buffered_amount(client.local) &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(0, (int)dc_channel_buffered_amount(client.local));
	TEST_ASSERT(client.buffered_low > 0);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(server.ack_source) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(server.ack_source));
	deadline = tmr_jiffies() + 3000;
	while (server.pressure_received < accepted &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS((int)accepted, (int)server.pressure_received);

	err = dc_channel_create(&client.drain_source, client.transport,
				"drain-source", &config);
	TEST_ERR(err);
	err = dc_channel_create(&client.release_on_low, client.transport,
				"drain-victim", &config);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while ((dc_channel_state(client.drain_source) != DC_STATE_OPEN ||
		dc_channel_state(client.release_on_low) != DC_STATE_OPEN) &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(client.drain_source));
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(client.release_on_low));
	for (;;) {
		err = dc_channel_send(client.drain_source, DC_MESSAGE_BINARY,
				      pressure, sizeof(pressure));
		if (err == EAGAIN)
			break;
		TEST_ERR(err);
	}
	TEST_ASSERT(dc_channel_buffered_amount(client.drain_source) > 0);
	deadline = tmr_jiffies() + 3000;
	while ((client.release_on_low ||
		dc_channel_buffered_amount(client.drain_source)) &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_ASSERT(client.release_on_low == NULL);
	TEST_EQUALS(0, (int)dc_channel_buffered_amount(client.drain_source));

	partial.protocol = "";
	partial.ordered = false;
	partial.reliability = DC_RELIABILITY_RETRANSMITS;
	partial.reliability_value = 3;
	err = dc_channel_create(&client.local2, client.transport, "partial",
				&partial);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(client.local2) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(client.local2));
	TEST_ASSERT(!(dc_channel_id(client.local2) & 1));
	err = dc_channel_send(client.local2, DC_MESSAGE_TEXT, NULL, 0);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (!client.empty_echoed && tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_ASSERT(client.empty_echoed);

	partial.ordered = false;
	partial.reliability = DC_RELIABILITY_RETRANSMITS;
	partial.reliability_value = 0;
	err = dc_channel_create(&client.local4, client.transport,
				"loss-retransmits", &partial);
	TEST_ERR(err);
	err = dc_channel_send(client.local4, DC_MESSAGE_BINARY,
			      payload, sizeof(payload));
	TEST_EQUALS(ENOTCONN, err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(client.local4) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(client.local4));
	messages_before = server.messages;
	dropped_before = client.dropped_packets;
	/* PMTU-safe AF_CONN output may emit control separately from user data.
	 * Hold the whole path down so the oracle does not depend on packet
	 * coalescing or on which SCTP packet happens to be emitted first. */
	client.drop_all = true;
	err = dc_channel_send(client.local4, DC_MESSAGE_BINARY,
			      payload, sizeof(payload));
	TEST_ERR(err);
	deadline = tmr_jiffies() + 500;
	while (tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	client.drop_all = false;
	TEST_ASSERT(client.dropped_packets > dropped_before);
	TEST_EQUALS((int)messages_before, (int)server.messages);

	partial.ordered = false;
	partial.reliability = DC_RELIABILITY_LIFETIME;
	partial.reliability_value = 100;
	err = dc_channel_create(&client.local5, client.transport,
				"loss-lifetime", &partial);
	TEST_ERR(err);
	err = dc_channel_send(client.local5, DC_MESSAGE_BINARY,
			      payload, sizeof(payload));
	TEST_EQUALS(ENOTCONN, err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(client.local5) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(client.local5));
	messages_before = server.messages;
	{
		union sctp_notification notification = {0};
		int stream_id = dc_channel_id(client.local5);

		err = dc_receive_record(server.transport, (uint16_t)stream_id,
					PPID_BINARY, oversized, 4, false);
		TEST_ERR(err);
		notification.sn_pdapi_event.pdapi_type =
			SCTP_PARTIAL_DELIVERY_EVENT;
		notification.sn_pdapi_event.pdapi_length =
			sizeof(notification.sn_pdapi_event);
		notification.sn_pdapi_event.pdapi_indication =
			SCTP_PARTIAL_DELIVERY_ABORTED;
		notification.sn_pdapi_event.pdapi_stream =
			(uint32_t)stream_id;
		dc_handle_notification(server.transport, &notification,
				       sizeof(notification.sn_pdapi_event));
		server.expect_recovery = true;
		err = dc_receive_record(server.transport, (uint16_t)stream_id,
					PPID_BINARY, payload, sizeof(payload),
					true);
	}
	TEST_ERR(err);
	TEST_ASSERT(server.recovery_seen);
	TEST_ASSERT(!server.recovery_error);

	partial.ordered = true;
	partial.reliability = DC_RELIABLE;
	partial.reliability_value = 0;
	err = dc_channel_create(&client.local3, client.transport,
				"callback-close", &partial);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(client.local3) == DC_STATE_CONNECTING &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&client, &server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_ASSERT(dc_channel_state(client.local3) != DC_STATE_CONNECTING);

	err = alloc_transport_limits(&narrow, 5002, 5002, 2, 2);
	TEST_ERR(err);
	err = alloc_transport_limits(&wide, 5002, 5002, 8, 8);
	TEST_ERR(err);
	asymmetric.negotiated = true;
	asymmetric.id = 1;
	err = dc_channel_create(&wide.local, wide.transport, "asymmetric-1",
				&asymmetric);
	TEST_ERR(err);
	err = dc_channel_create(&narrow.local, narrow.transport, "asymmetric-1",
				&asymmetric);
	TEST_ERR(err);
	err = dc_channel_create(&wide.local2, wide.transport,
				"asymmetric-dcep", &config);
	TEST_ERR(err);
	err = dc_channel_create(&wide.local3, wide.transport,
				"asymmetric-exhausted", &config);
	TEST_ERR(err);
	err = dc_transport_start(narrow.transport, DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(wide.transport, DC_ROLE_CLIENT);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while ((dc_channel_state(wide.local) != DC_STATE_OPEN ||
		dc_channel_state(wide.local2) == DC_STATE_CONNECTING) &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&narrow, &wide);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(wide.local));
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(narrow.local));
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(wide.local2));
	TEST_EQUALS(DC_STATE_CLOSED, dc_channel_state(wide.local3));
	asymmetric.id = 3;
	err = dc_channel_create(&wide.local4, wide.transport, "asymmetric-2",
				&asymmetric);
	TEST_EQUALS(EINVAL, err);
	err = dc_channel_create(&narrow.local2, narrow.transport,
				"asymmetric-2", &asymmetric);
	TEST_EQUALS(EINVAL, err);

	err = dc_channel_close(wide.local2);
	TEST_ERR(err);
	err = dc_channel_close(narrow.remote);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (narrow.remote &&
	       dc_channel_state(narrow.remote) != DC_STATE_CLOSED &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&narrow, &wide);
		TEST_ERR(err);
		sys_msleep(10);
	}
	while ((narrow.packets.head || wide.packets.head) &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&narrow, &wide);
		TEST_ERR(err);
	}
	wide.local2 = mem_deref(wide.local2);
	narrow.remote = mem_deref(narrow.remote);
	deadline = tmr_jiffies() + 3000;
	do {
		err = dc_channel_create(&wide.local2, wide.transport,
					"asymmetric-reused", &config);
		if (err != ENOSPC)
			break;
		err = pump_pair(&narrow, &wide);
		TEST_ERR(err);
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	} while (tmr_jiffies() < deadline);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(wide.local2) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&narrow, &wide);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(wide.local2));
	TEST_EQUALS(0, dc_channel_id(wide.local2));
	deadline = tmr_jiffies() + 500;
	while (tmr_jiffies() < deadline) {
		err = pump_pair(&narrow, &wide);
		TEST_ERR(err);
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(wide.local2));

	large_label = mem_alloc(15901, NULL);
	TEST_ASSERT(large_label != NULL);
	memset(large_label, 'x', 15900);
	large_label[15900] = '\0';
	err = alloc_transport_policy(&retry_server, 5003, 5003, 16384, 1024);
	TEST_ERR(err);
	err = alloc_transport(&retry_client, 5003, 5003);
	TEST_ERR(err);
	err = dc_channel_create(&retry_client.local, retry_client.transport,
				large_label, &config);
	TEST_ERR(err);
	err = dc_channel_create(&retry_client.local2, retry_client.transport,
				large_label, &config);
	TEST_ERR(err);
	err = dc_channel_create(&retry_client.local3, retry_client.transport,
				large_label, &config);
	TEST_ERR(err);
	err = dc_channel_create(&retry_client.local4, retry_client.transport,
				large_label, &config);
	TEST_ERR(err);
	err = dc_transport_start(retry_server.transport, DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(retry_client.transport, DC_ROLE_CLIENT);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 5000;
	while (dc_channel_state(retry_client.local4) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&retry_client, &retry_server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(retry_client.local4));

	err = alloc_transport(&lifecycle_server, 5004, 5004);
	TEST_ERR(err);
	err = alloc_transport(&lifecycle_client, 5004, 5004);
	TEST_ERR(err);
	err = dc_channel_create(&lifecycle_client.local,
				lifecycle_client.transport,
				"callback-output-close", &config);
	TEST_ERR(err);
	err = dc_transport_start(lifecycle_server.transport, DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(lifecycle_client.transport, DC_ROLE_CLIENT);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(lifecycle_client.local) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&lifecycle_client, &lifecycle_server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(lifecycle_client.local));
	lifecycle_client.close_on_packet = lifecycle_client.local;
	err = dc_channel_send(lifecycle_client.local, DC_MESSAGE_BINARY,
			      payload, sizeof(payload));
	TEST_ERR(err);
	TEST_EQUALS(DC_STATE_CLOSING,
		    dc_channel_state(lifecycle_client.local));

	err = dc_channel_create(&lifecycle_client.local2,
				lifecycle_client.transport,
				"timer-output-error", &config);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(lifecycle_client.local2) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&lifecycle_client, &lifecycle_server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(lifecycle_client.local2));
	lifecycle_client.drop_packets = 1;
	err = dc_channel_send(lifecycle_client.local2, DC_MESSAGE_BINARY,
			      payload, sizeof(payload));
	TEST_ERR(err);
	TEST_EQUALS(1, (int)lifecycle_client.dropped_packets);
	lifecycle_client.output_error = EIO;
	deadline = tmr_jiffies() + 5000;
	while (dc_channel_state(lifecycle_client.local2) != DC_STATE_CLOSED &&
	       tmr_jiffies() < deadline) {
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS(DC_STATE_CLOSED,
		    dc_channel_state(lifecycle_client.local2));
	TEST_EQUALS(EIO, lifecycle_client.close_error);

	(void)dc_transport_close(lifecycle_client.transport, ECANCELED);
	(void)dc_transport_close(lifecycle_server.transport, ECANCELED);
	flush_packets(&lifecycle_client);
	flush_packets(&lifecycle_server);
	lifecycle_client.local = mem_deref(lifecycle_client.local);
	lifecycle_client.local2 = mem_deref(lifecycle_client.local2);
	lifecycle_client.remote = mem_deref(lifecycle_client.remote);
	lifecycle_server.remote = mem_deref(lifecycle_server.remote);
	lifecycle_client.transport =
		mem_deref(lifecycle_client.transport);
	lifecycle_server.transport =
		mem_deref(lifecycle_server.transport);
	deadline = tmr_jiffies() + 100;
	while (tmr_jiffies() < deadline) {
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}

	err = alloc_liveness_transport(&liveness_server, 5005);
	TEST_ERR(err);
	err = alloc_liveness_transport(&liveness_client, 5005);
	TEST_ERR(err);
	err = dc_channel_create(&liveness_client.local,
				liveness_client.transport,
				"abrupt-peer-death", &config);
	TEST_ERR(err);
	err = dc_transport_start(liveness_server.transport, DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(liveness_client.transport, DC_ROLE_CLIENT);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(liveness_client.local) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&liveness_client, &liveness_server);
		TEST_ERR(err);
		sys_msleep(10);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(liveness_client.local));

	/*
	 * The test policy has a conservative failure budget below 500 ms:
	 * (50 ms heartbeat + 1.5 * 50 ms RTO) * (2 retries + 1).
	 */
	liveness_client.drop_all = true;
	liveness_server.drop_all = true;
	flush_packets(&liveness_client);
	flush_packets(&liveness_server);
	deadline = tmr_jiffies() + 1000;
	while (!liveness_client.transport_closed &&
	       tmr_jiffies() < deadline) {
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS(1, (int)liveness_client.transport_closed);
	TEST_EQUALS(ECONNRESET, liveness_client.transport_close_error);
	TEST_EQUALS(DC_STATE_CLOSED,
		    dc_channel_state(liveness_client.local));

	err = alloc_transport(&sync_server, 5006, 5006);
	TEST_ERR(err);
	err = alloc_transport(&sync_client, 5006, 5006);
	TEST_ERR(err);
	negotiated.id = 6;
	err = dc_channel_create(&sync_server.negotiated,
				sync_server.transport, "sync-ready",
				&negotiated);
	TEST_ERR(err);
	err = dc_channel_create(&sync_client.negotiated,
				sync_client.transport, "sync-ready",
				&negotiated);
	TEST_ERR(err);
	err = dc_transport_start(sync_server.transport, DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(sync_client.transport, DC_ROLE_CLIENT);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while (dc_channel_state(sync_client.negotiated) != DC_STATE_OPEN &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&sync_client, &sync_server);
		TEST_ERR(err);
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS(DC_STATE_OPEN,
		    dc_channel_state(sync_client.negotiated));
	sync_client.creating_channel = true;
	sync_client.send_on_open = true;
	err = dc_channel_create(&sync_client.local, sync_client.transport,
				"synchronous-publication", &config);
	sync_client.creating_channel = false;
	TEST_ERR(err);
	TEST_ASSERT(sync_client.local != NULL);
	TEST_ASSERT(!sync_client.create_callback_error);
	deadline = tmr_jiffies() + 3000;
	while ((dc_channel_state(sync_client.local) != DC_STATE_OPEN ||
		sync_client.send_on_open) &&
	       tmr_jiffies() < deadline) {
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_EQUALS(DC_STATE_OPEN, dc_channel_state(sync_client.local));
	TEST_ERR(sync_client.send_on_open_error);
	TEST_ASSERT(!sync_client.send_on_open);
	TEST_ASSERT(sync_server.incoming_seen);
	TEST_ASSERT(!sync_server.incoming_order_error);

	sync_client.synchronous = false;
	sync_server.synchronous = false;
	closing_before = sync_client.closing;
	closed_before = sync_client.closed;
	sync_client.release_local_on_close = true;
	err = dc_channel_close(sync_client.local);
	TEST_ERR(err);
	TEST_EQUALS((int)closing_before + 1, (int)sync_client.closing);
	TEST_EQUALS((int)closed_before, (int)sync_client.closed);
	TEST_EQUALS(DC_STATE_CLOSING, dc_channel_state(sync_client.local));
	deadline = tmr_jiffies() + 3000;
	while (sync_client.release_local_on_close &&
	       tmr_jiffies() < deadline) {
		do {
			err = pump_pair(&sync_client, &sync_server);
			TEST_ERR(err);
		} while ((sync_client.packets.head ||
			  sync_server.packets.head) &&
			 tmr_jiffies() < deadline);
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_ASSERT(!sync_client.release_local_on_close);
	TEST_EQUALS((int)closed_before + 1, (int)sync_client.closed);

	/* A reset generated for an unknown stream must quarantine that SID until
	 * bilateral completion.  Automatic allocation must skip it even though no
	 * application-facing channel has ever marked the ledger entry as used. */
	err = alloc_transport(&reset_alloc_server, 5016, 5016);
	TEST_ERR(err);
	err = alloc_transport(&reset_alloc_client, 5016, 5016);
	TEST_ERR(err);
	err = dc_transport_start(reset_alloc_server.transport, DC_ROLE_SERVER);
	TEST_ERR(err);
	err = dc_transport_start(reset_alloc_client.transport, DC_ROLE_CLIENT);
	TEST_ERR(err);
	deadline = tmr_jiffies() + 3000;
	while ((!dc_transport_association_ready(reset_alloc_client.transport) ||
		!dc_transport_association_ready(reset_alloc_server.transport)) &&
	       tmr_jiffies() < deadline) {
		err = pump_pair(&reset_alloc_client, &reset_alloc_server);
		TEST_ERR(err);
		err = re_main_timeout(10);
		if (err == ETIMEDOUT)
			err = 0;
		TEST_ERR(err);
	}
	TEST_ASSERT(dc_transport_association_ready(reset_alloc_client.transport));
	++reset_alloc_client.transport->input_depth;
	err = dc_request_stream_reset(reset_alloc_client.transport, 0,
				      SCTP_STREAM_RESET_OUTGOING);
	TEST_ERR(err);
	err = dc_channel_create(&reset_alloc_client.local,
				reset_alloc_client.transport,
				"reset-in-flight-exclusion", &config);
	--reset_alloc_client.transport->input_depth;
	TEST_ERR(err);
	TEST_EQUALS(2, dc_channel_id(reset_alloc_client.local));

	/* An unordered user message can overtake DCEP ACK.  It must be retained
	 * for this known local stream and published only after the OPEN state. */
	{
		const uint8_t early = 0x5a;
		const uint8_t ack = DCEP_ACK;
		unsigned opened = client.opened;
		unsigned messages = client.messages;
		uint16_t id;

		partial = config;
		partial.ordered = false;
		err = dc_channel_create(&client.pre_ack_source, client.transport,
					"pre-ack-reorder", &partial);
		TEST_ERR(err);
		TEST_EQUALS(DC_STATE_CONNECTING,
			    dc_channel_state(client.pre_ack_source));
		id = (uint16_t)dc_channel_id(client.pre_ack_source);
		TEST_ASSERT(client.pre_ack_source->open_sent);
		err = dc_receive_record(client.transport, id, PPID_BINARY,
					&early, sizeof(early), true);
		TEST_ERR(err);
		TEST_EQUALS((int)messages, (int)client.messages);
		TEST_EQUALS(1,
			    (int)list_count(&client.pre_ack_source->inboundq));
		err = dc_receive_record(client.transport, id, PPID_DCEP,
					&ack, sizeof(ack), true);
		TEST_ERR(err);
		TEST_EQUALS(DC_STATE_OPEN,
			    dc_channel_state(client.pre_ack_source));
		TEST_EQUALS((int)opened + 1, (int)client.opened);
		TEST_EQUALS((int)messages + 1, (int)client.messages);
		TEST_ASSERT(client.pre_ack_open_seen);
		TEST_ASSERT(client.pre_ack_message_ok);
		TEST_EQUALS(0,
			    (int)list_count(&client.pre_ack_source->inboundq));
	}

	/* Deployed WebRTC peers commonly encode the historical DCEP default as
	 * zero.  It maps to the constrained profile's RFC 8864 default weight. */
	{
		const uint8_t open[] = {
			DCEP_OPEN, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x0d, 0x00, 0x00,
			'w', 'i', 'r', 'e', '-', 'd', 'e', 'f', 'a', 'u', 'l', 't', '0'
		};
		struct dc_channel *remote;

		err = dc_receive_record(client.transport, 27, PPID_DCEP,
					open, sizeof(open), true);
		TEST_ERR(err);
		remote = dc_channel_find(client.transport, 27);
		TEST_ASSERT(remote != NULL);
		TEST_EQUALS(DC_PRIORITY_DEFAULT, remote->priority);
		TEST_EQUALS(DC_STATE_OPEN, remote->state);
	}

	/* A remote non-default priority is rejected before channel allocation or
	 * callback dispatch and closes the offending stream. */
	{
		const uint8_t open[] = {
			DCEP_OPEN, 0x00, 0x00, 0x80,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x0c, 0x00, 0x00,
			'b', 'a', 'd', '-', 'p', 'r', 'i', 'o', 'r', 'i', 't', 'y'
		};
		unsigned opened = client.opened;
		bool reset_requested = false;

		err = dc_receive_record(client.transport, 31, PPID_DCEP,
					open, sizeof(open), true);
		TEST_EQUALS(EPROTO, err);
		TEST_ASSERT(dc_channel_find(client.transport, 31) == NULL);
		TEST_EQUALS((int)opened, (int)client.opened);
		for (struct le *le = client.transport->reusable_ids.head;
		     le; le = le->next) {
			const struct dc_reusable_id *state = le->data;

			if (state->id == 31 &&
			    (state->requested_flags &
			     SCTP_STREAM_RESET_OUTGOING_SSN)) {
				reset_requested = true;
				break;
			}
		}
		TEST_ASSERT(reset_requested);
		err = 0;
	}

	/* Negative control: the RFC 8864 default priority is accepted. RFC 8832
	 * also ignores the reliability word for reliable channel types. */
	{
		const uint8_t open[] = {
			DCEP_OPEN, 0x00, 0x01, 0x00,
			0x01, 0x02, 0x03, 0x04,
			0x00, 0x08, 0x00, 0x00,
			'r', 'e', 'l', 'i', 'a', 'b', 'l', 'e'
		};
		struct dc_channel *remote;

		err = dc_receive_record(client.transport, 29, PPID_DCEP,
					open, sizeof(open), true);
		TEST_ERR(err);
		remote = dc_channel_find(client.transport, 29);
		TEST_ASSERT(remote != NULL);
		TEST_EQUALS(DC_RELIABLE, remote->reliability);
		TEST_EQUALS(0, remote->reliability_value);
		TEST_EQUALS(DC_STATE_OPEN, remote->state);
	}

	err = alloc_transport(&failed, 5001, 5001);
	TEST_ERR(err);
	err = dc_channel_create(&failed.local, failed.transport,
				"failed-output", &config);
	TEST_ERR(err);
	err = dc_transport_start(failed.transport, DC_ROLE_CLIENT);
	TEST_EQUALS(ENOTCONN, err);
	TEST_EQUALS(DC_STATE_CLOSED, dc_channel_state(failed.local));
	TEST_EQUALS(ENOTCONN, failed.close_error);
	TEST_EQUALS(0, (int)failed.closing);
	TEST_EQUALS(1, (int)failed.closed);
	err = 0;

out:
	if (client.transport)
		(void)dc_transport_close(client.transport, ECANCELED);
	if (server.transport)
		(void)dc_transport_close(server.transport, ECANCELED);
	if (failed.transport)
		(void)dc_transport_close(failed.transport, ECANCELED);
	if (narrow.transport)
		(void)dc_transport_close(narrow.transport, ECANCELED);
	if (wide.transport)
		(void)dc_transport_close(wide.transport, ECANCELED);
	if (retry_client.transport)
		(void)dc_transport_close(retry_client.transport, ECANCELED);
	if (retry_server.transport)
		(void)dc_transport_close(retry_server.transport, ECANCELED);
	if (lifecycle_client.transport)
		(void)dc_transport_close(lifecycle_client.transport, ECANCELED);
	if (lifecycle_server.transport)
		(void)dc_transport_close(lifecycle_server.transport, ECANCELED);
	if (liveness_client.transport)
		(void)dc_transport_close(liveness_client.transport, ECANCELED);
	if (liveness_server.transport)
		(void)dc_transport_close(liveness_server.transport, ECANCELED);
	if (sync_client.transport)
		(void)dc_transport_close(sync_client.transport, ECANCELED);
	if (sync_server.transport)
		(void)dc_transport_close(sync_server.transport, ECANCELED);
	if (reset_alloc_client.transport)
		(void)dc_transport_close(reset_alloc_client.transport, ECANCELED);
	if (reset_alloc_server.transport)
		(void)dc_transport_close(reset_alloc_server.transport, ECANCELED);
	if (reset_oom.transport)
		(void)dc_transport_close(reset_oom.transport, ECANCELED);
	if (reset_failed.transport)
		(void)dc_transport_close(reset_failed.transport, ECANCELED);
	if (timer_release_client.transport)
		(void)dc_transport_close(timer_release_client.transport,
					 ECANCELED);
	if (timer_release_server.transport)
		(void)dc_transport_close(timer_release_server.transport,
					 ECANCELED);
	if (association_lost.transport)
		(void)dc_transport_close(association_lost.transport, ECANCELED);
	if (association_shutdown.transport)
		(void)dc_transport_close(association_shutdown.transport, ECANCELED);
	if (terminal_close.transport)
		(void)dc_transport_close(terminal_close.transport, ECANCELED);
	flush_packets(&client);
	flush_packets(&server);
	flush_packets(&narrow);
	flush_packets(&wide);
	flush_packets(&liveness_client);
	flush_packets(&liveness_server);
	flush_packets(&retry_client);
	flush_packets(&retry_server);
	flush_packets(&lifecycle_client);
	flush_packets(&lifecycle_server);
	flush_packets(&sync_client);
	flush_packets(&sync_server);
	flush_packets(&reset_alloc_client);
	flush_packets(&reset_alloc_server);
	flush_packets(&timer_release_client);
	flush_packets(&timer_release_server);
	mem_deref(client.local);
	mem_deref(client.local2);
	mem_deref(client.local3);
	mem_deref(client.local4);
	mem_deref(client.local5);
	mem_deref(client.pre_ack_source);
	mem_deref(client.pre_ack_remote);
	mem_deref(client.reliable_remote);
	mem_deref(client.negotiated);
	mem_deref(client.late_negotiated);
	mem_deref(client.drain_source);
	mem_deref(client.fragment_source);
	mem_deref(client.fragment_remote);
	mem_deref(client.release_on_low);
	mem_deref(client.remote);
	mem_deref(server.local);
	mem_deref(server.ack_source);
	mem_deref(server.fragment_remote);
	mem_deref(server.pre_ack_remote);
	mem_deref(server.reliable_remote);
	mem_deref(server.remote);
	mem_deref(server.negotiated);
	mem_deref(server.late_negotiated);
	mem_deref(client.release_on_open);
	mem_deref(failed.local);
	mem_deref(narrow.local);
	mem_deref(narrow.local2);
	mem_deref(narrow.remote);
	mem_deref(wide.local);
	mem_deref(wide.local2);
	mem_deref(wide.local3);
	mem_deref(wide.local4);
	mem_deref(retry_client.local);
	mem_deref(retry_client.local2);
	mem_deref(retry_client.local3);
	mem_deref(retry_client.local4);
	mem_deref(retry_server.remote);
	mem_deref(lifecycle_client.local);
	mem_deref(lifecycle_client.local2);
	mem_deref(lifecycle_client.remote);
	mem_deref(lifecycle_server.remote);
	mem_deref(liveness_client.local);
	mem_deref(liveness_client.remote);
	mem_deref(liveness_server.remote);
	mem_deref(sync_client.local);
	mem_deref(sync_client.negotiated);
	mem_deref(sync_client.remote);
	mem_deref(sync_server.negotiated);
	mem_deref(sync_server.remote);
	mem_deref(reset_alloc_client.local);
	mem_deref(reset_alloc_client.remote);
	mem_deref(reset_alloc_server.remote);
	mem_deref(preclosed);
	mem_deref(reused_negotiated);
	mem_deref(bad_ppid);
	mem_deref(bad_text);
	mem_deref(large_label);
	client.transport = mem_deref(client.transport);
	server.transport = mem_deref(server.transport);
	failed.transport = mem_deref(failed.transport);
	narrow.transport = mem_deref(narrow.transport);
	wide.transport = mem_deref(wide.transport);
	retry_client.transport = mem_deref(retry_client.transport);
	retry_server.transport = mem_deref(retry_server.transport);
	lifecycle_client.transport = mem_deref(lifecycle_client.transport);
	lifecycle_server.transport = mem_deref(lifecycle_server.transport);
	liveness_client.transport = mem_deref(liveness_client.transport);
	liveness_server.transport = mem_deref(liveness_server.transport);
	sync_client.transport = mem_deref(sync_client.transport);
	sync_server.transport = mem_deref(sync_server.transport);
	reset_alloc_client.transport = mem_deref(reset_alloc_client.transport);
	reset_alloc_server.transport = mem_deref(reset_alloc_server.transport);
	reset_oom.transport = mem_deref(reset_oom.transport);
	reset_failed.local = mem_deref(reset_failed.local);
	reset_failed.local2 = mem_deref(reset_failed.local2);
	reset_failed.transport = mem_deref(reset_failed.transport);
	timer_release_client.local =
		mem_deref(timer_release_client.local);
	timer_release_client.remote =
		mem_deref(timer_release_client.remote);
	timer_release_server.remote =
		mem_deref(timer_release_server.remote);
	timer_release_client.transport =
		mem_deref(timer_release_client.transport);
	timer_release_server.transport =
		mem_deref(timer_release_server.transport);
	association_lost.transport = mem_deref(association_lost.transport);
	association_shutdown.transport =
		mem_deref(association_shutdown.transport);
	terminal_close.transport = mem_deref(terminal_close.transport);
	cross.endpoint.transport = mem_deref(cross.endpoint.transport);
	mtx_unlock(&datachannel_test_mtx);
	return err;
}
