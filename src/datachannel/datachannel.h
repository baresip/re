#ifndef DATA_CHANNEL_INTERNAL_H__
#define DATA_CHANNEL_INTERNAL_H__

#include <re.h>
#include <re_datachannel.h>
#include <usrsctp.h>

enum {
	DCEP_ACK = 0x02,
	DCEP_OPEN = 0x03,
	PPID_DCEP = 50,
	PPID_TEXT = 51,
	PPID_BINARY = 53,
	PPID_TEXT_EMPTY = 56,
	PPID_BINARY_EMPTY = 57
};

struct dc_channel {
	struct le le;
	struct list sendq;
	struct list inboundq;
	struct tmr open_tmr;
	struct dc_transport *transport;
	char *label;
	char *protocol;
	enum dc_state state;
	enum dc_reliability reliability;
	uint32_t reliability_value;
	struct mbuf *inbound;
	struct dc_reusable_id *reservation;
	uint32_t inbound_ppid;
	size_t buffered_amount;
	uint16_t priority;
	int id;
	bool ordered;
	bool negotiated;
	bool remote;
	bool open_sent;
	bool ack_pending;
	bool open_pending;
	bool dispatching;
	bool draining_inbound;
	bool draining;
};

struct dc_transport {
	struct le global_le;
	struct list channels;
	struct list partials;
	struct list resets;
	struct list reusable_ids;
	struct list outbound_packets;
	struct socket *socket;
	struct dc_address *address;
	struct dc_transport_config config;
	dc_packet_h *packeth;
	dc_channel_h *channelh;
	dc_message_h *messageh;
	dc_state_h *stateh;
	dc_buffered_low_h *buffered_lowh;
	dc_transport_close_h *closeh;
	void *arg;
	enum dc_role role;
	sctp_assoc_t assoc_id;
	uint32_t next_id;
	uint16_t outbound_streams;
	uint16_t inbound_streams;
	size_t queued_amount;
	size_t inbound_amount;
	size_t queue_limit;
	size_t send_free;
	uint64_t invalid_text;
	unsigned input_depth;
	unsigned packet_callback_depth;
	int packet_error;
	bool registered;
	bool stack_acquired;
	bool started;
	bool association_up;
	bool draining_output;
	bool closing;
	bool close_notified;
};

int dc_request_stream_reset(struct dc_transport *dt, uint16_t id,
			    uint16_t flags);

struct dc_partial {
	struct le le;
	struct dc_transport *transport;
	struct mbuf *mb;
	size_t cost;
	uint32_t ppid;
	uint16_t id;
};

struct dc_message {
	struct le le;
	size_t len;
	size_t cost;
	size_t allocation_cost;
	size_t offset;
	uint32_t ppid;
	uint8_t data[];
};

struct dc_inbound {
	struct le le;
	struct dc_transport *transport;
	size_t len;
	size_t cost;
	uint32_t ppid;
	uint8_t data[];
};

struct dc_outbound {
	struct le le;
	struct mbuf *mb;
};

struct dc_reset {
	struct le le;
	uint16_t flags;
	uint16_t id;
	bool sent;
};

struct dc_reusable_id {
	struct le le;
	uint16_t requested_flags;
	uint16_t flags;
	uint16_t id;
	bool used;
	bool available;
};

bool dc_utf8_valid(const uint8_t *buf, size_t len, bool reject_nul);
struct dc_channel *dc_channel_find(struct dc_transport *dt, uint16_t id);
void dc_channel_set_state(struct dc_channel *dc, enum dc_state state, int err);
int dc_send_record(struct dc_channel *dc, uint32_t ppid,
		   const uint8_t *buf, size_t len);
void dc_sctp_send_params(struct sctp_sendv_spa *spa,
			 const struct dc_channel *dc, uint32_t ppid);
void dc_transport_fail(struct dc_transport *dt, int err);
void dc_handle_notification(struct dc_transport *dt,
			    const union sctp_notification *notification,
			    size_t len);
int dc_receive_record(struct dc_transport *dt, uint16_t id,
		      uint32_t ppid, const uint8_t *buf, size_t len,
		      bool complete);

#endif
