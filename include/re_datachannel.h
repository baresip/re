/**
 * @file re_datachannel.h WebRTC data channels over caller-owned DTLS
 *
 * Copyright (C) 2026 The baresip project
 */

#ifndef RE_DATACHANNEL_H__
#define RE_DATACHANNEL_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mbuf;
struct dc_transport;
struct dc_channel;

#if defined(_WIN32)
#if defined(RE_DATACHANNEL_EXPORTS)
#define RE_DATACHANNEL_API __declspec(dllexport)
#else
#define RE_DATACHANNEL_API
#endif
#else
#define RE_DATACHANNEL_API __attribute__((visibility("default")))
#endif

#define RE_DATACHANNEL_API_VERSION 1U

/**
 * The only priority supported by the current equal-share SCTP profile.
 *
 * RFC 8864 defines 256 as the default WebRTC data-channel priority.  Until
 * the SCTP backend exposes RFC 8260 weighted-fair-queue stream weights, local
 * channel creation with any other value returns ENOTSUP. Incoming DCEP OPEN
 * priority zero, used as the default by deployed RFC 8832 peers, is normalized
 * to 256; any other non-default value is rejected as a channel protocol error.
 */
#define DC_PRIORITY_DEFAULT 256U

RE_DATACHANNEL_API uint32_t dc_api_version_1(void);

enum dc_role {
	DC_ROLE_CLIENT,
	DC_ROLE_SERVER
};

enum dc_state {
	DC_STATE_CONNECTING,
	DC_STATE_OPEN,
	DC_STATE_CLOSING,
	DC_STATE_CLOSED
};

enum dc_message_type {
	DC_MESSAGE_TEXT,
	DC_MESSAGE_BINARY
};

enum dc_reliability {
	DC_RELIABLE,
	DC_RELIABILITY_RETRANSMITS,
	DC_RELIABILITY_LIFETIME
};

struct dc_transport_config {
	uint16_t local_port;          /**< Local SCTP port                 */
	uint16_t remote_port;         /**< Remote SCTP port                */
	uint16_t outbound_streams;    /**< Initial outgoing stream count   */
	uint16_t inbound_streams;     /**< Maximum incoming stream count   */
	size_t receive_limit;         /**< Maximum incoming message bytes  */
	size_t send_limit;            /**< Maximum outgoing message bytes  */
	size_t send_high_water;       /**< Total outgoing memory budget    */
	size_t send_low_water;        /**< Per-channel low-water threshold */
	uint32_t heartbeat_interval_ms; /**< Idle path probe interval      */
	uint32_t rto_max_ms;          /**< Maximum retransmission timeout  */
	uint16_t max_retransmissions; /**< Path and association failures   */
};

struct dc_channel_config {
	const char *protocol;          /**< WebRTC subprotocol string       */
	uint16_t priority;             /**< Must be DC_PRIORITY_DEFAULT     */
	enum dc_reliability reliability; /**< Reliability policy           */
	uint32_t reliability_value;    /**< Retransmit or lifetime limit    */
	int id;                        /**< Negotiated SCTP stream id       */
	bool ordered;                 /**< Preserve message order          */
	bool negotiated;              /**< Do not use DCEP                 */
};

/**
 * Outbound packet callback.
 *
 * The packet is borrowed and valid only until the callback returns. The
 * callback runs synchronously and must copy the packet if it is retained.
 * A returned error fails the transport.
 */
typedef int (dc_packet_h)(struct mbuf *packet, void *arg);

/**
 * Incoming channel callback.
 *
 * The channel is borrowed for the callback. Retain it with mem_ref() before
 * returning if the application needs to keep it.
 */
typedef void (dc_channel_h)(struct dc_channel *channel, void *arg);

/** Message callback; the channel and payload are borrowed for the callback. */
typedef void (dc_message_h)(struct dc_channel *channel,
			    enum dc_message_type type,
			    const uint8_t *buf, size_t len, void *arg);

/** State callback; the channel is borrowed for the callback. */
typedef void (dc_state_h)(struct dc_channel *channel,
			  enum dc_state state, int err, void *arg);

/** Low-water callback; the channel is borrowed for the callback. */
typedef void (dc_buffered_low_h)(struct dc_channel *channel, void *arg);

/** Unexpected transport failure callback. */
typedef void (dc_transport_close_h)(int err, void *arg);

/**
 * Allocate a data-channel transport on the current libre event-loop thread.
 *
 * The usrsctp stack is process-global. All simultaneously live transports,
 * their channels, callbacks, input, and destruction therefore belong to the
 * thread that allocated the first transport. Allocation from another thread
 * returns EBUSY; mutable operations from another thread return EPERM. The
 * owning event loop must remain active until its final transport and channels
 * have been released.
 */
RE_DATACHANNEL_API int dc_transport_alloc(struct dc_transport **dtp,
		       const struct dc_transport_config *config,
		       dc_packet_h *packeth, dc_channel_h *channelh,
		       dc_message_h *messageh, dc_state_h *stateh,
		       dc_buffered_low_h *buffered_lowh,
		       dc_transport_close_h *closeh, void *arg);
RE_DATACHANNEL_API int dc_transport_start(struct dc_transport *dt,
					  enum dc_role local_role);
RE_DATACHANNEL_API int dc_transport_input(struct dc_transport *dt,
					  struct mbuf *packet);
RE_DATACHANNEL_API int dc_transport_close(struct dc_transport *dt, int err);
RE_DATACHANNEL_API bool
dc_transport_association_ready(const struct dc_transport *dt);
RE_DATACHANNEL_API uint64_t
dc_transport_invalid_text_count(const struct dc_transport *dt);

RE_DATACHANNEL_API int dc_channel_create(struct dc_channel **dcp,
		      struct dc_transport *dt,
		      const char *label,
		      const struct dc_channel_config *config);
RE_DATACHANNEL_API int dc_channel_send(struct dc_channel *dc,
		    enum dc_message_type type,
		    const uint8_t *buf, size_t len);
RE_DATACHANNEL_API int dc_channel_close(struct dc_channel *dc);
RE_DATACHANNEL_API const char *
dc_channel_label(const struct dc_channel *dc);
RE_DATACHANNEL_API const char *
dc_channel_protocol(const struct dc_channel *dc);
RE_DATACHANNEL_API int dc_channel_id(const struct dc_channel *dc);
RE_DATACHANNEL_API enum dc_state
dc_channel_state(const struct dc_channel *dc);
RE_DATACHANNEL_API size_t
dc_channel_buffered_amount(const struct dc_channel *dc);

#ifdef __cplusplus
}
#endif

#endif
