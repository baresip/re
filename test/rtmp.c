/**
 * @file rtmp.c RTMP Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "rtmp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define NUM_MEDIA_PACKETS 4


/* Force testing of Extended Timestamp */
#define TS_OFFSET 0x00fffffe


#define DUMMY_STREAM_ID 42


#define CHUNK_SIZE 4096


enum mode {
	MODE_PLAY,
	MODE_PUBLISH,
};


struct rtmp_endpoint {
	struct rtmp_endpoint *other;
	struct rtmp_conn *conn;
	struct rtmp_stream *stream;
	struct tcp_sock *ts;     /* server only */
	struct tls *tls;
	const char *tag;
	enum mode mode;
	uint32_t stream_id;
	bool is_client;
	unsigned n_estab;
	unsigned n_cmd;
	unsigned n_stream_cmd;
	unsigned n_close;
	unsigned n_ready;
	unsigned n_play;
	unsigned n_publish;
	unsigned n_publish_start;
	unsigned n_deletestream;
	unsigned n_audio;
	unsigned n_video;
	unsigned n_data;
	int err;
};


static const uint8_t fake_audio_packet[CHUNK_SIZE + 6] = {
	0x5b, 0xb2, 0xfb, 0x11, 0x46, 0xe9
};

static const uint8_t fake_video_packet[CHUNK_SIZE + 8] = {
	0xcb, 0x9c, 0xb5, 0x60, 0x7f, 0xe9, 0xbd, 0xe1
};

static const char *fake_stream_name = "sample.mp4";
static const char *fake_app_inst = "vod";


static void endpoint_terminate(struct rtmp_endpoint *ep, int err)
{
	if (err) {
		DEBUG_INFO("[ %s ] terminate: %m\n", ep->tag, err);
	}

	ep->err = err;
	re_cancel();
}


/* criteria for test to be finished */
static bool client_is_finished(const struct rtmp_endpoint *ep)
{
	switch (ep->mode) {

	case MODE_PLAY:
		return ep->n_ready > 0 &&
			ep->n_audio >= NUM_MEDIA_PACKETS &&
			ep->n_video >= NUM_MEDIA_PACKETS;

	case MODE_PUBLISH:
		return ep->n_ready > 0 &&
			ep->n_publish_start > 0;
	}

	return false;
}


static bool server_is_finished(const struct rtmp_endpoint *ep)
{
	switch (ep->mode) {

	case MODE_PLAY:
		return ep->n_play > 0;

	case MODE_PUBLISH:
		return ep->n_publish > 0 &&
			ep->n_audio >= NUM_MEDIA_PACKETS &&
			ep->n_video >= NUM_MEDIA_PACKETS;
	}

	return false;
}


static bool endpoints_are_finished(const struct rtmp_endpoint *ep)
{
	if (ep->is_client) {
		return client_is_finished(ep) &&
			server_is_finished(ep->other);
	}
	else {
		return client_is_finished(ep->other) &&
			server_is_finished(ep);
	}
}


static int send_media(struct rtmp_endpoint *ep_cli)
{
	unsigned i;
	int err = 0;

	/* Send some dummy media packets to server */
	for (i=0; i<NUM_MEDIA_PACKETS; i++) {

		err = rtmp_send_audio(ep_cli->stream, i,
				      fake_audio_packet,
				      sizeof(fake_audio_packet));
		if (err)
			return err;

		err = rtmp_send_video(ep_cli->stream,
				      TS_OFFSET + i,
				      fake_video_packet,
				      sizeof(fake_video_packet));
		if (err)
			return err;
	}

	return 0;
}


static void stream_command_handler(const struct odict *msg, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	const char *name;
	int err = 0;

	name = odict_string(msg, "0");

	DEBUG_INFO("[%s] stream command: %s\n", ep->tag, name);

	TEST_EQUALS(DUMMY_STREAM_ID, ep->stream_id);

	++ep->n_stream_cmd;

	if (0 == str_casecmp(name, "play")) {

		const char *stream_name;
		uint64_t tid;
		uint32_t i;

		++ep->n_play;

		if (!odict_get_number(msg, &tid, "1")) {
			err = EPROTO;
			goto out;
		}
		TEST_EQUALS(0, tid);

		stream_name = odict_string(msg, "3");
		TEST_STRCMP(fake_stream_name, strlen(fake_stream_name),
			    stream_name, str_len(stream_name));

		err = rtmp_amf_data(ep->conn, DUMMY_STREAM_ID,
				    "|RtmpSampleAccess",
				    2,
				        RTMP_AMF_TYPE_BOOLEAN, false,
				        RTMP_AMF_TYPE_BOOLEAN, false);
		if (err)
			goto out;

		/* Send some dummy media packets to client */

		for (i=0; i<NUM_MEDIA_PACKETS; i++) {

			err = rtmp_send_audio(ep->stream, i,
					      fake_audio_packet,
					      sizeof(fake_audio_packet));
			if (err)
				goto out;

			err = rtmp_send_video(ep->stream, TS_OFFSET + i,
					      fake_video_packet,
					      sizeof(fake_video_packet));
			if (err)
				goto out;
		}
	}
	else if (0 == str_casecmp(name, "publish")) {

		const char *stream_name;
		const char *code = "NetStream.Publish.Start";
		uint64_t tid;

		++ep->n_publish;

		if (!odict_get_number(msg, &tid, "1")) {
			err = EPROTO;
			goto out;
		}
		TEST_EQUALS(0, tid);

		stream_name = odict_string(msg, "3");
		TEST_STRCMP(fake_stream_name, strlen(fake_stream_name),
			    stream_name, str_len(stream_name));

		err = rtmp_amf_command(ep->conn, ep->stream_id, "onStatus",
			       3,
			       RTMP_AMF_TYPE_NUMBER, (double)0,
			       RTMP_AMF_TYPE_NULL,
			       RTMP_AMF_TYPE_OBJECT, 2,
			           RTMP_AMF_TYPE_STRING, "level", "status",
			           RTMP_AMF_TYPE_STRING, "code", code);
		if (err)
			goto out;
	}
	else if (0 == str_casecmp(name, "onStatus")) {

		struct odict *obj;
		const char *level;

		obj = odict_get_object(msg, "3");

		level = odict_string(obj, "level");
		if (0 == str_casecmp(level, "status")) {

			const char *code = odict_string(obj, "code");
			const char *exp_code = "NetStream.Publish.Start";

			++ep->n_publish_start;

			TEST_STRCMP(exp_code, str_len(exp_code),
				    code, str_len(code));

			err = rtmp_meta(ep->stream);
			if (err)
				goto out;

			err = send_media(ep);
			if (err)
				goto out;
		}
		else {
			DEBUG_WARNING("unsupported level %s\n", level);
		}
	}
	else {
		DEBUG_NOTICE("[ %s ] stream: command not handled (%s)\n",
			     ep->tag, name);
		err = ENOTSUP;
		goto out;
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void test_done(struct rtmp_endpoint *ep)
{
	struct rtmp_endpoint *client;

	if (ep->is_client)
		client = ep;
	else
		client = ep->other;

	/* Force destruction here to test robustness */

	client->stream = mem_deref(client->stream);
}


static void stream_control_handler(enum rtmp_event_type event, struct mbuf *mb,
				   void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err = 0;
	(void)mb;

	TEST_EQUALS(DUMMY_STREAM_ID, ep->stream_id);

	DEBUG_INFO("[ %s ] got control event:  event=%d (%s)\n",
		     ep->tag, event, rtmp_event_name(event));

	switch (event) {

	default:
		break;
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void audio_handler(uint32_t timestamp,
			  const uint8_t *pld, size_t len, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err = 0;

	TEST_EQUALS(DUMMY_STREAM_ID, ep->stream_id);

	TEST_EQUALS(ep->n_audio, timestamp);

	++ep->n_audio;

	TEST_MEMCMP(fake_audio_packet, sizeof(fake_audio_packet), pld, len);

	/* Test complete ? */
	if (endpoints_are_finished(ep)) {

		test_done(ep);
		return;
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void video_handler(uint32_t timestamp,
			  const uint8_t *pld, size_t len, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err = 0;

	TEST_EQUALS(DUMMY_STREAM_ID, ep->stream_id);

	TEST_EQUALS(TS_OFFSET + ep->n_video, timestamp);

	++ep->n_video;

	TEST_MEMCMP(fake_video_packet, sizeof(fake_video_packet), pld, len);

	/* Test complete ? */
	if (endpoints_are_finished(ep)) {

		test_done(ep);
		return;
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void stream_data_handler(const struct odict *msg, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	const char *command;
	bool ret;
	bool value;
	int err = 0;

	TEST_EQUALS(DUMMY_STREAM_ID, ep->stream_id);

	++ep->n_data;

	command = odict_string(msg, "0");

	if (ep->is_client) {

		TEST_STRCMP("|RtmpSampleAccess", 17,
			    command, str_len(command));

		ret = odict_get_boolean(msg, &value, "1");
		TEST_ASSERT(ret);
		TEST_ASSERT(!value);

		ret = odict_get_boolean(msg, &value, "2");
		TEST_ASSERT(ret);
		TEST_ASSERT(!value);
	}
	else {
		const struct odict_entry *e;
		uint64_t num;

		TEST_STRCMP("@setDataFrame", 13, command, str_len(command));

		e = odict_get_type(msg, ODICT_OBJECT, "2");
		TEST_ASSERT(e != NULL);

		ret = odict_get_number(odict_entry_object(e), &num,
				       "audiocodecid");
		TEST_ASSERT(ret);
		TEST_EQUALS(10ULL, num);

		ret = odict_get_number(odict_entry_object(e), &num,
				       "videocodecid");
		TEST_ASSERT(ret);
		TEST_EQUALS(7ULL, num);
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void stream_create_resp_handler(bool success,
				       const struct odict *msg, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	uint64_t stream_id;
	int err;

	TEST_ASSERT(success);

	++ep->n_ready;

	/* the stream-id was assigned by the server */
	if (!odict_get_number(msg, &stream_id, "3")) {
		err = EPROTO;
		goto out;
	}
	ep->stream_id = (uint32_t)stream_id;

	switch (ep->mode) {

	case MODE_PLAY:
		err = rtmp_play(ep->stream, fake_stream_name);
		if (err)
			goto out;
		break;

	case MODE_PUBLISH:
		err = rtmp_publish(ep->stream, fake_stream_name);
		if (err)
			goto out;
		break;

	default:
		err = EPROTO;
		goto out;
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void estab_handler(void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err = 0;

	DEBUG_INFO("[%s] Established\n", ep->tag);

	++ep->n_estab;

	if (ep->is_client) {

		TEST_ASSERT(ep->stream == NULL);

		err = rtmp_stream_create(&ep->stream, ep->conn,
					 stream_create_resp_handler,
					 stream_command_handler,
					 stream_control_handler,
					 audio_handler,
					 video_handler, stream_data_handler,
					 ep);
		if (err)
			goto out;
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


/* Server */
static int server_send_reply(struct rtmp_conn *conn, const struct odict *req)
{
	const char *code = "NetConnection.Connect.Success";
	const char *descr = "Connection succeeded.";
	int err;

	err = rtmp_amf_reply(conn, 0, true, req,
				2,

		RTMP_AMF_TYPE_OBJECT, 3,
			RTMP_AMF_TYPE_STRING, "fmsVer",       "FMS/3,5,7,7009",
			RTMP_AMF_TYPE_NUMBER, "capabilities", 31.0,
			RTMP_AMF_TYPE_NUMBER, "mode",         1.0,

		RTMP_AMF_TYPE_OBJECT, 6,
			RTMP_AMF_TYPE_STRING, "level",        "status",
			RTMP_AMF_TYPE_STRING, "code",         code,
			RTMP_AMF_TYPE_STRING, "description",  descr,
			RTMP_AMF_TYPE_ECMA_ARRAY,  "data",         1,
			    RTMP_AMF_TYPE_STRING, "version",      "3,5,7,7009",
			RTMP_AMF_TYPE_NUMBER, "clientid",     734806661.0,
			RTMP_AMF_TYPE_NUMBER, "objectEncoding", 0.0);

	return err;
}


static void command_handler(const struct odict *msg, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	const char *name;
	int err = 0;

	TEST_ASSERT(!ep->is_client);

	name = odict_string(msg, "0");

	++ep->n_cmd;

	if (0 == str_casecmp(name, "connect")) {

		const struct odict_entry *entry;
		uint32_t window_ack_size = 32000;
		const char *app;

		entry = odict_lookup(msg, "2");
		TEST_ASSERT(entry != NULL);

		app = odict_string(odict_entry_object(entry), "app");
		TEST_STRCMP(fake_app_inst, strlen(fake_app_inst),
			    app, str_len(app));

		err = rtmp_control(ep->conn, RTMP_TYPE_WINDOW_ACK_SIZE,
				   (uint32_t)window_ack_size);
		if (err)
			goto out;

		err = server_send_reply(ep->conn, msg);
		if (err) {
			re_printf("rtmp: reply failed (%m)\n", err);
			goto out;
		}
	}
	else if (0 == str_casecmp(name, "createStream")) {

		uint32_t stream_id = DUMMY_STREAM_ID;

		TEST_ASSERT(ep->stream == NULL);

		ep->stream_id = stream_id;

		err = rtmp_stream_alloc(&ep->stream, ep->conn, stream_id,
					stream_command_handler,
					stream_control_handler, audio_handler,
					video_handler, stream_data_handler,
					ep);
		if (err) {
			goto out;
		}

		err = rtmp_amf_reply(ep->conn, 0, true, msg,
					2,
				RTMP_AMF_TYPE_NULL,
				RTMP_AMF_TYPE_NUMBER, (double)stream_id);
		if (err) {
			re_printf("rtmp: reply failed (%m)\n", err);
			goto out;
		}
	}
	else if (0 == str_casecmp(name, "deleteStream")) {

		uint64_t stream_id;

		++ep->n_deletestream;

		if (!odict_get_number(msg, &stream_id, "3")) {
			err = EPROTO;
			goto out;
		}

		TEST_EQUALS(DUMMY_STREAM_ID, stream_id);

		if (stream_id == ep->stream_id)
			ep->stream = mem_deref(ep->stream);

		/* re_main will be stopped when the
		 * TCP connection is closed
		 */

		endpoint_terminate(ep, 0);
	}
	else {
		DEBUG_NOTICE("[ %s ] command not handled (%s)\n",
			     ep->tag, name);
		err = ENOTSUP;
		goto out;
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void close_handler(int err, void *arg)
{
	struct rtmp_endpoint *ep = arg;

	if (err) {
		DEBUG_INFO("[ %s ] rtmp connection closed (%m)\n",
			     ep->tag, err);
	}

	++ep->n_close;

	endpoint_terminate(ep, err);
}


static void endpoint_destructor(void *data)
{
	struct rtmp_endpoint *ep = data;

	mem_deref(ep->stream);
	mem_deref(ep->conn);
	mem_deref(ep->tls);
	mem_deref(ep->ts);
}


static struct rtmp_endpoint *rtmp_endpoint_alloc(enum mode mode,
						 bool is_client, bool secure)
{
	struct rtmp_endpoint *ep;
	int err = 0;

	ep = mem_zalloc(sizeof(*ep), endpoint_destructor);
	if (!ep)
		return NULL;

	ep->is_client = is_client;
	ep->mode = mode;

	if (secure) {

#ifdef USE_TLS
		char path[256];

		re_snprintf(path, sizeof(path), "%s/server-ecdsa.pem",
			    test_datapath());

		err = tls_alloc(&ep->tls, TLS_METHOD_SSLV23,
				is_client ? NULL : path, NULL);
		if (err)
			goto out;

		/* Client: Add the server's certificate as a CA cert.
		 *         This is required for authentication to work.
		 */
		if (is_client) {

			err = tls_add_ca(ep->tls, path);
			if (err)
				goto out;
		}
#else
		err = ENOSYS;
		goto out;
#endif
	}

	ep->tag = is_client ? "Client" : "Server";

 out:
	if (err)
		return mem_deref(ep);

	return ep;
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err;
	(void)peer;

	err = rtmp_accept(&ep->conn, ep->ts, ep->tls, command_handler,
			  close_handler, ep);
	if (err)
		goto out;

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static int test_rtmp_client_server_conn(enum mode mode, bool secure)
{
	struct rtmp_endpoint *cli, *srv;
	struct sa srv_addr;
	char uri[256];
	int err = 0;

	cli = rtmp_endpoint_alloc(mode, true, secure);
	srv = rtmp_endpoint_alloc(mode, false, secure);
	if (!cli || !srv) {
		err = ENOMEM;
		goto out;
	}

	cli->other = srv;
	srv->other = cli;

	err = sa_set_str(&srv_addr, "127.0.0.1", 0);
	TEST_ERR(err);

	err = tcp_listen(&srv->ts, &srv_addr, tcp_conn_handler, srv);
	if (err)
		goto out;

	err = tcp_local_get(srv->ts, &srv_addr);
	TEST_ERR(err);

	re_snprintf(uri, sizeof(uri), "rtmp%s://%J/%s/foo",
		    secure ? "s" : "", &srv_addr, fake_app_inst);

	err = rtmp_connect(&cli->conn, NULL, uri, cli->tls, estab_handler,
			   command_handler, close_handler, cli);
	if (err)
		goto out;

	err = re_main_timeout(1000);
	if (err)
		goto out;

	if (cli->err) {
		err = cli->err;
		goto out;
	}
	if (srv->err) {
		err = srv->err;
		goto out;
	}

	TEST_EQUALS(1, cli->n_estab);
	TEST_EQUALS(0, srv->n_estab);
	TEST_EQUALS(0, cli->n_cmd);
	TEST_EQUALS(3, srv->n_cmd);

	TEST_EQUALS(1, srv->n_stream_cmd);

	TEST_EQUALS(0, cli->n_close);

	TEST_EQUALS(1, cli->n_ready);
	TEST_EQUALS(0, srv->n_ready);
	TEST_EQUALS(0, cli->n_deletestream);
	TEST_EQUALS(1, srv->n_deletestream);

	switch (mode) {

	case MODE_PLAY:
		TEST_EQUALS(1, srv->n_play);
		TEST_EQUALS(0, srv->n_publish);

		TEST_EQUALS(NUM_MEDIA_PACKETS, cli->n_audio);
		TEST_EQUALS(NUM_MEDIA_PACKETS, cli->n_video);
		TEST_EQUALS(1,                 cli->n_data);
		TEST_EQUALS(0, srv->n_audio);
		TEST_EQUALS(0, srv->n_video);
		TEST_EQUALS(0, srv->n_data);
		break;

	case MODE_PUBLISH:
		TEST_EQUALS(0, srv->n_play);
		TEST_EQUALS(1, srv->n_publish);

		TEST_EQUALS(0, cli->n_audio);
		TEST_EQUALS(0, cli->n_video);
		TEST_EQUALS(0, cli->n_data);
		TEST_EQUALS(NUM_MEDIA_PACKETS, srv->n_audio);
		TEST_EQUALS(NUM_MEDIA_PACKETS, srv->n_video);
		TEST_EQUALS(1,                 srv->n_data);
		break;
	}

 out:
	mem_deref(srv);
	mem_deref(cli);

	return err;
}


int test_rtmp_play(void)
{
	int err = 0;

	err = test_rtmp_client_server_conn(MODE_PLAY, false);
	TEST_ERR(err);

out:
	return err;
}


int test_rtmp_publish(void)
{
	int err = 0;

	err = test_rtmp_client_server_conn(MODE_PUBLISH, false);
	TEST_ERR(err);

out:
	return err;
}


#ifdef USE_TLS
int test_rtmps_publish(void)
{
	int err = 0;

	err = test_rtmp_client_server_conn(MODE_PUBLISH, true);
	TEST_ERR(err);

out:
	return err;
}
#endif
