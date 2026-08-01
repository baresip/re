/**
 * @file sdp.c SDP Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define TEST_STRCMP_LEN(exp, actual) \
	TEST_STRCMP((exp), str_len((exp)), (actual), str_len((actual)))


static const char ref_host[] = "1.2.3.4";
static const uint16_t ref_port = 5004;
static const char ref_pt[] = "0";
static const char *ref_cname   = "PCMU";
static const char *cname_speex = "speex";
static const uint32_t ref_srate = 8000;
static const char ref_msg[] =
	"v=0\r\n"
	"o=- 1234 5678 IN IP4 1.2.3.4\r\n"
	"s=-\r\n"
	"c=IN IP4 1.2.3.4\r\n"
	"t=0 0\r\n"
	"m=audio 5004 RTP/AVP 0 110\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:110 speex/16000/2\r\n"
	"a=sendrecv\r\n";


static const char *msgs[] = {
	/* Counterpath */
	"v=0\n"
	"o=- 1 2 IN IP4 84.209.220.122\r\n"
	"s=<CounterPath eyeBeam 1.5>\r\n"
	"c=IN IP4 84.209.220.122\r\n"
	"t=0 0\r\n"
	"m=audio 24484 RTP/AVP 107 119 0 98 8 3 101\r\n"
	"a=alt:1 2 : 8KiUNmDF 2AKrU/iZ 192.168.1.100 24484\r\n"
	"a=alt:2 1 : uEmq9erD rG6uFpsK 84.209.220.122 24484\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=rtpmap:107 BV32/16000\r\n"
	"a=rtpmap:119 BV32-FEC/16000\r\n"
	"a=rtpmap:98 iLBC/8000\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
	"a=sendrecv\r\n"
	"a=x-rtp-session-id:EE42E5DC96034E1A95B8843DA28640E4\r\n"
	"m=video 5040 RTP/AVP 115 34\r\n"
	"a=alt:1 2 : 6zn66DoK 0TsJT2lQ 192.168.1.100 5040\r\n"
	"a=alt:2 1 : JTVNzu+a 8pvqo0dE 84.209.220.122 5040\r\n"
	"a=fmtp:115 QCIF=2 MAXBR=2180\r\n"
	"a=fmtp:34 QCIF=2 MAXBR=2180\r\n"
	"a=rtpmap:115 H263-1998/90000\r\n"
	"a=rtpmap:34 H263/90000\r\n"
	"a=sendrecv\r\n"
	"a=x-rtp-session-id:E6856C1F08904D6B88B129266C82D351\r\n",

	/** Freeswitch 1.0rc1 */
	"v=0\r\n"
	"o=FreeSWITCH 531003883936 28814208941 IN IP4 1.2.3.4\r\n"
	"s=FreeSWITCH\r\n"
	"c=IN IP4 1.2.3.4\r\n"
	"t=0 0\r\n"
	"a=sendrecv\r\n"
	"m=audio 16610 RTP/AVP 8 99 13\r\n"
	"a=rtpmap:8 PCMA/8000\r\n"
	"a=rtpmap:99 telephone-event/8000\r\n"
	"a=fmtp:99 0-16\r\n"
	"a=rtpmap:13 CN/8000\r\n"
	"a=ptime:20\r\n"
	"a=nortpproxy:yes\r\n",

	/* newline termination */
	"v=0\n"
	"o=- 531003883936 28814208941 IN IP4 1.2.3.4\n"
	"s=-\n"
	"t=0 0\n"
	"m=audio 16610 RTP/AVP 8\n"
	"c=IN IP4 1.2.3.4\n"
	"a=rtpmap:8 PCMA/8000\n",

	/* Polycom */
	"v=0\r\n"
	"o=- 1197975037 1197975037 IN IP4 192.168.9.74\r\n"
	"s=Polycom IP Phone\r\n"
	"c=IN IP4 192.168.9.74\r\n"
	"t=0 0\r\n"
	"m=audio 49200 RTP/AVP 8 0 9 18 96\r\n"
	"a=sendrecv\r\n"
	"a=crypto:1 AES_CM_128_HMAC_SHA1_80"
	" inline:tMuyik1Aiiq9p4DQVHhAASSWDEP7K7wo0cICOn39\r\n"
	"a=rtpmap:8 PCMA/8000\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:9 G722/8000\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=rtpmap:96 telephone-event/8000\r\n",

	/* Ekiga 3.0 */
	"v=0\r\n"
	"o=- 1235562135 1235562135 IN IP4 192.168.1.55\r\n"
	"s=Opal SIP Session\r\n"
	"c=IN IP4 192.168.1.55\r\n"
	"t=0 0\r\n"
	"m=audio 5062 RTP/AVP 106 105 9 117 8 0 104 103 102 120 3 116 101\r\n"
	"a=sendrecv\r\n"
	"a=rtpmap:106 CELT/48000/1\r\n"
	"a=rtpmap:105 CELT/32000/1\r\n"
	"a=rtpmap:9 G722/8000/1\r\n"
	"a=rtpmap:117 Speex/16000/1\r\n"
	"a=fmtp:117 sr=16000,mode=any\r\n"
	"a=rtpmap:8 PCMA/8000/1\r\n"
	"a=rtpmap:0 PCMU/8000/1\r\n"
	"a=rtpmap:104 G726-16/8000/1\r\n"
	"a=rtpmap:103 G726-24/8000/1\r\n"
	"a=rtpmap:102 G726-32/8000/1\r\n"
	"a=rtpmap:120 G726-40/8000/1\r\n"
	"a=rtpmap:3 gsm/8000/1\r\n"
	"a=rtpmap:116 Speex/8000/1\r\n"
	"a=fmtp:116 sr=8000,mode=any\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
	"a=fmtp:101 0-16,32,36\r\n"

	/* LG */
	"v=0\r\n"
	"o=LGN_IP_PHONE 29386 29386 IN IP4 192.168.1.97\r\n"
	"s=SIP Call\r\n"
	"c=IN IP4 85.112.135.82\r\n"
	"t=0 0\r\n"
	"m=audio 17412 RTP/AVP 9 8 0 18 101\r\n"
	"c=IN IP4 85.112.135.82\r\n"
	"b=AS:82\r\n"
	"a=rtpmap:9 G722/8000\r\n"
	"a=rtpmap:8 PCMA/8000\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=fmtp:18 annexb=no\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=ptime:20\r\n"
	"a=sendrecv\r\n"
	"m=video 16512 RTP/AVP 98 102 34 105\r\n"
	"c=IN IP4 85.112.135.82\r\n"
	"b=TIAS:329000\r\n"
	"b=AS:366\r\n"
	"a=rtpmap:98 H264/90000\r\n"
	"a=rtpmap:102 H264/90000\r\n"
	"a=fmtp:98 profile-level-id=42800C; packetization-mode=0\r\n"
	"a=fmtp:102 profile-level-id=42800C; packetization-mode=1\r\n"
	"a=rtpmap:34 H263/90000\r\n"
	"a=fmtp:34 CIF=1;QCIF=1\r\n"
	"a=rtpmap:105 MP4V-ES/90000\r\n"
};


/** Compare two SDP messages line-by-line (exclude owner) */
static bool sdp_cmp(struct mbuf *mb, const char *msg)
{
	struct pl pl;

	if (!mb || !msg)
		return false;

	pl.p = (char *)mb->buf;
	pl.l = mb->end;

	while (pl.l && strlen(msg)) {
		struct pl n1, v1, n2, v2;

		if (re_regex(pl.p, pl.l,
			     "[^=]1=[^\r\n]+", &n1, &v1))
			return false;

		if (re_regex(msg, strlen(msg),
			     "[^=]1=[^\r\n]+", &n2, &v2))
			return false;

		pl_advance(&pl, 2 + v1.l + 2);
		msg += (2 + v2.l + 2);

		if (0 != pl_cmp(&n1, &n2)) {
			DEBUG_WARNING("name mismatch: %r=%r\n", &n1, &v1);
			return false;
		}

		/* ignore owner */
		if (n1.p[0] == 'o')
			continue;

		if (0 != pl_cmp(&v1, &v2)) {
			DEBUG_WARNING("value mismatch: %r=%r\n",
				      &n1, &v1);
			return false;
		}
	}

	if (pl.l) {
		DEBUG_WARNING("%u bytes junk at end: %r\n", pl.l, &pl);
	}

	if (strlen(msg)) {
		DEBUG_WARNING("%u bytes junk at end: %s\n", strlen(msg), msg);
	}

	return !pl.l && !strlen(msg);
}


struct attr_values {
	const char *values[4];
	size_t count;
};


static bool collect_attr(const char *name, const char *value, void *arg)
{
	struct attr_values *values = arg;

	(void)name;
	if (values->count < RE_ARRAY_SIZE(values->values))
		values->values[values->count++] = value;
	return false;
}


static int test_sdp_session_state(void)
{
	static const char initial_remote[] =
		"v=0\r\n"
		"o=- 1 1 IN IP4 192.0.2.1\r\n"
		"s=-\r\n"
		"c=IN IP4 192.0.2.1\r\n"
		"b=AS:96\r\n"
		"t=0 0\r\n"
		"a=x-session:first\r\n"
		"a=x-session:second\r\n"
		"m=audio 4000 RTP/AVP 109 0\r\n"
		"c=IN IP4 192.0.2.2\r\n"
		"b=TIAS:64000\r\n"
		"a=rtpmap:109 opus/48000/2\r\n"
		"a=fmtp:109 minptime=10\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtcp:4001 IN IP4 192.0.2.3\r\n"
		"a=recvonly\r\n"
		"a=x-media:first\r\n"
		"a=x-media:second\r\n";
	static const char replacement_remote[] =
		"v=0\r\n"
		"o=- 2 2 IN IP4 198.51.100.1\r\n"
		"s=-\r\n"
		"c=IN IP4 198.51.100.1\r\n"
		"t=0 0\r\n"
		"a=x-session:replacement\r\n"
		"m=audio 9000 RTP/SAVP 112 0\r\n"
		"a=rtpmap:112 opus/48000/2\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=sendonly\r\n"
		"a=x-media:replacement\r\n"
		"m=video 9002 RTP/AVP 96\r\n"
		"a=rtpmap:96 VP8/90000\r\n";
	static const char malformed_remote[] =
		"v=0\r\n"
		"o=- 3 3 IN IP4 203.0.113.1\r\n"
		"s=-\r\n"
		"t=0 0\r\n"
		"a=x-session:partial\r\n"
		"m=audio 7000 RTP/SAVP 113 0\r\n"
		"a=rtpmap:113 opus/48000/2\r\n"
		"m=video 7002 RTP/AVP 96\r\n"
		"a=rtpmap:96 VP8/90000\r\n"
		"malformed-line\r\n";
	struct sdp_session_state *baseline_state = NULL;
	struct sdp_session_state *state = NULL;
	struct sdp_session *sess = NULL;
	struct sdp_media *audio = NULL;
	struct sdp_format *opus = NULL;
	const struct sdp_format *remote_opus;
	const struct sdp_format *saved_remote_pcmu;
	const struct sdp_format *saved_remote_opus;
	struct mbuf *remote = NULL;
	struct mbuf *baseline = NULL;
	struct mbuf *actual = NULL;
	struct attr_values attrs = {0};
	struct sa laddr;
	struct sa media_addr;
	struct sa rtcp_addr;
	struct sa expected_local;
	struct sa expected_media;
	struct sa expected_remote;
	struct sa expected_remote_rtcp;
	struct sa remote_rtcp;
	size_t negotiated_count;
	bool allocation_blocked = false;
	int err;

	err = sa_set_str(&laddr, "10.0.0.1", 0);
	if (err)
		goto out;
	err = sdp_session_alloc(&sess, &laddr);
	if (err)
		goto out;
	err = sdp_session_set_lattr(sess, false, "x-local", "first");
	err |= sdp_session_set_lattr(sess, false, "x-local", "second");
	sdp_session_set_lbandwidth(sess, SDP_BANDWIDTH_AS, 128);
	if (err)
		goto out;

	err = sa_set_str(&media_addr, "10.0.0.2", 5004);
	err |= sa_set_str(&rtcp_addr, "10.0.0.3", 5005);
	if (err)
		goto out;
	err = sdp_media_add(&audio, sess, sdp_media_audio,
			    sa_port(&media_addr), sdp_proto_rtpavp);
	if (err)
		goto out;
	sdp_media_set_laddr(audio, &media_addr);
	sdp_media_set_laddr_rtcp(audio, &rtcp_addr);
	sdp_media_set_lbandwidth(audio, SDP_BANDWIDTH_TIAS, 96000);
	sdp_media_set_ldir(audio, SDP_SENDRECV);
	err = sdp_media_set_alt_protos(audio, 1, "RTP/SAVP");
	err |= sdp_media_set_lattr(audio, false, "x-local-media", "first");
	err |= sdp_media_set_lattr(audio, false, "x-local-media", "second");
	err |= sdp_format_add(&opus, audio, false, "111", "opus",
			      48000, 2, NULL, NULL, NULL, false,
			      "stereo=1");
	err |= sdp_format_add(NULL, audio, false, "0", "PCMU",
			      8000, 1, NULL, NULL, NULL, false, NULL);
	if (err)
		goto out;

	remote = mbuf_alloc(sizeof(initial_remote));
	if (!remote) {
		err = ENOMEM;
		goto out;
	}
	err = mbuf_write_mem(remote, (const uint8_t *)initial_remote,
			     sizeof(initial_remote) - 1);
	if (err)
		goto out;
	remote->pos = 0;
	err = sdp_decode(sess, remote, true);
	if (err)
		goto out;

	saved_remote_opus = sdp_media_rformat(audio, "opus");
	saved_remote_pcmu = sdp_media_rformat(audio, "PCMU");
	if (!saved_remote_opus || !saved_remote_pcmu) {
		err = EPROTO;
		goto out;
	}
	negotiated_count = list_count(sdp_session_medial(sess, false));
	if (negotiated_count != 1) {
		err = EPROTO;
		goto out;
	}

	/*
	 * Encode a reference from this exact state, then roll that encode back:
	 * sdp_encode itself advances the origin version and can move media.
	 */
	err = sdp_session_state_save(&baseline_state, sess);
	if (!err)
		err = sdp_encode(&baseline, sess, false);
	if (err)
		goto out;
	sdp_session_state_restore(baseline_state);
	baseline_state = NULL;

	err = sdp_session_state_save(&state, sess);
	if (err)
		goto out;

	mbuf_reset(remote);
	err = mbuf_write_mem(remote, (const uint8_t *)replacement_remote,
			     sizeof(replacement_remote) - 1);
	if (err)
		goto out;
	remote->pos = 0;
	err = sdp_decode(sess, remote, true);
	if (err)
		goto out;

	err = sa_set_str(&laddr, "10.9.9.1", 0);
	if (err)
		goto out;
	sdp_session_set_laddr(sess, &laddr);
	sdp_session_set_lbandwidth(sess, SDP_BANDWIDTH_AS, 1);
	err = sdp_session_set_lattr(sess, true, "x-local", "changed");
	if (err)
		goto out;
	err = sa_set_str(&media_addr, "10.9.9.2", 9998);
	err |= sa_set_str(&rtcp_addr, "10.9.9.3", 9999);
	if (err)
		goto out;
	sdp_media_set_laddr(audio, &media_addr);
	sdp_media_set_laddr_rtcp(audio, &rtcp_addr);
	sdp_media_set_lbandwidth(audio, SDP_BANDWIDTH_TIAS, 1);
	sdp_media_set_ldir(audio, SDP_INACTIVE);
	sdp_media_set_disabled(audio, true);
	sdp_media_set_fmt_ignore(audio, true);
	err = sdp_media_set_lattr(audio, true, "x-local-media", "changed");
	err |= sdp_format_set_params(opus, "changed=1");
	err |= sdp_format_add(NULL, audio, false, NULL, "new-format",
			      16000, 1, NULL, NULL, NULL, false, NULL);
	err |= sdp_media_add(NULL, sess, "application", 9996,
			     "UDP/DTLS/SCTP");
	if (err)
		goto out;

	/* Any allocation attempted by restore now fails. */
	if (test_mode != TEST_MEMORY) {
		mem_threshold_set(0);
		allocation_blocked = true;
	}
	sdp_session_state_restore(state);
	state = NULL;
	if (allocation_blocked) {
		mem_threshold_set(-1);
		allocation_blocked = false;
	}

	if (list_count(sdp_session_medial(sess, false)) != negotiated_count ||
	    list_count(sdp_session_medial(sess, true)) != 0 ||
	    sdp_media_format(audio, true, NULL, 109, "opus",
			     48000, 2) != opus ||
	    sdp_media_format(audio, true, NULL, -1, "new-format",
			     16000, 1)) {
		err = EPROTO;
		goto out;
	}
	remote_opus = sdp_media_rformat(audio, "opus");
	if (remote_opus != saved_remote_opus ||
	    sdp_media_rformat(audio, "PCMU") != saved_remote_pcmu ||
	    list_head(sdp_media_format_lst(audio, false))->data !=
		    saved_remote_opus ||
	    list_tail(sdp_media_format_lst(audio, false))->data !=
		    saved_remote_pcmu ||
	    str_cmp(remote_opus->id, "109") ||
	    str_cmp(remote_opus->params, "minptime=10") ||
	    str_cmp(opus->params, "stereo=1") ||
	    str_cmp(sdp_media_proto(audio), sdp_proto_rtpavp)) {
		err = EPROTO;
		goto out;
	}

	attrs.count = 0;
	(void)sdp_session_lattr_apply(sess, "x-local",
				      collect_attr, &attrs);
	if (attrs.count != 2 ||
	    str_cmp(attrs.values[0], "first") ||
	    str_cmp(attrs.values[1], "second")) {
		err = EPROTO;
		goto out;
	}
	attrs.count = 0;
	(void)sdp_session_rattr_apply(sess, "x-session",
				      collect_attr, &attrs);
	if (attrs.count != 2 ||
	    str_cmp(attrs.values[0], "first") ||
	    str_cmp(attrs.values[1], "second") ||
	    sdp_session_lbandwidth(sess, SDP_BANDWIDTH_AS) != 128 ||
	    sdp_session_rbandwidth(sess, SDP_BANDWIDTH_AS) != 96) {
		err = EPROTO;
		goto out;
	}
	attrs.count = 0;
	(void)sdp_media_lattr_apply(audio, "x-local-media",
				    collect_attr, &attrs);
	if (attrs.count != 2 ||
	    str_cmp(attrs.values[0], "first") ||
	    str_cmp(attrs.values[1], "second")) {
		err = EPROTO;
		goto out;
	}
	attrs.count = 0;
	(void)sdp_media_rattr_apply(audio, "x-media",
				    collect_attr, &attrs);
	err = sa_set_str(&expected_local, "10.0.0.1", 0);
	err |= sa_set_str(&expected_media, "10.0.0.2", 5004);
	err |= sa_set_str(&expected_remote, "192.0.2.2", 4000);
	err |= sa_set_str(&expected_remote_rtcp, "192.0.2.3", 4001);
	if (err)
		goto out;
	sdp_media_raddr_rtcp(audio, &remote_rtcp);
	if (attrs.count != 2 ||
	    str_cmp(attrs.values[0], "first") ||
	    str_cmp(attrs.values[1], "second") ||
	    !sa_cmp(sdp_session_laddr(sess), &expected_local, SA_ALL) ||
	    !sa_cmp(sdp_media_laddr(audio), &expected_media, SA_ALL) ||
	    !sa_cmp(sdp_media_raddr(audio), &expected_remote, SA_ALL) ||
	    !sa_cmp(&remote_rtcp, &expected_remote_rtcp, SA_ALL) ||
	    sdp_media_rbandwidth(audio, SDP_BANDWIDTH_TIAS) != 64000 ||
	    sdp_media_rdir(audio) != SDP_SENDONLY ||
	    sdp_media_ldir(audio) != SDP_SENDRECV ||
	    sdp_media_disabled(audio)) {
		err = EPROTO;
		goto out;
	}

	/* A follow-up decode proves fmt_ignore was restored to false. */
	err = sdp_session_state_save(&state, sess);
	if (err)
		goto out;
	mbuf_reset(remote);
	err = mbuf_write_mem(remote, (const uint8_t *)replacement_remote,
			     sizeof(replacement_remote) - 1);
	if (err)
		goto out;
	remote->pos = 0;
	err = sdp_decode(sess, remote, true);
	if (err)
		goto out;
	if (sdp_media_format(audio, true, NULL, 112, "opus",
			     48000, 2) != opus) {
		err = EPROTO;
		goto out;
	}
	sdp_session_state_restore(state);
	state = NULL;

	/*
	 * A decode error after session, audio and a new remote-only video
	 * section have already been applied must still be fully reversible.
	 */
	err = sdp_session_state_save(&state, sess);
	if (err)
		goto out;
	mbuf_reset(remote);
	err = mbuf_write_mem(remote, (const uint8_t *)malformed_remote,
			     sizeof(malformed_remote) - 1);
	if (err)
		goto out;
	remote->pos = 0;
	err = sdp_decode(sess, remote, true);
	if (!err) {
		err = EPROTO;
		goto out;
	}
	err = 0;
	sdp_session_state_restore(state);
	state = NULL;
	if (list_count(sdp_session_medial(sess, false)) != negotiated_count ||
	    sdp_media_format(audio, true, NULL, 109, "opus",
			     48000, 2) != opus ||
	    sdp_media_rformat(audio, "opus") != saved_remote_opus) {
		err = EPROTO;
		goto out;
	}

	err = sdp_encode(&actual, sess, false);
	if (err)
		goto out;
	if (baseline->end != actual->end ||
	    memcmp(baseline->buf, actual->buf, baseline->end)) {
		err = EPROTO;
		goto out;
	}

	/*
	 * Discarding a state commits the replacement.  Exercise ownership
	 * release after the original remote formats have been displaced and
	 * new local/remote objects have been added.
	 */
	err = sdp_session_state_save(&state, sess);
	if (err)
		goto out;
	mbuf_reset(remote);
	err = mbuf_write_mem(remote, (const uint8_t *)replacement_remote,
			     sizeof(replacement_remote) - 1);
	if (err)
		goto out;
	remote->pos = 0;
	err = sdp_decode(sess, remote, true);
	if (!err)
		err = sdp_format_add(NULL, audio, false, NULL,
				     "committed-format", 32000, 1,
				     NULL, NULL, NULL, false, NULL);
	if (!err)
		err = sdp_media_add(NULL, sess, "application", 9994,
				    "UDP/DTLS/SCTP");
	if (err)
		goto out;
	state = mem_deref(state);

out:
	if (allocation_blocked)
		mem_threshold_set(-1);
	mem_deref(state);
	mem_deref(baseline_state);
	mem_deref(actual);
	mem_deref(baseline);
	mem_deref(remote);
	mem_deref(audio);
	mem_deref(sess);
	return err;
}


int test_sdp_all(void)
{
	struct sdp_session *sess = NULL;
	struct sdp_media *audio = NULL;
	struct sdp_media_lattr_state *attrs = NULL;
	struct mbuf *desc = NULL;
	struct sa ref;
	const struct sdp_format *rc = NULL, *sc;
	struct sa laddr;
	int err;

	err = test_sdp_session_state();
	if (err)
		return err;

	(void)sa_set_str(&laddr, ref_host, 0);

	err = sdp_session_alloc(&sess, &laddr);
	if (err)
		goto out;

	err = sdp_media_add(&audio, sess, sdp_media_audio, 5004,
			    sdp_proto_rtpavp);
	if (err)
		goto out;

	err  = sdp_format_add(NULL, audio, false, ref_pt, ref_cname,
			      ref_srate, 1, NULL, NULL, NULL, false, NULL);
	err |= sdp_format_add(NULL, audio, false, "110", cname_speex,
			      16000, 2, NULL, NULL, NULL, false, NULL);
	if (err)
		goto out;

	err = sdp_media_set_lattr(audio, false, "x-first", "one");
	err |= sdp_media_set_lattr(audio, false, "x-second", "two");
	err |= sdp_media_save_lattrs(&attrs, audio);
	if (err)
		goto out;

	err = sdp_media_set_lattr(audio, true, "x-first", "changed");
	err |= sdp_media_set_lattr(audio, false, "x-third", "three");
	sdp_media_del_lattr(audio, "x-second");
	if (err)
		goto out;

	err = sdp_media_apply_lattrs(audio, attrs);
	if (err)
		goto out;
	if (0 != str_cmp(sdp_media_lattr_apply(audio, "x-first", NULL, NULL),
			 "one") ||
	    0 != str_cmp(sdp_media_lattr_apply(audio, "x-second", NULL, NULL),
			 "two") ||
	    sdp_media_lattr_apply(audio, "x-third", NULL, NULL)) {
		err = EPROTO;
		goto out;
	}

	err = sdp_media_set_lattr(audio, true, "x-first", "changed-again");
	if (!err)
		err = sdp_media_apply_lattrs(audio, attrs);
	if (err)
		goto out;
	sdp_media_restore_lattrs(audio, attrs);
	attrs = NULL;
	if (0 != str_cmp(sdp_media_lattr_apply(audio, "x-first", NULL, NULL),
			 "one") ||
	    0 != str_cmp(sdp_media_lattr_apply(audio, "x-second", NULL, NULL),
			 "two") ||
	    sdp_media_lattr_apply(audio, "x-third", NULL, NULL)) {
		err = EPROTO;
		goto out;
	}

	sdp_media_del_lattr(audio, "x-first");
	sdp_media_del_lattr(audio, "x-second");
	err = sdp_media_save_lattrs(&attrs, audio);
	err |= sdp_media_set_lattr(audio, false, "x-third", "three");
	if (err)
		goto out;
	sdp_media_restore_lattrs(audio, attrs);
	attrs = NULL;
	if (sdp_media_lattr_apply(audio, "x-third", NULL, NULL)) {
		err = EPROTO;
		goto out;
	}

	/* find codec - expected */
	sc = sdp_media_format(audio, true, NULL, 0, "PCMU", 8000, 1);
	if (!sc) {
		DEBUG_WARNING("codec not found\n");
		err = ENOENT;
		goto out;
	}

	sc = sdp_media_format(audio, true, NULL, 110, "Speex", 16000, 2);
	if (!sc) {
		DEBUG_WARNING("codec not found: speex\n");
		err = ENOENT;
		goto out;
	}

	/* find codec - not expected */
	sc = sdp_media_format(audio, true, NULL, -1, "Speex", 8000, 1);
	if (sc) {
		DEBUG_WARNING("unexpected codec found\n");
		err = EINVAL;
		goto out;
	}

	err = sdp_encode(&desc, sess, true);
	if (err)
		goto out;

	if (!sdp_cmp(desc, ref_msg)) {
		DEBUG_WARNING("ref: %s\n", ref_msg);
		DEBUG_WARNING("sdp: %b\n", desc->buf, desc->end);
		err = EBADMSG;
		goto out;
	}

	err = sdp_decode(sess, desc, false);
	if (err)
		goto out;

	rc = sdp_media_rformat(audio, NULL);
	if (!rc) {
		err = ENOENT;
		goto out;
	}

	err = sa_set_str(&ref, ref_host, ref_port);
	if (err)
		goto out;

	err = EINVAL;

	if (!sa_cmp(sdp_media_raddr(audio), &ref, SA_ALL))
		goto out;

	if (0 != strcmp(rc->id, ref_pt))
		goto out;

	if (0 != strcmp(ref_cname, rc->name))
		goto out;

	if (rc->srate != ref_srate)
		goto out;

	err = 0;

 out:
	mem_deref(audio);
	mem_deref(sess);
	mem_deref(desc);
	mem_deref(attrs);

	return err;
}


/**
 * Test parsing of various SDP messages from various vendors
 */
int test_sdp_parse(void)
{
	struct sdp_session *sess = NULL;
	struct sdp_media *audio;
	struct mbuf *mb;
	struct sa laddr;
	uint32_t i;
	int err = 0;

	mb = mbuf_alloc(2048);
	if (!mb)
		return ENOMEM;

	sa_init(&laddr, AF_INET);

	for (i=0; i<RE_ARRAY_SIZE(msgs); i++) {

		sess = mem_deref(sess);

		err = sdp_session_alloc(&sess, &laddr);
		if (err)
			goto out;
		err = sdp_session_set_lattr(sess, true, "test-local",
					    "value");
		if (err)
			goto out;
		TEST_STRCMP_LEN(
			"value",
			sdp_session_lattr_apply(sess, "test-local",
						NULL, NULL));

		err = sdp_media_add(&audio, sess, sdp_media_audio, 5004,
				    sdp_proto_rtpavp);
		if (err)
			goto out;

		err = sdp_format_add(NULL, audio, false, ref_pt, ref_cname,
				     ref_srate, 1, NULL, NULL, NULL, false,
				     NULL);
		if (err)
			goto out;

		err = sdp_format_add(NULL, audio, false, "8", "PCMA", 8000, 1,
				     NULL, NULL, NULL, false, NULL);
		if (err)
			goto out;

		mbuf_rewind(mb);
		(void)mbuf_write_str(mb, msgs[i]);
		mb->pos = 0;

		err = sdp_decode(sess, mb, true);
		if (err)
			goto out;

		sdp_media_set_rdir(audio, SDP_SENDRECV);
		ASSERT_EQ(SDP_SENDRECV, sdp_media_rdir(audio));
		sdp_media_set_rport(audio, 9);
		ASSERT_EQ(9, sdp_media_rport(audio));
	}

 out:
	mem_deref(sess);
	mem_deref(mb);

	return err;
}


struct oa {
	struct sdp_session *alice, *bob;
};


static int oa_init(struct oa *oa)
{
	struct sa laddr;
	int err;

	if (!oa->alice) {
		(void)sa_set_str(&laddr, "1.2.3.4", 0);
		err = sdp_session_alloc(&oa->alice, &laddr);
		if (err)
			return err;
	}
	if (!oa->bob) {
		(void)sa_set_str(&laddr, "5.6.7.8", 0);
		err = sdp_session_alloc(&oa->bob, &laddr);
		if (err)
			return err;
	}

	return 0;
}


static void oa_reset(struct oa *oa)
{
	oa->alice = mem_deref(oa->alice);
	oa->bob = mem_deref(oa->bob);
}


static int oa_addmedia(struct oa *oa, bool local,
		       const char *mname, uint16_t port, const char *transp,
		       enum sdp_dir dir, uint32_t ncodec, ...)
{
	struct sdp_media *m;
	va_list ap;
	int err;

	err = oa_init(oa);
	if (err)
		return err;

	err = sdp_media_add(&m, local ? oa->alice : oa->bob,
			    mname, port, transp);
	if (err)
		return err;

	sdp_media_set_ldir(m, dir);

	va_start(ap, ncodec);

	while (ncodec--) {
		const char *id = va_arg(ap, char *);
		const char *cname = va_arg(ap, char *);
		int srate = va_arg(ap, int);

		err = sdp_format_add(NULL, m, false, id, cname, srate, 1,
				     NULL, NULL, NULL, false, NULL);
		if (err)
			break;
	}

	va_end(ap);

	return err;
}


static int oa_offeranswer(struct oa *oa, const char *offer, const char *answer)
{
	struct mbuf *mbo = NULL, *mba = NULL;
	int err = 0;

	/* create and send offer, compare offer */
	err = sdp_encode(&mbo, oa->alice, true);
	if (err)
		goto out;

	if (!sdp_cmp(mbo, offer)) {
		DEBUG_WARNING("offer failed:\n%b", mbo->buf, mbo->end);
		err = EBADMSG;
		goto out;
	}

	/* bob decodes offer */
	err = sdp_decode(oa->bob, mbo, true);
	if (err)
		goto out;

	/* create and send answer, compare answer */
	err = sdp_encode(&mba, oa->bob, false);
	if (err)
		goto out;

	if (!sdp_cmp(mba, answer)) {
		DEBUG_WARNING("answer failed:\n%b", mba->buf, mba->end);
		err = EBADMSG;
		TEST_ERR(err);
	}

	err = sdp_decode(oa->alice, mba, false);

 out:
	oa_reset(oa);
	mem_deref(mbo);
	mem_deref(mba);

	return err;
}


/* RFC 4317 - section 2.1 */
static int rfc4317_section2_1(struct oa *oa)
{
	int err = 0;

	err |= oa_addmedia(oa, 1, "audio", 49170, "RTP/AVP", SDP_SENDRECV, 3,
			   "0", "PCMU", 8000,
			   "8", "PCMA", 8000,
			   "97", "iLBC", 8000);
	err |= oa_addmedia(oa, 1, "video", 51372, "RTP/AVP", SDP_SENDRECV, 2,
			   "31", "H261", 90000,
			   "32", "MPV", 90000);
	err |= oa_addmedia(oa, 0, "audio", 49174, "RTP/AVP", SDP_SENDRECV, 1,
			   "0", "PCMU", 8000);
	err |= oa_addmedia(oa, 0, "video", 49170, "RTP/AVP", SDP_SENDRECV, 1,
			   "32", "MPV", 90000);
	if (err)
		return err;

	err = oa_offeranswer(oa,
			     "v=0\r\n"
			     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
			     "s=-\r\n"
			     "c=IN IP4 1.2.3.4\r\n"
			     "t=0 0\r\n"
			     "m=audio 49170 RTP/AVP 0 8 97\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=rtpmap:8 PCMA/8000\r\n"
			     "a=rtpmap:97 iLBC/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 51372 RTP/AVP 31 32\r\n"
			     "a=rtpmap:31 H261/90000\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=sendrecv\r\n"
			     ,
			     "v=0\r\n"
			     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
			     "s=-\r\n"
			     "c=IN IP4 5.6.7.8\r\n"
			     "t=0 0\r\n"
			     "m=audio 49174 RTP/AVP 0\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 49170 RTP/AVP 32\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=sendrecv\r\n");
	return err;
}


/* RFC 4317 - section 2.2 */
static int rfc4317_section2_2(struct oa *oa)
{
	int err = 0;

	err |= oa_addmedia(oa, 1, "audio", 49170, "RTP/AVP", SDP_SENDRECV, 3,
			   "0", "PCMU", 8000,
			   "8", "PCMA", 8000,
			   "97", "iLBC", 8000);
	err |= oa_addmedia(oa, 1, "video", 51372, "RTP/AVP", SDP_SENDRECV, 2,
			   "31", "H261", 90000,
			   "32", "MPV", 90000);
	err |= oa_addmedia(oa, 0, "audio", 49172, "RTP/AVP", SDP_SENDRECV, 2,
			   "0", "PCMU", 8000,
			   "8", "PCMA", 8000);
	if (err)
		return err;

	return oa_offeranswer(oa,
			     "v=0\r\n"
			     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
			     "s=-\r\n"
			     "c=IN IP4 1.2.3.4\r\n"
			     "t=0 0\r\n"
			     "m=audio 49170 RTP/AVP 0 8 97\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=rtpmap:8 PCMA/8000\r\n"
			     "a=rtpmap:97 iLBC/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 51372 RTP/AVP 31 32\r\n"
			     "a=rtpmap:31 H261/90000\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=sendrecv\r\n"
			     ,
			     "v=0\r\n"
			     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
			     "s=-\r\n"
			     "c=IN IP4 5.6.7.8\r\n"
			     "t=0 0\r\n"
			     "m=audio 49172 RTP/AVP 0 8\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=rtpmap:8 PCMA/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 0 RTP/AVP 0\r\n"
			     );
}


/* RFC 4317 - section 2.4 */
static int rfc4317_section2_4(struct oa *oa)
{
	int err = 0;

	err |= oa_addmedia(oa, 1, "audio", 49170, "RTP/AVP", SDP_SENDRECV, 2,
			   "0", "PCMU", 8000,
			   "97", "iLBC", 8000);
	err |= oa_addmedia(oa, 1, "audio", 49172, "RTP/AVP", SDP_SENDRECV, 1,
			   "98", "telephone-event", 8000);
	err |= oa_addmedia(oa, 0, "audio", 49172, "RTP/AVP", SDP_SENDRECV, 1,
			   "97", "iLBC", 8000);
	err |= oa_addmedia(oa, 0, "audio", 49174, "RTP/AVP", SDP_RECVONLY, 1,
			   "98", "telephone-event", 8000);
	if (err)
		return err;

	err = oa_offeranswer(oa,
			     "v=0\r\n"
			     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
			     "s=-\r\n"
			     "c=IN IP4 1.2.3.4\r\n"
			     "t=0 0\r\n"
			     "m=audio 49170 RTP/AVP 0 97\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=rtpmap:97 iLBC/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=audio 49172 RTP/AVP 98\r\n"
			     "a=rtpmap:98 telephone-event/8000\r\n"
			     "a=sendrecv\r\n"
			     ,
			     "v=0\r\n"
			     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
			     "s=-\r\n"
			     "c=IN IP4 5.6.7.8\r\n"
			     "t=0 0\r\n"
			     "m=audio 49172 RTP/AVP 97\r\n"
			     "a=rtpmap:97 iLBC/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=audio 49174 RTP/AVP 98\r\n"
			     "a=rtpmap:98 telephone-event/8000\r\n"
			     "a=recvonly\r\n");
	return err;
}


/* RFC 4317 - section 5.1 */
static int rfc4317_section5_1(struct oa *oa)
{
	int err = 0;

	err |= oa_init(oa);

	if (err)
		return err;

	err = oa_offeranswer(oa,
			     "v=0\r\n"
			     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
			     "s=-\r\n"
			     "c=IN IP4 1.2.3.4\r\n"
			     "t=0 0\r\n"
			     ,
			     "v=0\r\n"
			     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
			     "s=-\r\n"
			     "c=IN IP4 5.6.7.8\r\n"
			     "t=0 0\r\n");
	return err;
}


/** Test SDP Offer/Answer examples in RFC 4317 */
int test_sdp_oa(void)
{
	struct oa oa;
	int err = 0;

	memset(&oa, 0, sizeof(oa));

	err |= rfc4317_section2_1(&oa);
	err |= rfc4317_section2_2(&oa);
	err |= rfc4317_section2_4(&oa);
	err |= rfc4317_section5_1(&oa);

	oa_reset(&oa);

	return err;
}


/** Test BFCP in SDP -- RFC 4583 */
int test_sdp_bfcp(void)
{
	static const char *msg_offer =
		"v=0\r\n"
		"o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
		"s=-\r\n"
		"c=IN IP4 1.2.3.4\r\n"
		"t=0 0\r\n"
		"m=application 50000 TCP/BFCP *\r\n"
		"a=sendrecv\r\n"
		"a=setup:passive\r\n"
		"a=connection:new\r\n"
		"a=floorctrl:s-only\r\n"
		"a=confid:4321\r\n"
		"a=userid:1234\r\n"
		"a=floorid:1 m-stream:10\r\n"
		"a=floorid:2 m-stream:11\r\n"
		"m=audio 50002 RTP/AVP 0\r\n"
		"a=sendrecv\r\n"
		"a=label:10\r\n"
		"m=video 50004 RTP/AVP 31\r\n"
		"a=sendrecv\r\n"
		"a=label:11\r\n"
		;
	struct sdp_session *alice = NULL, *bob = NULL;
	struct sdp_media *bfcp, *audio, *video;
	struct mbuf *mbo = NULL, *mba = NULL;
	struct sa laddr;
	int err;

	/* create sessions */
	(void)sa_set_str(&laddr, "1.2.3.4", 0);
	err  = sdp_session_alloc(&alice, &laddr);
	if (err)
		goto out;

	err = sdp_media_add(&bfcp, alice, "application", 50000, "TCP/BFCP");
	if (err)
		goto out;

	err |= sdp_media_set_lattr(bfcp, true, "setup", "passive");
	err |= sdp_media_set_lattr(bfcp, true, "connection", "new");
	err |= sdp_media_set_lattr(bfcp, true, "floorctrl", "s-only");
	err |= sdp_media_set_lattr(bfcp, true, "confid", "4321");
	err |= sdp_media_set_lattr(bfcp, true, "userid", "1234");
	err |= sdp_media_set_lattr(bfcp, false, "floorid", "1 m-stream:10");
	sdp_media_del_lattr(bfcp, "floorid"); /* test attr delete */
	err |= sdp_media_set_lattr(bfcp, false, "floorid", "1 m-stream:10");
	err |= sdp_media_set_lattr(bfcp, false, "floorid", "2 m-stream:11");
	if (err)
		goto out;

	err = sdp_media_add(&audio, alice, "audio", 50002, "RTP/AVP");
	if (err)
		goto out;

	err = sdp_media_add(&video, alice, "video", 50004, "RTP/AVP");
	if (err)
		goto out;

	err |= sdp_media_set_lattr(audio, true, "label", "10");
	err |= sdp_media_set_lattr(video, true, "label", "11");
	if (err)
		goto out;

	err  = sdp_format_add(NULL, bfcp, false, "*", NULL, 0, 0,
			      NULL, NULL, NULL, false, NULL);
	err |= sdp_format_add(NULL, audio, false, "0", NULL, 0, 0,
			      NULL, NULL, NULL, false, NULL);
	err |= sdp_format_add(NULL, video, false, "31", NULL, 0, 0,
			      NULL, NULL, NULL, false, NULL);
	if (err)
		goto out;

	/* create and send offer, compare offer */
	err = sdp_encode(&mbo, alice, true);
	if (err)
		goto out;

	if (!sdp_cmp(mbo, msg_offer)) {
		DEBUG_WARNING("offer failed:\n%b", mbo->buf, mbo->end);
		err = EBADMSG;
		goto out;
	}

 out:
	mem_deref(alice);
	mem_deref(bob);
	mem_deref(mbo);
	mem_deref(mba);

	return err;
}


int test_sdp_extmap(void)
{
	static const char *extmapv[3] = {
		"extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
		"extmap:2/sendrecv http://example.com/ext.htm#xmeta short",
		"extmap:4096/recvonly URI-gps-string"
	};
	struct sdp_extmap ext;
	int err = 0;

	/* extmap 1 */
	err = sdp_extmap_decode(&ext, extmapv[0]);
	TEST_EQUALS(0, err);
	TEST_STRCMP("urn:ietf:params:rtp-hdrext:ssrc-audio-level",
		    strlen("urn:ietf:params:rtp-hdrext:ssrc-audio-level"),
		    ext.name.p, ext.name.l);
	TEST_ASSERT(!pl_isset(&ext.attrs));
	TEST_EQUALS(SDP_SENDRECV, ext.dir);
	TEST_ASSERT(!ext.dir_set);
	TEST_EQUALS(1, ext.id);

	/* extmap 2 */
	err = sdp_extmap_decode(&ext, extmapv[1]);
	TEST_EQUALS(0, err);
	TEST_STRCMP("http://example.com/ext.htm#xmeta",
		    strlen("http://example.com/ext.htm#xmeta"),
		    ext.name.p, ext.name.l);
	TEST_STRCMP("short", strlen("short"),
		    ext.attrs.p, ext.attrs.l);
	TEST_EQUALS(SDP_SENDRECV, ext.dir);
	TEST_ASSERT(ext.dir_set);
	TEST_EQUALS(2, ext.id);

	/* extmap 3 */
	err = sdp_extmap_decode(&ext, extmapv[2]);
	TEST_EQUALS(0, err);
	TEST_STRCMP("URI-gps-string",
		    strlen("URI-gps-string"),
		    ext.name.p, ext.name.l);
	TEST_ASSERT(!pl_isset(&ext.attrs));
	TEST_EQUALS(SDP_RECVONLY, ext.dir);
	TEST_ASSERT(ext.dir_set);
	TEST_EQUALS(4096, ext.id);

 out:
	return err;
}


static int disabled_local_medialine(struct oa *oa)
{
	int err = 0;

	err |= oa_addmedia(oa, 1, "audio", 49170, "RTP/AVP", SDP_SENDRECV, 3,
			   "0", "PCMU", 8000,
			   "8", "PCMA", 8000,
			   "97", "iLBC", 8000);
	err |= oa_addmedia(oa, 1, "video", 51372, "RTP/AVP", SDP_INACTIVE, 2,
			   "31", "H261", 90000,
			   "32", "MPV", 90000);
	err |= oa_addmedia(oa, 0, "audio", 49174, "RTP/AVP", SDP_SENDRECV, 1,
			   "0", "PCMU", 8000);
	err |= oa_addmedia(oa, 0, "video", 49170, "RTP/AVP", SDP_SENDRECV, 1,
			   "32", "MPV", 90000);
	if (err)
		return err;

	err = oa_offeranswer(oa,
			     "v=0\r\n"
			     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
			     "s=-\r\n"
			     "c=IN IP4 1.2.3.4\r\n"
			     "t=0 0\r\n"
			     "m=audio 49170 RTP/AVP 0 8 97\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=rtpmap:8 PCMA/8000\r\n"
			     "a=rtpmap:97 iLBC/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 51372 RTP/AVP 31 32\r\n"
			     "a=rtpmap:31 H261/90000\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=inactive\r\n"
			     ,
			     "v=0\r\n"
			     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
			     "s=-\r\n"
			     "c=IN IP4 5.6.7.8\r\n"
			     "t=0 0\r\n"
			     "m=audio 49174 RTP/AVP 0\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 49170 RTP/AVP 32\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=inactive\r\n");
	return err;
}


static int disabled_remote_medialine(struct oa *oa)
{
	int err = 0;

	err |= oa_addmedia(oa, 1, "audio", 49170, "RTP/AVP", SDP_SENDRECV, 3,
			   "0", "PCMU", 8000,
			   "8", "PCMA", 8000,
			   "97", "iLBC", 8000);
	err |= oa_addmedia(oa, 1, "video", 51372, "RTP/AVP", SDP_SENDRECV, 2,
			   "31", "H261", 90000,
			   "32", "MPV", 90000);
	err |= oa_addmedia(oa, 0, "audio", 49174, "RTP/AVP", SDP_SENDRECV, 1,
			   "0", "PCMU", 8000);
	err |= oa_addmedia(oa, 0, "video", 49170, "RTP/AVP", SDP_INACTIVE, 1,
			   "32", "MPV", 90000);
	if (err)
		return err;

	err = oa_offeranswer(oa,
			     "v=0\r\n"
			     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
			     "s=-\r\n"
			     "c=IN IP4 1.2.3.4\r\n"
			     "t=0 0\r\n"
			     "m=audio 49170 RTP/AVP 0 8 97\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=rtpmap:8 PCMA/8000\r\n"
			     "a=rtpmap:97 iLBC/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 51372 RTP/AVP 31 32\r\n"
			     "a=rtpmap:31 H261/90000\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=sendrecv\r\n"
			     ,
			     "v=0\r\n"
			     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
			     "s=-\r\n"
			     "c=IN IP4 5.6.7.8\r\n"
			     "t=0 0\r\n"
			     "m=audio 49174 RTP/AVP 0\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 49170 RTP/AVP 32\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=inactive\r\n");
	return err;
}


static int reject_video_medialine(struct oa *oa)
{
	int err = 0;

	err |= oa_addmedia(oa, 1, "audio", 49170, "RTP/AVP", SDP_SENDRECV, 3,
			   "0", "PCMU", 8000,
			   "8", "PCMA", 8000,
			   "97", "iLBC", 8000);
	err |= oa_addmedia(oa, 1, "video", 51372, "RTP/AVP", SDP_SENDRECV, 2,
			   "31", "H261", 90000,
			   "32", "MPV", 90000);
	err |= oa_addmedia(oa, 0, "audio", 49174, "RTP/AVP", SDP_SENDRECV, 1,
			   "0", "PCMU", 8000);

	if (err)
		return err;

	err = oa_offeranswer(oa,
			     "v=0\r\n"
			     "o=alice 2890844526 2890844526 IN IP4 1.2.3.4\r\n"
			     "s=-\r\n"
			     "c=IN IP4 1.2.3.4\r\n"
			     "t=0 0\r\n"
			     "m=audio 49170 RTP/AVP 0 8 97\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=rtpmap:8 PCMA/8000\r\n"
			     "a=rtpmap:97 iLBC/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 51372 RTP/AVP 31 32\r\n"
			     "a=rtpmap:31 H261/90000\r\n"
			     "a=rtpmap:32 MPV/90000\r\n"
			     "a=sendrecv\r\n"
			     ,
			     "v=0\r\n"
			     "o=bob 2808844564 2808844564 IN IP4 5.6.7.8\r\n"
			     "s=-\r\n"
			     "c=IN IP4 5.6.7.8\r\n"
			     "t=0 0\r\n"
			     "m=audio 49174 RTP/AVP 0\r\n"
			     "a=rtpmap:0 PCMU/8000\r\n"
			     "a=sendrecv\r\n"
			     "m=video 0 RTP/AVP 0\r\n");
	return err;
}


int test_sdp_disabled_rejected(void)
{
	struct oa oa;
	int err = 0;

	memset(&oa, 0, sizeof(oa));

	err |= disabled_local_medialine(&oa);
	err |= disabled_remote_medialine(&oa);
	err |= reject_video_medialine(&oa);

	oa_reset(&oa);

	return err;
}


struct fixture {
	struct sdp_session *sess;
	struct sdp_media *audio;
	struct sdp_media *video;
};

struct attr {
	const char *name;
	const char *value;
};

struct codec {
	const char *id;
	const char *name;
	uint32_t srate;
	uint8_t ch;
	bool audio;
};

struct args {
	const struct attr *attrv;
	size_t attrc;
	size_t ix;
};


static int fixture_init(struct fixture *fix,
			const struct attr *session_attrv,
			size_t session_attrc,
			const struct attr *media_attrv,
			size_t media_attrc,
			const struct codec *codecv,
			size_t codecc)
{
	struct sa laddr;

	int err = sa_set_str(&laddr, "127.0.0.1", 9);
	TEST_ERR(err);

	err = sdp_session_alloc(&fix->sess, &laddr);
	TEST_ERR(err);

	for (size_t i=0; i<session_attrc; i++) {
		const struct attr *attr = &session_attrv[i];

		err = sdp_session_set_lattr(fix->sess, false,
					    attr->name, attr->value);
		TEST_ERR(err);
	}

	err = sdp_media_add(&fix->audio, fix->sess, "audio",
			    9, "UDP/TLS/RTP/SAVPF");
	TEST_ERR(err);

	for (size_t i=0; i<media_attrc; i++) {
		const struct attr *attr = &media_attrv[i];

		err = sdp_media_set_lattr(fix->audio, false,
					  attr->name, attr->value);
		TEST_ERR(err);
	}

	for (size_t i=0; i<codecc; i++) {
		const struct codec *codec = &codecv[i];

		if (!codec->audio)
			continue;

		err = sdp_format_add(NULL, fix->audio, false, codec->id,
				     codec->name, codec->srate, codec->ch,
				     NULL, NULL, NULL, false, NULL);
		TEST_ERR(err);
	}

	err = sdp_media_add(&fix->video, fix->sess, "video",
			    10, "RTP/AVP");
	TEST_ERR(err);

	for (size_t i=0; i<codecc; i++) {
		const struct codec *codec = &codecv[i];

		if (codec->audio)
			continue;

		err = sdp_format_add(NULL, fix->video, false, codec->id,
				     codec->name, codec->srate, codec->ch,
				     NULL, NULL, NULL, false, NULL);
		TEST_ERR(err);
	}

 out:
	return err;
}


static void fixture_close(struct fixture *fix)
{
	mem_deref(fix->audio);
	mem_deref(fix->sess);
}


static bool sdp_attr_handler(const char *name, const char *value, void *arg)
{
	struct args *args = arg;
	int err = 0;

	if (args->ix >= args->attrc) {
		DEBUG_WARNING("sdp_attr_handler: attr count mismatch\n");
		return true;
	}

	const struct attr *attr = &args->attrv[args->ix];

	TEST_STRCMP_LEN(attr->name, name);
	TEST_STRCMP_LEN(attr->value, value);

	++args->ix;

 out:
	return err != 0;
}


static int test_sdp_param(const char *sdp,
			  const struct attr *session_attrv,
			  size_t session_attrc,
			  const struct attr *media_attrv,
			  size_t media_attrc,
			  const struct codec *codecv,
			  size_t codecc)
{
	struct fixture fix = { 0 };
	struct mbuf *offer = mbuf_alloc(str_len(sdp));

	if (!offer)
		return ENOMEM;

	int err = mbuf_write_str(offer, sdp);
	if (err)
		goto out;

	mbuf_set_pos(offer, 0);

	err = fixture_init(&fix,
			   session_attrv, session_attrc,
			   media_attrv, media_attrc,
			   codecv, codecc);
	TEST_ERR(err);

	err = sdp_decode(fix.sess, offer, true);
	TEST_ERR(err);

	for (size_t i=0; i<session_attrc; i++) {
		const struct attr *attr = &session_attrv[i];

		const char *rattr = sdp_session_rattr(fix.sess, attr->name);
		TEST_STRCMP_LEN(attr->value, rattr);
	}

	struct args args = {
		.attrv = media_attrv,
		.attrc = media_attrc
	};

	sdp_media_rattr_apply(fix.audio, NULL, sdp_attr_handler, &args);
	ASSERT_EQ(media_attrc, args.ix);

	TEST_STRCMP_LEN("UDP/TLS/RTP/SAVPF", sdp_media_proto(fix.audio));

	const struct sdp_format *audio_fmt =
		sdp_media_rformat(fix.audio, NULL);
	TEST_STRCMP_LEN("opus", audio_fmt->name);

	const struct sdp_format *video_fmt =
		sdp_media_lformat(fix.video, 102);
	TEST_ASSERT(video_fmt);
	TEST_STRCMP_LEN("H264", video_fmt->name);

 out:
	fixture_close(&fix);
	mem_deref(offer);

	return err;
}


int test_sdp_interop(void)
{
	static const char sdp_chrome[] =

	"v=0\r\n"
	"o=- 6851975412855494469 2 IN IP4 127.0.0.1\r\n"
	"s=-\r\n"
	"c=IN IP4 127.0.0.1\r\n"
	"t=0 0\r\n"
	"a=group:BUNDLE 0 1\r\n"
	"a=extmap-allow-mixed\r\n"
	"a=msid-semantic: WMS 2a30d377-cd13-4454-974c-0144db0118a6\r\n"
	"m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126\r\n"
	"c=IN IP4 0.0.0.0\r\n"
	"a=rtcp:9 IN IP4 0.0.0.0\r\n"
	"a=ice-ufrag:ie02\r\n"
	"a=ice-pwd:CWO5WLKWo2j5QmsY1396cvFe\r\n"
	"a=ice-options:trickle\r\n"
	"a=fingerprint:sha-256"
	  " A9:1F:F1:FD:FB:90:7D:4D:F7:DF:C4:6E:F8:6A:7B:E7"
	  ":87:1B:07:4E:22:3C:80:99:83:E6:9A:34:BD:93:F5:CE\r\n"
	"a=setup:actpass\r\n"
	"a=mid:0\r\n"
	"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
	"a=extmap:2"
	  " http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
	"a=extmap:3 http://www.ietf.org/id/"
	  "draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
	"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
	"a=sendrecv\r\n"
	"a=msid:2a30d377-cd13-4454-974c-0144db0118a6"
	  " c061a2b9-95bc-45fb-9e5d-6df08d8e1d0f\r\n"
	"a=rtcp-mux\r\n"
	"a=rtcp-rsize\r\n"
	"a=rtpmap:111 opus/48000/2\r\n"
	"a=rtcp-fb:111 transport-cc\r\n"
	"a=fmtp:111 minptime=10;useinbandfec=1\r\n"
	"a=rtpmap:63 red/48000/2\r\n"
	"a=fmtp:63 111/111\r\n"
	"a=rtpmap:9 G722/8000\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:8 PCMA/8000\r\n"
	"a=rtpmap:13 CN/8000\r\n"
	"a=rtpmap:110 telephone-event/48000\r\n"
	"a=rtpmap:126 telephone-event/8000\r\n"
	"a=ssrc:2161565476 cname:P6e47zI3iVPviKRL\r\n"
	"a=ssrc:2161565476 msid:2a30d377-cd13-4454-974c-0144db0118a6"
	  " c061a2b9-95bc-45fb-9e5d-6df08d8e1d0f\r\n"
	"m=video 29942 RTP/AVP 102 104 106 108 127 112 116\r\n"
	"b=AS:3072\r\n"
	"a=rtpmap:102 H264/90000\r\n"
	"a=fmtp:102 level-asymmetry-allowed=1;"
	  "packetization-mode=1;profile-level-id=42001f\r\n"
	"a=rtpmap:104 H264/90000\r\n"
	"a=fmtp:104 level-asymmetry-allowed=1;"
	  "packetization-mode=0;profile-level-id=42001f\r\n"
	"a=rtpmap:106 H264/90000\r\n"
	"a=fmtp:106 level-asymmetry-allowed=1;"
	  "packetization-mode=1;profile-level-id=42e01f\r\n"
	"a=rtpmap:108 H264/90000\r\n"
	"a=fmtp:108 level-asymmetry-allowed=1;"
	  "packetization-mode=0;profile-level-id=42e01f\r\n"
	"a=rtpmap:127 H264/90000\r\n"
	"a=fmtp:127 level-asymmetry-allowed=1;"
	  "packetization-mode=1;profile-level-id=4d001f\r\n"
	"a=rtpmap:112 H264/90000\r\n"
	"a=fmtp:112 level-asymmetry-allowed=1;"
	  "packetization-mode=1;profile-level-id=64001f\r\n"
	"a=rtpmap:116 H265/90000\r\n"
	"a=fmtp:116 level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST\r\n"
	"a=rtcp-fb:102 ccm fir\r\n"
	"a=rtcp-fb:102 ccm tmmbr\r\n"
	"a=rtcp-fb:102 nack\r\n"
	"a=rtcp-fb:102 nack pli\r\n"
	"a=rtcp-fb:104 ccm fir\r\n"
	"a=rtcp-fb:104 ccm tmmbr\r\n"
	"a=rtcp-fb:104 nack\r\n"
	"a=rtcp-fb:104 nack pli\r\n"
	"a=rtcp-fb:106 ccm fir\r\n"
	"a=rtcp-fb:106 ccm tmmbr\r\n"
	"a=rtcp-fb:106 nack\r\n"
	"a=rtcp-fb:106 nack pli\r\n"
	"a=rtcp-fb:108 ccm fir\r\n"
	"a=rtcp-fb:108 ccm tmmbr\r\n"
	"a=rtcp-fb:108 nack\r\n"
	"a=rtcp-fb:108 nack pli\r\n"
	"a=rtcp-fb:127 ccm fir\r\n"
	"a=rtcp-fb:127 ccm tmmbr\r\n"
	"a=rtcp-fb:127 nack\r\n"
	"a=rtcp-fb:127 nack pli\r\n"
	"a=rtcp-fb:112 ccm fir\r\n"
	"a=rtcp-fb:112 ccm tmmbr\r\n"
	"a=rtcp-fb:112 nack\r\n"
	"a=rtcp-fb:112 nack pli\r\n"
	"a=rtcp-fb:116 ccm fir\r\n"
	"a=rtcp-fb:116 ccm tmmbr\r\n"
	"a=rtcp-fb:116 nack\r\n"
	"a=rtcp-fb:116 nack pli\r\n"
	;

	static const struct attr session_attrv[] = {

	{"group",              "BUNDLE 0 1"},
	{"extmap-allow-mixed", ""},
	{"msid-semantic",      " WMS 2a30d377-cd13-4454-974c-0144db0118a6"},
	};

	static const struct attr audio_attrv[] = {

	{"ice-ufrag",    "ie02"},
	{"ice-pwd",      "CWO5WLKWo2j5QmsY1396cvFe"},
	{"ice-options",  "trickle"},
	{"fingerprint",  "sha-256 A9:1F:F1:FD:FB:90:7D:4D:F7:DF:C4:6E:F8:6A"
	                 ":7B:E7:87:1B:07:4E:22:3C:80"
	                 ":99:83:E6:9A:34:BD:93:F5:CE"},
	{"setup",        "actpass"},
	{"mid",          "0"},
	{"extmap",       "1 urn:ietf:params:rtp-hdrext:ssrc-audio-level"},
	{"extmap",       "2 http://www.webrtc.org/experiments/"
	                 "rtp-hdrext/abs-send-time"},
	{"extmap",       "3 http://www.ietf.org/id/"
	                 "draft-holmer-rmcat-transport-wide-cc-extensions-01"},
	{"extmap",       "4 urn:ietf:params:rtp-hdrext:sdes:mid"},
	{"msid",         "2a30d377-cd13-4454-974c-0144db0118a6"
	                 " c061a2b9-95bc-45fb-9e5d-6df08d8e1d0f"},
	{"rtcp-mux",     ""},
	{"rtcp-rsize",   ""},
	{"rtcp-fb",      "111 transport-cc"},
	{"ssrc",         "2161565476 cname:P6e47zI3iVPviKRL"},
	{"ssrc",         "2161565476 msid:2a30d377-cd13-4454-974c-0144db0118a6"
	                 " c061a2b9-95bc-45fb-9e5d-6df08d8e1d0f"},
	};

	static const struct codec codecv[] = {

		{  NULL, "opus",            48000, 2, true},
		{  "63", "red",             48000, 2, true},
		{   "9", "G722",             8000, 1, true},
		{   "0", "PCMU",             8000, 1, true},
		{   "8", "PCMA",             8000, 1, true},
		{  "13", "CN",               8000, 1, true},
		{ "110", "telephone-event", 48000, 1, true},
		{ "126", "telephone-event",  8000, 1, true},
		{ "150", "H264",            90000, 1, false},
	};

	int err;

	err = test_sdp_param(sdp_chrome,
			     session_attrv, RE_ARRAY_SIZE(session_attrv),
			     audio_attrv, RE_ARRAY_SIZE(audio_attrv),
			     codecv, RE_ARRAY_SIZE(codecv));
	TEST_ERR(err);

 out:
	return err;
}
