/**
 * @file sipauth.c SIP Auth testcode
 */
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_sipauth"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static const char *testv[] = {
	/* without algorithm - default MD5 */
	"SIP/2.0 401 Unauthorized\r\n"
	"Via: SIP/2.0/TLS "
	"10.0.0.1:37589;branch=z9hG4bK5625ce6f310a0fc8;rport=13718;"
	"received=10.0.0.2\r\n"
	"WWW-Authenticate: Digest realm=\"example.net\", "
	"nonce=\"YZlVk2GZVGegVBZVKaMHpnxmUA+QyoSl\"\r\n"
	"Content-Length: 0\r\n\r\n",

	/* explicit MD5 */
	"SIP/2.0 401 Unauthorized\r\n"
	"Via: SIP/2.0/TLS "
	"10.0.0.1:37589;branch=z9hG4bK5625ce6f310a0fc8;rport=13718;"
	"received=10.0.0.2\r\n"
	"WWW-Authenticate: Digest realm=\"example.net\", "
	"algorithm=\"MD5\", "
	"nonce=\"YZlVk2GZVGegVBZVKaMHpnxmUA+QyoSl\"\r\n"
	"Content-Length: 0\r\n\r\n",

	/* explicit SHA-256 */
	"SIP/2.0 401 Unauthorized\r\n"
	"Via: SIP/2.0/TLS "
	"10.0.0.1:37589;branch=z9hG4bK5625ce6f310a0fc8;rport=13718;"
	"received=10.0.0.2\r\n"
	"WWW-Authenticate: Digest realm=\"example.net\", "
	"algorithm=\"SHA-256\", "
	"nonce=\"YZlVk2GZVGegVBZVKaMHpnxmUA+QyoSl\"\r\n"
	"Content-Length: 0\r\n\r\n",

	/* explicit SHA-256 qop */
	"SIP/2.0 401 Unauthorized\r\n"
	"Via: SIP/2.0/TLS "
	"10.0.0.1:37589;branch=z9hG4bK5625ce6f310a0fc8;rport=13718;"
	"received=10.0.0.2\r\n"
	"WWW-Authenticate: Digest realm=\"example.net\", "
	"algorithm=\"SHA-256\", "
	"qop=\"auth\", "
	"nonce=\"YZlVk2GZVGegVBZVKaMHpnxmUA+QyoS\"\r\n"
	"Content-Length: 0\r\n\r\n"
};


static const char *testr[] = {
	"algorithm=MD5",
	"algorithm=MD5",
	"algorithm=SHA-256",
	"algorithm=SHA-256"
};


static int auth_handler(char **user, char **pass, const char *rlm, void *arg)
{
	(void)user;
	(void)pass;
	(void)rlm;
	(void)arg;

	return 0;
}


static int test_sip_auth_encode(void)
{
	int err = 0;
	struct mbuf *mb, *mb_enc;
	struct sip_auth *auth = NULL;
	char buf[1024] = {0};
	struct sip_msg *msg = NULL;
	const char met[]    = "REGISTER";
	const char uri[]    = "<sip:user@host:5060;transport=udp>";

	mb = mbuf_alloc(2048);
	if (!mb)
		return ENOMEM;

	mb_enc = mbuf_alloc(2048);
	if (!mb_enc) {
		mem_deref(mb);
		return ENOMEM;
	}

	for (size_t i = 0; i < RE_ARRAY_SIZE(testv); i++) {
		mbuf_rewind(mb);
		mbuf_rewind(mb_enc);

		err = sip_auth_alloc(&auth, auth_handler, NULL, false);
		TEST_ERR(err);

		err = mbuf_write_str(mb, testv[i]);
		TEST_ERR(err);

		mbuf_set_pos(mb, 0);

		err = sip_msg_decode(&msg, mb);
		TEST_ERR(err);

		err = sip_auth_authenticate(auth, msg);
		TEST_ERR(err);

		err = sip_auth_encode(mb_enc, auth, met, uri);
		TEST_ERR(err);

		mbuf_set_pos(mb_enc, 0);
		mbuf_read_str(mb_enc, buf, sizeof(buf));

		err = re_regex(buf, str_len(buf), testr[i]);
		TEST_ERR(err);

		mem_deref(msg);
		mem_deref(auth);
	}

out:
	mem_deref(mb);
	mem_deref(mb_enc);
	if (err) {
		mem_deref(msg);
		mem_deref(auth);
	}

	return err;
}


static int challenge(struct sip_auth *auth, const char *nonce, bool stale)
{
	struct sip_msg *msg = NULL;
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = mbuf_printf(mb,
			  "SIP/2.0 401 Unauthorized\r\n"
			  "Via: SIP/2.0/UDP 10.0.0.1:5060;"
			  "branch=z9hG4bK5625ce6f310a0fc8\r\n"
			  "WWW-Authenticate: Digest realm=\"example.net\", "
			  "nonce=\"%s\"%s\r\n"
			  "Content-Length: 0\r\n\r\n",
			  nonce, stale ? ", stale=TRUE" : "");
	if (err)
		goto out;

	mbuf_set_pos(mb, 0);

	err = sip_msg_decode(&msg, mb);
	if (err)
		goto out;

	err = sip_auth_authenticate(auth, msg);

out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


/* Send n authenticated requests with the current credentials */
static int send_req(struct sip_auth *auth, unsigned n)
{
	struct mbuf *mb;
	int err = 0;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	while (n-- && !err) {
		mbuf_rewind(mb);
		err = sip_auth_encode(mb, auth, "INVITE",
				      "sip:bob@example.net");
	}

	mem_deref(mb);

	return err;
}


static int test_sip_auth_rechallenge(void)
{
	struct sip_auth *auth = NULL;
	int err;

	err = sip_auth_alloc(&auth, auth_handler, NULL, false);
	TEST_ERR(err);

	/* Initial challenge */
	err = challenge(auth, "nonce1", false);
	TEST_ERR(err);
	err = send_req(auth, 1);
	TEST_ERR(err);

	/* stale=true with new nonce must be accepted */
	err = challenge(auth, "nonce2", true);
	TEST_ERR(err);
	err = send_req(auth, 1);
	TEST_ERR(err);

	/* Same nonce re-challenged without stale -> wrong credentials */
	err = challenge(auth, "nonce2", false);
	TEST_EQUALS(EAUTH, err);

	/* New nonce without stale directly after first attempt is a
	 * rejection of the credentials (no endless retry loop) */
	sip_auth_reset(auth);
	err = challenge(auth, "nonce3", false);
	TEST_ERR(err);
	err = send_req(auth, 1);
	TEST_ERR(err);
	err = challenge(auth, "nonce4", false);
	TEST_EQUALS(EAUTH, err);

	/* Broken server: nonce was used successfully, then rotated
	 * without stale=true -> treat as stale */
	sip_auth_reset(auth);
	err = challenge(auth, "nonce5", false);
	TEST_ERR(err);
	err = send_req(auth, 2);
	TEST_ERR(err);
	err = challenge(auth, "nonce6", false);
	TEST_ERR(err);

out:
	mem_deref(auth);

	return err;
}


int test_sip_auth(void)
{
	int err;

	err = test_sip_auth_encode();
	TEST_ERR(err);

	err = test_sip_auth_rechallenge();
	TEST_ERR(err);

out:
	return err;
}
