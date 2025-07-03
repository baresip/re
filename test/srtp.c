/**
 * @file srtp.c SRTP Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "srtptest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define SSRC 0x31323334


enum {
	SALT_LEN_CTR = 14
};


static const uint8_t fixed_payload[20] = {
	0x55, 0x55, 0x55, 0x55,
	0x11, 0x11, 0x11, 0x11,
	0xee, 0xee, 0xee, 0xee,
	0x11, 0x11, 0x11, 0x11,
	0x55, 0x55, 0x55, 0x55,
};


static size_t get_keylen(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return 16;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return 16;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return 32;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return 32;
	case SRTP_AES_128_GCM:             return 16;
	case SRTP_AES_256_GCM:             return 32;
	default: return 0;
	}
}


static size_t get_saltlen(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return 14;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return 14;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return 14;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return 14;
	case SRTP_AES_128_GCM:             return 12;
	case SRTP_AES_256_GCM:             return 12;
	default: return 0;
	}
}


static size_t get_taglen(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return 4;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return 10;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return 4;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return 10;
	case SRTP_AES_128_GCM:             return 16;
	case SRTP_AES_256_GCM:             return 16;
	default: return 0;
	}
}


/*
 * RFC 3711 B.2.  AES-CM Test Vectors
 */
static int test_srtp_aescm128(void)
{
	uint8_t k_e[16], iv[16];
	struct aes *aes = NULL;
	uint8_t keystream[16], nulldata[16];
	size_t i;
	int err = 0;
	static const struct {
		const char *counter;
		const char *keystream;
	} testv[] = {
		{"F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000",
		 "E03EAD0935C95E80E166B16DD92B4EB4"},

		{"F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001",
		 "D23513162B02D0F72A43A2FE4A5F97AB"},

		{"F0F1F2F3F4F5F6F7F8F9FAFBFCFD0002",
		 "41E95B3BB0A2E8DD477901E4FCA894C0"},
	};

	memset(nulldata, 0, sizeof(nulldata));

	err |= str_hex(k_e, sizeof(k_e), "2B7E151628AED2A6ABF7158809CF4F3C");
	err |= str_hex(iv,  sizeof(iv),  "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000");
	if (err)
		return err;

	err = aes_alloc(&aes, AES_MODE_CTR, k_e, 128, iv);
	if (err)
		return err;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		uint8_t t_count[16], t_kstrm[16];

		err |= str_hex(t_count, sizeof(t_count), testv[i].counter);
		err |= str_hex(t_kstrm, sizeof(t_kstrm), testv[i].keystream);
		if (err)
			break;

		err = aes_encr(aes, keystream, nulldata, sizeof(nulldata));
		if (err)
			break;

		TEST_MEMCMP(t_kstrm, sizeof(t_kstrm),
			    keystream, sizeof(keystream));
	}

 out:
	mem_deref(aes);
	return err;
}


/*
 * RFC 6188 7.1.  AES-256-CM Test Cases
 */
static int test_srtp_aescm256(void)
{
	uint8_t k_e[32], iv[16];
	struct aes *aes = NULL;
	uint8_t keystream[16], nulldata[16];
	size_t i;
	int err = 0;
	static const struct {
		const char *counter;
		const char *keystream;
	} testv[] = {
		{"F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000",
		 "92bdd28a93c3f52511c677d08b5515a4"},

		{"F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001",
		 "9da71b2378a854f67050756ded165bac"},

		{"F0F1F2F3F4F5F6F7F8F9FAFBFCFD0002",
		 "63c4868b7096d88421b563b8c94c9a31"},
	};

	memset(nulldata, 0, sizeof(nulldata));

	err |= str_hex(k_e, sizeof(k_e),
		       "57f82fe3613fd170a85ec93c40b1f092"
		       "2ec4cb0dc025b58272147cc438944a98");
	err |= str_hex(iv, sizeof(iv),
		       "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000");
	if (err)
		return err;

	err = aes_alloc(&aes, AES_MODE_CTR, k_e, 256, iv);
	if (err)
		return err;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		uint8_t t_keystream[16];

		err |= str_hex(t_keystream, sizeof(t_keystream),
			       testv[i].keystream);
		if (err)
			break;

		err = aes_encr(aes, keystream, nulldata, sizeof(nulldata));
		if (err)
			break;

		TEST_MEMCMP(t_keystream, sizeof(t_keystream),
			    keystream, sizeof(keystream));
	}

 out:
	mem_deref(aes);
	return err;
}


#if 0
/*
 * RFC 3711, B.3.  Key Derivation Test Vectors
 */
static int test_srtp_keys(void)
{
	uint8_t key[16], salt[14];
	uint8_t k_e[16], k_s[14], k_a[20];
	uint8_t k_e_ref[16], k_s_ref[14], k_a_ref[20];
	int err = 0;

	err |= str_hex(key,  sizeof(key),  "E1F97A0D3E018BE0D64FA32C06DE4139");
	err |= str_hex(salt, sizeof(salt), "0EC675AD498AFEEBB6960B3AABE6");
	if (err)
		return err;

	err |= str_hex(k_e_ref, 16, "C61E7A93744F39EE10734AFE3FF7A087");
	err |= str_hex(k_s_ref, 14, "30CBBC08863D8C85D49DB34A9AE1");
	err |= str_hex(k_a_ref, 20,
		       "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4");
	if (err)
		return err;

	err |= srtp_derive_key(k_e, 16, 0x00, key, sizeof(key),
			       salt, sizeof(salt));
	err |= srtp_derive_key(k_a, 20, 0x01, key, sizeof(key),
			       salt, sizeof(salt));
	err |= srtp_derive_key(k_s, 14, 0x02, key, sizeof(key),
			       salt, sizeof(salt));
	if (err)
		return err;

	TEST_MEMCMP(k_e_ref, sizeof(k_e_ref), k_e, 16);
	TEST_MEMCMP(k_a_ref, sizeof(k_a_ref), k_a, 20);
	TEST_MEMCMP(k_s_ref, sizeof(k_s_ref), k_s, 14);

 out:
	return err;
}


/*
 * RFC 6188, 7.2.  AES_256_CM_PRF Test Cases
 */
static int test_srtp_keys256(void)
{
	uint8_t key[32], salt[14];
	uint8_t k_e[32], k_s[14], k_a[20];
	uint8_t k_e_ref[32], k_s_ref[14], k_a_ref[20];
	int err = 0;

	err |= str_hex(key, sizeof(key),
		       "f0f04914b513f2763a1b1fa130f10e29"
		       "98f6f6e43e4309d1e622a0e332b9f1b6");
	err |= str_hex(salt, sizeof(salt),
		       "3b04803de51ee7c96423ab5b78d2");
	if (err)
		return err;

	err |= str_hex(k_e_ref, 32,
		       "5ba1064e30ec51613cad926c5a28ef73"
		       "1ec7fb397f70a960653caf06554cd8c4");
	err |= str_hex(k_s_ref, 14, "fa31791685ca444a9e07c6c64e93");
	err |= str_hex(k_a_ref, 20,
		       "fd9c32d39ed5fbb5a9dc96b30818454d1313dc05");
	if (err)
		return err;

	/* verify cipher key */
	err |= srtp_derive_key(k_e, 32, 0x00, key, sizeof(key),
			       salt, sizeof(salt));
	TEST_MEMCMP(k_e_ref, sizeof(k_e_ref), k_e, sizeof(k_e));

	/* verify auth key */
	err |= srtp_derive_key(k_a, 20, 0x01, key, sizeof(key),
			       salt, sizeof(salt));
	TEST_MEMCMP(k_a_ref, sizeof(k_a_ref), k_a, sizeof(k_a));

	/* verify cipher salt */
	err |= srtp_derive_key(k_s, 14, 0x02, key, sizeof(key),
			       salt, sizeof(salt));
	TEST_MEMCMP(k_s_ref, sizeof(k_s_ref), k_s, sizeof(k_s));

 out:
	return err;
}


static int test_srtcp_keys(void)
{
	uint8_t key[16], salt[14];
	uint8_t k_e[16], k_e_ref[16];
	uint8_t k_a[20], k_a_ref[20];
	uint8_t k_s[14], k_s_ref[14];
	int err = 0;

	err |= str_hex(key,  sizeof(key),  "E1F97A0D3E018BE0D64FA32C06DE4139");
	err |= str_hex(salt, sizeof(salt), "0EC675AD498AFEEBB6960B3AABE6");
	if (err)
		return err;

	err |= str_hex(k_e_ref, 16,"4c1aa45a81f73d61c800bbb00fbb1eaa");
	err |= str_hex(k_a_ref, 20,"8d54534feb49ae8e7993a6bd0b844fc323a93dfd");
	err |= str_hex(k_s_ref, 14,"9581c7ad87b3e530bf3e4454a8b3");
	if (err)
		return err;

	err |= srtp_derive_key(k_e, 16, 0x03, key, sizeof(key),
			       salt, sizeof(salt));
	err |= srtp_derive_key(k_a, 20, 0x04, key, sizeof(key),
			       salt, sizeof(salt));
	err |= srtp_derive_key(k_s, 14, 0x05, key, sizeof(key),
			       salt, sizeof(salt));

	TEST_MEMCMP(k_e_ref, sizeof(k_e_ref), k_e, 16);
	TEST_MEMCMP(k_a_ref, sizeof(k_a_ref), k_a, 20);
	TEST_MEMCMP(k_s_ref, sizeof(k_s_ref), k_s, 14);

 out:
	return err;
}
#endif


static int test_srtp_loop(size_t offset, enum srtp_suite suite, uint16_t seq)
{
	struct srtp *ctx_tx = NULL, *ctx_rx = NULL;
	struct mbuf *mb = NULL;
	const size_t key_len = get_keylen(suite);
	const size_t salt_len = get_saltlen(suite);
	const size_t tag_len = get_taglen(suite);
	unsigned i;
	int err = 0;

	static const uint8_t master_key[16+16+14] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};

	mb = mbuf_alloc(offset + 32);
	if (!mb)
		return ENOMEM;

	err  = srtp_alloc(&ctx_tx, suite, master_key, key_len + salt_len, 0);
	err |= srtp_alloc(&ctx_rx, suite, master_key, key_len + salt_len, 0);
	if (err)
		goto out;

	for (i=0; i<10; i++) {
		struct rtp_header hdr;
		uint8_t hdrbuf[12];
		size_t end;

		mb->pos = mb->end = offset;

		memset(&hdr, 0, sizeof(hdr));

		hdr.ver  = RTP_VERSION;
		hdr.seq  = seq++;
		hdr.ssrc = SSRC;

		err = rtp_hdr_encode(mb, &hdr);
		if (err)
			break;

		memcpy(hdrbuf, &mb->buf[mb->pos-12], 12);

		err = mbuf_write_mem(mb, fixed_payload, sizeof(fixed_payload));
		if (err)
			break;

		end = mb->end;

		/* tx */
		mb->pos = offset;
		err = srtp_encrypt(ctx_tx, mb);
		if (err)
			break;

		TEST_EQUALS(offset, mb->pos);
		TEST_EQUALS(end + tag_len, mb->end);

		/* verify that srtp_encrypt() did not tamper with RTP header */
		TEST_MEMCMP(hdrbuf, sizeof(hdrbuf), &mb->buf[offset], 12);

		/* rx */
		mb->pos = offset;
		err = srtp_decrypt(ctx_rx, mb);
		if (err) {
			DEBUG_WARNING("srtp_decrypt: %m\n", err);
			break;
		}

		TEST_EQUALS(offset, mb->pos);
		TEST_EQUALS(end, mb->end);

		mb->pos = offset + RTP_HEADER_SIZE;

		TEST_MEMCMP(fixed_payload, sizeof(fixed_payload),
			    mbuf_buf(mb), mbuf_get_left(mb));
	}

 out:
	mem_deref(ctx_tx);
	mem_deref(ctx_rx);
	mem_deref(mb);

	return err;
}


static int test_srtcp_loop(size_t offset, enum srtp_suite suite,
			   enum rtcp_type type)
{
	struct srtp *ctx_tx = NULL, *ctx_rx = NULL;
	struct mbuf *mb1 = NULL, *mb2 = NULL;
	const size_t key_len = get_keylen(suite);
	const size_t salt_len = get_saltlen(suite);
	const size_t tag_len = get_taglen(suite);
	unsigned i;
	int err = 0;

	static const uint8_t master_key[16+16+14] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};

	mb1 = mbuf_alloc(1024);
	mb2 = mbuf_alloc(1024);
	if (!mb1 || !mb2) {
		err = ENOMEM;
		goto out;
	}

	err  = srtp_alloc(&ctx_tx, suite, master_key, key_len + salt_len, 0);
	err |= srtp_alloc(&ctx_rx, suite, master_key, key_len + salt_len, 0);
	if (err)
		goto out;

	for (i=0; i<10; i++) {

		const uint32_t srcv[2] = {0x12345678, 0x00abcdef};
		size_t end;

		mb1->pos = mb1->end = offset;
		mb2->pos = mb2->end = offset;

		if (type == RTCP_BYE) {
			err = rtcp_encode(mb1, RTCP_BYE, 2, srcv, "ciao");
		}
		else if (type == RTCP_RR) {
			err = rtcp_encode(mb1, RTCP_RR, 0, srcv[0],
					  NULL, NULL);
		}
		else {
			re_printf("unknown type %d\n", type);
			err = EINVAL;
			break;
		}

		if (err)
			break;

		end = mb1->end;

		mb1->pos = offset;
		(void)mbuf_write_mem(mb2, mbuf_buf(mb1), mbuf_get_left(mb1));
		mb2->pos = offset;

		/* tx */
		mb1->pos = offset;
		err = srtcp_encrypt(ctx_tx, mb1);
		if (err)
			break;

		TEST_EQUALS(offset, mb1->pos);
		TEST_ASSERT(mb1->end != end);
		TEST_EQUALS((mbuf_get_left(mb2) + 4 + tag_len),
			    mbuf_get_left(mb1));

		/* rx */
		mb1->pos = offset;
		err = srtcp_decrypt(ctx_rx, mb1);
		if (err)
			break;

		TEST_EQUALS(offset, mb1->pos);
		TEST_EQUALS(end, mb1->end);
		TEST_MEMCMP(mbuf_buf(mb2), mbuf_get_left(mb2),
			    mbuf_buf(mb1), mbuf_get_left(mb1));
	}

 out:
	mem_deref(ctx_tx);
	mem_deref(ctx_rx);
	mem_deref(mb1);
	mem_deref(mb2);

	return err;
}


/*
 * Reference SRTP-packet generated by libsrtp
 *
 * cipher:       AES-CM-128
 * auth:         HMAC-SHA1 80-bits tag
 * master key:   0x22222222222222222222222222222222
 * master salt:  0x4444444444444444444444444444
 * SSRC:         0x01020304
 * Seq:          0x0001
 * RTP payload:  0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5
 */
static const char *srtp_libsrtp =
	"800000010000000001020304"
	"f5b44b7e3ad4eb057bc6480c45df6547bb70bcc2"
	"7b136e1f3d3a62821b15";


static int test_srtp_libsrtp(void)
{
	uint8_t pkt[12+20+10];
	struct srtp *srtp_enc = NULL;
	static const uint8_t mast_key[16+14] =
		"\x22\x22\x22\x22\x22\x22\x22\x22"
		"\x22\x22\x22\x22\x22\x22\x22\x22"
		"\x44\x44\x44\x44\x44\x44\x44"
		"\x44\x44\x44\x44\x44\x44\x44";
	static const uint8_t rtp_payload[20] =
		"\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5"
		"\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5";
	struct mbuf *mb;
	struct rtp_header hdr;
	int err = 0;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ver  = RTP_VERSION;
	hdr.ssrc = 0x01020304;
	hdr.seq  = 0x0001;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = str_hex(pkt, sizeof(pkt), srtp_libsrtp);
	if (err)
		goto out;

	err = srtp_alloc(&srtp_enc, SRTP_AES_CM_128_HMAC_SHA1_80,
			 mast_key, sizeof(mast_key), 0);
	if (err)
		goto out;

	err  = rtp_hdr_encode(mb, &hdr);
	err |= mbuf_write_mem(mb, rtp_payload, sizeof(rtp_payload));
	if (err)
		goto out;
	mb->pos = 0;

	err = srtp_encrypt(srtp_enc, mb);
	if (err)
		goto out;

	TEST_MEMCMP(pkt, sizeof(pkt), mb->buf, mb->end);

 out:
	mem_deref(srtp_enc);
	mem_deref(mb);
	return err;
}


/*
 * Reference SRTCP-packet generated by libsrtp
 *
 * cipher:       AES-CM-128
 * auth:         HMAC-SHA1 32-bits tag
 * master key:   0x22222222222222222222222222222222
 * master salt:  0x4444444444444444444444444444
 * SSRC:         0x01020304
 * RTCP packet:  BYE-message
 */
static const char *srtcp_libsrtp =
	"81cb00020102030487c9fcdb80000001e9442fcc";
/*                               ^^^^^^^^________
 *                                index    tag
 */


static int test_srtcp_libsrtp(void)
{
	uint8_t pkt[12+4+4];
	struct srtp *srtp_enc = NULL;
	static const uint8_t mast_key[16+14] =
		"\x22\x22\x22\x22\x22\x22\x22\x22"
		"\x22\x22\x22\x22\x22\x22\x22\x22"
		"\x44\x44\x44\x44\x44\x44\x44"
		"\x44\x44\x44\x44\x44\x44\x44";
	const uint32_t srcv[1] = {0x01020304};
	struct mbuf *mb;
	int err = 0;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = str_hex(pkt, sizeof(pkt), srtcp_libsrtp);
	if (err)
		goto out;

	err = srtp_alloc(&srtp_enc, SRTP_AES_CM_128_HMAC_SHA1_32,
			 mast_key, sizeof(mast_key), 0);
	if (err)
		goto out;

	err = rtcp_encode(mb, RTCP_BYE, 1, srcv, "b");
	if (err)
		goto out;

	mb->pos = 0;

	err = srtcp_encrypt(srtp_enc, mb);
	if (err)
		goto out;

	TEST_MEMCMP(pkt, sizeof(pkt), mb->buf, mb->end);

 out:
	mem_deref(srtp_enc);
	mem_deref(mb);
	return err;
}


static int send_rtp_packet(struct srtp *srtp, struct mbuf *mb, uint16_t seq)
{
	struct rtp_header hdr;
	size_t len;
	int err;

	memset(&hdr, 0, sizeof(hdr));

	hdr.ver  = RTP_VERSION;
	hdr.seq  = seq;
	hdr.ssrc = SSRC;

	mb->pos = mb->end = 0;
	err  = rtp_hdr_encode(mb, &hdr);
	err |= mbuf_write_mem(mb, fixed_payload, sizeof(fixed_payload));
	if (err)
		return err;

	len = mb->end;

	mb->pos = 0;
	err = srtp_encrypt(srtp, mb);
	if (err)
		return err;

	TEST_EQUALS(0, mb->pos);
	TEST_ASSERT(mb->end > len);

 out:
	return err;
}


static int recv_srtp_packet(struct srtp *srtp, struct mbuf *mb)
{
	const size_t len = mb->end;
	int err = 0;

	mb->pos = 0;
	err = srtp_decrypt(srtp, mb);
	if (err)
		return err;

	TEST_EQUALS(0, mb->pos);
	TEST_ASSERT(mb->end < len);
	TEST_MEMCMP(fixed_payload, sizeof(fixed_payload),
		    mb->buf + 12, mb->end - 12);
 out:
	return err;
}


static int test_srtp_replay(enum srtp_suite suite)
{
	static const uint8_t key[32+14] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};
	struct srtp *ctx = NULL;
	struct mbuf *mb = NULL;
	const size_t key_len = get_keylen(suite);
	const size_t salt_len = get_saltlen(suite);
	int e, err = 0;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err  = srtp_alloc(&ctx, suite, key, key_len + salt_len, 0);
	if (err)
		goto out;

	/* send/receive one RTP packet first */
	err = send_rtp_packet(ctx, mb, 42);
	if (err)
		goto out;

	err = srtp_decrypt(ctx, mb);
	if (err)
		goto out;

	/* then send/receive the same packet again,
	   expect replay protection */
	err = send_rtp_packet(ctx, mb, 42);
	if (err)
		goto out;

	e = srtp_decrypt(ctx, mb);
	TEST_EQUALS(EALREADY, e);

 out:
	mem_deref(ctx);
	mem_deref(mb);

	return err;
}


static int test_seq_loop(const uint16_t *seqv, size_t seqn)
{
	static const uint8_t key[16+14] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};
	struct srtp *srtp_tx = NULL, *srtp_rx = NULL;
	struct mbuf *mb;
	size_t i;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	/* note: we must use two separate SRTP instances here,
	   since the SSRC is the same */
	err  = srtp_alloc(&srtp_tx, SRTP_AES_CM_128_HMAC_SHA1_32,
			  key, sizeof(key), 0);
	err |= srtp_alloc(&srtp_rx, SRTP_AES_CM_128_HMAC_SHA1_32,
			  key, sizeof(key), 0);
	if (err)
		goto out;

	for (i=0; i<seqn; i++) {

		err = send_rtp_packet(srtp_tx, mb, seqv[i]);
		if (err)
			break;

		/* mb now contains the SRTP packet */

		err = recv_srtp_packet(srtp_rx, mb);
		if (err)
			break;
	}

 out:
	mem_deref(srtp_tx);
	mem_deref(srtp_rx);
	mem_deref(mb);

	/* for reordered packets that arrive too late */
	if (err == ETIMEDOUT)
		err = 0;

	return err;
}


static int test_srtp_reordering_and_wrap(void)
{
	static const uint16_t seqv1[] = {0, 1, 2};
	static const uint16_t seqv2[] = {0, 2, 1};
	static const uint16_t seqv3[] = {65534, 65535, 0, 1};
	static const uint16_t seqv4[] = {65534, 0, 1};
	static const uint16_t seqv5[] = {65534, 1, 2};
	static const uint16_t seqv6[] = {65534, 1, 2, 65535};
	int err = 0;

	err  = test_seq_loop(seqv1, RE_ARRAY_SIZE(seqv1));
	err |= test_seq_loop(seqv2, RE_ARRAY_SIZE(seqv2));
	err |= test_seq_loop(seqv3, RE_ARRAY_SIZE(seqv3));
	err |= test_seq_loop(seqv4, RE_ARRAY_SIZE(seqv4));
	err |= test_seq_loop(seqv5, RE_ARRAY_SIZE(seqv5));
	err |= test_seq_loop(seqv6, RE_ARRAY_SIZE(seqv6));

	return err;
}


/* verify that we dont crash on random input */
static int test_srtp_random(enum srtp_suite suite)
{
	struct rtp_header hdr;
	struct srtp *ctx = NULL;
	struct mbuf *mb = NULL;
	const size_t key_len = get_keylen(suite);
	const size_t salt_len = get_saltlen(suite);
	size_t sz, i;
	int err = 0;

	static const uint8_t master_key[16+16+14] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err  = srtp_alloc(&ctx, suite, master_key, key_len + salt_len, 0);
	if (err)
		goto out;

	memset(&hdr, 0, sizeof(hdr));

	hdr.ver  = RTP_VERSION;
	hdr.seq  = 1234;
	hdr.ssrc = SSRC;

	err = rtp_hdr_encode(mb, &hdr);
	if (err)
		goto out;

	err = mbuf_fill(mb, 0xd5, 32);
	if (err)
		goto out;

	sz = mb->end;

	for (i=0; i<sz; i++) {

		mb->pos = 0; mb->end = i;
		(void)srtp_encrypt(ctx, mb);

		mb->pos = 0; mb->end = i;
		(void)srtp_decrypt(ctx, mb);
	}

 out:
	mem_deref(ctx);
	mem_deref(mb);

	return err;
}


/* verify that we dont crash on random input */
static int test_srtcp_random(enum srtp_suite suite)
{
	struct srtp *ctx = NULL;
	struct mbuf *mb = NULL;
	const size_t key_len = get_keylen(suite);
	const size_t salt_len = get_saltlen(suite);
	const uint32_t srcv[2] = {0x12345678, 0x00abcdef};
	size_t sz, i;
	int err = 0;

	static const uint8_t master_key[16+16+14] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err  = srtp_alloc(&ctx, suite, master_key, key_len + salt_len, 0);
	if (err)
		goto out;

	err = rtcp_encode(mb, RTCP_BYE, 2, srcv, "ciao");
	if (err)
		goto out;

	err = mbuf_fill(mb, 0xd5, 32);
	if (err)
		goto out;

	sz = mb->end;

	for (i=0; i<sz; i++) {

		mb->pos = 0;
		mb->end = i;
		(void)srtcp_encrypt(ctx, mb);

		mb->pos = 0;
		mb->end = i;
		(void)srtcp_decrypt(ctx, mb);
	}

 out:
	mem_deref(ctx);
	mem_deref(mb);

	return err;
}


static int test_srtp_unauth(enum srtp_suite suite)
{
	struct srtp *srtp_tx, *srtp_rx;
	struct mbuf *mb = NULL;
	const size_t key_len = get_keylen(suite);
	const size_t salt_len = get_saltlen(suite);
	int err = 0;

	static const uint8_t master_key[32 + SALT_LEN_CTR] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};

	mb = mbuf_alloc(32);
	if (!mb)
		return ENOMEM;

	err  = srtp_alloc(&srtp_tx, suite, master_key, key_len+salt_len, 0);
	err |= srtp_alloc(&srtp_rx, suite, master_key, key_len+salt_len, 0);
	if (err)
		goto out;

	err = send_rtp_packet(srtp_tx, mb, 3);
	if (err)
		goto out;

	/* flip bits in the auth-tag to force authentication error */
	mb->buf[mb->end - 1] ^= 0x55;

	err = recv_srtp_packet(srtp_rx, mb);

	TEST_EQUALS(EAUTH, err);

	err = 0;

 out:
	mem_deref(srtp_tx);
	mem_deref(srtp_rx);
	mem_deref(mb);

	return err;
}


/*
 * Special test for Unencrypted SRTCP. This is a special case in
 * SDES, See RFC 4568 section 6.3.2
 */
static int test_unencrypted_srtcp(void)
{
	struct srtp *srtp = NULL;
	struct mbuf *mb1 = NULL, *mb2 = NULL;
	enum srtp_suite suite = SRTP_AES_CM_128_HMAC_SHA1_32;
	const size_t tag_len = get_taglen(suite);
	size_t end;
	uint32_t v;
	bool ep;
	int err = 0;

	const uint32_t srcv[2] = {0x12345678, 0x00abcdef};
	static const uint8_t master_key[16+14] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	};

	mb1 = mbuf_alloc(1024);
	mb2 = mbuf_alloc(1024);
	if (!mb1 || !mb2) {
		err = ENOMEM;
		goto out;
	}

	err  = srtp_alloc(&srtp, suite, master_key, 16 + SALT_LEN_CTR,
			  SRTP_UNENCRYPTED_SRTCP);
	if (err)
		goto out;

	err  = rtcp_encode(mb1, RTCP_BYE, 2, srcv, "ciao");
	err |= rtcp_encode(mb2, RTCP_BYE, 2, srcv, "ciao");
	if (err)
		goto out;

	end = mb1->end;

	/* tx */
	mb1->pos = 0;
	err = srtcp_encrypt(srtp, mb1);
	if (err)
		goto out;

	TEST_EQUALS(0, mb1->pos);

	mb1->pos = end;
	v = ntohl(mbuf_read_u32(mb1));
	ep = (v >> 31) & 1;

	mb1->pos = 0;

	/* verify that RTCP packet is not encrypted */
	TEST_ASSERT(ep == false);
	TEST_MEMCMP(mb2->buf, mb2->end, mb1->buf, mb1->end - 4 - tag_len);

	/* rx */
	err = srtcp_decrypt(srtp, mb1);
	if (err)
		goto out;

	TEST_EQUALS(0, mb1->pos);
	TEST_MEMCMP(mb2->buf, mb2->end, mb1->buf, mb1->end);

 out:
	mem_deref(srtp);
	mem_deref(mb1);
	mem_deref(mb2);

	return err;
}


static bool have_srtp(void)
{
	static const uint8_t nullkey[30];
	struct srtp *srtp = NULL;
	int err;

	err = srtp_alloc(&srtp, SRTP_AES_CM_128_HMAC_SHA1_32,
			 nullkey, sizeof(nullkey), 0);

	mem_deref(srtp);

	return err != ENOSYS;
}


/*
 * test low-level code first, then high-level at the end
 */
int test_srtp(void)
{
	int err = 0;

	/* XXX: find a better solution for optional SRTP.
	   perhaps only register this test if SRTP is available? */
	if (!have_srtp()) {
		(void)re_printf("skipping SRTP test\n");
		return ESKIPPED;
	}

	err  = test_srtp_aescm128();
	TEST_ERR(err);

	err = test_srtp_aescm256();
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_CM_128_HMAC_SHA1_32, 3);
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_CM_128_HMAC_SHA1_80, 3);
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_256_CM_HMAC_SHA1_32, 3);
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_256_CM_HMAC_SHA1_80, 3);
	TEST_ERR(err);

	err = test_srtp_loop(4, SRTP_AES_CM_128_HMAC_SHA1_32, 3);
	TEST_ERR(err);

	err = test_srtp_loop(4, SRTP_AES_CM_128_HMAC_SHA1_80, 3);
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_CM_128_HMAC_SHA1_32, 65530);
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_CM_128_HMAC_SHA1_80, 65530);
	TEST_ERR(err);

	err  = test_srtp_libsrtp();
	TEST_ERR(err);

	err = test_srtp_replay(SRTP_AES_CM_128_HMAC_SHA1_32);
	TEST_ERR(err);

	err = test_srtp_reordering_and_wrap();
	TEST_ERR(err);

	err = test_srtp_unauth(SRTP_AES_CM_128_HMAC_SHA1_32);
	TEST_ERR(err);

	err = test_srtp_random(SRTP_AES_CM_128_HMAC_SHA1_32);
	TEST_ERR(err);

out:
	return err;
}


int test_srtcp(void)
{
	int err = 0;

	if (!have_srtp()) {
		(void)re_printf("skipping SRTCP test\n");
		return ESKIPPED;
	}

	err = test_srtcp_loop(0, SRTP_AES_CM_128_HMAC_SHA1_32, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(0, SRTP_AES_CM_128_HMAC_SHA1_80, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(0, SRTP_AES_256_CM_HMAC_SHA1_32, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(0, SRTP_AES_256_CM_HMAC_SHA1_80, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(4, SRTP_AES_CM_128_HMAC_SHA1_32, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(4, SRTP_AES_CM_128_HMAC_SHA1_80, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(0, SRTP_AES_CM_128_HMAC_SHA1_32, RTCP_RR);
	TEST_ERR(err);

	err = test_srtcp_libsrtp();
	TEST_ERR(err);

	err = test_unencrypted_srtcp();
	TEST_ERR(err);

	err = test_srtcp_random(SRTP_AES_CM_128_HMAC_SHA1_32);
	TEST_ERR(err);

out:
	return err;
}


int test_srtp_gcm(void)
{
	int err;

	if (!have_srtp()) {
		re_printf("skipping SRTP GCM test\n");
		return ESKIPPED;
	}

	err = test_srtp_loop(0, SRTP_AES_128_GCM, 3);
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_256_GCM, 3);
	TEST_ERR(err);

	err = test_srtp_loop(0, SRTP_AES_256_GCM, 65530);
	TEST_ERR(err);

	err = test_srtp_unauth(SRTP_AES_256_GCM);
	TEST_ERR(err);

	err = test_srtp_replay(SRTP_AES_128_GCM);
	TEST_ERR(err);

	err = test_srtp_random(SRTP_AES_128_GCM);
	TEST_ERR(err);

out:
	return err;
}


int test_srtcp_gcm(void)
{
	int err;

	if (!have_srtp()) {
		re_printf("skipping SRTCP GCM test\n");
		return ESKIPPED;
	}

	err = test_srtcp_loop(0, SRTP_AES_128_GCM, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(0, SRTP_AES_256_GCM, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(4, SRTP_AES_128_GCM, RTCP_BYE);
	TEST_ERR(err);

	err = test_srtcp_loop(0, SRTP_AES_128_GCM, RTCP_RR);
	TEST_ERR(err);

	err = test_srtcp_random(SRTP_AES_128_GCM);
	TEST_ERR(err);

out:
	return err;
}
