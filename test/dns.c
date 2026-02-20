/**
 * @file dns.c DNS Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "dns"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	NUM_TESTS    = 32,
	IP_127_0_0_1 = 0x7f000001,
	IP_127_0_0_2 = 0x7f000002,
	IP_127_0_0_3 = 0x7f000003,
	IP_127_0_0_4 = 0x7f000004,
	IP_127_0_0_5 = 0x7f000005,
};

static const uint8_t IP6_1[16] = {
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const uint8_t IP6_2[16] = {
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

static const uint8_t IP6_3[16] = {
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
};

static const uint8_t IP6_4[16] = {
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
};


static int mkstr(char **strp)
{
	size_t sz = 8;
	char *str;

	str = mem_alloc(sz, NULL);
	if (!str)
		return ENOMEM;

	rand_str(str, sz);

	*strp = str;

	return 0;
}


static int mkrr(struct dnsrr *rr, uint16_t type)
{
	int err;

	err = mkstr(&rr->name);
	if (err)
		return err;

	rr->type = type;
	rr->dnsclass = DNS_CLASS_IN;
	rr->ttl = 3600;
	rr->rdlen = 2;

	switch (type) {

	case DNS_TYPE_A:
		rr->rdata.a.addr = rand_u32();
		break;

	case DNS_TYPE_NS:
		err |= mkstr(&rr->rdata.ns.nsdname);
		break;

	case DNS_TYPE_CNAME:
		err |= mkstr(&rr->rdata.cname.cname);
		break;

	case DNS_TYPE_SOA:
		err |= mkstr(&rr->rdata.soa.mname);
		err |= mkstr(&rr->rdata.soa.rname);
		rr->rdata.soa.serial  = rand_u32();
		rr->rdata.soa.refresh = rand_u32();
		rr->rdata.soa.retry   = rand_u32();
		rr->rdata.soa.expire  = rand_u32();
		rr->rdata.soa.ttlmin  = rand_u32();
		break;

	case DNS_TYPE_PTR:
		err |= mkstr(&rr->rdata.ptr.ptrdname);
		break;

	case DNS_TYPE_MX:
		rr->rdata.mx.pref = rand_u16();
		err |= mkstr(&rr->rdata.mx.exchange);
		break;

	case DNS_TYPE_TXT:
		err |= mkstr(&rr->rdata.txt.data);
		break;

	case DNS_TYPE_AAAA:
		rand_bytes(rr->rdata.aaaa.addr, 16);
		break;

	case DNS_TYPE_SRV:
		rr->rdata.srv.pri    = rand_u16();
		rr->rdata.srv.weight = rand_u16();
		rr->rdata.srv.port   = rand_u16();
		err |= mkstr(&rr->rdata.srv.target);
		break;

	case DNS_TYPE_NAPTR:
		rr->rdata.naptr.order = rand_u16();
		rr->rdata.naptr.pref  = rand_u16();
		err |= mkstr(&rr->rdata.naptr.flags);
		err |= mkstr(&rr->rdata.naptr.services);
		err |= mkstr(&rr->rdata.naptr.regexp);
		err |= mkstr(&rr->rdata.naptr.replace);
		break;
	}

	return err;
}


int test_dns_hdr(void)
{
	struct mbuf *mb;
	uint16_t u16 = 9753;  /* pseudo-random (predictable) */
	size_t i;
	int err = 0;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	for (i=0; i<NUM_TESTS; i++) {

		struct dnshdr hdr, hdr2;

		memset(&hdr, 0, sizeof(hdr));
		memset(&hdr2, 0, sizeof(hdr2));

		hdr.id     = u16;
		hdr.qr     = u16 & 1;
		hdr.opcode = u16 & 0xf;
		hdr.aa     = u16 & 1;
		hdr.tc     = u16 & 1;
		hdr.rd     = u16 & 1;
		hdr.ra     = u16 & 1;
		hdr.z      = u16 & 0x7;
		hdr.rcode  = u16 & 0xf;
		hdr.nq     = u16;
		hdr.nans   = u16;
		hdr.nauth  = u16;
		hdr.nadd   = u16;

		mb->pos = mb->end = 0;
		err = dns_hdr_encode(mb, &hdr);
		if (err)
			break;

		mb->pos = 0;
		err = dns_hdr_decode(mb, &hdr2);
		if (err)
			break;

		if (0 != memcmp(&hdr, &hdr2, sizeof(hdr))) {
			(void)re_fprintf(stderr,
					 "dnshdr mismatch:\n%02w\n%02w\n",
					 &hdr, sizeof(hdr),
					 &hdr2, sizeof(hdr2));
			err = EBADMSG;
			break;
		}

		u16 *= 17;
	}

	for (uint8_t j=0; j<10; j++) {

		char debug[256] = "";

		re_snprintf(debug, sizeof(debug), "%s%s",
			  dns_hdr_opcodename(j), dns_hdr_rcodename(j));

		ASSERT_TRUE(str_isset(debug));
	}

 out:
	mem_deref(mb);

	return err;
}


int test_dns_rr(void)
{
	struct hash *ht = NULL;
	struct dnsrr *rr = NULL, *rr2 = NULL;
	struct mbuf *mb;
	size_t i;
	char debug[256] = "";
	int err = ENOMEM;

	static const uint16_t typev[] = {
		DNS_TYPE_A,    DNS_TYPE_NS,  DNS_TYPE_CNAME,
		DNS_TYPE_SOA,  DNS_TYPE_PTR, DNS_TYPE_MX,
		DNS_TYPE_AAAA, DNS_TYPE_SRV, DNS_TYPE_NAPTR,
		DNS_TYPE_TXT
	};

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = hash_alloc(&ht, 32);
	if (err)
		goto out;

	for (i=0; i<RE_ARRAY_SIZE(typev); i++) {

		hash_flush(ht);

		rr = dns_rr_alloc();
		if (!rr) {
			err = ENOMEM;
			break;
		}

		err = mkrr(rr, typev[i]);
		if (err)
			break;

		mb->pos = mb->end = 0;
		err = dns_rr_encode(mb, rr, 0, ht, 0);
		if (err)
			break;

		mb->pos = 0;
		err = dns_rr_decode(mb, &rr2, 0);
		if (err)
			break;

		if (!dns_rr_cmp(rr, rr2, true)) {
			(void)re_fprintf(stderr,
					 "dns_rr:\nrr:  %02w\n\nrr2: %02w\n",
					 rr, sizeof(*rr), rr2, sizeof(*rr2));
			hexdump(stderr, mb->buf, mb->end);
			err = EBADMSG;
			break;
		}

		re_snprintf(debug, sizeof(debug), "%H", dns_rr_print, rr);
		TEST_ASSERT(str_isset(debug));

		rr = mem_deref(rr);
		rr2 = mem_deref(rr2);
	}

 out:
	hash_flush(ht);
	mem_deref(ht);
	mem_deref(rr2);
	mem_deref(rr);
	mem_deref(mb);

	return err;
}


int test_dns_rr_dup(void)
{
	struct dnsrr *rr = NULL, *dup = NULL;
	size_t i;
	int err = ENOMEM;

	static const uint16_t typev[] = {
		DNS_TYPE_A,    DNS_TYPE_NS,  DNS_TYPE_CNAME,
		DNS_TYPE_SOA,  DNS_TYPE_PTR, DNS_TYPE_MX,
		DNS_TYPE_AAAA, DNS_TYPE_SRV, DNS_TYPE_NAPTR,
		DNS_TYPE_TXT
	};

	for (i=0; i<RE_ARRAY_SIZE(typev); i++) {

		rr = dns_rr_alloc();
		if (!rr) {
			err = ENOMEM;
			break;
		}

		err = mkrr(rr, typev[i]);
		if (err)
			break;

		err = dns_rr_dup(&dup, rr);
		if (err)
			break;

		if (!dns_rr_cmp(rr, dup, true)) {
			(void)re_fprintf(stderr,
					 "dns_rr_dup mismatch for type %s:\n",
					 dns_rr_typename(typev[i]));
			err = EBADMSG;
			break;
		}

		ASSERT_TRUE(rr != dup);
		ASSERT_TRUE(rr->name != dup->name);

		switch (typev[i]) {
		case DNS_TYPE_NS:
			ASSERT_TRUE(rr->rdata.ns.nsdname !=
				    dup->rdata.ns.nsdname);
			break;
		case DNS_TYPE_CNAME:
			ASSERT_TRUE(rr->rdata.cname.cname !=
				    dup->rdata.cname.cname);
			break;
		case DNS_TYPE_SOA:
			ASSERT_TRUE(rr->rdata.soa.mname !=
				    dup->rdata.soa.mname);
			ASSERT_TRUE(rr->rdata.soa.rname !=
				    dup->rdata.soa.rname);
			break;
		case DNS_TYPE_PTR:
			ASSERT_TRUE(rr->rdata.ptr.ptrdname !=
				    dup->rdata.ptr.ptrdname);
			break;
		case DNS_TYPE_MX:
			ASSERT_TRUE(rr->rdata.mx.exchange !=
				    dup->rdata.mx.exchange);
			break;
		case DNS_TYPE_TXT:
			ASSERT_TRUE(rr->rdata.txt.data !=
				    dup->rdata.txt.data);
			break;
		case DNS_TYPE_SRV:
			ASSERT_TRUE(rr->rdata.srv.target !=
				    dup->rdata.srv.target);
			break;
		case DNS_TYPE_NAPTR:
			ASSERT_TRUE(rr->rdata.naptr.flags !=
				    dup->rdata.naptr.flags);
			ASSERT_TRUE(rr->rdata.naptr.services !=
				    dup->rdata.naptr.services);
			ASSERT_TRUE(rr->rdata.naptr.regexp !=
				    dup->rdata.naptr.regexp);
			ASSERT_TRUE(rr->rdata.naptr.replace !=
				    dup->rdata.naptr.replace);
			break;
		}

		rr = mem_deref(rr);
		dup = mem_deref(dup);
	}

 out:
	mem_deref(dup);
	mem_deref(rr);

	return err;
}


/* Testcase to reproduce dname_decode looping error */
int test_dns_dname(void)
{
	static struct test {
		const char *str;
	} testv[] = {
		{
			"c000000c000100000e10002725324a57"
			"4d6e3837745836435541597754705361"
			"4c4c626743726e3475424e3642365957"
			"524e00"
		},
		{
			"31203700a22c9f17ea75de16785277fa"
			"db1094a7782b65a177715e45ffc59f9a"
			"73143748aaaf99aede63325c1f48e7fa"
			"56f9da"
		},
	};
	struct mbuf *mb;
	char *name = NULL;
	size_t i;
	int err = 0;

	mb = mbuf_alloc(4096);
	if (!mb)
		return ENOMEM;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct test *test = &testv[i];
		const size_t size = str_len(test->str) / 2;
		int e;

		err = str_hex(mb->buf, size, test->str);
		if (err)
			goto out;

		mb->pos = 0;
		mb->end = size;
		mb->size = size;

		/* Expect EINVAL */
		e = dns_dname_decode(mb, &name, 0);
		TEST_EQUALS(EINVAL, e);

		name = mem_deref(name);
	}

 out:
	mem_deref(mb);

	return err;
}


struct test_dns {
	int err;
	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	} addr;
	struct dnsc *dnsc;
	struct dnsrr *rr;
};


static void query_handler(int err, const struct dnshdr *hdr, struct list *ansl,
			  struct list *authl, struct list *addl, void *arg)
{
	struct dnsrr *rr      = list_ledata(list_head(ansl));
	struct test_dns *data = arg;
	struct sa sa;
	(void)hdr;
	(void)authl;
	(void)addl;
	(void)arg;

	if (!data || !rr) {
		re_cancel();
		return;
	}

	TEST_ERR(err);

	data->rr = mem_ref(rr);

	if (rr->type == DNS_TYPE_A) {
		sa_set_in(&sa, rr->rdata.a.addr, 0);
		DEBUG_INFO("%s. IN A %j\n", rr->name, &sa);
	}
	else if (rr->type == DNS_TYPE_AAAA) {
		sa_set_in6(&sa, rr->rdata.aaaa.addr, 0);
		DEBUG_INFO("%s. IN AAAA %j\n", rr->name, &sa);
	}

out:
	data->err = err;
	re_cancel();
}


static int check_dns_async(struct dns_query **qp,
			   struct test_dns *data, const char *name,
			   uint32_t addr)
{
	int err;

	data->addr.ipv4 = addr;
	data->err = ENODATA;
	data->rr  = NULL;

	err = dnsc_query(qp, data->dnsc, name, DNS_TYPE_A, DNS_CLASS_IN,
			 true, query_handler, data);
	TEST_ERR(err);
out:
	return err;
}


static int check_dns6_async(struct dns_query **qp,
			    struct test_dns *data, const char *name,
			    const uint8_t addr[16])
{
	int err;

	memcpy(data->addr.ipv6, addr, 16);
	data->err = ENODATA;
	data->rr  = NULL;

	err = dnsc_query(qp, data->dnsc, name, DNS_TYPE_AAAA, DNS_CLASS_IN,
			 true, query_handler, data);
	TEST_ERR(err);
out:
	return err;
}


static int check_dns(struct test_dns *data, const char *name, uint32_t addr)
{
	struct dns_query *q = NULL;
	int err;

	err = check_dns_async(&q, data, name, addr);
	TEST_ERR(err);

	err = re_main_timeout(100);
	TEST_ERR(err);

	/* check query handler result */
	err = data->err;
	if (err)
		goto out;

	TEST_ASSERT(data->rr);
	TEST_EQUALS(DNS_TYPE_A, data->rr->type);
	TEST_EQUALS(addr, data->rr->rdata.a.addr);
out:
	mem_deref(q);
	mem_deref(data->rr);
	return err;
}


static int check_dns6(struct test_dns *data, const char *name,
		      const uint8_t addr[16])
{
	struct dns_query *q = NULL;
	int err;

	err = check_dns6_async(&q, data, name, addr);
	TEST_ERR(err);

	err = re_main_timeout(100);
	TEST_ERR(err);

	/* check query handler result */
	err = data->err;
	if (err)
		goto out;

	TEST_ASSERT(data->rr);
	TEST_EQUALS(data->rr->type, DNS_TYPE_AAAA);
	TEST_EQUALS(0, memcmp(data->addr.ipv6, data->rr->rdata.aaaa.addr, 16));
out:
	mem_deref(q);
	mem_deref(data->rr);
	return err;
}


static int test_dns_integration_param(const char *laddr)
{
	struct dns_server *srv = NULL;
	struct test_dns data = {0};
	int err;

	/* Setup Mocking DNS Server */
	err = dns_server_alloc(&srv, laddr);
	TEST_ERR(err);

	err = dns_server_add_a(srv, "test1.example.net", IP_127_0_0_1, 1);
	TEST_ERR(err);

	err = dns_server_add_aaaa(srv, "test1.example.net", IP6_1, 1);
	TEST_ERR(err);

	err = dnsc_alloc(&data.dnsc, NULL, &srv->addr, 1);
	TEST_ERR(err);

	/* Test system getaddrinfo */
	dnsc_getaddrinfo(data.dnsc, true);
	err = check_dns(&data, "localhost", IP_127_0_0_1);
	TEST_EQUALS(dnsc_getaddrinfo_enabled(data.dnsc), true);
	TEST_ERR(err);
	dnsc_getaddrinfo(data.dnsc, false);
	TEST_EQUALS(dnsc_getaddrinfo_enabled(data.dnsc), false);

	err = check_dns(&data, "test1.example.net", IP_127_0_0_1);
	TEST_ERR(err);

	err = check_dns6(&data, "test1.example.net", IP6_1);
	TEST_ERR(err);

	/* Test does not exist */
	err = check_dns(&data, "test2.example.net", IP_127_0_0_1);
	TEST_EQUALS(ENODATA, err);

	err = check_dns6(&data, "test2.example.net", IP6_1);
	TEST_EQUALS(ENODATA, err);

	dns_server_flush(srv);

	err = dns_server_add_a(srv, "test1.example.net", IP_127_0_0_2, 1);
	TEST_ERR(err);

	err = dns_server_add_a(srv, "test2.example.net", IP_127_0_0_3, 1);
	TEST_ERR(err);

	err = dns_server_add_a(srv, "test3.example.net", IP_127_0_0_4, 1);
	TEST_ERR(err);

	err = dns_server_add_aaaa(srv, "test1.example.net", IP6_2, 1);
	TEST_ERR(err);

	err = dns_server_add_aaaa(srv, "test2.example.net", IP6_3, 1);
	TEST_ERR(err);

	err = dns_server_add_aaaa(srv, "test3.example.net", IP6_4, 1);
	TEST_ERR(err);


	/* --- Test DNS Cache --- */
	err = check_dns(&data, "test1.example.net", IP_127_0_0_1);
	TEST_ERR(err);

	err = check_dns6(&data, "test1.example.net", IP6_1);
	TEST_ERR(err);

	err = check_dns(&data, "test2.example.net", IP_127_0_0_3);
	TEST_ERR(err);

	err = check_dns(&data, "test2.example.net", IP_127_0_0_3);
	TEST_ERR(err);

	err = check_dns6(&data, "test2.example.net", IP6_3);
	TEST_ERR(err);

	err = check_dns6(&data, "test2.example.net", IP6_3);
	TEST_ERR(err);

	/* Check another resource record afterwards */
	err = check_dns(&data, "test3.example.net", IP_127_0_0_4);
	TEST_ERR(err);

	err = check_dns6(&data, "test3.example.net", IP6_4);
	TEST_ERR(err);

	sys_msleep(100);
	re_main_timeout(1);

	/* --- Check expired TTL --- */
	err = check_dns(&data, "test1.example.net", IP_127_0_0_2);
	TEST_ERR(err);

	err = check_dns6(&data, "test1.example.net", IP6_2);
	TEST_ERR(err);

	/* --- Test explicit DNS cache flush --- */
	dns_server_flush(srv);
	err = dns_server_add_a(srv, "test1.example.net", IP_127_0_0_5, 1);
	TEST_ERR(err);
	dnsc_cache_flush(data.dnsc);
	err = check_dns(&data, "test1.example.net", IP_127_0_0_5);
	TEST_ERR(err);

	/* --- Again DNS Cache --- */
	err = check_dns(&data, "test1.example.net", IP_127_0_0_5);
	TEST_ERR(err);

out:
	mem_deref(data.dnsc);
	mem_deref(srv);

	return err;
}


int test_dns_integration(void)
{
	int err;

	err = test_dns_integration_param("127.0.0.1");
	TEST_ERR(err);

	if (test_ipv6_supported()) {
		err = test_dns_integration_param("::1");
		TEST_ERR(err);
	}

 out:
	return err;
}


static int test_dns_reg_param(const char *laddr)
{
	struct dns_server *srv = NULL;
	struct test_dns data = {0};
	struct dns_query *q;
	int err;

	/* Setup Mocking DNS Server */
	err = dns_server_alloc(&srv, laddr);
	TEST_ERR(err);

	err = dns_server_add_a(srv, "test1.example.net", IP_127_0_0_1, 1);
	TEST_ERR(err);

	err = dns_server_add_aaaa(srv, "test1.example.net", IP6_1, 1);
	TEST_ERR(err);

	err = dnsc_alloc(&data.dnsc, NULL, &srv->addr, 1);
	TEST_ERR(err);

	err = check_dns(&data, "test1.example.net", IP_127_0_0_1);
	TEST_ERR(err);

	err = check_dns6(&data, "test1.example.net", IP6_1);
	TEST_ERR(err);

	dns_server_flush(srv);

	/* --- Test DNS Cache --- */
	err = check_dns(&data, "test1.example.net", IP_127_0_0_1);
	TEST_ERR(err);

	err = check_dns6(&data, "test1.example.net", IP6_1);
	TEST_ERR(err);

	dnsc_cache_flush(data.dnsc);

	/* --- Test early query cancellation --- */
	err = dnsc_query(&q, data.dnsc, "test1.example.net", DNS_TYPE_A,
			 DNS_CLASS_IN, true, query_handler, &data);
	TEST_ERR(err);
	mem_deref(q);

	/* --- Leave query open for cleanup test --- */
	err = dnsc_query(NULL, data.dnsc, "test1.example.net", DNS_TYPE_A,
			 DNS_CLASS_IN, true, query_handler, &data);
	TEST_ERR(err);

	err = dnsc_query(NULL, data.dnsc, "test1.example.net", DNS_TYPE_AAAA,
			 DNS_CLASS_IN, true, query_handler, &data);
	TEST_ERR(err);

out:
	mem_deref(data.dnsc);
	mem_deref(srv);

	return err;
}


int test_dns_reg(void)
{
	int err;

	err = test_dns_reg_param("127.0.0.1");
	TEST_ERR(err);

	if (test_ipv6_supported()) {
		err = test_dns_reg_param("::1");
		TEST_ERR(err);
	}

 out:
	return err;
}


int test_dns_nameservers(void)
{
	struct sa srvv[8];
	uint32_t srvc = RE_ARRAY_SIZE(srvv);

	int err = dns_srv_get(NULL, 0, srvv, &srvc);
	TEST_ERR(err);

	ASSERT_TRUE(srvc >= 1);

	for (uint32_t i=0; i<srvc; i++) {
		ASSERT_TRUE(sa_isset(&srvv[i], SA_ALL));
	}

 out:
	return err;
}


struct fixture {
	struct dnsc *dnsc;
	const struct sa *srv_addr;
	uint32_t srvc;
	unsigned answers;
	int proto;
};


enum { EXPECTED_ANSWERS = 2 };


static void dns_query_handler(int err, const struct dnshdr *hdr,
			      struct list *ansl, struct list *authl,
			      struct list *addl, void *arg)
{
	struct fixture *fix = arg;
	(void)hdr;
	(void)authl;
	(void)addl;

	if (err) {
		DEBUG_WARNING("dns query error: %m\n", err);
		re_cancel();
		return;
	}

	fix->answers += list_count(ansl);

	if (fix->answers < EXPECTED_ANSWERS) {

		err = dnsc_query_srv(NULL, fix->dnsc, "foo.example.com",
				     DNS_TYPE_AAAA, DNS_CLASS_IN,
				     fix->proto, fix->srv_addr,
				     &fix->srvc, false,
				     dns_query_handler, fix);
		TEST_ERR(err);
	}

 out:
	if (fix->answers >= EXPECTED_ANSWERS || err) {
		re_cancel();
	}
}


static int test_dns_param(const char *laddr, int proto)
{
	struct dns_server *srv = NULL;
	struct fixture fix = {
		.srvc = 1,
		.proto = proto
	};

	int err = dnsc_alloc(&fix.dnsc, NULL, NULL, 0);
	TEST_ERR(err);

	dnsc_cache_max(fix.dnsc, 0);

	err = dns_server_alloc(&srv, laddr);
	TEST_ERR(err);

	uint8_t ipv6_addr[16] = {0};
	err = dns_server_add_aaaa(srv, "foo.example.com", ipv6_addr, 3600);
	TEST_ERR(err);

	switch (proto) {

	case IPPROTO_UDP:
		fix.srv_addr = &srv->addr;
		break;

	case IPPROTO_TCP:
		fix.srv_addr = &srv->addr_tcp;
		break;
	}

	err = dnsc_query_srv(NULL, fix.dnsc, "foo.example.com",
			     DNS_TYPE_AAAA, DNS_CLASS_IN, proto,
			     fix.srv_addr, &fix.srvc, false,
			     dns_query_handler, &fix);
	TEST_ERR(err);

	err = re_main_timeout(5000);
	TEST_ERR(err);

	ASSERT_TRUE(fix.answers >= EXPECTED_ANSWERS);

 out:
	mem_deref(fix.dnsc);
	mem_deref(srv);

	return err;
}


int test_dns_proto(void)
{
	int err;

	err = test_dns_param("127.0.0.1", IPPROTO_UDP);
	TEST_ERR(err);

	err = test_dns_param("127.0.0.1", IPPROTO_TCP);
	TEST_ERR(err);

	if (test_ipv6_supported()) {

		err = test_dns_param("::1", IPPROTO_UDP);
		TEST_ERR(err);

		err = test_dns_param("::1", IPPROTO_TCP);
		TEST_ERR(err);
	}

 out:
	return err;
}
