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

	mem_deref(mb);

	return err;
}


int test_dns_rr(void)
{
	struct hash *ht = NULL;
	struct dnsrr *rr = NULL, *rr2 = NULL;
	struct mbuf *mb;
	size_t i;
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

		if (!dns_rr_cmp(rr, rr2, false)) {
			(void)re_fprintf(stderr,
					 "dns_rr:\nrr:  %02w\n\nrr2: %02w\n",
					 rr, sizeof(*rr), rr2, sizeof(*rr2));
			hexdump(stderr, mb->buf, mb->end);
			err = EBADMSG;
			break;
		}

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
	uint32_t addr;
	struct dnsc *dnsc;
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

	TEST_EQUALS(DNS_TYPE_A, rr->type);
	TEST_EQUALS(data->addr, rr->rdata.a.addr);

	sa_set_in(&sa, rr->rdata.a.addr, 0);

	DEBUG_INFO("%s. IN A %j\n", rr->name, &sa);

out:
	data->err = err;
	re_cancel();
}


static int check_dns(struct test_dns *data, const char *name, uint32_t addr,
		     bool main)
{
	struct dns_query *q = NULL;
	int err;

	data->addr = addr;
	data->err  = ENODATA;

	err = dnsc_query(&q, data->dnsc, name, DNS_TYPE_A, DNS_CLASS_IN, true,
			 query_handler, data);
	TEST_ERR(err);

	if (main) {
		err = re_main_timeout(100);
		TEST_ERR(err);
	}

	/* check query handler result */
	err = data->err;

out:
	mem_deref(q);
	return err;
}


int test_dns_integration(void)
{
	struct dns_server *srv = NULL;
	struct test_dns data = {0};
	struct dns_query *q;
	int err;

	/* Setup Mocking DNS Server */
	err = dns_server_alloc(&srv, false);
	TEST_ERR(err);

	err = dns_server_add_a(srv, "test1.example.net", IP_127_0_0_1, 1);
	TEST_ERR(err);

	err = dnsc_alloc(&data.dnsc, NULL, &srv->addr, 1);
	TEST_ERR(err);

	/* Test system getaddrinfo */
	dnsc_getaddrinfo(data.dnsc, true);
	err = check_dns(&data, "localhost", IP_127_0_0_1, true);
	TEST_EQUALS(dnsc_getaddrinfo_enabled(data.dnsc), true);
	TEST_ERR(err);
	dnsc_getaddrinfo(data.dnsc, false);
	TEST_EQUALS(dnsc_getaddrinfo_enabled(data.dnsc), false);

	err = check_dns(&data, "test1.example.net", IP_127_0_0_1, true);
	TEST_ERR(err);

	/* Test does not exist */
	err = check_dns(&data, "test2.example.net", IP_127_0_0_1, true);
	TEST_EQUALS(ENODATA, err);

	dns_server_flush(srv);

	err = dns_server_add_a(srv, "test1.example.net", IP_127_0_0_2, 1);
	TEST_ERR(err);

	err = dns_server_add_a(srv, "test2.example.net", IP_127_0_0_3, 1);
	TEST_ERR(err);

	err = dns_server_add_a(srv, "test3.example.net", IP_127_0_0_4, 1);
	TEST_ERR(err);

	/* --- Test DNS Cache --- */
	err = check_dns(&data, "test1.example.net", IP_127_0_0_1, true);
	TEST_ERR(err);

	err = check_dns(&data, "test2.example.net", IP_127_0_0_3, true);
	TEST_ERR(err);

	err = check_dns(&data, "test2.example.net", IP_127_0_0_3, true);
	TEST_ERR(err);

	/* Check another resource record afterwards */
	err = check_dns(&data, "test3.example.net", IP_127_0_0_4, true);
	TEST_ERR(err);

	sys_msleep(100);    /* wait until TTL timer expires */
	re_main_timeout(1); /* execute tmr callbacks */

	/* --- Check expired TTL --- */
	err = check_dns(&data, "test1.example.net", IP_127_0_0_2, true);
	TEST_ERR(err);

	/* --- Test explicit DNS cache flush --- */
	dns_server_flush(srv);
	err = dns_server_add_a(srv, "test1.example.net", IP_127_0_0_5, 1);
	TEST_ERR(err);
	dnsc_cache_flush(data.dnsc);
	err = check_dns(&data, "test1.example.net", IP_127_0_0_5, true);
	TEST_ERR(err);

	/* --- Test early query cancellation --- */
	err = dnsc_query(&q, data.dnsc, "test1.example.net", DNS_TYPE_A,
			 DNS_CLASS_IN, true, query_handler, &data);
	TEST_ERR(err);
	mem_deref(q);

	err = check_dns(&data, "test1.example.net", IP_127_0_0_5, true);
	TEST_ERR(err);

	/* --- Leave query open for cleanup test --- */
	err = dnsc_query(&q, data.dnsc, "test1.example.net", DNS_TYPE_A,
			 DNS_CLASS_IN, true, query_handler, &data);
	TEST_ERR(err);

out:
	mem_deref(data.dnsc);
	mem_deref(srv);

	return err;
}
