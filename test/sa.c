/**
 * @file sa.c Socket address Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_sa"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_sa_cmp(void)
{
	const struct {
		const char *host1;
		uint16_t port1;
		const char *host2;
		uint16_t port2;
		bool eq;
	} testv[] = {
#if HAVE_UNIXSOCK
		{
			"unix:/test.sock", 0,
			"unix:/test.sock", 0,
			true
		},
#endif
		{
			"1.2.3.4", 12345,
			"1.2.3.4", 12345,
			true
		},
		{
			"1.2.3.4", 12345,
			"1.2.3.5", 12345,
			false
		},
		{
			"1.2.3.4", 12345,
			"1.2.3.4", 12344,
			false
		},
		{
			"0:0:0:0:0:0:0:0", 123,
			"::", 123,
			true
		},
		{
			"0:0:0:0:0:0:0:1", 123,
			"::1", 123,
			true
		},
		{
			"0:0:0:0:0:0:1:1", 123,
			"::1", 123,
			false
		},
		{
			"2001:0:53aa:64c:0:fbff:ab2e:1eac",        2001,
			"2001:0000:53aa:064c:0000:fbff:ab2e:1eac", 2001,
			true
		},
		{
			"3001:0:53aa:64c:0:fbff:ab2e:1eac",        2001,
			"2001:0000:53aa:064c:0000:fbff:ab2e:1eac", 2001,
			false
		},
		{
			"192.168.1.1",                             123,
			"2001:0000:53aa:064c:0000:fbff:ab2e:1eac", 123,
			false
		},
		{ /* IPv6-mapped IPv4-address */
			"::ffff:208.68.208.201",                   3478,
			"208.68.208.201",                          3478,
			true
		},
		{
			"fe80::215:58ff:fe2d:90ab", 3333,
			"fe80:0000:0000:0000:0215:58ff:fe2d:90ab", 3333,
			true
		},
		{
			"fe80::215:58ff:fe2d:90ab", 3333,
			"fe80:0000:0000:0000:1215:58ff:fe2d:90ab", 3333,
			false
		},
	};
	size_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		struct sa sa1, sa2;
		bool eq;

		err = sa_set_str(&sa1, testv[i].host1, testv[i].port1);
		if (err)
			break;
		err = sa_set_str(&sa2, testv[i].host2, testv[i].port2);
		if (err)
			break;

		eq = sa_cmp(&sa1, &sa2, SA_ALL);
		if (!testv[i].eq == !eq)
			continue;

		DEBUG_WARNING("sa cmp %u: (%J) (%J) expected (%d),"
			      " got (%d)\n", i, &sa1, &sa2,
			      testv[i].eq, eq);
		return EINVAL;
	}

	return err;
}


int test_sa_decode(void)
{
	const struct {
		int err;
		int af;
		const char *str;
		const char *addr;
		uint16_t port;
	} testv[] = {
		{0,      AF_INET,  "1.2.3.4:1234",  "1.2.3.4", 1234},
		{0,      AF_INET,  "1.2.3.4:0",     "1.2.3.4", 0},
		{EINVAL, AF_INET,  "1.2.3.4",       "",        0},
		{EINVAL, AF_INET,  "1.2.3.4.:1234", "",        0},
		{0, AF_INET6, "[::1]:1", "::1", 1},
		{0, AF_INET6, "[fe80::215:58ff:fe2d:90ab]:3333",
		 "fe80::215:58ff:fe2d:90ab", 3333},
		{EINVAL, AF_INET6, "[::1]", "", 0},
	};
	uint32_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		struct sa sa, sa2;
		char buf[64];
		int e;

		e = sa_decode(&sa, testv[i].str, strlen(testv[i].str));
		if (testv[i].err != e) {
			DEBUG_WARNING("sa_decode: test %u:"
				      " expected (%m) got (%m) [%s]\n", i,
				      testv[i].err, e, testv[i].str);
			err = EINVAL;
			break;
		}
		if (e)
			continue;

		if (testv[i].af != sa_af(&sa)) {
			DEBUG_WARNING("sa_decode: af mismatch %d != %d\n",
				      testv[i].af, sa_af(&sa));
			err = EINVAL;
			break;
		}

		err = sa_set_str(&sa2, testv[i].addr, testv[i].port);
		if (err)
			break;

		if (!sa_cmp(&sa, &sa2, SA_ALL)) {
			DEBUG_WARNING("sa_decode: sa_cmp() failed\n");
			err = EINVAL;
			break;
		}

		(void)re_snprintf(buf, sizeof(buf), "%J", &sa);
		if (0 != strcmp(testv[i].str, buf)) {
			DEBUG_WARNING("%u: strcmp: %s != %s\n",
				      testv[i].str, buf);
			err = EINVAL;
			break;
		}
	}

	return err;
}


/* Test classification of loopback and link-local IP address */
int test_sa_class(void)
{
	const struct {
		bool lo;
		bool ll;
		bool any;
		const char *addr;
	} testv[] = {
		{false, false, true,  "0.0.0.0"},
		{false, false, false, "1.2.3.4"},
		{true,  false, false, "127.0.0.0"},
		{true,  false, false, "127.0.0.1"},
		{true,  false, false, "127.3.0.3"},
		{false, true,  false, "169.254.1.2"},
		{false, false, true,  "::"},
		{true,  false, false, "::1"},
		{false, true,  false, "fe80::215:58ff:fe2d:90ab"},
		{false, false, false, "2610:a0:c779:b::d1ad:35b4"}
	};
	uint32_t i;
	int err = 0;

	/*
	 * NOTE: The application and library must use the same build flags,
	 *       so that the size of "struct sa" is the same.
	 */
	ASSERT_EQ(sizeof(struct sa), sa_struct_get_size());

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		struct sa sa;
		int lo, ll, any;

		err = sa_set_str(&sa, testv[i].addr, 0);
		if (err)
			goto out;

		lo = sa_is_loopback(&sa);
		if ((int)testv[i].lo != lo) {
			DEBUG_WARNING("%u: %s: loopback mismatch %d!=%d\n",
				      i, testv[i].addr, testv[i].lo, lo);
			err = EINVAL;
			goto out;
		}

		ll = sa_is_linklocal(&sa);
		if ((int)testv[i].ll != ll) {
			DEBUG_WARNING("%u: %s: linklocal mismatch %d!=%d\n",
				      i, testv[i].addr, testv[i].ll, ll);
			err = EINVAL;
			goto out;
		}

		if (ll && sa_af(&sa)==AF_INET6) {
			sa_set_scopeid(&sa, 2);
			TEST_EQUALS(2, sa_scopeid(&sa));
		}

		any = sa_is_any(&sa);
		if ((int)testv[i].any != any) {
			DEBUG_WARNING("%u: %s: any mismatch %d!=%d\n",
				      i, testv[i].addr, testv[i].any, any);
			err = EINVAL;
			goto out;
		}
	}

#if 0
	{
		struct sa sax;
		TEST_ASSERT(sizeof(sax.u) <= sizeof(sax.u.padding));
	}
#endif

 out:
	return err;
}


int test_sa_ntop(void)
{
	const struct {
		int af;
		const char *addr;
	} testv[] = {
		{AF_INET,  "0.0.0.0"},
		{AF_INET,  "1.2.3.4"},
		{AF_INET,  "255.254.253.128"},
		{AF_INET6, "::1"},
		{AF_INET6, "fe80::215:58ff:fe2d:90ab"},
		{AF_INET6, "2610:a0:c779:b::d1ad:35b4"}
	};
	uint32_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {
		struct sa sa0, sa;
		char buf[64];

		err = sa_set_str(&sa0, testv[i].addr, 0);
		if (err)
			break;

		if (testv[i].af != sa_af(&sa0)) {
			DEBUG_WARNING("ntop: af mismatch %d != %d\n",
				      testv[i].af, sa_af(&sa0));
			err = EINVAL;
			break;
		}

		err = sa_ntop(&sa0, buf, 2);
		TEST_NOT_EQUALS(0, err);

		err = sa_ntop(&sa0, buf, sizeof(buf));
		if (err)
			break;

		if (0 != strcmp(buf, testv[i].addr)) {
			DEBUG_WARNING("ntop: addr mismatch (%s) != (%s)\n",
				      testv[i].addr, buf);
			err = EINVAL;
			break;
		}

		err = sa_set_sa(&sa, &sa0.u.sa);
		if (err) {
			DEBUG_WARNING("sa_set_sa: %m\n", err);
			break;
		}
		if (testv[i].af != sa_af(&sa)) {
			err = EINVAL;
			DEBUG_WARNING("af mismatch (test=%d sa=%d)\n",
				      testv[i].af, sa_af(&sa));
			break;
		}
	}

out:
	return err;
}


int test_sa_pton(void)
{
	struct sa sa;
	int err = 0;
	const struct {
		const char *addr;
		int err;
	} testv[] = {
		{"github.com",                      EINVAL       },
		{"6002",                            EINVAL       },
		{"ga01::3a28",                      EINVAL       },
		{"fa01::2a29",                      0            },
		{"127.0.0.1",                       0            },
		{"192.168.110.2",                   0            },
#if HAVE_UNIXSOCK
		{"unix:/test.sock",                 0            },
#endif
		{"fe80::xxxx:d8d9:ddc3:25dd:%eth0", EADDRNOTAVAIL},
	};

	for (size_t i=0; i<RE_ARRAY_SIZE(testv); i++) {
		int e = sa_pton(testv[i].addr, &sa);
		TEST_EQUALS(testv[i].err, e);
	}

 out:
	return err;
}


int test_sa_pton_linklocal(void)
{
	const char test_ipv6ll_scope[] = "fe80::3a28:d8d9:ddc3:25dd%";
	char buf[256];
	struct sa sa_default_ip, sa;
	int err;
#ifndef WIN32
	char ifname[64];
#endif

	if (0 != net_if_getlinklocal(NULL, AF_INET6, &sa_default_ip))
		return ESKIPPED;

	/* Use IPv4 since not all test systems have a default IPv6 route */
	net_default_source_addr_get(AF_INET, &sa_default_ip);

#ifdef WIN32
	re_snprintf(buf, sizeof(buf), "%s%d",
		    test_ipv6ll_scope, sa_scopeid(&sa_default_ip));
#else
	net_if_getname(ifname, sizeof(ifname), AF_INET, &sa_default_ip);
	re_snprintf(buf, sizeof(buf), "%s%s",
		    test_ipv6ll_scope, ifname);
#endif

	err = sa_pton(buf, &sa);
	TEST_ERR(err);

	ASSERT_EQ(AF_INET6, sa_af(&sa));
	ASSERT_TRUE(sa_is_linklocal(&sa));

 out:
	return err;
}
