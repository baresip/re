/**
 * @file net.c Network Testcode
 */
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_net"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static bool ipv6_handler(const char *ifname, const struct sa *sa, void *arg)
{
	bool *supp = arg;
	(void)ifname;

	if (AF_INET6 == sa_af(sa)) {
		*supp = true;
		return true;
	}

	return false;
}


bool test_ipv6_supported(void)
{
	bool supp = false;

	net_if_apply(ipv6_handler, &supp);

	return supp;
}


int test_net_dst_source_addr_get(void)
{
	struct sa dst;
	struct sa ip;
	int err;

	sa_init(&dst, AF_INET);
	sa_init(&ip, AF_UNSPEC);

	sa_set_str(&dst, "127.0.0.1", 53);

	err = net_dst_source_addr_get(&dst, &ip);
	if (err)
		return err;

	TEST_ASSERT(sa_is_loopback(&ip));

	if (test_ipv6_supported()) {

		sa_init(&dst, AF_INET6);
		sa_init(&ip, AF_UNSPEC);
		sa_set_str(&dst, "::1", 53);

		err = net_dst_source_addr_get(&dst, &ip);
		if (err)
			return err;

		TEST_ASSERT(sa_is_loopback(&ip));
	}
	else {
		DEBUG_NOTICE("ipv6 disabled\n");
	}

out:
	return err;
}


int test_net_if(void)
{
	struct sa ip;
	int err;
	char ifname[255];

	sa_set_str(&ip, "127.0.0.1", 0);

	err = net_if_getname(ifname, sizeof(ifname), AF_INET, &ip);
	TEST_ERR(err);
	TEST_ASSERT(str_isset(ifname));

out:
	return err;
}
