/**
 * @file net.c  Networking code.
 *
 * Copyright (C) 2010 Creytiv.com
 */
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <stdlib.h>
#include <string.h>
#if !defined(WIN32)
#define __USE_BSD 1  /**< Use BSD code */
#include <unistd.h>
#include <netdb.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_udp.h>
#include <re_mem.h>


#define DEBUG_MODULE "net"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/**
 * Get the source IP address for a specified destination
 *
 * @param dst Destination IP address
 * @param ip  Returned Source IP address
 *
 * @return 0 if success, otherwise errorcode
 */
int net_dst_source_addr_get(const struct sa *dst, struct sa *ip)
{
	int err;
	struct udp_sock *us;

	if (!dst || !ip || !sa_isset(dst, SA_ADDR)) {
		return EINVAL;
	}

	if (sa_af(dst) == AF_INET6)
		err = sa_set_str(ip, "::", 0);
	else
		err = sa_set_str(ip, "0.0.0.0", 0);

	if (err)
		return err;

	err = udp_listen(&us, ip, NULL, NULL);
	if (err)
		return err;

	err = udp_connect(us, dst);
	if (err)
		goto out;

	err = udp_local_get(us, ip);

out:
	mem_deref(us);
	return err;
}


/**
 * Get the default source IP address
 *
 * @param af  Address Family
 * @param ip  Returned IP address
 *
 * @return 0 if success, otherwise errorcode
 */
int net_default_source_addr_get(int af, struct sa *ip)
{
	struct sa dst;
	int err;
#if !defined(WIN32)
	char ifname[64] = "";
#endif

	sa_init(&dst, af);

	if (af == AF_INET6)
		sa_set_str(&dst, "1::1", 53);
	else
		sa_set_str(&dst, "1.1.1.1", 53);

	err = net_dst_source_addr_get(&dst, ip);

	if (af == AF_INET6 && sa_is_linklocal(ip)) {
		sa_init(ip, af);
		return 0;
	}

	if (!err)
		return 0;

#ifdef WIN32
	return err;
#else
#ifdef HAVE_ROUTE_LIST
	/* Get interface with default route */
	(void)net_rt_default_get(af, ifname, sizeof(ifname));
#endif

	/* First try with default interface */
	if (0 == net_if_getaddr(ifname, af, ip))
		return 0;

	/* Then try first real IP */
	if (0 == net_if_getaddr(NULL, af, ip))
		return 0;

	return net_if_getaddr4(ifname, af, ip);
#endif
}


/**
 * Get a list of all network interfaces including name and IP address.
 * Both IPv4 and IPv6 are supported
 *
 * @param ifh Interface handler, called once per network interface
 * @param arg Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int net_if_apply(net_ifaddr_h *ifh, void *arg)
{
#ifdef HAVE_GETIFADDRS
	return net_getifaddrs(ifh, arg);
#else
	return net_if_list(ifh, arg);
#endif
}


static bool net_rt_handler(const char *ifname, const struct sa *dst,
			   int dstlen, const struct sa *gw, void *arg)
{
	void **argv = arg;
	struct sa *ip = argv[1];
	(void)dst;
	(void)dstlen;

	if (0 == str_cmp(ifname, argv[0])) {
		*ip = *gw;
		return true;
	}

	return false;
}


/**
 * Get the IP-address of the default gateway
 *
 * @param af  Address Family
 * @param gw  Returned Gateway address
 *
 * @return 0 if success, otherwise errorcode
 */
int net_default_gateway_get(int af, struct sa *gw)
{
	char ifname[64];
	void *argv[2];
	int err;

	if (!af || !gw)
		return EINVAL;

	err = net_rt_default_get(af, ifname, sizeof(ifname));
	if (err)
		return err;

	argv[0] = ifname;
	argv[1] = gw;

	err = net_rt_list(net_rt_handler, argv);
	if (err)
		return err;

	return 0;
}
