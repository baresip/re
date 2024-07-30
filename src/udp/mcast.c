/**
 * @file mcast.c  UDP Multicast
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <net/if.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_net.h>
#include <re_sa.h>
#include <re_udp.h>


static int multicast_update(struct udp_sock *us, const struct sa *group,
			    const struct sa *local, bool join)
{
	struct ip_mreqn mreq;
	struct ipv6_mreq mreq6;
	int err;
	int if_index = 0;

	if (!us || !group)
		return EINVAL;

	if (local && !sa_is_any(local)) {
		char name[64];
		if (net_if_getname(name, sizeof(name), sa_af(local), local) != 0)
			return EADDRNOTAVAIL;

		if ((if_index = if_nametoindex(name)) == 0)
			return ENXIO;
	}


	switch (sa_af(group)) {

	case AF_INET:
		mreq.imr_multiaddr = group->u.in.sin_addr;
		mreq.imr_ifindex = if_index;
		if (if_index == 0) {
			mreq.imr_address.s_addr = 0;
		}

		err = udp_setsockopt(us, IPPROTO_IP,
				     join
				     ? IP_ADD_MEMBERSHIP
				     : IP_DROP_MEMBERSHIP,
				     &mreq, sizeof(mreq));
		break;

	case AF_INET6:
		mreq6.ipv6mr_multiaddr = group->u.in6.sin6_addr;
		mreq6.ipv6mr_interface = if_index;
		if (if_index == 0) {
			mreq6.ipv6mr_interface = sa_scopeid(group);
		}

		err = udp_setsockopt(us, IPPROTO_IPV6,
				     join
				     ? IPV6_JOIN_GROUP
				     : IPV6_LEAVE_GROUP,
				     &mreq6, sizeof(mreq6));
		break;

	default:
		return EAFNOSUPPORT;
	}

	return err;
}

int udp_multicast_join(struct udp_sock *us, const struct sa *group)
{
	return multicast_update(us, group, NULL, true);
}


int udp_multicast_leave(struct udp_sock *us, const struct sa *group)
{
	return multicast_update(us, group, NULL, false);
}

int udp_multicast_join_local(struct udp_sock *us, const struct sa *group,
			     const struct sa *local)
{
	return multicast_update(us, group, local, true);
}

int udp_multicast_leave_local(struct udp_sock *us, const struct sa *group,
			      const struct sa *local)
{
	return multicast_update(us, group, local, false);
}
