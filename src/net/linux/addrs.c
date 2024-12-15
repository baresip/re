/**
 * @file linux/addrs.c Get interface addresses (See rtnetlink(7))
 *
 * Copyright (C) 2024 Sebastian Reimers
 */

#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_sa.h>
#include <re_net.h>
#include "macros.h"

#define DEBUG_MODULE "linuxaddrs"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void parse_rtattr(struct rtattr *tb[], struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (IFA_MAX + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= IFA_MAX) {
			tb[rta->rta_type] = rta;
		}
		rta = RTA_NEXT(rta, len);
	}
}


static bool is_ipv6_deprecated(uint32_t flags)
{
	if (flags & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC | IFA_F_DADFAILED |
		     IFA_F_DEPRECATED))
		return true;

	return false;
}

static bool parse_msg(struct nlmsghdr *msg, int len, net_ifaddr_h *ifh,
		      void *arg)
{
	struct nlmsghdr *nlh;
	for (nlh = msg; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct sa sa;
		uint32_t flags;
		char if_name[IF_NAMESIZE];

		if (nlh->nlmsg_type == NLMSG_DONE) {
			return true;
		}
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			DEBUG_WARNING("netlink recv error\n");
			return false;
		}

		struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
		struct rtattr *rta_tb[IFA_MAX + 1];

		parse_rtattr(rta_tb, IFA_RTA(ifa),
			     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

		if (!rta_tb[IFA_ADDRESS])
			continue;

		if (rta_tb[IFA_FLAGS] && ifa->ifa_family == AF_INET6) {
			flags = *(uint32_t *)RTA_DATA(rta_tb[IFA_FLAGS]);
			if (is_ipv6_deprecated(flags))
				continue;
		}

		if (ifa->ifa_family == AF_INET) {
			sa_init(&sa, AF_INET);
			sa.u.in.sin_addr.s_addr =
				*(uint32_t *)RTA_DATA(rta_tb[IFA_ADDRESS]);
		}
		else if (ifa->ifa_family == AF_INET6) {
			sa_set_in6(&sa, RTA_DATA(rta_tb[IFA_ADDRESS]), 0);
			sa_set_scopeid(&sa, ifa->ifa_index);
		}
		else
			continue;

		if (!if_indextoname(ifa->ifa_index, if_name))
			continue;

		if (ifh(if_name, &sa, arg))
			return true;
	}

	return false;
}


int net_netlink_addrs(net_ifaddr_h *ifh, void *arg)
{
	int err = 0;
	char buffer[8192];
	re_sock_t sock;
	int len;

	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req;

	if (!ifh)
		return EINVAL;

	if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		err = errno;
		DEBUG_WARNING("socket failed %m\n", err);
		return err;
	}

	struct timeval timeout = {5, 0};
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type  = RTM_GETADDR;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		err = errno;
		DEBUG_WARNING("sendto failed %m\n", err);
		goto out;
	}

	while ((len = (int)recv(sock, buffer, sizeof(buffer), 0)) > 0) {
		if (parse_msg((struct nlmsghdr *)buffer, len, ifh, arg))
			break;
	}

out:
	close(sock);

	return err;
}
