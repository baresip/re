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
#include <re_list.h>
#include <re_mem.h>
#include <re_sa.h>
#include <re_net.h>
#include "macros.h"

#define DEBUG_MODULE "linuxaddrs"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

enum { RE_NETLINK_BUFSZ = 8192 };

struct iff_up_e {
	struct le le;
	uint32_t ifi_index;
};


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


static int parse_msg_link(struct nlmsghdr *msg, ssize_t len,
			  struct list *iff_up_l)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

	for (nlh = msg; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type == NLMSG_DONE) {
			return 0;
		}
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			DEBUG_WARNING("netlink recv error\n");
			return EBADMSG;
		}

		ifi = NLMSG_DATA(nlh);

		if (!(ifi->ifi_flags & IFF_UP))
			continue;

		struct iff_up_e *e = mem_zalloc(sizeof(struct iff_up_e), NULL);
		if (!e)
			return ENOMEM;

		e->ifi_index = ifi->ifi_index;

		list_append(iff_up_l, &e->le, e);
	}

	return EALREADY;
}


static int parse_msg_addr(struct nlmsghdr *msg, ssize_t len, net_ifaddr_h *ifh,
			  struct list *iff_up_l, void *arg)
{
	struct nlmsghdr *nlh;
	for (nlh = msg; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct sa sa;
		uint32_t flags;
		bool iff_up = false;
		void *addr;
		char if_name[IF_NAMESIZE];

		if (nlh->nlmsg_type == NLMSG_DONE) {
			return 0;
		}
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			DEBUG_WARNING("netlink recv error\n");
			return EBADMSG;
		}

		struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
		struct rtattr *rta_tb[IFA_MAX + 1];

		parse_rtattr(rta_tb, IFA_RTA(ifa),
			     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

		if (!rta_tb[IFA_ADDRESS])
			continue;

		struct le *le;
		LIST_FOREACH(iff_up_l, le)
		{
			struct iff_up_e *e = le->data;
			if (ifa->ifa_index == e->ifi_index) {
				iff_up = true;
				break;
			}
		}

		if (!iff_up)
			continue;

		if (rta_tb[IFA_FLAGS] && ifa->ifa_family == AF_INET6) {
			flags = *(uint32_t *)RTA_DATA(rta_tb[IFA_FLAGS]);
			if (is_ipv6_deprecated(flags))
				continue;
		}

		if (rta_tb[IFA_LOCAL])
			/* looks like point-to-point network, use local
			 * address, instead of peer */
			addr = RTA_DATA(rta_tb[IFA_LOCAL]);
		else
			addr = RTA_DATA(rta_tb[IFA_ADDRESS]);

		if (ifa->ifa_family == AF_INET) {
			sa_init(&sa, AF_INET);
			sa.u.in.sin_addr.s_addr = *(uint32_t *)addr;
		}
		else if (ifa->ifa_family == AF_INET6) {
			sa_set_in6(&sa, addr, 0);
			sa_set_scopeid(&sa, ifa->ifa_index);
		}
		else
			continue;

		if (!if_indextoname(ifa->ifa_index, if_name))
			continue;

		if (ifh(if_name, &sa, arg))
			return 0;
	}

	return EALREADY;
}


int net_netlink_addrs(net_ifaddr_h *ifh, void *arg)
{
	int err = 0;
	re_sock_t sock;
	ssize_t len;
	struct list iff_up_l = LIST_INIT;

	struct {
		struct nlmsghdr nlh;
		union
		{
			struct ifinfomsg ifi;
			struct ifaddrmsg ifa;
		} u;
	} req;

	if (!ifh)
		return EINVAL;

	void *buffer = mem_zalloc(RE_NETLINK_BUFSZ, NULL);
	if (!buffer)
		return ENOMEM;

	if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		err = errno;
		DEBUG_WARNING("socket failed %m\n", err);
		return err;
	}

	struct timeval timeout = {5, 0};
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	/* GETLINK */
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type  = RTM_GETLINK;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		err = errno;
		DEBUG_WARNING("GETLINK send failed %m\n", err);
		goto out;
	}

	while ((len = recv(sock, buffer, RE_NETLINK_BUFSZ, 0)) > 0) {
		err = parse_msg_link((struct nlmsghdr *)buffer, len,
				     &iff_up_l);
		if (err != EALREADY)
			break;
	}
	if (err)
		goto out;

	if (len < 0) {
		err = errno;
		DEBUG_WARNING("GETLINK recv failed %m\n", err);
		goto out;
	}

	/* GETADDR */
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type  = RTM_GETADDR;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		err = errno;
		DEBUG_WARNING("GETADDR send failed %m\n", err);
		goto out;
	}

	while ((len = recv(sock, buffer, RE_NETLINK_BUFSZ, 0)) > 0) {
		err = (parse_msg_addr((struct nlmsghdr *)buffer, len, ifh,
				      &iff_up_l, arg));
		if (err != EALREADY)
			break;
	}
	if (err)
		goto out;

	if (len < 0) {
		err = errno;
		DEBUG_WARNING("GETADDR recv failed %m\n", err);
	}

out:
	close(sock);
	list_flush(&iff_up_l);
	mem_deref(buffer);

	return err;
}
