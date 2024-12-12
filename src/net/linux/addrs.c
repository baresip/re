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


static bool is_deprecated(uint32_t flags)
{
	if (flags & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC | IFA_F_DADFAILED |
		     IFA_F_DEPRECATED))
		return true;

	return false;
}


static int parse_msg(struct nlmsghdr *msg, size_t len, net_ifaddr_h *ifh,
		     void *arg)
{
	struct nlmsghdr *nlh;
	for (nlh = msg; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct sa sa;
		uint32_t flags;
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

		if (rta_tb[IFA_FLAGS]) {
			flags = *(uint32_t *)RTA_DATA(rta_tb[IFA_FLAGS]);
			if (is_deprecated(flags))
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
			break;
	}

	return EAGAIN;
}


int net_netlink_addrs(net_ifaddr_h *ifh, void *arg)
{
	int err = 0;
	char buffer[8192];
	re_sock_t sock;
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req;
	size_t len;

	if (!ifh)
		return EINVAL;

	if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		err = errno;
		DEBUG_WARNING("socket failed %m\n", err);
		return err;
	}

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type  = RTM_GETADDR;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		err = errno;
		DEBUG_WARNING("sendto failed %m\n", err);
		goto out;
	}

	while ((len = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
		err = parse_msg((struct nlmsghdr *)buffer, len, ifh, arg);
		if (!err)
			goto out;
	}

out:
	close(sock);

	return err;
}
