
#include <unistd.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <net/if.h>


#include <re_types.h>
#include <re_fmt.h>
#include <re_net.h>
#include <re_sa.h>


#define DEBUG_MODULE "route"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void set_sa(struct sa *sa, int af, void *data)
{
	switch (af) {

	case AF_INET:
		sa_init(sa, AF_INET);
		sa->u.in.sin_addr.s_addr
			= *(uint32_t *)data;
		break;
		
	case AF_INET6:
		sa_set_in6(sa, data, 0);
		break;

	default:
		break;
	}
}


static void handle_newroute(const struct nlmsghdr *h, net_rt_h *rth, void *arg)
{
	struct rtattr * rta;

	int rlen = h->nlmsg_len;

	struct rtmsg *rtmsg = (struct rtmsg *)NLMSG_DATA(h);

	//re_printf("|| NEWROUTE ||\n");

	rlen -= NLMSG_LENGTH(sizeof(struct rtmsg));

	struct sa gw, dst;
	char ifname[256];

	sa_init(&gw, rtmsg->rtm_family);
	sa_init(&dst, rtmsg->rtm_family);

        


	for (rta = RTM_RTA(NLMSG_DATA((h))); RTA_OK(rta, rlen); rta = RTA_NEXT(rta,rlen)) {

		unsigned char * data = RTA_DATA(rta);

		//re_printf(".... RTA: %d\n", rta->rta_type);

		if (rta->rta_type == RTA_OIF) {

			//char ifname[256];
			int index = *(int *)data;

			if_indextoname(index, ifname);

			//re_printf("index: %d (%s)\n", index, ifname);


		}
		else if (rta->rta_type == RTA_GATEWAY) {

			//struct sa gw;

			set_sa(&gw, rtmsg->rtm_family, RTA_DATA(rta));

			//re_printf("gateway: %j\n", &gw);
		}
		else if (rta->rta_type == RTA_DST) {

			//struct sa dst;

			set_sa(&dst, rtmsg->rtm_family, RTA_DATA(rta));

			//re_printf("dst: %j\n", &dst);
		}
		else if (rta->rta_type == RTA_PRIORITY) {
		}
		else if (rta->rta_type == RTA_TABLE) {
		}
		else if (rta->rta_type == RTA_CACHEINFO) {
		}
		else if (rta->rta_type == RTA_PREF) {
		}
		else if (rta->rta_type == RTA_PREFSRC) {
			struct sa src;

			set_sa(&src, rtmsg->rtm_family, RTA_DATA(rta));

			//re_printf("prefsrc: %j\n", &src);
		}
		else {
			DEBUG_WARNING("rta_type: %d\n", rta->rta_type);
		}

					
	}

	//	re_printf("ROUTE:  dst=%-26j  dst_len=%d  gw=%j  if=%s\n",
	//		  &dst, rtmsg->rtm_dst_len, &gw, ifname);

	rth(ifname, &dst, rtmsg->rtm_dst_len, &gw, arg);
}


int net_rt_list(net_rt_h *rth, void *arg)
{
	int fd;
	int err = 0;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	
	re_printf("fd: %d\n", fd);

	struct {
		struct nlmsghdr  n;
                struct rtmsg r;
		//char             attrbuf[8192];
	} req_in;


	memset(&req_in, 0, sizeof(req_in));

	req_in.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
        req_in.n.nlmsg_type  = RTM_GETROUTE;
        req_in.n.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req_in.n.nlmsg_seq = 42;
	req_in.n.nlmsg_pid = 123;

	ssize_t n = send(fd, &req_in, req_in.n.nlmsg_len, 0);

	if (n < 0) {

		DEBUG_WARNING("send failed (%m)\n", err);
		err = errno;
		goto out;
	}

	re_printf("send: %zd bytes\n", n);

	struct {
		struct nlmsghdr  n;
                struct rtmsg r;
		char             attrbuf[8192];
	} req_out;

	//memset(&req_out, 0, sizeof(req_out));

	for (;;) {

		struct nlmsghdr *h;

		n = recv(fd, &req_out, sizeof(req_out), 0);

                if (n < 0) {
			re_printf("error\n");
                        if (errno == EINTR || errno == EAGAIN)
                                continue;
			err = errno;
                        DEBUG_WARNING("recvmsg(rtnetlink) %m\n", err);
                        goto out;
                }
                if (n == 0) {
                        DEBUG_WARNING("recvmsg(rtnetlink) EOF\n");
                        goto out;
                }

		re_printf("\nrecv: %zd bytes\n", n);

		re_printf("len:   %u\n", req_out.n.nlmsg_len);
		re_printf("type:  %u\n", req_out.n.nlmsg_type);
		re_printf("flags: %u\n", req_out.n.nlmsg_flags);
		re_printf("seq:   %u\n", req_out.n.nlmsg_seq);
		re_printf("pid:   %u\n", req_out.n.nlmsg_pid);

		for (h = (struct nlmsghdr*)&req_out.n; n >= (int)sizeof(*h); ) {
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

			//re_printf("~~ new nlmsg:\n");

			struct rtmsg *rtmsg;

			rtmsg = (struct rtmsg *)NLMSG_DATA(h);


                        if (l<0 || len > n) {
                                //if (msg.msg_flags & MSG_TRUNC) {
				//      DEBUG_WARNING("Truncated message");
                                //}
                                DEBUG_WARNING("malformed message: len=%d\n", len);
				err = EPROTO;
                                goto out;
                        }

#if 0
                        if (nladdr.nl_pid != 0 || h->nlmsg_seq != 1/*seq*/) {

                                syslog(LOG_ERR, "wrong seq = %d\n", h->nlmsg_seq);

                                /* Don't forget to skip that message. */
                                status -= NLMSG_ALIGN(len);
                                h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                                continue;
                        }
#endif

                        if (h->nlmsg_type == NLMSG_ERROR) {

                                struct nlmsgerr *nlerr = (struct nlmsgerr*)NLMSG_DATA(h);

                                DEBUG_WARNING("NLMSG_ERROR %d : %s\n",
					      nlerr->error, strerror(-nlerr->error));

				err = EPROTO;
                                goto out;
                        }
			else if (h->nlmsg_type == NLMSG_DONE) {
				re_printf("Done\n");
				goto out;
			}
			else if (h->nlmsg_type == RTM_NEWROUTE) {

				handle_newroute(h, rth, arg);

                        }
			else {
				DEBUG_NOTICE("ignored: type=%d\n", h->nlmsg_type);
			}

                        n -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }


	}


 out:
	close(fd);

	return err;
}




