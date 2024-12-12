/* Override macros to avoid casting alignment warning */
#undef RTM_RTA
#define RTM_RTA(r) (void *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct rtmsg)))
#undef RTA_NEXT
#define RTA_NEXT(rta, len)                                                    \
	((len) -= RTA_ALIGN((rta)->rta_len),                                  \
	 (void *)(((char *)(rta)) + RTA_ALIGN((rta)->rta_len)))
#undef NLMSG_NEXT
#define NLMSG_NEXT(nlh, len)                                                  \
	((len) -= NLMSG_ALIGN((nlh)->nlmsg_len),                              \
	 (void *)(((char *)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#undef IFA_RTA
#define IFA_RTA(r)                                                            \
	((void *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
