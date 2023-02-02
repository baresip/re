/**
 * @file sa/printaddr.c  Socket Address printing
 *
 * Copyright (C) 2010 Creytiv.com
 */
#ifdef HAVE_GETIFADDRS
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_sa.h>


/**
 * Print a Socket Address including IPv6 scope identifier
 *
 * @param pf Print function
 * @param sa Socket Address
 *
 * @return 0 if success, otherwise errorcode
 */
int sa_print_addr(struct re_printf *pf, const struct sa *sa)
{
	int err;

	if (!sa)
		return 0;

	err = re_hprintf(pf, "%j", sa);

#ifdef HAVE_INET6
	if (sa_af(sa) == AF_INET6 && sa_is_linklocal(sa)) {
#ifdef HAVE_GETIFADDRS
		char ifname[IF_NAMESIZE];

		if (!if_indextoname(sa->u.in6.sin6_scope_id, ifname))
			return errno;

		err |= re_hprintf(pf, "%%%s", ifname);
#else
		uint32_t scope_id = sa_scopeid(sa);
		err |= re_hprintf(pf, "%%%d", scope_id);
#endif
	}
#endif

	return err;
}
