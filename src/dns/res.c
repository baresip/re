/**
 * @file res.c  Get DNS Server IP using resolv
 *
 * Copyright (C) 2010 Creytiv.com
 */
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_dns.h>
#include <re_mem.h>
#include "dns.h"


int get_resolv_dns(char *domain, size_t dsize, struct sa *nsv, uint32_t *n)
{
	struct __res_state state;
	uint32_t i;
	int ret, err;

#ifdef OPENBSD
	ret = res_init();
	state = _res;
#else
	memset(&state, 0, sizeof(state));
	ret = res_ninit(&state);
#endif
	if (0 != ret)
		return ENOENT;

	if (state.dnsrch[0])
		str_ncpy(domain, state.dnsrch[0], dsize);
	else if (str_isset(state.defdname))
		str_ncpy(domain, state.defdname, dsize);

	if (!state.nscount) {
		err = ENOENT;
		goto out;
	}

	err = 0;
#ifdef DARWIN
	int memsize = state.nscount * sizeof(union res_sockaddr_union);
	union res_sockaddr_union *addr = mem_alloc(memsize, NULL);
	int servers = res_getservers(&state, addr,  state.nscount);

	for (i = 0; i < min(*n, (uint32_t)servers) && !err; i++) {
		if (addr[i].sin.sin_family == AF_INET)
			err |= sa_set_sa(&nsv[i],
					(struct sockaddr *)&addr[i].sin);
		else if (addr[i].sin6.sin6_family == AF_INET6)
			err |= sa_set_sa(&nsv[i],
					(struct sockaddr *)&addr[i].sin6);
		else
			(void)re_fprintf(stderr,
					"get_resolv_dns: Undefined family.\n");
	}
	mem_deref(addr);
#else
	for (i=0; i<min(*n, (uint32_t)state.nscount) && !err; i++) {
		struct sockaddr_in *addr = &state.nsaddr_list[i];
		err |= sa_set_sa(&nsv[i], (struct sockaddr *)addr);
	}
#endif
	if (err)
		goto out;

	*n = i;

 out:
#ifdef OPENBSD
#else
	res_nclose(&state);
#endif

	return err;
}
