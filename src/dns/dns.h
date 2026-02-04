/**
 * @file dns.h  Internal DNS header file
 *
 * Copyright (C) 2010 Creytiv.com
 */


#ifdef HAVE_RESOLV
int get_resolv_dns(struct sa *nsv, uint32_t *n);
#endif
#ifdef WIN32
int get_windns(struct sa *nav, uint32_t *n);
#endif
#ifdef DARWIN
int get_darwin_dns(struct sa *nsv, uint32_t *n);
#endif
