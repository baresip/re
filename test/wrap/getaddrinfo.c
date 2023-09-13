#include <netdb.h>

#include <re.h>
#include "test.h"


int __wrap_getaddrinfo(const char *restrict node, const char *restrict service,
		       const struct addrinfo *restrict hints,
		       struct addrinfo **restrict res);
int __real_getaddrinfo(const char *restrict node, const char *restrict service,
		       const struct addrinfo *restrict hints,
		       struct addrinfo **restrict res);
int __wrap_getaddrinfo(const char *restrict node, const char *restrict service,
		       const struct addrinfo *restrict hints,
		       struct addrinfo **restrict res)
{
	return __real_getaddrinfo(node, service, hints, res);
}


void __wrap_freeaddrinfo(struct addrinfo *res);
void __real_freeaddrinfo(struct addrinfo *res);
void __wrap_freeaddrinfo(struct addrinfo *res)
{
	__real_freeaddrinfo(res);
}
