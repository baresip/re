/**
 * @file re_btrace.h  Backtrace API (Linux/Unix only)
 *
 */
#define BTRACE_SZ 10

struct btrace {
	void *stack[BTRACE_SZ];
	size_t len;
};

int btrace_print(struct re_printf *pf, struct btrace *btrace);
int btrace_println(struct re_printf *pf, struct btrace *btrace);
int btrace_print_json(struct re_printf *pf, struct btrace *btrace);

#if defined(HAVE_EXECINFO) && !defined(RELEASE)
#include <execinfo.h>
static inline int btrace(struct btrace *btrace)
{
	if (!btrace)
		return EINVAL;

	btrace->len = backtrace(btrace->stack, BTRACE_SZ);

	return 0;
}
#else
static inline int btrace(struct btrace *btrace)
{
	(void)btrace;
	return 0;
}
#endif
