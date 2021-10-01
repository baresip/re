/**
 * @file btrace.c Backtrace API (Linux/Unix only)
 */

#include <stdlib.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_btrace.h>


int btrace_print(struct re_printf *pf, struct btrace *btrace)
{
#if defined(WIN32) && defined(RELEASE)
	(void)pf;
	(void)btrace;

	return 0;
#endif
	char **symbols;

	if (!pf || !btrace)
		return EINVAL;

	if (!btrace->len)
		return 0;

	symbols = backtrace_symbols(btrace->stack, btrace->len);

	if (!symbols)
		return 0;

	for (int j = 0; j < btrace->len; j++)
		re_hprintf(pf, "%s ", symbols[j]);

	free(symbols);

	return 0;
}
