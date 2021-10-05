/**
 * @file btrace.c Backtrace API (Linux/Unix only)
 */

#include <stdlib.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_btrace.h>


static int print_debug(struct re_printf *pf, struct btrace *btrace,
		       bool newline)
{
#if defined(WIN32) || defined(RELEASE)
	(void)pf;
	(void)btrace;
	(void)newline;

	return 0;
#else
	char **symbols;

	if (!pf || !btrace)
		return EINVAL;

	if (!btrace->len)
		return 0;

	symbols = backtrace_symbols(btrace->stack, btrace->len);

	if (!symbols)
		return 0;

	for (int j = 0; j < btrace->len; j++) {
		if (newline)
			re_hprintf(pf, "%s \n", symbols[j]);
		else
			re_hprintf(pf, "%s ", symbols[j]);
	}

	free(symbols);

	return 0;
#endif
}


/**
 * Print debug backtrace with newlines
 *
 * @param pf     Print function for debug output
 * @param btrace Backtrace object
 *
 * @return 0 if success, otherwise errorcode
 */
int btrace_println(struct re_printf *pf, struct btrace *btrace)
{
	return print_debug(pf, btrace, true);
}


/**
 * Print debug backtrace without newlines
 *
 * @param pf     Print function for debug output
 * @param btrace Backtrace object
 *
 * @return 0 if success, otherwise errorcode
 */
int btrace_print(struct re_printf *pf, struct btrace *btrace)
{
	return print_debug(pf, btrace, false);
}
