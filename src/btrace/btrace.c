/**
 * @file btrace.c Backtrace API (Linux/Unix only)
 */
#include <stdlib.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_btrace.h>

enum print_type { BTRACE_CSV, BTRACE_NEWLINE, BTRACE_JSON };

static int print_debug(struct re_printf *pf, struct btrace *bt,
		       enum print_type type)
{
#if !defined(HAVE_EXECINFO) || defined(RELEASE)
	(void)pf;
	(void)bt;
	(void)type;

	return 0;
#else
	char **symbols;

	if (!pf || !bt)
		return EINVAL;

	if (!bt->len)
		return 0;

#if defined(FREEBSD) || defined(OPENBSD)
	symbols = backtrace_symbols(bt->stack, bt->len);
#else
	symbols = backtrace_symbols(bt->stack, (int)bt->len);
#endif

	if (!symbols)
		return 0;

	switch (type) {
	case BTRACE_CSV:
		for (size_t j = 0; j < bt->len; j++) {
			re_hprintf(pf, "%s%s", symbols[j],
				   ((j + 1) < bt->len) ? ", " : "");
		}
		break;
	case BTRACE_NEWLINE:
		for (size_t j = 0; j < bt->len; j++) {
			re_hprintf(pf, "%s \n", symbols[j]);
		}
		break;
	case BTRACE_JSON:
		re_hprintf(pf, "[");
		for (size_t j = 0; j < bt->len; j++) {
			re_hprintf(pf, "\"%s\"%s", symbols[j],
				   ((j + 1) < bt->len) ? ", " : "");
		}
		re_hprintf(pf, "]");
		break;
	}

	free(symbols);

	return 0;
#endif
}


/**
 * Print debug backtrace (comma separated)
 *
 * @param pf Print function for debug output
 * @param bt Backtrace object
 *
 * @return 0 if success, otherwise errorcode
 */
int btrace_print(struct re_printf *pf, struct btrace *bt)
{
	return print_debug(pf, bt, BTRACE_CSV);
}


/**
 * Print debug backtrace with newlines
 *
 * @param pf Print function for debug output
 * @param bt Backtrace object
 *
 * @return 0 if success, otherwise errorcode
 */
int btrace_println(struct re_printf *pf, struct btrace *bt)
{
	return print_debug(pf, bt, BTRACE_NEWLINE);
}


/**
 * Print debug backtrace as json array
 *
 * @param pf Print function for debug output
 * @param bt Backtrace object
 *
 * @return 0 if success, otherwise errorcode
 */
int btrace_print_json(struct re_printf *pf, struct btrace *bt)
{
	return print_debug(pf, bt, BTRACE_JSON);
}
