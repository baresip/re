/**
 * @file types.c Types Testcode
 *
 */
#include <re.h>
#include "test.h"

int test_re_assert_se(void)
{
	int err;

	re_assert(true);
	re_assert_se(!(err = 0));

	return err;
}
