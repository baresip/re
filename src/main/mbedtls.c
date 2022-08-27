/**
 * @file mbedtls.c  MbedTLS initialisation and multi-threading routines
 *
 */
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#include "main.h"


#ifdef SIGPIPE
static void sigpipe_handler(int x)
{
	(void)x;
	(void)signal(SIGPIPE, sigpipe_handler);
}
#endif


int mbedtls_init(void)
{
#ifdef SIGPIPE
	(void)signal(SIGPIPE, sigpipe_handler);
#endif

	return 0;
}
