/**
 * @file wrap.c  SHA wrappers
 *
 * Copyright (C) 2022 Sebastian Reimers <hallo@studio-link.de>
 */

#include <re_types.h>
#ifdef USE_OPENSSL
#include <openssl/sha.h>
#endif
#include <re_sha.h>


/**
 * Calculate the SHA1 hash from a buffer
 *
 * @param d  Data buffer (input)
 * @param n  Number of input bytes
 * @param md Calculated SHA1 hash (output)
 */
void sha1(const uint8_t *d, size_t n, uint8_t *md)
{
#ifdef USE_OPENSSL
	(void)SHA1(d, n, md);
#else
	(void)d;
	(void)n;
	(void)md;
#error missing SHA-1 backend
#endif
}
