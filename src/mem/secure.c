/**
 * @file mem/secure.c  Secure memory functions
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re_types.h>
#include <re_mem.h>


/**
 * Compare two byte strings in constant time. This function can be used
 * by secure code to compare secret data, such as authentication tags,
 * to avoid side-channel attacks.
 *
 * @param s1 First byte string
 * @param s2 Second byte string
 * @param n  Number of bytes
 *
 * @return a negative number if argument errors
 *         0 if both byte strings matching
 *         a positive number if not matching
 */
int mem_seccmp(const uint8_t *s1, const uint8_t *s2, size_t n)
{
	uint8_t val = 0;
	const volatile uint8_t *p1 = s1;
	const volatile uint8_t *p2 = s2;

	if (!p1 || !p2)
		return -1;

	while (n--)
		val |= *p1++ ^ *p2++;

	return val;
}
