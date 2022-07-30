/**
 * @file mem/secure.c  Secure memory functions
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#if !defined(__GNUC__) && defined(WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif /* !defined(__GNUC__) && defined(WIN32) */

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


#if !defined(__GNUC__) && !defined(WIN32)
/* Use a volatile pointer to memset to force the compiler always
 * call it and not optimize away. */
typedef void *(memset_t)(void *, int, size_t);
static memset_t *const volatile memset_ptr = &memset;
#endif

/**
 * Securely clean memory. This function is guaranteed not to get optimized
 * away by compiler.
 *
 * @param data Pointer to data buffer
 * @param size Size of the buffer
 */
void mem_secclean(void *data, size_t size)
{
#if defined(__GNUC__)
	memset(data, 0, size);
	/* Insert an asm statement that may potentially depend
	 * on the memory contents that were affected by memset.
	 * This prevents optimizing away the memset. */
	__asm__ __volatile__("" : : "r" (data), "r" (size) : "memory");
#elif defined(WIN32)
	SecureZeroMemory(data, size);
#else
	(*memset_ptr)(data, 0, size);
#endif
}
