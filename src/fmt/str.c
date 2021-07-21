/**
 * @file fmt/str.c String format functions
 *
 * Copyright (C) 2010 Creytiv.com
 */
#undef __STRICT_ANSI__ /* for mingw32 */
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <re_types.h>
#include <re_mem.h>
#include <re_fmt.h>

enum {
	X64_STRSIZE = 17,
};

/**
 * Convert a ascii hex string to binary format
 *
 * @param hex Destinatin binary buffer
 * @param len Length of binary buffer
 * @param str Source ascii string
 *
 * @return 0 if success, otherwise errorcode
 */
int str_hex(uint8_t *hex, size_t len, const char *str)
{
	size_t i;

	if (!hex || !str || (strlen(str) != (2 * len)))
		return EINVAL;

	for (i=0; i<len*2; i+=2) {
		hex[i/2]  = ch_hex(str[i]) << 4;
		hex[i/2] += ch_hex(str[i+1]);
	}

	return 0;
}


/**
 * Copy a 0-terminated string with maximum length
 *
 * @param dst Destinatin string
 * @param src Source string
 * @param n   Maximum size of destination, including 0-terminator
 */
void str_ncpy(char *dst, const char *src, size_t n)
{
	if (!dst || !src || !n)
		return;

	(void)strncpy(dst, src, n-1);
	dst[n-1] = '\0'; /* strncpy does not null terminate if overflow */
}


/**
 * Duplicate a 0-terminated string
 *
 * @param dst Pointer to destination string (set on return)
 * @param src Source string
 *
 * @return 0 if success, otherwise errorcode
 */
int str_dup(char **dst, const char *src)
{
	char *p;
	size_t sz;

	if (!dst || !src)
		return EINVAL;

	sz = strlen(src) + 1;

	p = mem_alloc(sz, NULL);
	if (!p)
		return ENOMEM;

	memcpy(p, src, sz);

	*dst = p;

	return 0;
}


/**
 * Converts an uint64_t to a 0-terminated string
 *
 * @param dst Pointer to destination string (set on return)
 * @param val Value
 *
 * @return 0 if success, otherwise errorcode
 */
int str_x64dup(char **dst, uint64_t val)
{
	char *str;

	str = mem_alloc(X64_STRSIZE, NULL);
	if (!str)
		return ENOMEM;

	(void)re_snprintf(str, X64_STRSIZE, "%016llx", val);

	*dst = str;
	return 0;
}


/**
 * Compare two 0-terminated strings
 *
 * @param s1 First string
 * @param s2 Second string
 *
 * @return an integer less than, equal to, or greater than zero if s1 is found
 *         respectively, to be less than, to match, or be greater than s2
 */
int str_cmp(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return 1;

	return strcmp(s1, s2);
}


/**
 * Compare two 0-terminated strings, ignoring case
 *
 * @param s1 First string
 * @param s2 Second string
 *
 * @return an integer less than, equal to, or greater than zero if s1 is found
 *         respectively, to be less than, to match, or be greater than s2
 */
int str_casecmp(const char *s1, const char *s2)
{
	/* Same strings -> equal */
	if (s1 == s2)
		return 0;

	if (!s1 || !s2)
		return 1;

#ifdef WIN32
	return _stricmp(s1, s2);
#else
	return strcasecmp(s1, s2);
#endif
}


/**
 * Calculate the length of a string, safe version.
 *
 * @param s String
 *
 * @return Length of the string
 */
size_t str_len(const char *s)
{
	return s ? strlen(s) : 0;
}


/**
 * Convert various possible boolean strings to a bool
 *
 * @param val  Pointer to bool for returned value
 * @param str  String to be converted
 *
 * @return int 0 if success, otherwise errorcode
 */
int str_bool(bool *val, const char *str)
{
	int err = 0;

	if (!val || !str_isset(str))
		return EINVAL;

	if (!str_casecmp(str, "0")) {
		*val = false;
	}
	else if (!str_casecmp(str, "1")) {
		*val = true;
	}
	else if (!str_casecmp(str, "false")) {
		*val = false;
	}
	else if (!str_casecmp(str, "true")) {
		*val = true;
	}
	else if (!str_casecmp(str, "disable")) {
		*val = false;
	}
	else if (!str_casecmp(str, "enable")) {
		*val = true;
	}
	else if (!str_casecmp(str, "off")) {
		*val = false;
	}
	else if (!str_casecmp(str, "on")) {
		*val = true;
	}
	else if (!str_casecmp(str, "no")) {
		*val = false;
	}
	else if (!str_casecmp(str, "yes")) {
		*val = true;
	}
	else {
		err = EINVAL;
	}

	return err;
}
