/**
 * @file re_sha.h  Interface to SHA (Secure Hash Standard) functions
 *
 * Copyright (C) 2010 Creytiv.com
 */

/** SHA-1 Digest size in bytes */
#define SHA1_DIGEST_SIZE 20

#ifndef SHA_DIGEST_LENGTH
/** SHA-1 Digest size in bytes (OpenSSL compat) */
#define SHA_DIGEST_LENGTH SHA1_DIGEST_SIZE
#endif

void sha1(const uint8_t *d, size_t n, uint8_t *md);
