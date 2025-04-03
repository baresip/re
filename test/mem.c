/**
 * @file mem.c Memory Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_mem"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define PATTERN 0xfcfcfcfc

enum {
#if defined(__x86_64__)
	/* Use 16-byte alignment on x86-x32 as well */
	mem_alignment = 16u,
#else
	mem_alignment = sizeof(void*) >= 8u ? 16u : 8u,
#endif
};

struct obj {
	uint32_t pattern;
};

static void destructor(void *arg)
{
	struct obj *obj = arg;

	if (PATTERN != obj->pattern) {
		DEBUG_WARNING("destroy error: %08x\n", obj->pattern);
	}
}


int test_mem(void)
{
	struct obj *obj, *old = NULL, *tmp = NULL;
	int err = EINVAL;

	obj = mem_alloc(sizeof(*obj), destructor);
	if (!obj)
		return ENOMEM;

	obj->pattern = PATTERN;

	TEST_EQUALS(1, mem_nrefs(obj));
	TEST_ASSERT(re_is_aligned(obj, mem_alignment));

	obj = mem_ref(obj);
	TEST_EQUALS(2, mem_nrefs(obj));

	mem_deref(obj);

	TEST_EQUALS(1, mem_nrefs(obj));

	old = obj;
	obj = mem_realloc(old, sizeof(*obj) + 16);

	if (!obj) {
		old = mem_deref(old);
		err = ENOMEM;
		TEST_ERR(err);
	}

	TEST_ASSERT(re_is_aligned(obj, mem_alignment));

	old = mem_ref(obj);
	TEST_EQUALS(2, mem_nrefs(obj));

	obj = mem_realloc(obj, sizeof(*obj) + 64);
	TEST_EQUALS(1, mem_nrefs(old));
	mem_deref(old);
	TEST_EQUALS(1, mem_nrefs(obj));

	old = mem_ref(obj);
	TEST_EQUALS(2, mem_nrefs(obj));

	tmp = mem_realloc(obj, sizeof(*obj) + 16);
	if (!tmp) {
		mem_deref(obj);
		err = ENOMEM;
		TEST_ERR(err);
	}
	TEST_EQUALS(1, mem_nrefs(old));
	TEST_EQUALS(1, mem_nrefs(tmp));

	err = 0;

 out:
	mem_deref(tmp);
	mem_deref(old);
	return err;
}


#ifndef SIZE_MAX
#define SIZE_MAX    (~((size_t)0))
#endif


int test_mem_reallocarray(void)
{
	void *a, *b;
	int err = 0;

	/* expect success */
	a = mem_reallocarray(NULL, 10, 10, NULL);
	if (!a)
		return ENOMEM;

	/* expect failure */
	b = mem_reallocarray(NULL, SIZE_MAX, SIZE_MAX, NULL);
	TEST_ASSERT(b == NULL);

 out:
	mem_deref(a);

	return err;
}


int test_mem_secure(void)
{
	int r, err = 0;

	/* compare */
	r = mem_seccmp(NULL, NULL, 42);
	TEST_ASSERT(r < 0);

	r = mem_seccmp((uint8_t *)"abc", (uint8_t *)"abc", 3);
	TEST_EQUALS(0, r);

	r = mem_seccmp((uint8_t *)"aaa", (uint8_t *)"bbb", 3);
	TEST_ASSERT(r > 0);

	r = mem_seccmp((uint8_t *)"ccc", (uint8_t *)"aaa", 3);
	TEST_ASSERT(r > 0);

 out:
	return err;
}
