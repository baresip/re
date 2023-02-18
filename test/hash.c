/**
 * @file hash.c Hash Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "testhash"
#define DEBUG_LEVEL 4
#include <re_dbg.h>


struct my_elem {
	struct le he;
	const struct pl *name;   /* hash key */
};

const struct pl martin = PL("Martin"),
	alfred = PL("Alfred"),
	atle = PL("Atle");


static bool hash_cmp_handler(struct le *le, void *arg)
{
	const struct my_elem *me = le->data;
	const struct pl *name = arg;

	return 0==pl_cmp(me->name, name);
}


static int test_hash_basic(void)
{
#define BUCKET_SIZE 4
	struct my_elem elems[3];
	struct hash *h;
	struct my_elem *elem;
	int err;

	/* Clear hash elements */
	memset(elems, 0, sizeof(elems));

	elems[0].name = &martin;
	elems[1].name = &alfred;
	elems[2].name = &atle;

	err = hash_alloc(&h, BUCKET_SIZE);
	if (err)
		return err;

	TEST_EQUALS(BUCKET_SIZE, hash_bsize(h));

	/* API test */
	if (hash_lookup(NULL, hash_joaat_pl(elems[0].name),
			hash_cmp_handler, (void *)elems[0].name)) {
		err = EINVAL;
		goto out;
	}
	if (hash_lookup(h, hash_joaat_pl(elems[0].name),
			NULL, (void *)elems[0].name)) {
		err = EINVAL;
		goto out;
	}

	/* Hashtable is empty */
	hash_unlink(&elems[0].he);
	hash_unlink(&elems[1].he);

	/* Hashtable with 1 element */
	hash_append(h, hash_joaat_pl(elems[0].name), &elems[0].he, &elems[0]);

	elem = list_ledata(hash_lookup(h, hash_joaat_pl(elems[0].name),
				       hash_cmp_handler,
				       (void *)elems[0].name));
	if (elem != &elems[0]) {
		err = EINVAL;
		goto out;
	}

	elem = list_ledata(hash_lookup(h, hash_joaat_pl(elems[1].name),
				       hash_cmp_handler,
				       (void *)elems[1].name));
	if (elem) {
		err = EINVAL;
		goto out;
	}

	/* Hashtable with 2 elements */
	hash_append(h, hash_joaat_pl(elems[1].name), &elems[1].he, &elems[1]);

	elem = list_ledata(hash_lookup(h, hash_joaat_pl(elems[0].name),
				       hash_cmp_handler,
				       (void *)elems[0].name));
	if (elem != &elems[0]) {
		err = EINVAL;
		goto out;
	}

	elem = list_ledata(hash_lookup(h, hash_joaat_pl(elems[1].name),
				       hash_cmp_handler,
				       (void *)elems[1].name));
	if (elem != &elems[1]) {
		err = EINVAL;
		goto out;
	}

	hash_unlink(&elems[0].he);
	hash_unlink(&elems[1].he);

	err = 0;
 out:
	h = mem_deref(h);
	return err;
}


static int test_hash_robustapi(void)
{
	struct hash *h = NULL;
	struct le he;
	int err = 0;

	TEST_EQUALS(EINVAL, hash_alloc(NULL, 4));
	TEST_EQUALS(EINVAL, hash_alloc(&h, 0));

	hash_append(h, 0, NULL, NULL);
	hash_append(NULL, 0, &he, NULL);

	hash_unlink(NULL);

 out:
	return err;
}


#define MAGIC1 0x7fbb0001
#define MAGIC2 0x7fbb0002
struct object {
	uint32_t magic1;
	struct le he;
	uint32_t magic2;
	char buffer[32];
	uint32_t key;
};


static void obj_destructor(void *arg)
{
	struct object *obj = arg;

	list_unlink(&obj->he);
}


static bool cmp_handler(struct le *le, void *arg)
{
	struct object *obj = le->data;

	return obj->key == *(uint32_t *)arg;
}


static int test_hash_large(void)
{
#define SZ 8
#define NUM_ENTRIES SZ*SZ
	struct hash *ht = NULL;
	unsigned i;
	int err = 0;

	err = hash_alloc(&ht, SZ);
	if (err)
		goto out;

	/* add a lot of objects to hash-table */
	for (i=0; i<NUM_ENTRIES; i++) {

		struct object *obj;
		uint32_t key = i;

		obj = mem_zalloc(sizeof(*obj), obj_destructor);
		if (!obj) {
			err = ENOMEM;
			goto out;
		}
		obj->magic1 = MAGIC1;
		obj->magic2 = MAGIC2;
		obj->key = key;

		/* ownership of 'obj' transferred to the hash-table */
		hash_append(ht, key, &obj->he, obj);
	}

	/* verify that all objects can be found */
	for (i=0; i<NUM_ENTRIES; i++) {

		struct object *obj;

		obj = list_ledata(hash_lookup(ht, i, cmp_handler, &i));
		TEST_ASSERT(obj != NULL);

		TEST_EQUALS(MAGIC1, obj->magic1);
		TEST_EQUALS(MAGIC2, obj->magic2);
		TEST_EQUALS(i, obj->key);
	}

 out:
	hash_flush(ht);  /* destroys all the objects */
	mem_deref(ht);

	return err;
}


int test_hash(void)
{
	int err;

	err = test_hash_basic();
	if (err)
		return err;

	err = test_hash_robustapi();
	if (err)
		return err;

	err = test_hash_large();
	if (err)
		return err;

	return 0;
}
