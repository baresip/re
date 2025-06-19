/**
 * @file list.c Linked-lists Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <assert.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "testlist"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct node {
	struct le le;
	struct le le2;
	int value;
};

int test_list(void)
{
	struct node node1 = {.value = 1}, node2 = {.value = 2};
	struct list list;
	int err = EINVAL;

	list_init(&list);

	/* Test empty list */
	TEST_EQUALS(0, list_count(&list));

	/* Test with one node */
	list_append(&list, &node1.le, &node1);
	TEST_EQUALS(1, list_count(&list));

	list_unlink(&node1.le);

	TEST_EQUALS(0, list_count(&list));

	/* Test with two nodes */
	list_append(&list, &node1.le, &node1);
	list_append(&list, &node2.le, &node2);
	TEST_EQUALS(2, list_count(&list));

	list_unlink(&node1.le);

	TEST_EQUALS(1, list_count(&list));

	list_unlink(&node2.le);

	/* Test empty list */
	TEST_EQUALS(0, list_count(&list));

	list_append(&list, &node1.le, &node1);
	list_append(&list, &node2.le, &node2);

	struct le *le;
	int i = 0;
	LIST_FOREACH(&list, le) {
		struct node *n = list_ledata(le);
		++i;
		TEST_EQUALS(i, n->value);
	}

	struct le *tmp;
	i = 0;
	LIST_FOREACH_SAFE(&list, le, tmp) {
		struct node *n = list_ledata(le);
		++i;
		TEST_EQUALS(i, n->value);
		list_unlink(le);
	}

	/* Test empty list */
	TEST_EQUALS(0, list_count(&list));

	err = 0;

 out:
	return err;
}


static void node_destructor(void *arg)
{
	struct node *node = arg;

	if (node->le.prev || node->le.next || node->le.list || node->le.data) {
		DEBUG_WARNING("le: prev=%p next=%p data=%p\n",
			      node->le.prev, node->le.next, node->le.data);
	}

	list_unlink(&node->le);
}


/**
 * Test linked list with external reference to objects
 */
int test_list_ref(void)
{
	struct list list;
	struct node *node, *node2;
	int err = 0;

	list_init(&list);

	node = mem_zalloc(sizeof(*node), node_destructor);
	node2 = mem_zalloc(sizeof(*node2), node_destructor);
	if (!node || !node2) {
		err = ENOMEM;
		goto out;
	}

	mem_ref(node);

	list_append(&list, &node->le, node);
	list_append(&list, &node2->le, node2);

 out:
	list_flush(&list);
	memset(&list, 0xa5, sizeof(list));  /* mark as deleted */

	/* note: done after list_flush() */
	mem_deref(node);

	return err;
}


static bool sort_handler1(struct le *le1, struct le *le2, void *arg)
{
	struct node *node1 = le1->data;
	struct node *node2 = le2->data;
	(void)arg;

	/* NOTE: important to use less than OR equal to, otherwise
	   the list_sort function may be stuck in a loop */
	return node1->value <= node2->value;
}


static bool sort_handler2(struct le *le1, struct le *le2, void *arg)
{
	struct node *node1 = le1->data;
	struct node *node2 = le2->data;
	(void)arg;

	/* NOTE: important to use greater than OR equal to, otherwise
	   the list_sort function may be stuck in a loop */
	return node1->value >= node2->value;
}


#define NUM_ELEMENTS 100
static int test_sort(bool sorted)
{
	struct list lst_1;
	struct list lst_2;
	struct le *le;
	int prev_value = 0;
	bool prev_value_set = false;
	unsigned i;
	unsigned value_counter = 7;
	int err = 0;

	list_init(&lst_1);
	list_init(&lst_2);

	/* add many elements with a random value */
	for (i=0; i<NUM_ELEMENTS; i++) {

		struct node *node;

		node = mem_zalloc(sizeof(*node), node_destructor);
		if (!node) {
			err = ENOMEM;
			goto out;
		}

		node->value = -50 + (value_counter % 100);
		value_counter *= 3;

		if (sorted) {
			list_insert_sorted(&lst_1, sort_handler1, NULL,
					   &node->le, node);
			list_insert_sorted(&lst_2, sort_handler2, NULL,
					   &node->le2, node);
		}
		else {
			list_append(&lst_1, &node->le, node);
			list_append(&lst_2, &node->le2, node);
		}
	}

	/* sort the list in ascending order */
	if (!sorted) {
		list_sort(&lst_1, sort_handler1, NULL);
		list_sort(&lst_2, sort_handler2, NULL);
	}

	/* verify that the list is sorted */
	for (le = lst_1.head; le; le = le->next) {
		struct node *node = le->data;

		if (prev_value_set) {
			TEST_ASSERT(node->value >= prev_value);
		}

		prev_value = node->value;
		prev_value_set = true;
	}

	prev_value_set = false;
	for (le = lst_2.head; le; le = le->next) {
		struct node *node = le->data;

		if (prev_value_set) {
			TEST_ASSERT(node->value <= prev_value);
		}

		prev_value = node->value;
		prev_value_set = true;
	}

 out:
	list_flush(&lst_1);

	return err;
}


int test_list_sort(void)
{
	int err;

	err = test_sort(false);
	TEST_ERR(err);

	err = test_sort(true);
	TEST_ERR(err);
 out:
	return err;
}


struct flush_data {
	struct le le;
	struct list *flushl;
};


static void data_destroy(void *arg)
{
	struct flush_data *data = arg;
	struct le *le;

	LIST_FOREACH(data->flushl, le)
	{
		assert(list_count(data->flushl));
	}
}


int test_list_flush(void)
{
	struct flush_data *data[2];
	struct list flushl = LIST_INIT;
	int err = 0;

	data[0] = mem_zalloc(sizeof(struct flush_data), data_destroy);
	if (!data[0])
		return ENOMEM;

	data[1] = mem_zalloc(sizeof(struct flush_data), data_destroy);
	if (!data[1]) {
		mem_deref(data[0]);
		return ENOMEM;
	}

	data[0]->flushl = &flushl;
	data[1]->flushl = &flushl;

	list_append(&flushl, &data[0]->le, data[0]);
	list_append(&flushl, &data[1]->le, data[1]);

	list_flush(&flushl);

	TEST_EQUALS(0, list_count(&flushl));

out:
	return err;
}
