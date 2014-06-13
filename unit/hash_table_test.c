#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>

#include "nat64/unit/unit_test.h"


/* Generate the hash table. */
struct table_key {
	unsigned int key;
};

struct table_value {
	int value;
};

#define HTABLE_NAME test_table
#define KEY_TYPE struct table_key
#define VALUE_TYPE struct table_value
#define HASH_TABLE_SIZE (10)
#define GENERATE_PRINT
#define GENERATE_FOR_EACH
#include "hash_table.c"

/* These are also kind of part of the table. */
static bool equals_function(struct table_key *key1, struct table_key *key2)
{
	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	return (key1->key == key2->key);
}

static unsigned int hash_code_function(struct table_key *key1)
{
	return (key1 != NULL) ? key1->key : 0;
}

/**
 * For every key (from the "keys" array), extracts its corresponding value from "table", and asserts
 * it equals its corresponding expected value (from the "expected_values" array).
 *
 * Assumes "keys" and "expected_values" have the same length.
 */
static bool assert_table_content(struct test_table *table,
		struct table_key *keys, struct table_value *expected_values,
		char *test_name)
{
	int i;
	bool success = true;

	for (i = 0; i < 4; i++) {
		struct table_value *current_val = test_table_get(table, &keys[i]);

		if (expected_values[i].value == -1) {
			success &= assert_null(current_val, test_name);
		} else {
			bool local = true;

			local &= assert_not_null(current_val, test_name);
			if (local)
				local &= assert_equals_int(expected_values[i].value, current_val->value, test_name);

			success &= local;
		}
	}

	return success;
}

/**
 * The functions are really interdependent, so most functions are tested in this single unit. Sorry.
 */
static bool test(void)
{
	struct test_table table;
	/*
	 * The second value is a normal, troubleless key-value pair.
	 * The first and third keys have the same hash code (tests the table doesn't override them or
	 * something).
	 * The fourth key-value shall not be inserted (tests the table doesn't go bananas attempting to
	 * retrieve it).
	 */
	struct table_key keys[] = { { 2 }, { 3 }, { 12 }, { 4 } };
	struct table_value values[] = { { 6623 }, { 784 }, { 736 }, { -1 } };
	int i;

	/* Init. */
	if (test_table_init(&table, &equals_function, &hash_code_function) < 0) {
		log_err("The init function failed.");
		return false;
	}
	test_table_print(&table, "After init");

	/* Test put and get. */
	for (i = 0; i < 3; i++)
		if (test_table_put(&table, &keys[i], &values[i]) != 0) {
			log_err("Put operation (1) failed on value %d.", i);
			goto failure;
		}

	if (!assert_table_content(&table, keys, values, "Hash table put/get"))
		goto failure;
	test_table_print(&table, "After puts");

	/* Test remove. */
	if (!test_table_remove(&table, &keys[1], NULL)) {
		log_err("Remove operation failed on value 1.");
		goto failure;
	}
	values[1].value = -1;

	if (!assert_table_content(&table, keys, values, "Hash table remove"))
		goto failure;
	test_table_print(&table, "After remove");

	/* Test empty. */
	test_table_empty(&table, NULL);
	values[0].value = -1;
	values[2].value = -1;

	if (!assert_table_content(&table, keys, values, "Hash table empty"))
		goto failure;
	test_table_print(&table, "After empty");

	/* Test put after the cleanup. */
	values[0].value = 6623;
	values[1].value = 784;
	values[2].value = 736;

	for (i = 0; i < 3; i++)
		if (test_table_put(&table, &keys[i], &values[i]) != 0) {
			log_err("Put operation (2) failed on value %d.", i);
			goto failure;
		}

	if (!assert_table_content(&table, keys, values, "Hash table put/get"))
		goto failure;
	test_table_print(&table, "After puts");

	/* Clean up. Also do a final assert just in case. */
	test_table_empty(&table, NULL);
	values[0].value = -1;
	values[1].value = -1;
	values[2].value = -1;
	if (!assert_table_content(&table, keys, values, "Needless extra test"))
		goto failure;

	test_table_empty(&table, NULL);
	return true;

failure:
	test_table_empty(&table, NULL);
	return false;
}

struct loop_summary {
	int values[3];
	int array_size;
};

static int for_each_func(struct table_value *val, void *arg)
{
	struct loop_summary *summary = arg;

	if (summary->array_size >= 3) {
		log_err("Expected only 3 values in the table.");
		return -EINVAL;
	}

	summary->values[summary->array_size] = val->value;
	summary->array_size++;

	return 0;
}

static bool test_for_each_function(void)
{
	struct test_table table;
	struct loop_summary summary = {
			.values = { 0, 0, 0 },
			.array_size = 0
	};
	int i;
	bool success;

	struct table_key keys[] = { { 2 }, { 3 }, { 12 } };
	struct table_value values[] = { { 6623 }, { 784 }, { 736 } };

	/* Init. */
	test_table_init(&table, &equals_function, &hash_code_function);
	for (i = 0; i < ARRAY_SIZE(values); i++) {
		if (test_table_put(&table, &keys[i], &values[i]) != 0) {
			log_err("Put operation failed on value %d.", i);
			test_table_empty(&table, NULL);
			return false;
		}
	}

	success &= assert_equals_int(0, test_table_for_each(&table, for_each_func, &summary), "");
	success &= assert_equals_int(3, summary.array_size, "");
	for (i = 0; i < ARRAY_SIZE(values); i++) {
		success &= assert_true(summary.values[0] == values[i].value
				|| summary.values[1] == values[i].value
				|| summary.values[2] == values[i].value, "");
	}

	test_table_empty(&table, NULL);
	return true;
}

int init_module(void)
{
	START_TESTS("Hash table");

	CALL_TEST(test(), "Everything, except for_each");
	CALL_TEST(test_for_each_function(), "for_each function");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Hash table module test.");
