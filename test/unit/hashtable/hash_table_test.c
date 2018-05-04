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
#include "common/hash_table.c"

/* These are also kind of part of the table. */
static bool equals_cb(const struct table_key *k1, const struct table_key *k2)
{
	if (k1 == k2)
		return true;
	if (k1 == NULL || k2 == NULL)
		return false;

	return (k1->key == k2->key);
}

static unsigned int hash_code_cb(const struct table_key *key)
{
	return (key != NULL) ? key->key : 0;
}

/**
 * assert_table_content - For every key (from the @keys array), extracts its
 * corresponding value from @table, and asserts it equals its corresponding
 * expected value (from the @expected array).
 *
 * Assumes both @keys and @expected have length 4.
 */
static bool assert_table_content(struct test_table *table,
		struct table_key *keys, struct table_value *expected,
		char *test_name)
{
	unsigned int i;
	bool local;
	bool success = true;

	for (i = 0; i < 4; i++) {
		struct table_value *value = test_table_get(table, &keys[i]);

		if (expected[i].value == -1) {
			success &= ASSERT_PTR(NULL, value,
					"%s - %uth value should not exist",
					test_name, i);
			continue;
		}

		local = ASSERT_BOOL(true, value != NULL,
				"%s - %uth value (%d) should exist",
				test_name, i, expected[i].value);
		if (local)
			local &= ASSERT_INT(expected[i].value, value->value,
					"%s - %uth value", test_name, i);

		success &= local;
	}

	return success;
}

/**
 * The functions are really interdependent, so most functions are tested in this
 * single unit. Sorry.
 */
static bool most_stuff(void)
{
	struct test_table table;
	/*
	 * The second value is a normal, troubleless key-value pair.
	 * The first and third keys have the same hash code (tests the table
	 * doesn't override them or something).
	 * The fourth key-value shall not be inserted (tests the table doesn't
	 * go bananas retrieving it).
	 */
	struct table_key keys[] = { { 2 }, { 3 }, { 12 }, { 4 } };
	struct table_value values[] = { { 6623 }, { 784 }, { 736 }, { -1 } };
	int i;

	/* Init. */
	if (test_table_init(&table, &equals_cb, &hash_code_cb) < 0) {
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

static int foreach_cb(struct table_value *val, void *arg)
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

	test_table_init(&table, &equals_cb, &hash_code_cb);
	for (i = 0; i < ARRAY_SIZE(values); i++) {
		if (test_table_put(&table, &keys[i], &values[i]) != 0) {
			log_err("Put operation failed on value %d.", i);
			test_table_empty(&table, NULL);
			return false;
		}
	}

	success &= ASSERT_INT(0, test_table_for_each(&table, foreach_cb,
			&summary), "Foreach call result");
	success &= ASSERT_INT(3, summary.array_size, "");
	for (i = 0; i < ARRAY_SIZE(values); i++) {
		success &= ASSERT_BOOL(true,
				summary.values[0] == values[i].value
				|| summary.values[1] == values[i].value
				|| summary.values[2] == values[i].value,
				"%uth value was visited", i);
	}

	test_table_empty(&table, NULL);
	return true;
}

int init_module(void)
{
	struct test_group test = {
		.name = "Hash table",
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, most_stuff, "Everything, except for_each");
	test_group_test(&test, test_for_each_function, "for_each function");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Hash table module test.");
