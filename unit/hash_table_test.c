#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>

#include "nat64/mod/unit_test.h"


// Generate the hash table.
struct table_key {
	int key;
};

struct table_value {
	int value;
};

#define HTABLE_NAME test_table
#define KEY_TYPE struct table_key
#define VALUE_TYPE struct table_value
#define HASH_TABLE_SIZE (10)
#define GENERATE_PRINT
#define GENERATE_TO_ARRAY
#include "hash_table.c"

// These are also kind of part of the table.
static bool equals_function(struct table_key *key1, struct table_key *key2)
{
	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	return (key1->key == key2->key);
}

static __u16 hash_code_function(struct table_key *key1)
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
	// The second value is a normal, troubleless key-value pair.
	// The first and third keys have the same hash code (tests the table doesn't override them or
	// something).
	// The fourth key-value shall not be inserted (tests the table doesn't go bananas attempting to
	// retrieve it).
	struct table_key keys[] = { { 2 }, { 3 }, { 12 }, { 4 } };
	struct table_value values[] = { { 6623 }, { 784 }, { 736 }, { -1 } };
	int i;

	// Init.
	test_table_init(&table, &equals_function, &hash_code_function);
	test_table_print(&table, "After init");

	// Test put and get.
	for (i = 0; i < 3; i++)
		if (test_table_put(&table, &keys[i], &values[i]) != ERR_SUCCESS) {
			log_warning("Put operation (1) failed on value %d.", i);
			goto failure;
		}

	if (!assert_table_content(&table, keys, values, "Hash table put/get"))
		goto failure;
	test_table_print(&table, "After puts");

	// Test remove.
	if (!test_table_remove(&table, &keys[1], false, false)) {
		log_warning("Remove operation failed on value 1.");
		goto failure;
	}
	values[1].value = -1;

	if (!assert_table_content(&table, keys, values, "Hash table remove"))
		goto failure;
	test_table_print(&table, "After remove");

	// Test empty.
	test_table_empty(&table, false, false);
	values[0].value = -1;
	values[2].value = -1;

	if (!assert_table_content(&table, keys, values, "Hash table empty"))
		goto failure;
	test_table_print(&table, "After empty");

	// Test put after the cleanup.
	values[0].value = 6623;
	values[1].value = 784;
	values[2].value = 736;

	for (i = 0; i < 3; i++)
		if (test_table_put(&table, &keys[i], &values[i]) != ERR_SUCCESS) {
			log_warning("Put operation (2) failed on value %d.", i);
			goto failure;
		}

	if (!assert_table_content(&table, keys, values, "Hash table put/get"))
		goto failure;
	test_table_print(&table, "After puts");

	// Clean up. Also do a final assert just in case.
	test_table_empty(&table, false, false);
	values[0].value = -1;
	values[1].value = -1;
	values[2].value = -1;
	if (!assert_table_content(&table, keys, values, "Needless extra test"))
		goto failure;

	test_table_empty(&table, false, false);
	return true;

failure:
	test_table_empty(&table, false, false);
	return false;
}

static bool test_to_array_function(void)
{
	struct test_table table;
	struct table_value **array = NULL;
	int array_size;
	int i;

	struct table_key keys[] = { { 2 }, { 3 }, { 12 } };
	struct table_value values[] = { { 6623 }, { 784 }, { 736 } };

	// Init.
	test_table_init(&table, &equals_function, &hash_code_function);
	for (i = 0; i < ARRAY_SIZE(values); i++)
		if (test_table_put(&table, &keys[i], &values[i]) != ERR_SUCCESS) {
			log_warning("Put operation failed on value %d.", i);
			goto failure;
		}

	// Call.
	array_size = test_table_to_array(&table, &array);

	// Assert.
	if (array_size != 3) {
		log_warning("Test failed: Array size. Expected: 3. Actual: %d", array_size);
		goto failure;
	}

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		if (array[0]->value != values[i].value
				&& array[1]->value != values[i].value
				&& array[2]->value != values[i].value) {
			log_warning("Test failed: To array function. Expected array to contain %d.",
					values[i].value);
			goto failure;
		}
	}

	kfree(array);
	test_table_empty(&table, false, false);
	return true;

failure:
	kfree(array);
	test_table_empty(&table, false, false);
	return false;
}

int init_module(void)
{
	START_TESTS("Hash table");

	CALL_TEST(test(), "Everything, except to_array");
	CALL_TEST(test_to_array_function(), "to_array function");

	END_TESTS;
}

void cleanup_module(void)
{
	// Sin codigo.
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Hash table module test.");
