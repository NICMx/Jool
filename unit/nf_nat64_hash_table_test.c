#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>

#include "unit_test.h"


// Generate the hash table.
struct key {
	int key;
};

struct value {
	int value;
};

#define HTABLE_NAME test_table
#define KEY_TYPE struct key
#define VALUE_TYPE struct value
#define HASH_TABLE_SIZE (10)
#define GENERATE_PRINT
#define GENERATE_TO_ARRAY
#include "nf_nat64_hash_table.c"

// These are also kind of part of the table.
static bool equals_function(struct key *key1, struct key *key2)
{
	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	return (key1->key == key2->key);
}

static __u16 hash_code_function(struct key *key1)
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
		struct key *keys, struct value *expected_values,
		char *test_name)
{
	int i;
	for (i = 0; i < 4; i++) {
		struct value *current_value = test_table_get(table, &keys[i]);

		if (expected_values[i].value == -1) {
			ASSERT_NULL(current_value, test_name);
		} else {
			ASSERT_NOT_NULL(current_value, test_name);
			ASSERT_EQUALS(expected_values[i].value, current_value->value, test_name);
		}
	}

	return true;
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
	struct key keys[] = { { 2 }, { 3 }, { 12 }, { 4 } };
	struct value values[] = { { 6623 }, { 784 }, { 736 }, { -1 } };
	int i;

	// Init.
	test_table_init(&table, &equals_function, &hash_code_function);
	test_table_print(&table, "After init");

	// Test put and get.
	for (i = 0; i < 3; i++)
		test_table_put(&table, &keys[i], &values[i]);

	assert_table_content(&table, keys, values, "Hash table put/get.");
	test_table_print(&table, "After puts");

	// Test remove.
	test_table_remove(&table, &keys[1], false, false);
	values[1].value = -1;

	assert_table_content(&table, keys, values, "Hash table remove.");
	test_table_print(&table, "After remove");

	// Test empty.
	test_table_empty(&table, false, false);
	values[0].value = -1;
	values[2].value = -1;

	assert_table_content(&table, keys, values, "Hash table empty.");
	test_table_print(&table, "After empty");

	// Test put after the cleanup.
	values[0].value = 6623;
	values[1].value = 784;
	values[2].value = 736;

	for (i = 0; i < 3; i++)
		test_table_put(&table, &keys[i], &values[i]);

	assert_table_content(&table, keys, values, "Hash table put/get.");
	test_table_print(&table, "After puts");

	// Clean up. Also do a final assert just in case.
	test_table_empty(&table, false, false);
	values[0].value = -1;
	values[1].value = -1;
	values[2].value = -1;
	assert_table_content(&table, keys, values, "Needless extra test.");

	return true;
}

static bool test_to_array_function(void)
{
	struct test_table table;
	struct value **array = NULL;
	int array_size;
	int i;

	// Init.
	struct key keys[] = { { 2 }, { 3 }, { 12 } };
	struct value values[] = { { 6623 }, { 784 }, { 736 } };

	for (i = 0; i < ARRAY_SIZE(values); i++)
		test_table_put(&table, &keys[i], &values[i]);

	// Call.
	array_size = test_table_to_array(&table, &array);

	// Assert.
	if (array_size != 3) {
		pr_warning("Test failed: Array size. Expected: 3. Actual: %d\n", array_size);
		goto failure;
	}

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		if (array[0]->value != values[i].value
				&& array[1]->value != values[i].value
				&& array[2]->value != values[i].value) {
			pr_warning("Test failed: To array function. Expected array to contain %d.\n",
					values[i].value);
			goto failure;
		}
	}

	kfree(array);
	return true;

failure:
	kfree(array);
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
