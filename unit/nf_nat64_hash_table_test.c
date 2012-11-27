#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>

#include "unit_test.h"

// TODO (test) refactoriza porque está bien mal.

// Burocracia de modulos.
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Hash table module test.");

// Generar la tabla de hash.
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

static int assert_table_content(struct test_table *table, struct key *keys, struct value *expected_values, char *test_name)
{
	int i;
	for (i = 0; i < 4; i++) {
		struct value *current_value = test_table_get(table, &keys[i]);

		if (expected_values[i].value != -1) {
			if (current_value == NULL) {
				printk(KERN_WARNING "Test failed: %s Expected: %d. Actual: NULL.", test_name, expected_values[i].value);
				return -EAGAIN;
			}
			ASSERT_EQUALS(expected_values[i].value, current_value->value, test_name);
		} else {
			ASSERT_NULL(current_value, test_name);
		}
	}

	return 0;
}

static bool test(void)
{
	struct test_table table;
	// The second value is a normal, troubleless key-value pair.
	// The first and third keys have the same hash code (tests the table knows how to differenciate them correctly).
	// The fourth key-value shall not be inserted (tests the table doesn't go bananas).
	struct key keys[] = { { 2 }, { 3 }, { 12 }, { 4 } };
	struct value values[] = { { 6623 }, { 784 }, { 736 }, { -1 } };
	int i;

	// Inicializar.
	test_table_init(&table, &equals_function, &hash_code_function);

	test_table_print(&table, "After init");

	// Probar put y get.
	for (i = 0; i < 3; i++)
		test_table_put(&table, &keys[i], &values[i]);

	assert_table_content(&table, keys, values, "Hash table put/get.");
	test_table_print(&table, "After puts");

	// Probar remove.
	test_table_remove(&table, &keys[1], false, false);
	values[1].value = -1;

	assert_table_content(&table, keys, values, "Hash table remove.");
	test_table_print(&table, "After remove");

	// Probar empty.
	test_table_empty(&table, false, false);
	values[0].value = -1;
	values[2].value = -1;

	assert_table_content(&table, keys, values, "Hash table empty.");
	test_table_print(&table, "After empty");

	// Probar put después de las borradas.
	values[0].value = 6623;
	values[1].value = 784;
	values[2].value = 736;

	for (i = 0; i < 3; i++)
		test_table_put(&table, &keys[i], &values[i]);

	assert_table_content(&table, keys, values, "Hash table put/get.");
	test_table_print(&table, "After puts");

	// Probar to_array.
	{
		int i;
		struct value **array = NULL;
		int array_size = test_table_to_array(&table, &array);

		printk(KERN_DEBUG "Array size: %d", array_size);
		printk(KERN_DEBUG "=======================");
		for (i = 0; i < array_size; ++i)
			printk(KERN_DEBUG "Value: %d", array[i]->value);
		printk(KERN_DEBUG "=======================");
	}

	// Limpiar memoria, probar de nuevo por si las moscas.
	test_table_empty(&table, false, false);
	values[0].value = -1;
	values[1].value = -1;
	values[2].value = -1;
	assert_table_content(&table, keys, values, "Needless extra test.");

	// Salir.
	return true;
}

int init_module(void)
{
	START_TESTS("Hash table");

	CALL_TEST(test(), "Everything");

	END_TESTS;
}

void cleanup_module(void)
{
	// Sin codigo.
}

