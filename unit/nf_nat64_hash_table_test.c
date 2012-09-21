#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>

#include "unit_test.h"

struct key {
	int key;
};

struct value {
	int value;
};

// Generar la tabla de hash.
#define HTABLE_NAME test_table
#define KEY_TYPE struct key
#define VALUE_TYPE struct value
#define HASH_TABLE_SIZE (10)
#define TESTING
#include "nf_nat64_hash_table.c"

// Burocracia de modulos.
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Hash table module test.");

bool equals_function(struct key *key1, struct key *key2)
{
	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	return (key1->key == key2->key);
}

__be16 hash_code_function(struct key *key1)
{
	return (key1 != NULL) ? key1->key : 0;
}

int assert_table_content(struct test_table *table, struct key *keys, struct value *expected_values, char *test_name)
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

int init_module(void) {
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

	// Limpiar memoria, probar de nuevo por si las moscas.
	test_table_empty(&table, false, false);
	values[0].value = -1;
	values[1].value = -1;
	values[2].value = -1;
	assert_table_content(&table, keys, values, "Needless extra test.");

	// Salir.
	printk(KERN_INFO "Todas las pruebas funcionaron.");
	return 0;
}

void cleanup_module(void) {
	// Sin codigo.
}

