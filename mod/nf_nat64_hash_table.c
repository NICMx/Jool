/**
 * @file
 * A generic hash table implementation. Its design is largely based off Java's java.util.HashMap.
 * One difference is that the internal array does not resize.
 *
 * Uses the kernel's hlist internally.
 * We're not using hlist directly because it implies a lot of code rewriting (eg. the entry
 * retrieval function; "get") and we need at least four different hash tables.
 *
 * Because C does not support templates or generics, you have to set a number of macros and then
 * include this file. These are the macros:
 * @macro HTABLE_NAME name of the hash table structure to generate. Optional; Default: hash_table.
 * @macro KEY_TYPE data type of the table's keys.
 * @macro VALUE_TYPE data type of the table's values.
 * @macro HASH_TABLE_SIZE The size of the internal array, in slots. Optional;
 *		Default = Max = 64k - 1.
 * @macro GENERATE_PRINT just define it if you want the print function; otherwise it will not be
 *		generated.
 * @macro GENERATE_TO_ARRAY just define it if you want the to_array function; otherwise it will not
 *		be generated.
 *
 * This module contains no header file; it needs to be #included directly.
 *
 * TODO (optimization) Use slab instead of kmalloc.
 * TODO (warning) we'll need locks; both the BIB and session tables are probably being called by
 * different threads.
 */

#include <linux/slab.h>
#include "nf_nat64_types.h"

/********************************************
 * Macros.
 ********************************************/

#ifndef HTABLE_NAME
#define HTABLE_NAME hash_table
#endif

#ifndef HASH_TABLE_SIZE
#define HASH_TABLE_SIZE (64 * 1024 - 1)
#endif

/** Creates a token name by concatenating prefix and suffix. */
#define CONCAT_AUX(prefix, suffix) prefix ## suffix
/** Seems useless, but if not present, the compiles won't expand the HTABLE_NAME macro... */
#define CONCAT(prefix, suffix) CONCAT_AUX(prefix, suffix)

/** The name of the key-value structure. */
#define KEY_VALUE_PAIR	CONCAT(HTABLE_NAME, _key_value)
/** The name of the init function. */
#define INIT			CONCAT(HTABLE_NAME, _init)
/** The name of the put function. */
#define PUT				CONCAT(HTABLE_NAME, _put)
/** The name of the get function. */
#define GET				CONCAT(HTABLE_NAME, _get)
/** The name of the remove function. */
#define REMOVE			CONCAT(HTABLE_NAME, _remove)
/** The name of the empty function. */
#define EMPTY			CONCAT(HTABLE_NAME, _empty)
/** The name of the auxiliary get function. */
#define GET_AUX			CONCAT(HTABLE_NAME, _get_aux)
/** The name of the print function. */
#define PRINT			CONCAT(HTABLE_NAME, _print)
/** The name of the to_array function. */
#define TO_ARRAY		CONCAT(HTABLE_NAME, _to_array)

/********************************************
 * Structures.
 ********************************************/

/** The hash table. */
struct HTABLE_NAME
{
	/**
	 * The array of linked lists.
	 * Each of these contains the values mapped to its index's hash code.
	 */
	struct hlist_head table[HASH_TABLE_SIZE];
	/** Number of key-value pairs currently stored by the table. */
	__u32 size;

	/** Used to locate the slot (within the linked list) of a value. */
	bool (*equals_function)(KEY_TYPE *, KEY_TYPE *);
	/** Used locate the linked list (within the array) of a value. */
	__u16 (*hash_function)(KEY_TYPE *);
};

/** Every entry in the table; the key used to access the value and the value. */
struct KEY_VALUE_PAIR
{
	/** Dictates where in the table the value is. */
	KEY_TYPE *key;
	/** The value the user wants to store in the table. */
	VALUE_TYPE *value;
	/** Other key-values chained with this one (see: HTABLE_NAME.table). */
	struct hlist_node nodes;
};

/********************************************
 * Private "methods".
 ********************************************/

/**
 * Returns the key-value mapped to the "key" key within the table.
 *
 * To be used by hash table functions; outside code should use GET instead.
 *
 * @param table hash table instance you want the key-value from.
 * @param key descriptor to which the associated key-value is to be returned.
 * @return the key-value to which "table" maps "key", "null" if there's no mapping for the key.
 */
static struct KEY_VALUE_PAIR *GET_AUX(struct HTABLE_NAME *table, KEY_TYPE *key)
{
	struct hlist_node *current_node;
	struct KEY_VALUE_PAIR *current_pair;
	__u16 hash_code;

	if (!table)
		return NULL;

	hash_code = table->hash_function(key) % HASH_TABLE_SIZE;
	hlist_for_each(current_node, &table->table[hash_code]) {
		current_pair = list_entry(current_node, struct KEY_VALUE_PAIR, nodes);
		if (table->equals_function(key, current_pair->key))
			return current_pair;
	}

	return NULL;
}

/********************************************
 * "Public" "methods".
 ********************************************/

/**
 * Readies "table" for future use.
 * TODO check return value.
 *
 * @param table the HTABLE_NAME instance you want to initialize.
 * @param equals_function function the table will use to locate slots.
 * @param hash_function function the table will use to locate linked lists.
 */
static bool INIT(struct HTABLE_NAME *table,
		bool (*equals_function)(KEY_TYPE *, KEY_TYPE *),
		__u16 (*hash_function)(KEY_TYPE *))
{
	__u16 i;

	if (!table)
		return false;
	if (!equals_function)
		return false;
	if (!hash_function)
		return false;

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&table->table[i]);

	table->equals_function = equals_function;
	table->hash_function = hash_function;
	table->size = 0;

	return true;
}

/**
 * Inserts "value" to the "table" table in the slot described by the "key" key.
 *
 * Important: The table stores pointers to (as opposed to "copies of") both key and value.
 * So please consider that neither must be released from memory after the call to this function.
 *
 * @param table the HTABLE_NAME instance you want to insert a value to.
 * @param key descriptor of the slot to place "value" in.
 * @param value element to store in the table.
 * @return success status. The value will not be inserted if a kmalloc fails.
 */
static bool PUT(struct HTABLE_NAME *table, KEY_TYPE *key, VALUE_TYPE *value)
{
	struct KEY_VALUE_PAIR *key_value;
	__u16 hash_code;

	if (!table)
		return false;

	// We're not going to insert the value alone, but a key-value structure.
	// (Because we'll later need the key available during lookups.)
	// We generate it here.
	key_value = kmalloc(sizeof(struct KEY_VALUE_PAIR), GFP_ATOMIC);
	if (!key_value)
		return false;
	key_value->key = key;
	key_value->value = value;

	// Insert the key-value to the table.
	hash_code = table->hash_function(key) % HASH_TABLE_SIZE;
	hlist_add_head(&key_value->nodes, &table->table[hash_code]);
	table->size++;

	return true;
}

/**
 * Returns from "table" the value mapped to the "key" key, if available.
 *
 * You will receive the actual stored value. Please don't release it from memory (use the REMOVE
 * function instead).
 *
 * @param table the HTABLE_NAME instance you want the value from.
 * @param key descriptor to which the associated value is to be returned.
 * @return the value to which "table" maps "key", "null" if there's no mapping for the key.
 */
static VALUE_TYPE *GET(struct HTABLE_NAME *table, KEY_TYPE *key)
{
	struct KEY_VALUE_PAIR *key_value = GET_AUX(table, key);
	return (key_value != NULL) ? key_value->value : NULL;
}

/**
 * Stops "key" from accesing its value in the "table" table.
 * Releases memory as well, depending on the release_* arguments.
 *
 * @param table the HTABLE_NAME instance you want to stop mapping "key" from.
 * @param key descriptor whose associated value will be removed from "table".
 * @param release_key send "true" if the key stored in the table should be released from memory.
 * @param release_value send "true" if the value stored in the table should be released from memory.
 */
static bool REMOVE(struct HTABLE_NAME *table, KEY_TYPE *key, bool release_key, bool release_value)
{
	struct KEY_VALUE_PAIR *key_value = GET_AUX(table, key);
	if (key_value == NULL)
		return false;

	hlist_del(&key_value->nodes);
	table->size--;

	if (release_key)
		kfree(key_value->key);
	if (release_value)
		kfree(key_value->value);
	kfree(key_value);

	return true;
}

/**
 * Clears all memory allocated by the table. You definitely want to call this before your table goes
 * into oblivion!!!
 *
 * @param table the HTABLE_NAME instance you want to clear.
 * @param release_keys send "true" if the table's stored keys should be deallocated.
 * @param release_values send "true" if the table's stored keys should be deallocated.
 *
 * Note that even if you want to release the keys and the values, you still need to call this
 * function since you have no control over the key-value pairs.
 */
static void EMPTY(struct HTABLE_NAME *table, bool release_keys, bool release_values)
{
	struct hlist_node *current_node;
	struct KEY_VALUE_PAIR *current_pair;
	__u16 row;

	if (!table)
		return;

	for (row = 0; row < HASH_TABLE_SIZE; row++) {
		while (!hlist_empty(&table->table[row])) {
			current_node = table->table[row].first;
			current_pair = container_of(current_node, struct KEY_VALUE_PAIR, nodes);

			hlist_del(current_node);
			table->size--;

			if (release_keys)
				kfree(current_pair->key);
			if (release_values)
				kfree(current_pair->value);
			kfree(current_pair);

			// log_debug("Deleted a node whose hash code was %d.", row);
		}
	}
}

#ifdef GENERATE_PRINT
/**
 * Printks the content of the table in KERN_DEBUG level.
 * Use for debugging purposes.
 *
 * @param the HTABLE_NAME instance you want to print.
 * @param header a header label for the table. Will precede the table so you can locate it in dmesg
 *		or something.
 */
static void PRINT(struct HTABLE_NAME *table, char *header)
{
	struct hlist_node *current_node;
	struct KEY_VALUE_PAIR *current_pair;
	__u16 row;

	log_debug("** Printing table: %s **", header);

	if (!table)
		goto end;
	for (row = 0; row < HASH_TABLE_SIZE; row++) {
		hlist_for_each(current_node, &table->table[row]) {
			current_pair = hlist_entry(current_node, struct KEY_VALUE_PAIR, nodes);
			log_debug("  hash:%d - key:%p - value:%p", row, &current_pair->key,
					&current_pair->value);
		}
	}

	/* Fall through.*/
end:
	log_debug("** End of table **");
}
#endif

#ifdef GENERATE_TO_ARRAY
/**
 * Builds an array out of the current table contents, and then returns it.
 * (It's a shallow copy).
 *
 * @param table the HTABLE_NAME instance you want to convert to an array.
 * @param result makes this point to the resulting array. "***" = "by-reference argument of an array
 *			of pointers."
 * @return the length of "result" (in array slots). May be -1, if memory could not be allocated.
 *
 * You have to kfree "result" after you use it. Don't kfree the objects pointed by its slots, as
 * they are the real entries from the hash table.
 */
static __s32 TO_ARRAY(struct HTABLE_NAME *table, VALUE_TYPE ***result)
{
	struct hlist_node *current_node;
	struct KEY_VALUE_PAIR *current_pair;
	__u16 row;

	VALUE_TYPE **array;
	__u32 array_counter = 0;

	if (!table || table->size < 1)
		return 0;

	array = kmalloc(table->size * sizeof(VALUE_TYPE *), GFP_ATOMIC);
	if (!array)
		return -1;

	for (row = 0; row < HASH_TABLE_SIZE; row++) {
		hlist_for_each(current_node, &table->table[row]) {
			current_pair = hlist_entry(current_node, struct KEY_VALUE_PAIR, nodes);
			array[array_counter] = current_pair->value;
			array_counter++;
		}
	}

	if (array_counter != table->size)
		log_crit("Programming error: The table's size field does not equal the seemingly "
				"actual number of objects it contains.");

	*result = array;
	return table->size;
}
#endif

// Compiler cleanup. The macros are freed, just so you can define another kind
// of hash table in the same file without compiler warnings.
#undef HTABLE_NAME
#undef KEY_TYPE
#undef VALUE_TYPE
#undef HASH_TABLE_SIZE
#undef GENERATE_PRINT
#undef GENERATE_TO_ARRAY
