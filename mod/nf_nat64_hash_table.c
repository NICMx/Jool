/**
 * @file
 * Contiene la implementación de una tabla de hash genérica.
 *
 * Usa internamente la hlist definida por el kernel.
 * La razón de esta capa extra es que no me gustó hlist por sí sola,
 * porque implica demasiada reescritura (ej. la función de acceso; get).
 *
 * La idea de esta implementación es que el API se parezca lo más posible
 * al HashMap de Java.
 *
 * Para llenar los espacios, definir las siguientes macros:
 * @macro HTABLE_NAME tipo de la estructura que va a sostener la tabla.
 * 		Opcional (Default: hash_table).
 * @macro KEY_TYPE tipo de dato que se va a usar como llave para acceder
 * 		a los valores.
 * @macro VALUE_TYPE tipo de dato de los valores a guardar en la tabla.
 * @macro HASH_TABLE_SIZE Número de renglones en la tabla. Opcional
 * 		(Default: 64k). Nótese que cada renglón es una lista encadenada
 *		para todos los datos que tengan el mismo código hash.
 *
 * TODO (Optimización) Usar slab en lugar de kmalloc.
 */

#include <linux/slab.h>

/********************************************
 * Macros.
 ********************************************/

#ifndef HTABLE_NAME
#define HTABLE_NAME hash_table
#endif

#ifndef HASH_TABLE_SIZE
#define HASH_TABLE_SIZE (100)
#endif

#define CONCAT_AUX(prefix, suffix) prefix ## suffix
/** Parece inutil, pero si no intermedia el compilador no expande la macro HTABLE_NAME... */
#define CONCAT(prefix, suffix) CONCAT_AUX(prefix, suffix)

#define KEY_VALUE_PAIR	CONCAT(HTABLE_NAME, _key_value)
#define INIT			CONCAT(HTABLE_NAME, _init)
#define PUT				CONCAT(HTABLE_NAME, _put)
#define GET				CONCAT(HTABLE_NAME, _get)
#define REMOVE			CONCAT(HTABLE_NAME, _remove)
#define EMPTY			CONCAT(HTABLE_NAME, _empty)
#define GET_AUX			CONCAT(HTABLE_NAME, _get_aux)
#define PRINT			CONCAT(HTABLE_NAME, _print)

/********************************************
 * Estructuras.
 ********************************************/

struct HTABLE_NAME
{
	struct hlist_head table[HASH_TABLE_SIZE];
	bool (*equals_function)(KEY_TYPE *, KEY_TYPE *);
	__be16 (*hash_function)(KEY_TYPE *);
};

struct KEY_VALUE_PAIR
{
	KEY_TYPE *key;
	VALUE_TYPE *value;
	struct hlist_node nodes;
};

/********************************************
 * "Metodos" privados.
 ********************************************/

static struct KEY_VALUE_PAIR *GET_AUX(struct HTABLE_NAME *table, KEY_TYPE *key)
{
	struct hlist_node *current_node;
	struct KEY_VALUE_PAIR *current_pair;
	__be16 hash_code;

	hash_code = table->hash_function(key) % HASH_TABLE_SIZE;
	printk(KERN_DEBUG "  -> Hash code: %d", hash_code);

	hlist_for_each(current_node, &table->table[hash_code]) {
		current_pair = list_entry(current_node, struct KEY_VALUE_PAIR, nodes);
		if (table->equals_function(key, current_pair->key)) {
			printk(KERN_DEBUG "  -> Found.");
			return current_pair;
		}
	}

	printk(KERN_DEBUG "  -> Not found.");
	return NULL;
}

/********************************************
 * "Metodos" publicos.
 ********************************************/

static void INIT(struct HTABLE_NAME *table,
		bool (*equals_function)(KEY_TYPE *, KEY_TYPE *),
		__be16 (*hash_function)(KEY_TYPE *))
{
	int i;
	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&table->table[i]);

	table->equals_function = equals_function;
	table->hash_function = hash_function;
}

/**
 * Important: The table stores pointers to (as opposed to "copies of") both key and value.
 * So please consider that neither must be released from memory after the call to this function.
 */
static bool PUT(struct HTABLE_NAME *table, KEY_TYPE *key, VALUE_TYPE *value)
{
	struct KEY_VALUE_PAIR *key_value;
	__be16 hash_code;

	// Lo que vamos a insertar no es el valor solo, sino que una estructura llave-valor.
	// (Porque necesitamos tener la llave disponible).
	// Aquí se genera.
	key_value = (struct KEY_VALUE_PAIR *) kmalloc(sizeof(struct KEY_VALUE_PAIR), GFP_ATOMIC);
	if (!key_value)
		return false;
	key_value->key = key;
	key_value->value = value;

	// Insertar la llave-valor.
	hash_code = table->hash_function(key) % HASH_TABLE_SIZE;
	hlist_add_head(&key_value->nodes, &table->table[hash_code]);

	return true;
}

/**
 * You will receive the actual stored value. Please don't release it from memory.
 */
static VALUE_TYPE *GET(struct HTABLE_NAME *table, KEY_TYPE *key)
{
	struct KEY_VALUE_PAIR *key_value = GET_AUX(table, key);
	return (key_value != NULL) ? key_value->value : NULL;
}

static bool REMOVE(struct HTABLE_NAME *table, KEY_TYPE *key, bool release_key, bool release_value)
{
	struct KEY_VALUE_PAIR *key_value = GET_AUX(table, key);
	if (key_value == NULL)
		return false;

	hlist_del(&key_value->nodes);

	if (release_key)
		kfree(key_value->key);
	if (release_value)
		kfree(key_value->value);
	kfree(key_value);

	return true;
}

/**
 * Because the table stores some data in the heap, you definitely want to call this
 * before your table goes into oblivion!!!
 */
static void EMPTY(struct HTABLE_NAME *table, bool release_keys, bool release_values)
{
	struct hlist_node *current_node;
	struct KEY_VALUE_PAIR *current_pair;
	int row;

	for (row = 0; row < HASH_TABLE_SIZE; row++) {
		while (!hlist_empty(&table->table[row])) {
			current_node = table->table[row].first;
			current_pair = container_of(current_node, struct KEY_VALUE_PAIR, nodes);

			hlist_del(current_node);

			if (release_keys)
				kfree(current_pair->key);
			if (release_values)
				kfree(current_pair->value);
			kfree(current_pair);

			printk(KERN_DEBUG "Deleted a node whose hash code was %d.", row);
		}
	}
}

#ifdef TESTING
static void PRINT(struct HTABLE_NAME *table, char *header)
{
	struct hlist_node *current_node;
	struct KEY_VALUE_PAIR *current_pair;
	int row;

	printk(KERN_DEBUG "** Printing table: %s **", header);
	for (row = 0; row < HASH_TABLE_SIZE; row++) {
		hlist_for_each(current_node, &table->table[row]) {
			current_pair = hlist_entry(current_node, struct KEY_VALUE_PAIR, nodes);
			printk(KERN_DEBUG "  hash:%d - key:%p - value:%p", row, &current_pair->key, &current_pair->value);
		}
	}
	printk(KERN_DEBUG "** End of table **");
}
#endif

// Compiler cleanup. The macros are freed, just so you can define
// another kind of hash table in the same file.
#undef HTABLE_NAME
#undef KEY_TYPE
#undef VALUE_TYPE
#undef HASH_TABLE_SIZE
