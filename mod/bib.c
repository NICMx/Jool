#include "nat64/mod/bib.h"

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/in6.h>


/********************************************
 * Structures and private variables.
 ********************************************/

/*
 * Hash table; indexes BIB entries by IPv4 address.
 * (this code generates the "ipv4_table" structure and related functions used below).
 */
#define HTABLE_NAME ipv4_table
#define KEY_TYPE struct ipv4_tuple_address
#define VALUE_TYPE struct bib_entry
#define GENERATE_FOR_EACH
#include "hash_table.c"

/*
 * Hash table; indexes BIB entries by IPv6 address.
 * (this code generates the "ipv6_table" structure and related functions used below).
 */
#define HTABLE_NAME ipv6_table
#define KEY_TYPE struct ipv6_tuple_address
#define VALUE_TYPE struct bib_entry
#include "hash_table.c"

/**
 * BIB table definition.
 * Holds two hash tables, one for each indexing need (IPv4 and IPv6).
 */
struct bib_table {
	/** Indexes entries by IPv4. */
	struct ipv4_table ipv4;
	/** Indexes entries by IPv6. */
	struct ipv6_table ipv6;
};

/** The BIB table for UDP connections. */
static struct bib_table bib_udp;
/** The BIB table for TCP connections. */
static struct bib_table bib_tcp;
/** The BIB table for ICMP connections. */
static struct bib_table bib_icmp;

DEFINE_SPINLOCK(bib_session_lock);

/********************************************
 * Private (helper) functions.
 ********************************************/

static int get_bib_table(l4_protocol l4_proto, struct bib_table **result)
{
	switch (l4_proto) {
	case L4PROTO_UDP:
		*result = &bib_udp;
		return 0;
	case L4PROTO_TCP:
		*result = &bib_tcp;
		return 0;
	case L4PROTO_ICMP:
		*result = &bib_icmp;
		return 0;
	case L4PROTO_NONE:
		log_crit(ERR_ILLEGAL_NONE, "Tuples are not supposed to contain NONE.");
		return -EINVAL;
	}

	log_crit(ERR_L4PROTO, "Unsupported transport protocol: %u.", l4_proto);
	return -EINVAL;
}

/*******************************
 * Public functions.
 *******************************/

int bib_init(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i, error;

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		error = ipv4_table_init(&tables[i]->ipv4, ipv4_tuple_addr_equals, ipv4_tuple_addr_hashcode);
		if (error)
			return error;
		error = ipv6_table_init(&tables[i]->ipv6, ipv6_tuple_addr_equals, ipv6_tuple_addr_hashcode);
		if (error)
			return error;
	}

	return 0;
}

int bib_add(struct bib_entry *entry, l4_protocol l4_proto)
{
	struct bib_table *table;
	int error;

	if (!entry) {
		log_err(ERR_NULL, "NULL is not a valid BIB entry.");
		return -EINVAL;
	}
	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	error = ipv4_table_put(&table->ipv4, &entry->ipv4, entry);
	if (error)
		return error;
	error = ipv6_table_put(&table->ipv6, &entry->ipv6, entry);
	if (error) {
		ipv4_table_remove(&table->ipv4, &entry->ipv4, NULL);
		return error;
	}

	return 0;
}

struct bib_entry *bib_get_by_ipv4(struct ipv4_tuple_address *address, l4_protocol l4_proto)
{
	struct bib_table *table;

	if (!address)
		return NULL;
	if (get_bib_table(l4_proto, &table) != 0)
		return NULL;

	return ipv4_table_get(&table->ipv4, address);
}

struct bib_entry *bib_get_by_ipv6(struct ipv6_tuple_address *address, l4_protocol l4_proto)
{
	struct bib_table *table;

	if (!address)
		return NULL;
	if (get_bib_table(l4_proto, &table) != 0)
		return NULL;

	return ipv6_table_get(&table->ipv6, address);
}

struct bib_entry *bib_get_by_ipv6_only(struct in6_addr *address, l4_protocol l4_proto)
{
	struct bib_table *table;
	__u16 hash_code;
	struct hlist_node *current_node;
	struct ipv6_tuple_address address_full;
	struct ipv6_table_key_value *keyvalue;

	if (!address)
		return NULL;
	if (get_bib_table(l4_proto, &table) != 0)
		return NULL;

	address_full.address = *address; /* Port doesn't matter; won't be used by the hash function. */
	hash_code = table->ipv6.hash_function(&address_full) % ARRAY_SIZE(table->ipv6.table);

	hlist_for_each(current_node, &table->ipv6.table[hash_code]) {
		keyvalue = list_entry(current_node, struct ipv6_table_key_value, hlist_hook);
		if (ipv6_addr_equals(address, &keyvalue->key.address))
			return keyvalue->value;
	}

	return NULL;
}

struct bib_entry *bib_get(struct tuple *tuple)
{
	struct ipv6_tuple_address address6;
	struct ipv4_tuple_address address4;

	if (!tuple)
		return NULL;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		address6.address = tuple->src.addr.ipv6;
		address6.l4_id = tuple->src.l4_id;
		return bib_get_by_ipv6(&address6, tuple->l4_proto);
	case L3PROTO_IPV4:
		address4.address = tuple->dst.addr.ipv4;
		address4.l4_id = tuple->dst.l4_id;
		return bib_get_by_ipv4(&address4, tuple->l4_proto);
	}

	log_crit(ERR_L3PROTO, "Unsupported network protocol: %u.", tuple->l3_proto);
	return NULL;
}

bool bib_remove(struct bib_entry *entry, l4_protocol l4_proto)
{
	struct bib_table *table;
	bool removed_from_ipv4, removed_from_ipv6;

	if (!entry) {
		log_err(ERR_NULL, "The BIB tables do not contain NULL entries.");
		return false;
	}
	if (get_bib_table(l4_proto, &table) != 0)
		return false;

	/* Free the memory from both tables. */
	removed_from_ipv4 = ipv4_table_remove(&table->ipv4, &entry->ipv4, NULL);
	removed_from_ipv6 = ipv6_table_remove(&table->ipv6, &entry->ipv6, NULL);

	if (removed_from_ipv4 && removed_from_ipv6)
		return true;
	if (!removed_from_ipv4 && !removed_from_ipv6)
		return false;

	/* Why was it not indexed by both tables? Programming error. */
	log_crit(ERR_INCOMPLETE_INDEX_BIB, "Programming error: Weird BIB removal: ipv4:%d; ipv6:%d.",
			removed_from_ipv4, removed_from_ipv6);
	return false;
}

static void bib_dealloc(struct bib_entry *bib)
{
	kfree(bib);
}

void bib_destroy(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	log_debug("Emptying the BIB tables...");
	/*
	 * The values need to be released only in one of the tables because both tables point to the
	 * same values.
	 */
	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		ipv4_table_empty(&tables[i]->ipv4, NULL);
		ipv6_table_empty(&tables[i]->ipv6, bib_dealloc);
	}
}

struct bib_entry *bib_create(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6,
		bool is_static)
{
	struct bib_entry *result = kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	result->is_static = is_static;
	INIT_LIST_HEAD(&result->sessions);

	return result;
}

int bib_for_each(l4_protocol l4_proto, int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_table *table;
	int error;

	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	return ipv4_table_for_each(&table->ipv4, func, arg);
}

int bib_for_each_ipv6(l4_protocol l4_proto, struct in6_addr *addr,
		int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_table *table;
	unsigned int hash_code;
	struct hlist_node *current_node;
	struct ipv6_table_key_value *current_pair;
	struct ipv6_tuple_address tuple_addr;
	int error;

	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	tuple_addr.address = *addr;
	tuple_addr.l4_id = 0; /* Not important because of the way the hash function is designed. */

	/* TODO - that constant. */
	hash_code = ipv6_tuple_addr_hashcode(&tuple_addr) % (64 * 1024 - 1);
	hlist_for_each(current_node, &table->ipv6.table[hash_code]) {
		current_pair = hlist_entry(current_node, struct ipv6_table_key_value, hlist_hook);
		if (ipv6_addr_equals(addr, &current_pair->key.address)) {
			error = func(current_pair->value, arg);
			if (error)
				return error;
		}
	}

	return 0;
}

bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2)
{
	if (bib_1 == bib_2)
		return true;
	if (bib_1 == NULL || bib_2 == NULL)
		return false;

	if (!ipv4_tuple_addr_equals(&bib_1->ipv4, &bib_2->ipv4))
		return false;
	if (!ipv6_tuple_addr_equals(&bib_1->ipv6, &bib_2->ipv6))
		return false;

	return true;
}
