#include "nat64/bib.h"

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/in6.h>

#include "nat64/types.h"

/********************************************
 * Structures and private variables.
 ********************************************/

// Hash table; indexes BIB entries by IPv4 address.
// (this code generates the "ipv4_table" structure and related functions used below).
#define HTABLE_NAME ipv4_table
#define KEY_TYPE struct ipv4_tuple_address
#define VALUE_TYPE struct bib_entry
#define GENERATE_TO_ARRAY
#include "hash_table.c"

// Hash table; indexes BIB entries by IPv6 address.
// (this code generates the "ipv6_table" structure and related functions used below).
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

static struct bib_table *get_bib_table(u_int8_t l4protocol)
{
	switch (l4protocol) {
		case IPPROTO_UDP:
			return &bib_udp;
		case IPPROTO_TCP:
			return &bib_tcp;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			return &bib_icmp;
	}

	log_crit(ERR_L4PROTO, "Unknown l4 protocol (%d); no BIB mapped to it.", l4protocol);
	return NULL;
}

/*******************************
 * Public functions.
 *******************************/

bool bib_init(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		if (!ipv4_table_init(&tables[i]->ipv4, ipv4_tuple_addr_equals, ipv4_tuple_addr_hashcode))
			return false;
		if (!ipv6_table_init(&tables[i]->ipv6, ipv6_tuple_addr_equals, ipv6_tuple_addr_hashcode))
			return false;
	}

	return true;
}

bool bib_add(struct bib_entry *entry, u_int8_t l4protocol)
{
	bool indexed_by_ipv4, indexed_by_ipv6;
	struct bib_table *table;

	if (!entry) {
		log_err(ERR_NULL, "NULL is not a valid BIB entry.");
		return false;
	}
	table = get_bib_table(l4protocol);
	if (!table)
		return false;

	indexed_by_ipv4 = ipv4_table_put(&table->ipv4, &entry->ipv4, entry);
	indexed_by_ipv6 = ipv6_table_put(&table->ipv6, &entry->ipv6, entry);

	if (!indexed_by_ipv4 || !indexed_by_ipv6) {
		ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
		ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);
		return false;
	}

	return true;
}

struct bib_entry *bib_get_by_ipv4(struct ipv4_tuple_address *address, u_int8_t l4protocol)
{
	struct bib_table *table;

	if (!address)
		return NULL;
	table = get_bib_table(l4protocol);
	if (!table)
		return NULL;

	return ipv4_table_get(&table->ipv4, address);
}

struct bib_entry *bib_get_by_ipv6(struct ipv6_tuple_address *address, u_int8_t l4protocol)
{
	struct bib_table *table;

	if (!address)
		return NULL;
	table = get_bib_table(l4protocol);
	if (!table)
		return NULL;

	return ipv6_table_get(&table->ipv6, address);
}

struct bib_entry *bib_get_by_ipv6_only(struct in6_addr *address, u_int8_t l4protocol)
{
	struct bib_table *table;
	__u16 hash_code;
	struct hlist_node *current_node;
	struct ipv6_tuple_address address_full;
	struct ipv6_table_key_value *keyvalue;

	if (!address)
		return NULL;
	table = get_bib_table(l4protocol);
	if (!table)
		return NULL;

	address_full.address = *address; // Port doesn't matter; won't be used by the hash function.
	hash_code = table->ipv6.hash_function(&address_full) % ARRAY_SIZE(table->ipv6.table);

	hlist_for_each(current_node, &table->ipv6.table[hash_code]) {
		keyvalue = list_entry(current_node, struct ipv6_table_key_value, nodes);
		if (ipv6_addr_equals(address, &keyvalue->key->address))
			return keyvalue->value;
	}

	return NULL;
}

struct bib_entry *bib_get(struct nf_conntrack_tuple *tuple)
{
	struct ipv6_tuple_address address6;
	struct ipv4_tuple_address address4;

	if (!tuple)
		return NULL;

	switch (tuple->L3_PROTOCOL) {
	case NFPROTO_IPV6:
		address6.address = tuple->ipv6_src_addr;
		address6.l4_id = be16_to_cpu(tuple->src_port);
		return bib_get_by_ipv6(&address6, tuple->L4_PROTOCOL);
	case NFPROTO_IPV4:
		address4.address = tuple->ipv4_dst_addr;
		address4.l4_id = be16_to_cpu(tuple->dst_port);
		return bib_get_by_ipv4(&address4, tuple->L4_PROTOCOL);
	default:
		log_crit(ERR_L3PROTO, "Programming error; unknown l3 protocol: %d", tuple->L3_PROTOCOL);
		return NULL;
	}
}

bool bib_remove(struct bib_entry *entry, u_int8_t l4protocol)
{
	struct bib_table *table;
	bool removed_from_ipv4, removed_from_ipv6;

	if (!entry) {
		log_err(ERR_NULL, "The BIB tables do not contain NULL entries.");
		return false;
	}
	table = get_bib_table(l4protocol);
	if (!table)
		return false;

	// Don't erase the BIB if there are still session entries related to it.
	if (!list_empty(&entry->sessions))
		return false;

	// Free the memory from both tables.
	removed_from_ipv4 = ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
	removed_from_ipv6 = ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);

	if (removed_from_ipv4 && removed_from_ipv6)
		return true;
	if (!removed_from_ipv4 && !removed_from_ipv6)
		return false;

	// Why was it not indexed by both tables? Programming error.
	log_crit(ERR_INCOMPLETE_INDEX_BIB, "Programming error: Weird BIB removal: ipv4:%d; ipv6:%d.",
			removed_from_ipv4, removed_from_ipv6);
	return true;
}

void bib_destroy(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	log_debug("Emptying the BIB tables...");
	// The keys needn't be released because they're part of the values.
	// The values need to be released only in one of the tables because both tables point to the
	// same values.
	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		ipv4_table_empty(&tables[i]->ipv4, false, false);
		ipv6_table_empty(&tables[i]->ipv6, false, true);
	}
}

struct bib_entry *bib_create(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6)
{
	struct bib_entry *result = kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	INIT_LIST_HEAD(&result->sessions);

	return result;
}

int bib_to_array(__u8 l4protocol, struct bib_entry ***array)
{
	struct bib_table *table = get_bib_table(l4protocol);
	if (!table)
		return 0;

	return ipv4_table_to_array(&table->ipv4, array);
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
