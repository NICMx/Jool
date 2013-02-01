#include "nf_nat64_bib.h"

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/in6.h>

#include "nf_nat64_types.h"

/********************************************
 * Structures and private variables.
 ********************************************/

// Hash table; indexes BIB entries by IPv4 address.
// (this code generates the "ipv4_table" structure and related functions used below).
#define HTABLE_NAME ipv4_table
#define KEY_TYPE struct ipv4_tuple_address
#define VALUE_TYPE struct bib_entry
#define GENERATE_TO_ARRAY
#include "nf_nat64_hash_table.c"

// Hash table; indexes BIB entries by IPv6 address.
// (this code generates the "ipv6_table" structure and related functions used below).
#define HTABLE_NAME ipv6_table
#define KEY_TYPE struct ipv6_tuple_address
#define VALUE_TYPE struct bib_entry
#include "nf_nat64_hash_table.c"

/**
 * BIB table definition.
 * Holds two hash tables, one for each indexing need (IPv4 and IPv6).
 */
struct bib_table
{
	/** Indexes entries by IPv4. */
	struct ipv4_table ipv4;
	/** Indexes entries by IPv6. */
	struct ipv6_table ipv6;

	spinlock_t lock;
};

/** The BIB table for UDP connections. */
static struct bib_table bib_udp;
/** The BIB table for TCP connections. */
static struct bib_table bib_tcp;
/** The BIB table for ICMP connections. */
static struct bib_table bib_icmp;

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

	log_crit("Error: Unknown l4 protocol (%d); no BIB mapped to it.", l4protocol);
	return NULL;
}

/*******************************
 * Public functions.
 *******************************/

void nat64_bib_init(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		ipv4_table_init(&tables[i]->ipv4, ipv4_tuple_addr_equals, ipv4_tuple_addr_hashcode);
		ipv6_table_init(&tables[i]->ipv6, ipv6_tuple_addr_equals, ipv6_tuple_addr_hashcode);
		spin_lock_init(tables[i]->lock);
	}
}

bool nat64_add_bib_entry(struct bib_entry *entry, u_int8_t l4protocol)
{
	bool indexed_by_ipv4, indexed_by_ipv6;
	struct bib_table *table;

	table = get_bib_table(l4protocol);
	if (!table)
		return false;
	spin_lock_bh(&table->lock);

	indexed_by_ipv4 = ipv4_table_put(&table->ipv4, &entry->ipv4, entry);
	indexed_by_ipv6 = ipv6_table_put(&table->ipv6, &entry->ipv6, entry);

	if (!indexed_by_ipv4 || !indexed_by_ipv6) {
		ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
		ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);

		spin_unlock_bh(&table->lock);
		return false;
	}

	spin_unlock_bh(&table->lock);
	return true;
}

bool nat64_get_bib_entry_by_ipv4(struct ipv4_tuple_address *address, u_int8_t l4protocol,
		struct bib_entry *result)
{
	struct bib_table *table;
	struct bib_entry *entry;

	table = get_bib_table(l4protocol);
	if (!table)
		return false;
	spin_lock_bh(&table->lock);

	entry = ipv4_table_get(&table->ipv4, address);
	if (!entry) {
		spin_unlock_bh(&table->lock);
		return false;
	}

	*result = *entry;
	spin_unlock_bh(&table->lock);
	return true;
}

bool nat64_get_bib_entry_by_ipv6(struct ipv6_tuple_address *address, u_int8_t l4protocol,
		struct bib_entry *result)
{
	struct bib_table *table;
	struct bib_entry *entry;

	table = get_bib_table(l4protocol);
	if (!table)
		return false;
	spin_lock_bh(&table->lock);

	entry = ipv6_table_get(&table->ipv6, address);
	if (!entry) {
		spin_unlock_bh(&table->lock);
		return false;
	}

	*result = *entry;
	spin_unlock_bh(&table->lock);
	return true;
}

bool nat64_get_bib_entry_by_ipv6_only(struct in6_addr *address, u_int8_t l4protocol,
		struct bib_entry *result)
{
	struct bib_table *table;
	__u16 hash_code;
	struct hlist_node *current_node;
	struct ipv6_tuple_address address_full;
	struct ipv6_table_key_value *keyvalue;

	table = get_bib_table(l4protocol);
	if (!table)
		return false;

	address_full.address = *address; // Port doesn't matter; won't be used by the hash function.
	hash_code = table->ipv6.hash_function(&address_full) % (64 * 1024);

	spin_lock_bh(&table->lock);

	hlist_for_each(current_node, &table->ipv6.table[hash_code]) {
		keyvalue = list_entry(current_node, struct ipv6_table_key_value, nodes);
		if (ipv6_addr_equals(address, &keyvalue->key->address)) {
			*result = *keyvalue->value;
			spin_unlock_bh(&table->lock);
			return true;
		}
	}

	spin_unlock_bh(&table->lock);
	return false;
}

bool nat64_get_bib_entry(struct nf_conntrack_tuple *tuple, struct bib_entry *result)
{
	struct ipv6_tuple_address address6;
	struct ipv4_tuple_address address4;

	switch (tuple->L3_PROTOCOL) {
	case NFPROTO_IPV6:
		address6.address = tuple->ipv6_src_addr;
		address6.l4_id = be16_to_cpu(tuple->src_port);
		return nat64_get_bib_entry_by_ipv6(&address6, tuple->L4_PROTOCOL, result);
	case NFPROTO_IPV4:
		address4.address = tuple->ipv4_dst_addr;
		address4.l4_id = be16_to_cpu(tuple->dst_port);
		return nat64_get_bib_entry_by_ipv4(&address4, tuple->L4_PROTOCOL, result);
	default:
		log_crit("Programming error; unknown l3 protocol: %d", tuple->L3_PROTOCOL);
		return false;
	}
}

bool nat64_remove_bib_entry(struct bib_entry *entry, u_int8_t l4protocol)
{
	bool removed_from_ipv4, removed_from_ipv6;
	struct bib_table *table;

	table = get_bib_table(l4protocol);
	if (!table)
		return false;
	spin_lock_bh(&table->lock);

	// Don't erase the BIB if there are still session entries related to it.
	if (!list_empty(&entry->session_entries)) {
		spin_unlock_bh(&table->lock);
		return false;
	}

	// Free the memory from both tables.
	removed_from_ipv4 = ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
	removed_from_ipv6 = ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);
	spin_unlock_bh(&table->lock);

	if (removed_from_ipv4 && removed_from_ipv6)
		return true;
	if (!removed_from_ipv4 && !removed_from_ipv6)
		return false;

	// Why was it not indexed by both tables?
	log_crit("Programming error: Weird BIB removal: ipv4:%d; ipv6:%d.", removed_from_ipv4,
			removed_from_ipv6);
	return true;
}

void nat64_bib_destroy(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	// The keys needn't be released because they're part of the values.
	// The values need to be released only in one of the tables because both tables point to the
	// same values.
	log_debug("Emptying the BIB tables...");
	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		spin_lock_bh(&tables[i]->lock);
		ipv4_table_empty(&tables[i]->ipv4, false, false);
		ipv6_table_empty(&tables[i]->ipv6, false, true);
		spin_unlock_bh(&tables[i]->lock);
	}
}

int nat64_bib_to_array(__u8 l4protocol, struct bib_entry ***array)
{
	struct bib_table *table;
	int result;

	table = get_bib_table(l4protocol);
	if (!table)
		return 0;

	spin_lock_bh(&table->lock);
	result = ipv4_table_to_array(&table->ipv4, array);
	spin_unlock_bh(&table->lock);

	return result;
}

struct bib_entry *nat64_create_bib_entry(struct ipv4_tuple_address *ipv4,
		struct ipv6_tuple_address *ipv6)
{
	struct bib_entry *result = kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	INIT_LIST_HEAD(&result->session_entries);

	return result;
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
