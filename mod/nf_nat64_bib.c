#include <linux/module.h>
#include <linux/printk.h>

#include "nf_nat64_bib.h"

/********************************************
 * Structures and private variables.
 ********************************************/

// Hash table; indexes BIB entries by IPv4 address.
// (this code generates the "ipv4_table" structure and related functions used below).
#define HTABLE_NAME ipv4_table
#define KEY_TYPE struct ipv4_tuple_address
#define VALUE_TYPE struct bib_entry
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
			return &bib_icmp;
	}

	printk(KERN_CRIT "Error: Unknown l4 protocol (%d); no BIB mapped to it.", l4protocol);
	return NULL;
}

/*******************************
 * Public functions.
 *******************************/

void nat64_bib_init(void)
{
	ipv4_table_init(&bib_udp.ipv4, ipv4_tuple_address_equals, ipv4_tuple_address_hash_code);
	ipv6_table_init(&bib_udp.ipv6, ipv6_tuple_address_equals, ipv6_tuple_address_hash_code);

	ipv4_table_init(&bib_tcp.ipv4, ipv4_tuple_address_equals, ipv4_tuple_address_hash_code);
	ipv6_table_init(&bib_tcp.ipv6, ipv6_tuple_address_equals, ipv6_tuple_address_hash_code);

	ipv4_table_init(&bib_icmp.ipv4, ipv4_tuple_address_equals, ipv4_tuple_address_hash_code);
	ipv6_table_init(&bib_icmp.ipv6, ipv6_tuple_address_equals, ipv6_tuple_address_hash_code);
}

bool nat64_add_bib_entry(struct bib_entry *entry, u_int8_t l4protocol)
{
	bool indexed_by_ipv4, indexed_by_ipv6;
	struct bib_table *bib = get_bib_table(l4protocol);

	indexed_by_ipv4 = ipv4_table_put(&bib->ipv4, &entry->ipv4, entry);
	indexed_by_ipv6 = ipv6_table_put(&bib->ipv6, &entry->ipv6, entry);

	if (!indexed_by_ipv4 || !indexed_by_ipv6) {
		ipv4_table_remove(&bib->ipv4, &entry->ipv4, false, false);
		ipv6_table_remove(&bib->ipv6, &entry->ipv6, false, false);
		return false;
	}

	return true;
}

struct bib_entry *nat64_get_bib_entry(struct nf_conntrack_tuple *tuple)
{
	struct bib_table *table = get_bib_table(tuple->l4_protocol);

	switch (tuple->l3_protocol) {
		case NFPROTO_IPV6: {
			struct ipv6_tuple_address address_6 = { tuple->ipv6_src_addr, { tuple->src_port } };
			printk(KERN_DEBUG "Searching BIB entry for address %pI4#%d...", &address_6.address, address_6.pi.port);
			return ipv6_table_get(&table->ipv6, &address_6);
		}
		case NFPROTO_IPV4: {
			struct ipv4_tuple_address address_4 = { tuple->ipv4_dst_addr, { tuple->dst_port } };
			printk(KERN_DEBUG "Searching BIB entry for address %pI6#%d...", &address_4.address, address_4.pi.port);
			return ipv4_table_get(&table->ipv4, &address_4);
		}
		default: {
			printk(KERN_CRIT "Programming error; unknown l3 protocol: %d", tuple->l3_protocol);
			return NULL;
		}
	}
}

bool nat64_remove_bib_entry(struct bib_entry *entry, u_int8_t l4protocol)
{
	bool removed_from_ipv4, removed_from_ipv6;
	struct bib_table *table = get_bib_table(l4protocol);

	// Don't erase the BIB if there are still session entries related to it.
	if (!list_empty(&entry->session_entries))
		return false;

	// Free the memory from both tables.
	removed_from_ipv4 = ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
	removed_from_ipv6 = ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);

	if (removed_from_ipv4 && removed_from_ipv6)
		return true;
	if (!removed_from_ipv4 && !removed_from_ipv6)
		return false;

	// Why was it not indexed by both tables? Programming error.
	printk(KERN_CRIT "Programming error: Weird BIB removal: ipv4:%d; ipv6:%d.", removed_from_ipv4, removed_from_ipv6);
	return true;
}

void nat64_bib_destroy(void)
{
	printk(KERN_DEBUG "Emptying the BIB tables...");

	// The keys needn't be released because they're part of the values.
	// The values need to be released only in one of the tables because both tables point to the same values.

	ipv4_table_empty(&bib_udp.ipv4, false, false);
	ipv6_table_empty(&bib_udp.ipv6, false, true);

	ipv4_table_empty(&bib_tcp.ipv4, false, false);
	ipv6_table_empty(&bib_tcp.ipv6, false, true);

	ipv4_table_empty(&bib_icmp.ipv4, false, false);
	ipv6_table_empty(&bib_icmp.ipv6, false, true);
}

struct bib_entry *nat64_create_bib_entry(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6)
{
	struct bib_entry *result = (struct bib_entry *) kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	return result;
}

bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2)
{
	if (bib_1 == bib_2)
		return true;
	if (bib_1 == NULL || bib_2 == NULL)
		return false;

	if (!ipv4_tuple_address_equals(&bib_1->ipv4, &bib_2->ipv4))
		return false;
	if (!ipv6_tuple_address_equals(&bib_1->ipv6, &bib_2->ipv6))
		return false;

	return true;
}
