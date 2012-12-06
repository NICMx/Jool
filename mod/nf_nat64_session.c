#include <linux/module.h>
#include <linux/printk.h>

#include "nf_nat64_session.h"

/********************************************
 * Structures and private variables.
 ********************************************/

// Hash table; indexes session entries by IPv4 address.
// (this code generates the "ipv4_table" structure and related functions used below).
#define HTABLE_NAME ipv4_table
#define KEY_TYPE struct ipv4_pair
#define VALUE_TYPE struct session_entry
#define GENERATE_TO_ARRAY
#include "nf_nat64_hash_table.c"

// Hash table; indexes BIB entries by IPv6 address.
// (this code generates the "ipv6_table" structure and related functions used below).
#define HTABLE_NAME ipv6_table
#define KEY_TYPE struct ipv6_pair
#define VALUE_TYPE struct session_entry
#include "nf_nat64_hash_table.c"

/**
 * Session table definition.
 * Holds two hash tables, one for each indexing need (IPv4 and IPv6).
 */
struct session_table
{
	/** Indexes entries by IPv4. */
	struct ipv4_table ipv4;
	/** Indexes entries by IPv6. */
	struct ipv6_table ipv6;
};

/** The session table for UDP connections. */
static struct session_table session_table_udp;
/** The session table for TCP connections. */
static struct session_table session_table_tcp;
/** The session table for ICMP connections. */
static struct session_table session_table_icmp;

/**
 * Chains all known session entries.
 * Currently only used while looking en deleting expired ones.
 */
static LIST_HEAD(all_sessions);

/********************************************
 * Private (helper) functions.
 ********************************************/

static struct session_table *get_session_table(u_int8_t l4protocol)
{
	switch (l4protocol) {
		case IPPROTO_UDP:
			return &session_table_udp;
		case IPPROTO_TCP:
			return &session_table_tcp;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			return &session_table_icmp;
	}

	pr_crit("get_session_table: Unknown l4 protocol (%d); no session table mapped to it.\n",
			l4protocol);
	return NULL;
}

static void tuple_to_ipv6_pair(struct nf_conntrack_tuple *tuple, struct ipv6_pair *pair)
{
	pair->remote.address = tuple->ipv6_src_addr;
	pair->remote.pi.port = tuple->src_port;
	pair->local.address = tuple->ipv6_dst_addr;
	pair->local.pi.port = tuple->dst_port;
}

static void tuple_to_ipv4_pair(struct nf_conntrack_tuple *tuple, struct ipv4_pair *pair)
{
	pair->remote.address = tuple->ipv4_src_addr;
	pair->remote.pi.port = tuple->src_port;
	pair->local.address = tuple->ipv4_dst_addr;
	pair->local.pi.port = tuple->dst_port;
}

/*******************************
 * Public functions.
 *******************************/

void nat64_session_init(void)
{
	ipv4_table_init(&session_table_udp.ipv4, ipv4_pair_equals, ipv4_pair_hash_code);
	ipv6_table_init(&session_table_udp.ipv6, ipv6_pair_equals, ipv6_pair_hash_code);

	ipv4_table_init(&session_table_tcp.ipv4, ipv4_pair_equals, ipv4_pair_hash_code);
	ipv6_table_init(&session_table_tcp.ipv6, ipv6_pair_equals, ipv6_pair_hash_code);

	ipv4_table_init(&session_table_icmp.ipv4, ipv4_pair_equals, ipv4_pair_hash_code);
	ipv6_table_init(&session_table_icmp.ipv6, ipv6_pair_equals, ipv6_pair_hash_code);
}

bool nat64_add_session_entry(struct session_entry *entry)
{
	bool inserted_to_ipv4, inserted_to_ipv6;
	struct session_table *table = get_session_table(entry->l4protocol);

	if (entry->bib == NULL)
		return false; // Because it's invalid.

	// Insert into the hash tables.
	inserted_to_ipv4 = ipv4_table_put(&table->ipv4, &entry->ipv4, entry);
	inserted_to_ipv6 = ipv6_table_put(&table->ipv6, &entry->ipv6, entry);

	if (!inserted_to_ipv4 || !inserted_to_ipv6) {
		ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
		ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);
		return false;
	}

	// Insert into the linked lists.
	list_add(&entry->entries_from_bib, &entry->bib->session_entries);
	list_add(&entry->all_sessions, &all_sessions);

	return true;
}

struct session_entry *nat64_get_session_entry_by_ipv4(struct ipv4_pair *pair, u_int8_t l4protocol)
{
	struct session_table *table = get_session_table(l4protocol);

	pr_debug("Searching session entry: [%pI4#%d, %pI4#%d]...\n",
			&pair->local.address, be16_to_cpu(pair->local.pi.port),
			&pair->remote.address, be16_to_cpu(pair->remote.pi.port));

	return ipv4_table_get(&table->ipv4, pair);
}

struct session_entry *nat64_get_session_entry_by_ipv6(struct ipv6_pair *pair, u_int8_t l4protocol)
{
	struct session_table *table = get_session_table(l4protocol);

	pr_debug("Searching session entry: [%pI6c#%d, %pI6c#%d]...\n",
			&pair->remote.address, be16_to_cpu(pair->remote.pi.port),
			&pair->local.address, be16_to_cpu(pair->local.pi.port));

	return ipv6_table_get(&table->ipv6, pair);
}

struct session_entry *nat64_get_session_entry(struct nf_conntrack_tuple *tuple)
{
	switch (tuple->l3_protocol) {
		case NFPROTO_IPV6: {
			struct ipv6_pair pair;
			tuple_to_ipv6_pair(tuple, &pair);
			return nat64_get_session_entry_by_ipv6(&pair, tuple->l4_protocol);
		}
		case NFPROTO_IPV4: {
			struct ipv4_pair pair;
			tuple_to_ipv4_pair(tuple, &pair);
			return nat64_get_session_entry_by_ipv4(&pair, tuple->l4_protocol);
		}
		default: {
			pr_crit("Programming error; unknown l3 protocol: %d\n", tuple->l3_protocol);
			return NULL;
		}
	}
}

// TODO Nadie está usando esta función.
bool nat64_is_allowed_by_address_filtering(struct nf_conntrack_tuple *tuple)
{
	struct ipv4_table *table;
	__u16 hash_code;
	struct hlist_node *current_node;
	struct ipv4_pair tuple_pair, *session_pair;

	tuple_to_ipv4_pair(tuple, &tuple_pair);
	table = &get_session_table(tuple->l4_protocol)->ipv4;
	hash_code = table->hash_function(&tuple_pair) % (64 * 1024);

	hlist_for_each(current_node, &table->table[hash_code]) {
		session_pair = list_entry(current_node, struct ipv4_table_key_value, nodes)->key;
		if (ipv4_tuple_address_equals(&session_pair->local, &tuple_pair.local)
				&& ipv4_addr_equals(&session_pair->remote.address, &tuple_pair.remote.address)) {
			return true;
		}
	}

	return false;
}

void nat64_update_session_lifetime(struct session_entry *entry, unsigned int ttl)
{
	entry->dying_time = jiffies_to_msecs(jiffies) + ttl;
}

bool nat64_remove_session_entry(struct session_entry *entry)
{
	struct session_table *table;
	bool removed_from_ipv4, removed_from_ipv6;

	table = get_session_table(entry->l4protocol);

	// Free from both tables.
	removed_from_ipv4 = ipv4_table_remove(&table->ipv4, &entry->ipv4, false, false);
	removed_from_ipv6 = ipv6_table_remove(&table->ipv6, &entry->ipv6, false, false);

	if (removed_from_ipv4 && removed_from_ipv6) {
		// Remove the entry from the linked lists.
		list_del(&entry->entries_from_bib);
		list_del(&entry->all_sessions);

		// Erase the BIB. Might not happen if it has more sessions.
		if (nat64_remove_bib_entry(entry->bib, entry->l4protocol)) {
			kfree(entry->bib);
			entry->bib = NULL;
		}

		return true;
	}
	if (!removed_from_ipv4 && !removed_from_ipv6) {
		return false;
	}

	// Why was it not indexed by both tables? Programming error.
	pr_crit("Programming error: Inconsistent session removal: ipv4:%d; ipv6:%d.\n",
			removed_from_ipv4, removed_from_ipv6);
	return true;
}

void nat64_clean_old_sessions(void)
{
	struct list_head *current_node, *next_node;
	struct session_entry *current_entry;
	unsigned int current_time = jiffies_to_msecs(jiffies);

	list_for_each_safe(current_node, next_node, &all_sessions) {
		current_entry = list_entry(current_node, struct session_entry, all_sessions);
		if (!current_entry->is_static && current_entry->dying_time <= current_time) {
			nat64_remove_session_entry(current_entry);
			kfree(current_entry);
		}
	}
}

void nat64_session_destroy(void)
{
	pr_debug("Emptying the session tables...\n");

	// The keys needn't be released because they're part of the values.
	// The values need to be released only in one of the tables because both tables point to the same values.

	ipv4_table_empty(&session_table_udp.ipv4, false, false);
	ipv6_table_empty(&session_table_udp.ipv6, false, true);

	ipv4_table_empty(&session_table_tcp.ipv4, false, false);
	ipv6_table_empty(&session_table_tcp.ipv6, false, true);

	ipv4_table_empty(&session_table_icmp.ipv4, false, false);
	ipv6_table_empty(&session_table_icmp.ipv6, false, true);

	INIT_LIST_HEAD(&all_sessions);
}

struct session_entry *nat64_create_static_session_entry(
		struct ipv4_pair *ipv4,struct ipv6_pair *ipv6,
		struct bib_entry *bib, u_int8_t l4protocol)
{
	struct session_entry *result = kmalloc(sizeof(struct session_entry), GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	result->is_static = true;
	result->dying_time = 0;
	result->bib = bib;
	INIT_LIST_HEAD(&result->entries_from_bib);
	INIT_LIST_HEAD(&result->all_sessions);
	result->l4protocol = l4protocol;

	return result;
}

int nat64_session_table_to_array(__u8 l4protocol, struct session_entry ***array)
{
	return ipv4_table_to_array(&get_session_table(l4protocol)->ipv4, array);
}

bool session_entry_equals(struct session_entry *session_1, struct session_entry *session_2)
{
	if (session_1 == session_2)
		return true;
	if (session_1 == NULL || session_2 == NULL)
		return false;

	if (session_1->l4protocol != session_2->l4protocol)
		return false;
	if (!ipv6_tuple_address_equals(&session_1->ipv6.remote, &session_2->ipv6.remote))
		return false;
	if (!ipv6_tuple_address_equals(&session_1->ipv6.local, &session_2->ipv6.local))
		return false;
	if (!ipv4_tuple_address_equals(&session_1->ipv4.local, &session_2->ipv4.local))
		return false;
	if (!ipv4_tuple_address_equals(&session_1->ipv4.remote, &session_2->ipv4.remote))
		return false;

	return true;
}
