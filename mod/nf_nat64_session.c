#include "nf_nat64_session.h"

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/timer.h>

#include "nf_nat64_filtering_and_updating.h"


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

struct timer_list expire_timer;
static bool expire_timer_active = true;
static DEFINE_SPINLOCK(expire_timer_lock);


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

	log_crit("get_session_table: Unknown l4 protocol (%d); no session table mapped to it.",
			l4protocol);
	return NULL;
}

static void tuple_to_ipv6_pair(struct nf_conntrack_tuple *tuple, struct ipv6_pair *pair)
{
	pair->remote.address = tuple->ipv6_src_addr;
	pair->remote.l4_id = be16_to_cpu(tuple->src_port);
	pair->local.address = tuple->ipv6_dst_addr;
	pair->local.l4_id = be16_to_cpu(tuple->dst_port);
}

static void tuple_to_ipv4_pair(struct nf_conntrack_tuple *tuple, struct ipv4_pair *pair)
{
	pair->remote.address = tuple->ipv4_src_addr;
	pair->remote.l4_id = be16_to_cpu(tuple->src_port);
	pair->local.address = tuple->ipv4_dst_addr;
	pair->local.l4_id = be16_to_cpu(tuple->dst_port);
}

/**
 * Removes from the tables the entries whose lifetime has expired. The entries are also freed from
 * memory.
 */
static void clean_expired_sessions(unsigned long param)
{
	struct list_head *current_node, *next_node;
	struct session_entry *current_entry;
	unsigned int current_time = jiffies_to_msecs(jiffies);
	unsigned int removed = 0;

	log_debug("Deleting expired sessions...");

	spin_lock_bh(&bib_session_lock);
	list_for_each_safe(current_node, next_node, &all_sessions) {
		current_entry = list_entry(current_node, struct session_entry, all_sessions);
		if (!current_entry->is_static && current_entry->dying_time <= current_time) {
			if (!session_expired(current_entry) && nat64_remove_session_entry(current_entry)) {
				removed++;
				kfree(current_entry);
			}
		}
	}
	spin_unlock_bh(&bib_session_lock);

	spin_lock_bh(&expire_timer_lock);
	if (expire_timer_active) {
		expire_timer.expires = jiffies + msecs_to_jiffies(SESSION_TIMER_INTERVAL);
		add_timer(&expire_timer);
	}
	spin_unlock_bh(&expire_timer_lock);

	log_debug("Done deleting expired sessions.");
}

/*******************************
 * Public functions.
 *******************************/

bool nat64_session_init(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		if (!ipv4_table_init(&tables[i]->ipv4, ipv4_pair_equals, ipv4_pair_hashcode))
			return false;
		if (!ipv6_table_init(&tables[i]->ipv6, ipv6_pair_equals, ipv6_pair_hashcode))
			return false;
	}

	INIT_LIST_HEAD(&all_sessions);

	init_timer(&expire_timer);
	expire_timer.function = clean_expired_sessions;
	expire_timer.expires = jiffies + msecs_to_jiffies(SESSION_TIMER_INTERVAL);
	expire_timer.data = 0;
	add_timer(&expire_timer);

	return true;
}

bool nat64_add_session_entry(struct session_entry *entry)
{
	bool inserted_to_ipv4, inserted_to_ipv6;
	struct session_table *table;

	if (!entry)
		return false;
	if (!entry->bib)
		return false;
	table = get_session_table(entry->l4protocol);
	if (!table)
		return false;

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
	if (!table)
		return NULL;
	return ipv4_table_get(&table->ipv4, pair);
}

struct session_entry *nat64_get_session_entry_by_ipv6(struct ipv6_pair *pair, u_int8_t l4protocol)
{
	struct session_table *table = get_session_table(l4protocol);
	if (!table)
		return NULL;
	return ipv6_table_get(&table->ipv6, pair);
}

struct session_entry *nat64_get_session_entry(struct nf_conntrack_tuple *tuple)
{
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;

	if (!tuple)
		return NULL;

	switch (tuple->L3_PROTOCOL) {
	case NFPROTO_IPV6:
		tuple_to_ipv6_pair(tuple, &pair6);
		return nat64_get_session_entry_by_ipv6(&pair6, tuple->L4_PROTOCOL);
	case NFPROTO_IPV4:
		tuple_to_ipv4_pair(tuple, &pair4);
		return nat64_get_session_entry_by_ipv4(&pair4, tuple->L4_PROTOCOL);
	default:
		log_crit("Programming error; unknown l3 protocol: %d", tuple->L3_PROTOCOL);
		return NULL;
	}
}

bool nat64_is_allowed_by_address_filtering(struct nf_conntrack_tuple *tuple)
{
	struct session_table *table;
	__u16 hash_code;
	struct hlist_node *current_node;
	struct ipv4_pair tuple_pair, *session_pair;

	if (!tuple)
		return false;
	table = get_session_table(tuple->L4_PROTOCOL);
	if (!table)
		return false;

	tuple_to_ipv4_pair(tuple, &tuple_pair);
	hash_code = table->ipv4.hash_function(&tuple_pair) % ARRAY_SIZE(table->ipv4.table);
	hlist_for_each(current_node, &table->ipv4.table[hash_code]) {
		session_pair = list_entry(current_node, struct ipv4_table_key_value, nodes)->key;
		if (ipv4_tuple_addr_equals(&session_pair->local, &tuple_pair.local)
				&& ipv4_addr_equals(&session_pair->remote.address, &tuple_pair.remote.address)) {
			return true;
		}
	}

	return false;
}

inline void nat64_update_session_lifetime(struct session_entry *entry, unsigned int ttl)
{
	entry->dying_time = jiffies_to_msecs(jiffies) + ttl;
}

inline void nat64_update_session_state(struct session_entry *entry, u_int8_t state)
{
	entry->current_state = state;
}

bool nat64_remove_session_entry(struct session_entry *entry)
{
	struct session_table *table;
	bool removed_from_ipv4, removed_from_ipv6;

	if (!entry)
		return false;
	table = get_session_table(entry->l4protocol);
	if (!table)
		return false;

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
	log_crit("Programming error: Inconsistent session removal: ipv4:%d; ipv6:%d.",
			removed_from_ipv4, removed_from_ipv6);
	return true;
}

void nat64_session_destroy(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;

	log_debug("Emptying the session tables...");
	// The keys needn't be released because they're part of the values.
	// The values need to be released only in one of the tables because both tables point to the
	// same values.
	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		ipv4_table_empty(&session_table_udp.ipv4, false, false);
		ipv6_table_empty(&session_table_udp.ipv6, false, true);
	}

	spin_lock_bh(&expire_timer_lock);
	expire_timer_active = false;
	spin_unlock_bh(&expire_timer_lock);
	del_timer_sync(&expire_timer);
}

struct session_entry *nat64_create_static_session_entry(
		struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
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

struct session_entry *nat64_create_session_entry(
		struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
		struct bib_entry *bib, u_int8_t l4protocol)
{
	struct session_entry *result = nat64_create_static_session_entry(ipv4, ipv6, bib, l4protocol);
	if (!result)
		return NULL;

	result->is_static = false;
	return result;
}

int nat64_session_table_to_array(__u8 l4protocol, struct session_entry ***array)
{
	struct session_table *table = get_session_table(l4protocol);
	if (!table)
		return 0;

	return ipv4_table_to_array(&table->ipv4, array);
}

bool session_entry_equals(struct session_entry *session_1, struct session_entry *session_2)
{
	if (session_1 == session_2)
		return true;
	if (session_1 == NULL || session_2 == NULL)
		return false;

	if (session_1->l4protocol != session_2->l4protocol)
		return false;
	if (!ipv6_tuple_addr_equals(&session_1->ipv6.remote, &session_2->ipv6.remote))
		return false;
	if (!ipv6_tuple_addr_equals(&session_1->ipv6.local, &session_2->ipv6.local))
		return false;
	if (!ipv4_tuple_addr_equals(&session_1->ipv4.local, &session_2->ipv4.local))
		return false;
	if (!ipv4_tuple_addr_equals(&session_1->ipv4.remote, &session_2->ipv4.remote))
		return false;

	return true;
}
