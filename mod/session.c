#include "nat64/mod/session.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/pool4.h"

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/timer.h>


/********************************************
 * Structures and private variables.
 ********************************************/

/*
 * Hash table; indexes session entries by IPv4 address.
 * (this code generates the "ipv4_table" structure and related functions used below).
 */
#define HTABLE_NAME ipv4_table
#define KEY_TYPE struct ipv4_pair
#define VALUE_TYPE struct session_entry
#define GENERATE_FOR_EACH
#include "hash_table.c"

/*
 * Hash table; indexes BIB entries by IPv6 address.
 * (this code generates the "ipv6_table" structure and related functions used below).
 */
#define HTABLE_NAME ipv6_table
#define KEY_TYPE struct ipv6_pair
#define VALUE_TYPE struct session_entry
#include "hash_table.c"

/**
 * Session table definition.
 * Holds two hash tables, one for each indexing need (IPv4 and IPv6).
 */
struct session_table {
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

static struct timer_list expire_timer;
static bool expire_timer_active = false;
static DEFINE_SPINLOCK(expire_timer_lock);

/**
 * This callback will be called by the session-cleaning thread for every session whose lifetime
 * just expired. It's expected to either update the session (particularly its lifetime) or approve
 * its deletion.
 *
 * @param session the session whose lifetime just expired.
 * @return whether the session should survive (true) or not (false).
 */
static bool (*session_expired_cb)(struct session_entry *session);


/********************************************
 * Private (helper) functions.
 ********************************************/

static int get_session_table(enum l4_proto l4protocol, struct session_table **result)
{
	switch (l4protocol) {
	case L4PROTO_UDP:
		*result = &session_table_udp;
		return 0;
	case L4PROTO_TCP:
		*result = &session_table_tcp;
		return 0;
	case L4PROTO_ICMP:
		*result = &session_table_icmp;
		return 0;
	case L4PROTO_NONE:
		break;
	}

	log_crit(ERR_L4PROTO, "Unsupported transport protocol: %u.", l4protocol);
	return -EINVAL;
}

static void tuple_to_ipv6_pair(struct tuple *tuple, struct ipv6_pair *pair)
{
	pair->remote.address = tuple->src.addr.ipv6;
	pair->remote.l4_id = tuple->src.l4_id;
	pair->local.address = tuple->dst.addr.ipv6;
	pair->local.l4_id = tuple->dst.l4_id;
}

static void tuple_to_ipv4_pair(struct tuple *tuple, struct ipv4_pair *pair)
{
	pair->remote.address = tuple->src.addr.ipv4;
	pair->remote.l4_id = tuple->src.l4_id;
	pair->local.address = tuple->dst.addr.ipv4;
	pair->local.l4_id = tuple->dst.l4_id;
}

/**
 * Removes from the tables the entries whose lifetime has expired. The entries are also freed from
 * memory.
 * TODO (fine) this is too much business logic to belong to this module; move it to a model.
 */
static void clean_expired_sessions(void)
{
	struct list_head *current_node, *next_node;
	struct session_entry *session;
	unsigned int s = 0;
	struct bib_entry *bib;
	unsigned int b = 0;
	unsigned int current_time = jiffies_to_msecs(jiffies);
	u_int8_t l4_proto;

	log_debug("Deleting expired sessions...");
	spin_lock_bh(&bib_session_lock);

	list_for_each_safe(current_node, next_node, &all_sessions) {
		session = list_entry(current_node, struct session_entry, all_sessions);

		if (session->dying_time > current_time)
			continue;
		session_expired_cb(session);
		if (session->dying_time > current_time)
			continue;

		if (!session_remove(session))
			continue; /* Error msg already printed. */

		bib = session->bib;
		l4_proto = session->l4_proto;

		list_del(&session->entries_from_bib);
		kfree(session);
		s++;

		if (!bib) {
			log_crit(ERR_NULL, "The session entry I just removed had no BIB entry."); /* ?? */
			continue;
		}

		if (!list_empty(&bib->sessions) || bib->is_static)
			continue;
		if (!bib_remove(bib, l4_proto))
			continue; /* Error msg already printed. */

		pool4_return(l4_proto, &bib->ipv4);
		kfree(bib);
		b++;
	}

	spin_unlock_bh(&bib_session_lock);
	log_debug("Deleted %u session entries and %u BIB entries.", s, b);
}

static void cleaner_timer(unsigned long param)
{
	clean_expired_sessions();

	spin_lock_bh(&expire_timer_lock);
	if (expire_timer_active) {
		expire_timer.expires = jiffies + msecs_to_jiffies(SESSION_TIMER_INTERVAL);
		add_timer(&expire_timer);
	}
	spin_unlock_bh(&expire_timer_lock);
}

/*******************************
 * Public functions.
 *******************************/

int session_init(bool (*session_expired_callback)(struct session_entry *))
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i, error;

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		error = ipv4_table_init(&tables[i]->ipv4, ipv4_pair_equals, ipv4_pair_hashcode);
		if (error)
			return error;
		error = ipv6_table_init(&tables[i]->ipv6, ipv6_pair_equals, ipv6_pair_hashcode);
		if (error)
			return error;
	}

	INIT_LIST_HEAD(&all_sessions);

	init_timer(&expire_timer);
	expire_timer.function = cleaner_timer;
	expire_timer.expires = jiffies + msecs_to_jiffies(SESSION_TIMER_INTERVAL);
	expire_timer.data = 0;
	add_timer(&expire_timer);
	expire_timer_active = true;

	session_expired_cb = session_expired_callback;

	return 0;
}

int session_add(struct session_entry *entry)
{
	struct session_table *table;
	enum error_code error;

	if (!entry) {
		log_err(ERR_NULL, "Cannot insert NULL as a session entry.");
		return -EINVAL;
	}

	error = get_session_table(entry->l4_proto, &table);
	if (error)
		return error;

	/* Insert into the hash tables. */
	error = ipv4_table_put(&table->ipv4, &entry->ipv4, entry);
	if (error)
		return error;

	error = ipv6_table_put(&table->ipv6, &entry->ipv6, entry);
	if (error) {
		ipv4_table_remove(&table->ipv4, &entry->ipv4, false);
		return error;
	}

	/* Insert into the linked list. */
	list_add(&entry->all_sessions, &all_sessions);

	return 0;
}

struct session_entry *session_get_by_ipv4(struct ipv4_pair *pair, u_int8_t l4protocol)
{
	struct session_table *table;
	if (get_session_table(l4protocol, &table) != 0)
		return NULL;
	return ipv4_table_get(&table->ipv4, pair);
}

struct session_entry *session_get_by_ipv6(struct ipv6_pair *pair, u_int8_t l4protocol)
{
	struct session_table *table;
	if (get_session_table(l4protocol, &table) != 0)
		return NULL;
	return ipv6_table_get(&table->ipv6, pair);
}

struct session_entry *session_get(struct tuple *tuple)
{
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;

	if (!tuple) {
		log_err(ERR_NULL, "There's no session entry mapped to NULL.");
		return NULL;
	}

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		tuple_to_ipv6_pair(tuple, &pair6);
		return session_get_by_ipv6(&pair6, tuple->l4_proto);
	case L3PROTO_IPV4:
		tuple_to_ipv4_pair(tuple, &pair4);
		return session_get_by_ipv4(&pair4, tuple->l4_proto);
	default:
		log_crit(ERR_L3PROTO, "Unsupported network protocol: %u.", tuple->l3_proto);
		return NULL;
	}
}

bool session_allow(struct tuple *tuple)
{
	struct session_table *table;
	__u16 hash_code;
	struct hlist_node *current_node;
	struct ipv4_pair tuple_pair, *session_pair;

	if (!tuple) {
		log_err(ERR_NULL, "Cannot extract addresses from NULL.");
		return false;
	}

	if (get_session_table(tuple->l4_proto, &table) != 0)
		return false;

	tuple_to_ipv4_pair(tuple, &tuple_pair);
	hash_code = table->ipv4.hash_function(&tuple_pair) % ARRAY_SIZE(table->ipv4.table);
	hlist_for_each(current_node, &table->ipv4.table[hash_code]) {
		session_pair = &list_entry(current_node, struct ipv4_table_key_value, nodes)->key;
		if (ipv4_tuple_addr_equals(&session_pair->local, &tuple_pair.local)
				&& ipv4_addr_equals(&session_pair->remote.address, &tuple_pair.remote.address)) {
			return true;
		}
	}

	return false;
}

bool session_remove(struct session_entry *entry)
{
	struct session_table *table;
	bool removed_from_ipv4, removed_from_ipv6;

	if (!entry) {
		log_err(ERR_NULL, "The Session tables do not contain NULL entries.");
		return false;
	}

	if (get_session_table(entry->l4_proto, &table) != 0)
		return false;

	/* Free from both tables. */
	removed_from_ipv4 = ipv4_table_remove(&table->ipv4, &entry->ipv4, false);
	removed_from_ipv6 = ipv6_table_remove(&table->ipv6, &entry->ipv6, false);

	if (removed_from_ipv4 && removed_from_ipv6) {
		list_del(&entry->all_sessions);
		return true;
	}
	if (!removed_from_ipv4 && !removed_from_ipv6) {
		return false;
	}

	/* Why was it not indexed by both tables? Programming error. */
	log_crit(ERR_INCOMPLETE_REMOVE, "Inconsistent session removal: ipv4:%d; ipv6:%d.",
			removed_from_ipv4, removed_from_ipv6);
	return false;
}

void session_destroy(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;

	log_debug("Emptying the session tables...");
	/*
	 * The keys needn't be released because they're part of the values.
	 * The values need to be released only in one of the tables because both tables point to the
	 * same values.
	 */
	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		ipv4_table_empty(&session_table_udp.ipv4, false);
		ipv6_table_empty(&session_table_udp.ipv6, true);
	}

	spin_lock_bh(&expire_timer_lock);
	if (expire_timer_active) {
		expire_timer_active = false;
		spin_unlock_bh(&expire_timer_lock);
		del_timer_sync(&expire_timer);
	} else {
		spin_unlock_bh(&expire_timer_lock);
	}
}

struct session_entry *session_create(struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
		u_int8_t l4protocol)
{
	struct session_entry *result = kmalloc(sizeof(struct session_entry), GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	result->dying_time = 0;
	INIT_LIST_HEAD(&result->entries_from_bib);
	INIT_LIST_HEAD(&result->all_sessions);
	result->l4_proto = l4protocol;

	return result;
}

int session_for_each(__u8 l4protocol, int (*func)(struct session_entry *, void *), void *arg)
{
	struct session_table *table;
	int error;

	error = get_session_table(l4protocol, &table);
	if (error)
		return error;

	return ipv4_table_for_each(&table->ipv4, func, arg);
}

bool session_entry_equals(struct session_entry *session_1, struct session_entry *session_2)
{
	if (session_1 == session_2)
		return true;
	if (session_1 == NULL || session_2 == NULL)
		return false;

	if (session_1->l4_proto != session_2->l4_proto)
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

