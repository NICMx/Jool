#include "nat64/mod/session.h"

#include <net/ipv6.h>
#include "nat64/mod/rbtree.h"


/********************************************
 * Structures and private variables.
 ********************************************/

/**
 * Session table definition.
 * Holds two hash tables, one for each indexing need (IPv4 and IPv6).
 */
struct session_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;

	u64 count;
};

/** The session table for UDP connections. */
static struct session_table session_table_udp;
/** The session table for TCP connections. */
static struct session_table session_table_tcp;
/** The session table for ICMP connections. */
static struct session_table session_table_icmp;

/** Cache for struct bib_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;


/********************************************
 * Private (helper) functions.
 ********************************************/

static int get_session_table(l4_protocol l4_proto, struct session_table **result)
{
	switch (l4_proto) {
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
		WARN(true, "There is no session table for the 'NONE' protocol.");
		return -EINVAL;
	}

	WARN(true, "Unsupported transport protocol: %u.", l4_proto);
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

static int compare_full6(struct session_entry *session, struct ipv6_pair *pair)
{
	int gap;

	gap = ipv6_addr_cmp(&session->ipv6.local.address, &pair->local.address);
	if (gap != 0)
		return gap;

	gap = ipv6_addr_cmp(&session->ipv6.remote.address, &pair->remote.address);
	if (gap != 0)
		return gap;

	gap = session->ipv6.local.l4_id - pair->local.l4_id;
	if (gap != 0)
		return gap;

	gap = session->ipv6.remote.l4_id - pair->remote.l4_id;
	return gap;
}

static int compare_addrs4(struct session_entry *session, struct ipv4_pair *pair)
{
	int gap;

	gap = ipv4_addr_cmp(&session->ipv4.local.address, &pair->local.address);
	if (gap != 0)
		return gap;

	gap = session->ipv4.local.l4_id - pair->local.l4_id;
	if (gap != 0)
		return gap;

	gap = ipv4_addr_cmp(&session->ipv4.remote.address, &pair->remote.address);
	return gap;
}

static int compare_full4(struct session_entry *session, struct ipv4_pair *pair)
{
	int gap;

	gap = compare_addrs4(session, pair);
	if (gap != 0)
		return gap;

	gap = session->ipv4.remote.l4_id - pair->remote.l4_id;
	return gap;
}

/*******************************
 * Public functions.
 *******************************/

int session_init(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;

	entry_cache = kmem_cache_create("jool_session_entries", sizeof(struct session_entry),
			0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the Session entry cache.");
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		tables[i]->tree6 = RB_ROOT;
		tables[i]->tree4 = RB_ROOT;
		tables[i]->count = 0;
	}

	return 0;
}

static void session_destroy_aux(struct rb_node *node)
{
	session_kfree(rb_entry(node, struct session_entry, tree6_hook));
}

void session_destroy(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;

	log_debug("Emptying the session tables...");
	/*
	 * The values need to be released only in one of the trees
	 * because both trees point to the same values.
	 */
	for (i = 0; i < ARRAY_SIZE(tables); i++)
		rbtree_clear(&tables[i]->tree6, session_destroy_aux);

	kmem_cache_destroy(entry_cache);
}

int session_get_by_ipv4(struct ipv4_pair *pair, l4_protocol l4_proto,
		struct session_entry **result)
{
	struct session_table *table;
	int error;

	if (WARN(!pair, "The session tables cannot contain NULL."))
		return -EINVAL;
	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	*result = rbtree_find(pair, &table->tree4, compare_full4, struct session_entry, tree4_hook);
	return (*result) ? 0 : -ENOENT;
}

int session_get_by_ipv6(struct ipv6_pair *pair, l4_protocol l4_proto,
		struct session_entry **result)
{
	struct session_table *table;
	int error;

	if (WARN(!pair, "The session tables cannot contain NULL."))
		return -EINVAL;
	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	*result = rbtree_find(pair, &table->tree6, compare_full6, struct session_entry, tree6_hook);
	return (*result) ? 0 : -ENOENT;
}

int session_get(struct tuple *tuple, struct session_entry **result)
{
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;

	if (WARN(!tuple, "There's no session entry mapped to NULL."))
		return -EINVAL;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		tuple_to_ipv6_pair(tuple, &pair6);
		return session_get_by_ipv6(&pair6, tuple->l4_proto, result);
	case L3PROTO_IPV4:
		tuple_to_ipv4_pair(tuple, &pair4);
		return session_get_by_ipv4(&pair4, tuple->l4_proto, result);
	}

	WARN(true, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

bool session_allow(struct tuple *tuple)
{
	struct session_table *table;
	struct ipv4_pair tuple_pair;
	int error;

	/* Sanity */
	if (WARN(!tuple, "Cannot extract addresses from NULL."))
		return false;
	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	tuple_to_ipv4_pair(tuple, &tuple_pair);
	return rbtree_find(&tuple_pair, &table->tree4, compare_addrs4, struct session_entry,
			tree4_hook);
}

int session_add(struct session_entry *entry)
{
	struct session_table *table;
	int error;

	/* Sanity */
	if (WARN(!entry, "Cannot insert NULL as a session entry."))
		return -EINVAL;
	error = get_session_table(entry->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	error = rbtree_add(entry, ipv6, &table->tree6, compare_full6, struct session_entry, tree6_hook);
	if (error)
		return error;

	error = rbtree_add(entry, ipv4, &table->tree4, compare_full4, struct session_entry, tree4_hook);
	if (error) {
		rb_erase(&entry->tree6_hook, &table->tree6);
		return error;
	}

	table->count++;
	return 0;
}

int session_remove(struct session_entry *entry)
{
	struct session_table *table;
	int error;

	/* Sanity */
	if (WARN(!entry, "The Session tables do not contain NULL entries."))
		return -EINVAL;
	error = get_session_table(entry->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	rb_erase(&entry->tree6_hook, &table->tree6);
	rb_erase(&entry->tree4_hook, &table->tree4);

	table->count--;
	return 0;
}

struct session_entry *session_create(struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
		l4_protocol l4_proto)
{
	struct session_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	result->dying_time = 0;
	result->bib = NULL;
	INIT_LIST_HEAD(&result->bib_list_hook);
	INIT_LIST_HEAD(&result->expire_list_hook);
	result->l4_proto = l4_proto;
	result->state = 0;
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);

	return result;
}

void session_kfree(struct session_entry *session)
{
	kmem_cache_free(entry_cache, session);
}

int session_for_each(l4_protocol l4_proto, int (*func)(struct session_entry *, void *), void *arg)
{
	struct session_table *table;
	struct rb_node *node;
	int error;

	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	for (node = rb_first(&table->tree4); node; node = rb_next(node)) {
		error = func(rb_entry(node, struct session_entry, tree4_hook), arg);
		if (error)
			return error;
	}

	return 0;
}

int session_count(l4_protocol proto, __u64 *result)
{
	struct session_table *table;
	int error;

	error = get_session_table(proto, &table);
	if (error)
		return error;

	*result = table->count;
	return 0;
}
