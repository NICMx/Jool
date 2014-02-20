#include "nat64/mod/bib.h"

#include <net/ipv6.h>
#include "nat64/mod/rbtree.h"


/********************************************
 * Structures and private variables.
 ********************************************/

/**
 * BIB table definition.
 * Holds two hash tables, one for each indexing need (IPv4 and IPv6).
 */
struct bib_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;
	/* Number of BIB entries in this table. */
	u64 count;
};

/** The BIB table for UDP connections. */
static struct bib_table bib_udp;
/** The BIB table for TCP connections. */
static struct bib_table bib_tcp;
/** The BIB table for ICMP connections. */
static struct bib_table bib_icmp;

/** Cache for struct bib_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

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
		log_crit(ERR_ILLEGAL_NONE, "There's no BIB for the 'NONE' protocol.");
		return -EINVAL;
	}

	log_crit(ERR_L4PROTO, "Unsupported transport protocol: %u.", l4_proto);
	return -EINVAL;
}

static int compare_addr6(struct bib_entry *bib, struct in6_addr *addr)
{
	return ipv6_addr_cmp(&bib->ipv6.address, addr);
}

static int compare_full6(struct bib_entry *bib, struct ipv6_tuple_address *addr)
{
	int gap;

	gap = compare_addr6(bib, &addr->address);
	if (gap != 0)
		return gap;

	gap = bib->ipv6.l4_id - addr->l4_id;
	return gap;
}

static int compare_full4(struct bib_entry *bib, struct ipv4_tuple_address *addr)
{
	int gap;

	gap = ipv4_addr_cmp(&bib->ipv4.address, &addr->address);
	if (gap != 0)
		return gap;

	gap = bib->ipv4.l4_id - addr->l4_id;
	return gap;
}

/*******************************
 * Public functions.
 *******************************/

int bib_init(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	entry_cache = kmem_cache_create("jool_bib_entries", sizeof(struct bib_entry), 0, 0, NULL);
	if (!entry_cache) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate the BIB entry cache.");
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		tables[i]->tree6 = RB_ROOT;
		tables[i]->tree4 = RB_ROOT;
		tables[i]->count = 0;
	}

	return 0;
}

static void bib_destroy_aux(struct rb_node *node)
{
	bib_kfree(rb_entry(node, struct bib_entry, tree6_hook));
}

void bib_destroy(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	log_debug("Emptying the BIB tables...");
	/*
	 * The values need to be released only in one of the trees
	 * because both tables point to the same values.
	 */

	for (i = 0; i < ARRAY_SIZE(tables); i++)
		rbtree_clear(&tables[i]->tree6, bib_destroy_aux);

	kmem_cache_destroy(entry_cache);
}

int bib_get_by_ipv4(struct ipv4_tuple_address *addr, l4_protocol l4_proto,
		struct bib_entry **result)
{
	struct bib_table *table;
	int error;

	/* Sanitize */
	if (!addr) {
		log_warning("The BIBs cannot contain NULL.");
		return -EINVAL;
	}
	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	*result = rbtree_find(addr, &table->tree4, compare_full4, struct bib_entry, tree4_hook);
	return (*result) ? 0 : -ENOENT;
}

int bib_get_by_ipv6(struct ipv6_tuple_address *addr, l4_protocol l4_proto,
		struct bib_entry **result)
{
	struct bib_table *table;
	int error;

	/* Sanitize */
	if (!addr) {
		log_warning("The BIBs cannot contain NULL.");
		return -EINVAL;
	}
	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	*result = rbtree_find(addr, &table->tree6, compare_full6, struct bib_entry, tree6_hook);
	return (*result) ? 0 : -ENOENT;
}

int bib_get(struct tuple *tuple, struct bib_entry **result)
{
	struct ipv6_tuple_address addr6;
	struct ipv4_tuple_address addr4;

	if (!tuple) {
		log_err(ERR_NULL, "There's no BIB entry mapped to NULL.");
		return -EINVAL;
	}

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		addr6.address = tuple->src.addr.ipv6;
		addr6.l4_id = tuple->src.l4_id;
		return bib_get_by_ipv6(&addr6, tuple->l4_proto, result);
	case L3PROTO_IPV4:
		addr4.address = tuple->dst.addr.ipv4;
		addr4.l4_id = tuple->dst.l4_id;
		return bib_get_by_ipv4(&addr4, tuple->l4_proto, result);
	}

	log_crit(ERR_L3PROTO, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

int bib_add(struct bib_entry *entry, l4_protocol l4_proto)
{
	struct bib_table *table;
	int error;

	/* Sanity */
	if (!entry) {
		log_err(ERR_NULL, "NULL is not a valid BIB entry.");
		return -EINVAL;
	}
	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	/* Index */
	error = rbtree_add(entry, ipv6, &table->tree6, compare_full6, struct bib_entry, tree6_hook);
	if (error)
		return error;

	error = rbtree_add(entry, ipv4, &table->tree4, compare_full4, struct bib_entry, tree4_hook);
	if (error) {
		rb_erase(&entry->tree6_hook, &table->tree6);
		return error;
	}

	table->count++;
	return 0;
}

int bib_remove(struct bib_entry *entry, l4_protocol l4_proto)
{
	struct bib_table *table;
	int error;

	if (!entry) {
		log_err(ERR_NULL, "The BIB tables do not contain NULL entries.");
		return -EINVAL;
	}
	if (RB_EMPTY_NODE(&entry->tree6_hook) || RB_EMPTY_NODE(&entry->tree4_hook)) {
		log_err(ERR_BIB_NOT_FOUND, "BIB entry does not belong to any trees.");
		return -EINVAL;
	}
	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	rb_erase(&entry->tree6_hook, &table->tree6);
	rb_erase(&entry->tree4_hook, &table->tree4);

	table->count--;
	return 0;
}

struct bib_entry *bib_create(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6,
		bool is_static)
{
	struct bib_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	result->is_static = is_static;
	INIT_LIST_HEAD(&result->sessions);
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);

	return result;
}

void bib_kfree(struct bib_entry *bib)
{
	kmem_cache_free(entry_cache, bib);
}

int bib_for_each(l4_protocol l4_proto, int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_table *table;
	struct rb_node *node;
	int error;

	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	for (node = rb_first(&table->tree4); node; node = rb_next(node)) {
		error = func(rb_entry(node, struct bib_entry, tree4_hook), arg);
		if (error)
			return error;
	}

	return 0;
}

int bib_for_each_ipv6(l4_protocol l4_proto, struct in6_addr *addr,
		int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_table *table;
	struct bib_entry *bib;
	struct rb_node *node;
	int error;
	bool found;

	/* Sanitize */
	if (!addr)
		return -EINVAL;
	error = get_bib_table(l4_proto, &table);
	if (error)
		return error;

	/* Find the top-most node in the tree whose IPv6 address is addr. */
	bib = rbtree_find(addr, &table->tree6, compare_addr6, struct bib_entry, tree6_hook);
	if (!bib)
		return 0; /* _Successfully_ iterated through no entries. */

	/* Keep moving left until we find the first node whose IPv6 address is addr. */
	found = false;
	do {
		node = rb_prev(&bib->tree6_hook);

		if (node) {
			struct bib_entry *tmp = rb_entry(node, struct bib_entry, tree6_hook);
			if (compare_addr6(tmp, addr))
				found = true;
			else
				bib = tmp;
		} else {
			found = true;
		}
	} while (!found);

	/*
	 * Keep moving right until the address changes.
	 * (The nodes are sorted by address first.)
	 */
	do {
		error = func(bib, arg);
		if (error)
			return error;

		node = rb_next(&bib->tree6_hook);
		if (!node)
			break;

		bib = rb_entry(node, struct bib_entry, tree6_hook);
	} while (ipv6_addr_equals(addr, &bib->ipv6.address));

	return 0;
}

int bib_count(l4_protocol proto, u64 *result)
{
	struct bib_table *table;
	int error;

	error = get_bib_table(proto, &table);
	if (error)
		return error;

	*result = table->count;
	return 0;
}
