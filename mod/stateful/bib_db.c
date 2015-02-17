#include "nat64/mod/stateful/bib_db.h"

#include <net/ipv6.h>
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/host6_node.h"

/**
 * BIB table definition.
 * Holds two red-black trees, one for each indexing need (IPv4 and IPv6).
 */
struct bib_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;
	/* Number of entries in this table. */
	u64 count;
	/**
	 * Lock to sync access.
	 * Note, this protects the structure of the trees, not the entries.
	 * The entries are immutable, and when they're part of the database, they can only be killed by
	 * bib_release(), which spinlockly deletes them from the trees first.
	 */
	spinlock_t lock;
};

/** The BIB table for UDP connections. */
static struct bib_table bib_udp;
/** The BIB table for TCP connections. */
static struct bib_table bib_tcp;
/** The BIB table for ICMP connections. */
static struct bib_table bib_icmp;

/** Cache for struct bib_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

/**
 * Removes the BIB entry from the database and kfrees it.
 *
 * @param ref kref field of the entry you want to remove.
 */
static void bib_release(struct kref *ref, bool lock)
{
	struct bib_entry *bib;
	int error;

	bib = container_of(ref, struct bib_entry, refcounter);

	error = bibdb_remove(bib, lock);
	WARN(error, "Error code %d when trying to remove a dying BIB entry from the DB. "
			"Maybe it should have been kfreed directly instead?", error);
	if (!bib->host4_addr) {
		WARN(true, "bib->host4_addr shouldn't be NULL");
		bib_kfree(bib);
		return;
	}

	host_addr4_return(bib->host4_addr);
	bib_kfree(bib);
}

static void bib_release_lock(struct kref *ref)
{
	bib_release(ref, true);
}

static void bib_release_lockless(struct kref *ref)
{
	bib_release(ref, false);
}

struct bib_entry *bib_create(struct ipv4_transport_addr *addr4, struct ipv6_transport_addr *addr6,
		bool is_static, l4_protocol l4_proto)
{
	struct bib_entry tmp = {
			.ipv4 = *addr4,
			.ipv6 = *addr6,
			.l4_proto = l4_proto,
			.is_static = is_static,
	};

	struct bib_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	memcpy(result, &tmp, sizeof(tmp));
	kref_init(&result->refcounter);
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);
	result->host4_addr = NULL;

	return result;
}

void bib_kfree(struct bib_entry *bib)
{
	/*
	 * We ignore the error of pool4_return(),
	 * because the user might have removed the address from the pool with --quick.
	 */
	pool4_return(bib->l4_proto, &bib->ipv4);
	kmem_cache_free(entry_cache, bib);
}

void bib_get(struct bib_entry *bib)
{
	kref_get(&bib->refcounter);
}

int bib_return(struct bib_entry *bib)
{
	return kref_put(&bib->refcounter, bib_release_lock);
}

int bib_return_lockless(struct bib_entry *bib)
{
	return kref_put(&bib->refcounter, bib_release_lockless);
}

/**
 * One-liner to get the BIB table corresponding to the "l4_proto" protocol.
 */
static int get_bibdb_table(l4_protocol l4_proto, struct bib_table **result)
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
	case L4PROTO_OTHER:
		break;
	}

	WARN(true, "Unsupported transport protocol: %u.", l4_proto);
	return -EINVAL;
}

/**
 * Returns > 0 if bib->ipv6.l3 > addr.
 * Returns < 0 if bib->ipv6.l3 < addr.
 * Returns 0 if bib->ipv6.l3 == addr.
 */
static int compare_addr6(const struct bib_entry *bib, const struct in6_addr *addr)
{
	return ipv6_addr_cmp(&bib->ipv6.l3, addr);
}

/**
 * Returns > 0 if bib->ipv6 > addr.
 * Returns < 0 if bib->ipv6 < addr.
 * Returns 0 if bib->ipv6 == addr.
 */
static int compare_full6(const struct bib_entry *bib, const struct ipv6_transport_addr *addr)
{
	int gap;

	gap = compare_addr6(bib, &addr->l3);
	if (gap)
		return gap;

	gap = bib->ipv6.l4 - addr->l4;
	return gap;
}

/**
 * Returns > 0 if bib->ipv4.l3 > addr.
 * Returns < 0 if bib->ipv4.l3 < addr.
 * Returns zero if bib->ipv4.l3 == addr.
 */
static int compare_addr4(const struct bib_entry *bib, const struct in_addr *addr)
{
	return ipv4_addr_cmp(&bib->ipv4.l3, addr);
}

/**
 * Returns > 0 if bib->ipv4 > addr.
 * Returns < 0 if bib->ipv4 < addr.
 * Returns 0 if bib->ipv4 == addr.
 */
static int compare_full4(const struct bib_entry *bib, const struct ipv4_transport_addr *addr)
{
	int gap;

	gap = compare_addr4(bib, &addr->l3);
	if (gap)
		return gap;

	gap = bib->ipv4.l4 - addr->l4;
	return gap;
}

struct iteration_args {
	struct tuple *tuple6;
	struct ipv4_transport_addr *result;
};

/**
 * Evaluates "bib", and returns whether it is a perfect match to "void_args"'s tuple.
 * See allocate_ipv4_transport_address().
 */
static int find_perfect_addr4(struct in_addr *host_addr, void *void_args)
{
	struct iteration_args *args = void_args;
	struct ipv4_transport_addr addr;
	int error;

	addr.l3 = *host_addr;
	addr.l4 = args->tuple6->src.addr6.l4;

	error = pool4_get_match(args->tuple6->l4_proto, &addr, &args->result->l4);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->l3 = *host_addr;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * Evaluates "bib", and returns whether it is an acceptable match to "void_args"'s tuple.
 * See allocate_ipv4_transport_address().
 */
static int find_runnerup_addr4(struct in_addr *host_addr, void *void_args)
{
	struct iteration_args *args = void_args;
	int error;

	error = pool4_get_any_port(args->tuple6->l4_proto, host_addr, &args->result->l4);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->l3 = *host_addr;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * "Allocates" from the IPv4 pool a new transport address. Attemps to make this address as similar
 * to "tuple6"'s contents as possible.
 *
 * Sorry, we're using the term "allocate" because the RFC does. A more appropriate name in this
 * context would be "borrow (from the IPv4 pool)".
 *
 * RFC6146 - Sections 3.5.1.1 and 3.5.2.3.
 *
 * @param[in] The table to iterate through.
 * @param[in] tuple6 this should contain the IPv6 source address you want the IPv4 address for.
 * @param[out] result the transport address we borrowed from the pool.
 * @return true if everything went OK, false otherwise.
 */
static int allocate_transport_address(struct host6_node *host_node, struct tuple *tuple6,
		struct ipv4_transport_addr *result)
{
	int error;
	struct iteration_args args = {
			.tuple6 = tuple6,
			.result = result
	};

	/* First, try to find a perfect match (Same address and a compatible port or id). */
	error = host6_node_for_each_addr4(host_node, find_perfect_addr4, &args);
	if (error > 0)
		return 0; /* A match was found and "result" is already populated, so report success. */
	else if (error < 0)
		return error; /* Something failed, report.*/

	/*
	 * Else, iteration ended with no perfect match. Find a good match instead...
	 * (good match = same address, any port or id)
	 */
	error = host6_node_for_each_addr4(host_node, find_runnerup_addr4, &args);
	if (error < 0)
		return error;
	else if (error > 0)
		return 0;

	/*
	 * There are no good matches. Just use any available IPv4 address and hope for the best.
	 * Alternatively, this could be the first BIB entry being created, so assign any address
	 * anyway.
	 */
	return pool4_get_any_addr(tuple6->l4_proto, tuple6->src.addr6.l4, result);
}

int bibdb_init(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i, error;

	error = host6_node_init();
	if (error) {
		return error;
	}

	entry_cache = kmem_cache_create("jool_bib_entries", sizeof(struct bib_entry), 0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the BIB entry cache.");
		host6_node_destroy();
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		tables[i]->tree6 = RB_ROOT;
		tables[i]->tree4 = RB_ROOT;
		tables[i]->count = 0;
		spin_lock_init(&tables[i]->lock);
	}

	return 0;
}

static void bibdb_destroy_aux(struct rb_node *node)
{
	bib_kfree(rb_entry(node, struct bib_entry, tree6_hook));
}

void bibdb_destroy(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int i;

	log_debug("Emptying the BIB tables...");
	/*
	 * The values need to be released only in one of the trees
	 * because both of them point to the same values.
	 */

	for (i = 0; i < ARRAY_SIZE(tables); i++)
		rbtree_clear(&tables[i]->tree6, bibdb_destroy_aux);

	kmem_cache_destroy(entry_cache);

	host6_node_destroy();
}

int bibdb_get(struct tuple *tuple, struct bib_entry **result)
{
	if (WARN(!tuple, "There's no BIB entry mapped to NULL."))
		return -EINVAL;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		return bibdb_get_by_ipv6(&tuple->src.addr6, tuple->l4_proto, result);
	case L3PROTO_IPV4:
		return bibdb_get_by_ipv4(&tuple->dst.addr4, tuple->l4_proto, result);
	}

	WARN(true, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

int bibdb_get_by_ipv4(const struct ipv4_transport_addr *addr, l4_protocol l4_proto,
		struct bib_entry **result)
{
	struct bib_table *table;
	int error;

	/* Sanitize */
	if (WARN(!addr, "The BIBs cannot contain NULL."))
		return -EINVAL;
	error = get_bibdb_table(l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);

	*result = rbtree_find(addr, &table->tree4, compare_full4, struct bib_entry, tree4_hook);
	if (*result)
		bib_get(*result);

	spin_unlock_bh(&table->lock);

	return (*result) ? 0 : -ENOENT;
}

int bibdb_get_by_ipv6(const struct ipv6_transport_addr *addr, l4_protocol l4_proto,
		struct bib_entry **result)
{
	struct bib_table *table;
	int error;

	/* Sanitize */
	if (WARN(!addr, "The BIBs cannot contain NULL."))
		return -EINVAL;
	error = get_bibdb_table(l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);

	*result = rbtree_find(addr, &table->tree6, compare_full6, struct bib_entry, tree6_hook);
	if (*result)
		bib_get(*result);

	spin_unlock_bh(&table->lock);

	return (*result) ? 0 : -ENOENT;
}

int bibdb_add(struct bib_entry *entry)
{
	struct bib_table *table;
	struct host6_node *host6;
	struct in6_addr addr6;
	int error;

	/* Sanity */
	if (WARN(!entry, "NULL is not a valid BIB entry."))
		return -EINVAL;
	error = get_bibdb_table(entry->l4_proto, &table);
	if (error)
		return error;

	/* Index */
	spin_lock_bh(&table->lock);

	addr6 = entry->ipv6.l3;
	error = host6_node_get_or_create(&addr6, &host6);
	if (error)
		goto spin_exit;

	error = rbtree_add(entry, &entry->ipv6, &table->tree6, compare_full6, struct bib_entry,
			tree6_hook);
	if (error) {
		log_debug("IPv6 index failed.");
		goto host6_exit;
	}

	error = rbtree_add(entry, &entry->ipv4, &table->tree4, compare_full4, struct bib_entry,
			tree4_hook);
	if (error) {
		/*
		 * This can happen if there's already a BIB entry with the same IPv4 transport address,
		 * and it's mapped to some other IPv6 transport address. It's normal when this is called
		 * from static_routes.
		 */
		rb_erase(&entry->tree6_hook, &table->tree6);
		log_debug("IPv4 index failed.");
		goto host6_exit;
	}

	table->count++;

	error = host6_node_add_or_increment_addr4(host6, entry);
	if (error)
		bibdb_remove(entry, false);

	/* Fall through. */

host6_exit:
	host6_node_return(host6);
spin_exit:
	spin_unlock_bh(&table->lock);
	return error;
}

int bibdb_remove(struct bib_entry *entry, const bool lock)
{
	struct bib_table *table;
	int error;

	if (WARN(!entry, "The BIBs cannot contain NULL."))
		return -EINVAL;
	if (RB_EMPTY_NODE(&entry->tree6_hook) || RB_EMPTY_NODE(&entry->tree4_hook)) {
		log_debug("BIB entry does not belong to any trees.");
		return -EINVAL;
	}
	error = get_bibdb_table(entry->l4_proto, &table);
	if (error)
		return error;

	if (lock) {
		spin_lock_bh(&table->lock);
		rb_erase(&entry->tree6_hook, &table->tree6);
		rb_erase(&entry->tree4_hook, &table->tree4);
		table->count--;
		spin_unlock_bh(&table->lock);
	} else {
		rb_erase(&entry->tree6_hook, &table->tree6);
		rb_erase(&entry->tree4_hook, &table->tree4);
		table->count--;
	}

	return 0;
}

int bibdb_for_each(l4_protocol l4_proto, int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_table *table;
	struct rb_node *node;
	int error;

	error = get_bibdb_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);

	for (node = rb_first(&table->tree4); node && !error; node = rb_next(node)) {
		error = func(rb_entry(node, struct bib_entry, tree4_hook), arg);
	}

	spin_unlock_bh(&table->lock);
	return error;
}

/**
 * Tries to find the BIB entry whose local IPv4 address is "addr".
 * If such an entry cannot be found, it returns the one right next to it if it existed.
 *
 * Why?
 * When the user requests the table to be displayed, the kernel module sends it in chunks because
 * it might be too big for a single Netlink message.
 * This is the function that finds the next chunk where iteration should continue. The quirk of
 * choosing the next entry if it doesn't exist is because the first entry of the next chunk
 * could have died while the previous chunk was transmitted... so the iteration should just ignore
 * it and continue with the next entry peacefully.
 */
static struct rb_node *find_next_chunk(struct bib_table *table, struct ipv4_transport_addr *addr4,
		bool starting)
{
	struct bib_entry *bib;
	struct rb_node **node;
	struct rb_node *parent;

	if (starting)
		return rb_first(&table->tree4);

	rbtree_find_node(addr4, &table->tree4, compare_full4, struct bib_entry, tree4_hook, parent,
			node);
	if (*node)
		return rb_next(*node);

	bib = rb_entry(parent, struct bib_entry, tree4_hook);
	return (compare_full4(bib, addr4) < 0) ? parent : rb_next(parent);
}

int bibdb_iterate_by_ipv4(l4_protocol l4_proto, struct ipv4_transport_addr *addr, bool starting,
		int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_table *table;
	struct rb_node *node;
	int error;

	if (WARN(!addr, "The IPv4 address is NULL."))
		return -EINVAL;
	error = get_bibdb_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	for (node = find_next_chunk(table, addr, starting); node && !error; node = rb_next(node)) {
		error = func(rb_entry(node, struct bib_entry, tree4_hook), arg);
	}

	spin_unlock_bh(&table->lock);
	return error;
}

int bibdb_count(l4_protocol proto, u64 *result)
{
	struct bib_table *table;
	int error;

	error = get_bibdb_table(proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	*result = table->count;
	spin_unlock_bh(&table->lock);
	return 0;
}

int bibdb_get_or_create_ipv6(struct sk_buff *skb, struct tuple *tuple6, struct bib_entry **bib)
{
	struct ipv4_transport_addr addr4;
	struct rb_node **node, *parent;
	struct bib_table *table;
	struct host6_node *host_node;
	int error;

	/* Sanitize */
	if (WARN(!tuple6, "The BIBs cannot contain NULL."))
		return -EINVAL;

	error = get_bibdb_table(tuple6->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);

	rbtree_find_node(&tuple6->src.addr6, &table->tree6, compare_full6, struct bib_entry,
			tree6_hook, parent, node);
	if (*node) {
		*bib = rb_entry(*node, struct bib_entry, tree6_hook);
		bib_get(*bib);
		goto end;
	}

	error = host6_node_get_or_create(&tuple6->src.addr6.l3, &host_node);
	if (error) {
		spin_unlock_bh(&table->lock);
		return error;
	}

	/* The entry is not in the table, so create it. */
	error = allocate_transport_address(host_node, tuple6, &addr4);
	if (error) {
		host6_node_return(host_node);
		log_debug("Error code %d while 'allocating' an address for a BIB entry.", error);
		spin_unlock_bh(&table->lock);
		if (tuple6->l4_proto != L4PROTO_ICMP) {
			/* I don't know why this is not supposed to happen with ICMP, but the RFC says so... */
			icmp64_send(skb, ICMPERR_ADDR_UNREACHABLE, 0);
		}
		return error;
	}

	*bib = bib_create(&addr4, &tuple6->src.addr6, false, tuple6->l4_proto);
	if (!(*bib)) {
		log_debug("Failed to allocate a BIB entry.");
		error = -ENOMEM;
		goto host_end;
	}

	/* Index it by IPv6. We already have the slot, so we don't need to do another rbtree_find(). */
	rb_link_node(&(*bib)->tree6_hook, parent, node);
	rb_insert_color(&(*bib)->tree6_hook, &table->tree6);

	/* Index it by IPv4. */
	error = rbtree_add(*bib, &(*bib)->ipv4, &table->tree4, compare_full4, struct bib_entry,
			tree4_hook);
	if (WARN(error, "The BIB entry could be indexed by IPv6 but not by IPv4.")) {
		rb_erase(&(*bib)->tree6_hook, &table->tree6);
		bib_kfree(*bib);
		goto host_end;
	}

	table->count++;

	error = host6_node_add_or_increment_addr4(host_node, *bib);
	if (error)
		bibdb_remove(*bib, false);

	/* Fall through. */

host_end:
	host6_node_return(host_node);
end:
	spin_unlock_bh(&table->lock);
	return error;
}

/**
 * Drops the fake user of "bib", if it has one.
 *
 * @return 1 if the removal triggered the destruction of "bib", zero otherwise.
 * 		Strictly speaking, note that if it returns zero, the entry might still have been removed
 * 		from the database (and will be kfreed later, when the other thread drops its reference).
 */
static int remove_fake_usr(struct bib_entry *bib)
{
	int b = 0;

	if (bib->is_static) {
		bib->is_static = false;
		b = bib_return_lockless(bib);
	}

	return b;
}

static int compare_prefix4(const struct bib_entry *bib, const struct ipv4_prefix *prefix)
{
	return ipv4_prefix_contains(prefix, &bib->ipv4.l3)
			? 0
			: ipv4_addr_cmp(&prefix->address, &bib->ipv4.l3);
}

static void delete_bibs_by_ipv4(struct bib_table *table, struct ipv4_prefix *prefix)
{
	struct bib_entry *root_bib, *bib;
	struct rb_node *node;
	int b = 0;

	spin_lock_bh(&table->lock);

	/* This is very similar to the for_each function. See that it you want comments. */
	root_bib = rbtree_find(prefix, &table->tree4, compare_prefix4, struct bib_entry, tree4_hook);
	if (!root_bib)
		goto success;

	node = rb_prev(&root_bib->tree4_hook);
	while (node) {
		bib = rb_entry(node, struct bib_entry, tree4_hook);
		node = rb_prev(&bib->tree4_hook);

		if (compare_prefix4(bib, prefix) != 0)
			break;
		b += remove_fake_usr(bib);
	}

	node = rb_next(&root_bib->tree4_hook);
	while (node) {
		bib = rb_entry(node, struct bib_entry, tree4_hook);
		node = rb_next(&bib->tree4_hook);

		if (compare_prefix4(bib, prefix) != 0)
			break;
		b += remove_fake_usr(bib);
	}

	b += remove_fake_usr(root_bib);
	/* Fall through. */

success:
	spin_unlock_bh(&table->lock);
	log_debug("Deleted %d BIB entries.", b);
}

int bibdb_delete_by_prefix4(struct ipv4_prefix *prefix)
{
	if (WARN(!prefix, "IPv4 address is NULL"))
		return -EINVAL;

	delete_bibs_by_ipv4(&bib_tcp, prefix);
	delete_bibs_by_ipv4(&bib_icmp, prefix);
	delete_bibs_by_ipv4(&bib_udp, prefix);

	return 0;
}

static void flush_aux(struct bib_table *table)
{
	struct bib_entry *root_bib, *bib;
	struct rb_node *node;
	int b = 0;

	spin_lock_bh(&table->lock);

	/* This is very similar to the for_each function. See that it you want comments. */
	node = (&table->tree4)->rb_node;
	if (!node)
		goto success;

	root_bib = rb_entry(node, struct bib_entry, tree4_hook);
	if (!root_bib)
		goto success;

	node = rb_prev(&root_bib->tree4_hook);
	while (node) {
		bib = rb_entry(node, struct bib_entry, tree4_hook);
		node = rb_prev(&bib->tree4_hook);
		b += remove_fake_usr(bib);
	}

	node = rb_next(&root_bib->tree4_hook);
	while (node) {
		bib = rb_entry(node, struct bib_entry, tree4_hook);
		node = rb_next(&bib->tree4_hook);
		b += remove_fake_usr(bib);
	}

	b += remove_fake_usr(root_bib);
	/* Fall through. */

success:
	spin_unlock_bh(&table->lock);
	log_debug("Deleted %d BIB entries.", b);
}

int bibdb_flush(void)
{
	log_debug("Emptying the BIB tables...");
	flush_aux(&bib_tcp);
	flush_aux(&bib_icmp);
	flush_aux(&bib_udp);

	return 0;
}
