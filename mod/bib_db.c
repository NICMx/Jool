#include "nat64/mod/bib_db.h"

#include <net/ipv6.h>
#include "nat64/mod/rbtree.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/icmp_wrapper.h"

#include "bib.c"

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
	case L4PROTO_NONE:
		WARN(true, "There's no BIB for the 'NONE' protocol.");
		return -EINVAL;
	}

	WARN(true, "Unsupported transport protocol: %u.", l4_proto);
	return -EINVAL;
}

/**
 * Returns a positive integer if bib->ipv6.address < addr.
 * Returns a negative integer if bib->ipv6.address > addr.
 * Returns zero if bib->ipv6.address == addr.
 */
static int compare_addr6(struct bib_entry *bib, struct in6_addr *addr)
{
	return ipv6_addr_cmp(addr, &bib->ipv6.address);
}

/**
 * Returns a positive integer if bib->ipv6 < addr.
 * Returns a negative integer if bib->ipv6 > addr.
 * Returns zero if bib->ipv6 == addr.
 */
static int compare_full6(struct bib_entry *bib, struct ipv6_tuple_address *addr)
{
	int gap;

	gap = compare_addr6(bib, &addr->address);
	if (gap != 0)
		return gap;

	gap = addr->l4_id - bib->ipv6.l4_id;
	return gap;
}

/**
 * Returns a positive integer if bib->ipv4.address < addr.
 * Returns a negative integer if bib->ipv4.address > addr.
 * Returns zero if bib->ipv4.address == addr.
 */
static int compare_addr4(struct bib_entry *bib, struct in_addr *addr)
{
	return ipv4_addr_cmp(addr, &bib->ipv4.address);
}

/**
 * Returns a positive integer if bib->ipv4 < addr.
 * Returns a negative integer if bib->ipv4 > addr.
 * Returns zero if bib->ipv4 == addr.
 */
static int compare_full4(struct bib_entry *bib, struct ipv4_tuple_address *addr)
{
	int gap;

	gap = compare_addr4(bib, &addr->address);
	if (gap != 0)
		return gap;

	gap = addr->l4_id - bib->ipv4.l4_id;
	return gap;
}

struct iteration_args {
	struct tuple *tuple;
	struct ipv4_tuple_address *result;
};

/**
 * Evaluates "bib", and returns whether it is a perfect match to "void_args"'s tuple.
 * See allocate_ipv4_transport_address().
 */
static int find_perfect_addr4(struct bib_entry *bib, void *void_args)
{
	struct iteration_args *args = void_args;
	struct ipv4_tuple_address tuple_addr;
	int error;

	tuple_addr.address = bib->ipv4.address;
	tuple_addr.l4_id = args->tuple->src.l4_id;

	error = pool4_get_match(args->tuple->l4_proto, &tuple_addr, &args->result->l4_id);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->address = bib->ipv4.address;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * Evaluates "bib", and returns whether it is an acceptable match to "void_args"'s tuple.
 * See allocate_ipv4_transport_address().
 */
static int find_runnerup_addr4(struct bib_entry *bib, void *void_args)
{
	struct iteration_args *args = void_args;
	int error;

	error = pool4_get_any_port(args->tuple->l4_proto, &bib->ipv4.address, &args->result->l4_id);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->address = bib->ipv4.address;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * Runs the "func" function on every entry in "table" whose IPv6 address is "addr".
 * Aside from each entry, it always sends "args" as a parameter to "func".
 *
 * This function's performance is critical; do not expect the entries to be visited in any
 * particular order.
 */
static int for_each_bib_ipv6(struct bib_table *table, struct in6_addr *addr,
		int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_entry *root_bib, *bib;
	struct rb_node *node;
	int error;

	/* Sanitize */
	if (!addr)
		return -EINVAL;

	/* Find the top-most node in the tree whose IPv6 address is addr. */
	root_bib = rbtree_find(addr, &table->tree6, compare_addr6, struct bib_entry, tree6_hook);
	if (!root_bib)
		return 0; /* "Successfully" iterated through no entries. */

	/*
	 * Run "func" for every entry left of root_bib that has "addr" as address.
	 * We can do this because all entries whose address is "addr" are glued together in the tree.
	 */
	bib = root_bib;
	do {
		node = rb_prev(&bib->tree6_hook);
		if (!node)
			break;

		bib = rb_entry(node, struct bib_entry, tree6_hook);
		if (compare_addr6(bib, addr) != 0)
			break;

		error = func(bib, arg);
		if (error)
			return error;
	} while (true);

	/* Run "func" for every entry right of (and including) root_bib that has "addr" as address. */
	bib = root_bib;
	do {
		error = func(bib, arg);
		if (error)
			return error;

		node = rb_next(&bib->tree6_hook);
		if (!node)
			break;

		bib = rb_entry(node, struct bib_entry, tree6_hook);
	} while (compare_addr6(bib, addr) == 0);

	return 0;
}

/**
 * "Allocates" from the IPv4 pool a new transport address. Attemps to make this address as similar
 * to "tuple"'s contents as possible.
 *
 * Sorry, we're using the term "allocate" because the RFC does. A more appropriate name in this
 * context would be "borrow (from the IPv4 pool)".
 *
 * RFC6146 - Sections 3.5.1.1 and 3.5.2.3.
 *
 * @param[in] The table to iterate through.
 * @param[in] base this should contain the IPv6 source address you want the IPv4 address for.
 * @param[out] result the transport address we borrowed from the pool.
 * @return true if everything went OK, false otherwise.
 */
static int allocate_transport_address(struct bib_table *table, struct tuple *base,
		struct ipv4_tuple_address *result)
{
	int error;
	struct iteration_args args = {
			.tuple = base,
			.result = result
	};

	/* First, try to find a perfect match (Same address and a compatible port or id). */
	error = for_each_bib_ipv6(table, &base->src.addr.ipv6, find_perfect_addr4, &args);
	if (error > 0)
		return 0; /* A match was found and "result" is already populated, so report success. */
	else if (error < 0)
		return error; /* Something failed, report.*/

	/*
	 * Else, iteration ended with no perfect match. Find a good match instead...
	 * (good match = same address, any port or id)
	 */
	error = for_each_bib_ipv6(table, &base->src.addr.ipv6, find_runnerup_addr4, &args);
	if (error < 0)
		return error;
	else if (error > 0)
		return 0;

	/*
	 * There are no good matches. Just use any available IPv4 address and hope for the best.
	 * Alternatively, this could be the first BIB entry being created, so assign any address
	 * anyway.
	 */
	return pool4_get_any_addr(base->l4_proto, base->src.l4_id, result);
}

int bibdb_init(void)
{
	struct bib_table *tables[] = { &bib_udp, &bib_tcp, &bib_icmp };
	int error;
	int i;

	error = bib_init();
	if (error)
		return error;

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

	bib_destroy();
}

int bibdb_get(struct tuple *tuple, struct bib_entry **result)
{
	struct ipv6_tuple_address addr6;
	struct ipv4_tuple_address addr4;

	if (WARN(!tuple, "There's no BIB entry mapped to NULL."))
		return -EINVAL;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		addr6.address = tuple->src.addr.ipv6;
		addr6.l4_id = tuple->src.l4_id;
		return bibdb_get_by_ipv6(&addr6, tuple->l4_proto, result);
	case L3PROTO_IPV4:
		addr4.address = tuple->dst.addr.ipv4;
		addr4.l4_id = tuple->dst.l4_id;
		return bibdb_get_by_ipv4(&addr4, tuple->l4_proto, result);
	}

	WARN(true, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

int bibdb_get_by_ipv4(struct ipv4_tuple_address *addr, l4_protocol l4_proto,
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

int bibdb_get_by_ipv6(struct ipv6_tuple_address *addr, l4_protocol l4_proto,
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
	int error;

	/* Sanity */
	if (WARN(!entry, "NULL is not a valid BIB entry."))
		return -EINVAL;
	error = get_bibdb_table(entry->l4_proto, &table);
	if (error)
		return error;

	/* Index */
	spin_lock_bh(&table->lock);

	error = rbtree_add(entry, ipv6, &table->tree6, compare_full6, struct bib_entry, tree6_hook);
	if (error) {
		log_debug("IPv6 index failed.");
		goto spin_exit;
	}

	error = rbtree_add(entry, ipv4, &table->tree4, compare_full4, struct bib_entry, tree4_hook);
	if (error) {
		/*
		 * This can happen if there's already a BIB entry with the same IPv4 transport address,
		 * and it's mapped to some other IPv6 transport address. It's normal when this is called
		 * from static_routes.
		 */
		rb_erase(&entry->tree6_hook, &table->tree6);
		log_debug("IPv4 index failed.");
		goto spin_exit;
	}

	table->count++;
	/* Fall through. */

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

	if (lock)
		spin_lock_bh(&table->lock);

	rb_erase(&entry->tree6_hook, &table->tree6);
	rb_erase(&entry->tree4_hook, &table->tree4);
	table->count--;

	if (lock)
		spin_unlock_bh(&table->lock);

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
 * Tries to find the session whose local IPv4 address is "addr".
 * If such an entry cannot be found, it returns the one right next to it if it existed.
 *
 * Why?
 * When the user requests the table to be displayed, the kernel module sends it in chunks because
 * it might be too big for a single Netlink message.
 * This is the function that finds the next chunk where iteration should continue. The quirk of
 * choosing the next session if it doesn't exist is because the first session of the next chunk
 * could have died while the previous chunk was transmitted... so the iteration should just ignore
 * it and continue with the next session peacefully.
 */
static struct rb_node *find_next_chunk(struct bib_table *table, struct ipv4_tuple_address *addr4,
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

int bibdb_iterate_by_ipv4(l4_protocol l4_proto, struct ipv4_tuple_address *ipv4, bool starting,
		int (*func)(struct bib_entry *, void *), void *arg)
{
	struct bib_table *table;
	struct rb_node *node;
	int error;

	if (WARN(!ipv4, "The IPv4 address is NULL."))
		return -EINVAL;
	error = get_bibdb_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	for (node = find_next_chunk(table, ipv4, starting); node && !error; node = rb_next(node)) {
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

int bibdb_get_or_create_ipv6(struct fragment *frag, struct tuple *tuple, struct bib_entry **bib)
{
	struct ipv6_tuple_address addr6;
	struct ipv4_tuple_address addr4;
	struct rb_node **node, *parent;
	struct bib_table *table;
	int error;

	/* Sanitize */
	if (WARN(!tuple, "The BIBs cannot contain NULL."))
		return -EINVAL;

	addr6.address = tuple->src.addr.ipv6;
	addr6.l4_id = tuple->src.l4_id;

	error = get_bibdb_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);

	rbtree_find_node(&addr6, &table->tree6, compare_full6, struct bib_entry, tree6_hook, parent,
			node);
	if (*node) {
		*bib = rb_entry(*node, struct bib_entry, tree6_hook);
		bib_get(*bib);
		goto end;
	}

	/* The entry is not in the table, so create it. */
	error = allocate_transport_address(table, tuple, &addr4);
	if (error) {
		log_debug("Error code %d while 'allocating' an address for a BIB entry.", error);
		if (tuple->l4_proto != L4PROTO_ICMP) {
			/* I don't know why this is not supposed to happen with ICMP, but the RFC says so... */
			icmp64_send(frag, ICMPERR_ADDR_UNREACHABLE, 0);
		}
		goto end;
	}

	*bib = bib_create(&addr4, &addr6, false, tuple->l4_proto);
	if (!(*bib)) {
		log_debug("Failed to allocate a BIB entry.");
		error = -ENOMEM;
		goto end;
	}

	/* Index it by IPv6. We already have the slot, so we don't need to do another rbtree_find(). */
	rb_link_node(&(*bib)->tree6_hook, parent, node);
	rb_insert_color(&(*bib)->tree6_hook, &table->tree6);

	/* Index it by IPv4. */
	error = rbtree_add(*bib, ipv4, &table->tree4, compare_full4, struct bib_entry, tree4_hook);
	if (error) {
		WARN(true, "The BIB entry could be indexed by IPv6 but not by IPv4.");
		rb_erase(&(*bib)->tree6_hook, &table->tree6);
		bib_kfree(*bib);
		goto end;
	}

	table->count++;
	/* Fall through. */

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

static void delete_bibs_by_ipv4(struct bib_table *table, struct in_addr *addr)
{
	struct bib_entry *root_bib, *bib;
	struct rb_node *node;
	int b = 0;

	spin_lock_bh(&table->lock);

	/* This is very similar to the for_each function. See that it you want comments. */
	root_bib = rbtree_find(addr, &table->tree4, compare_addr4, struct bib_entry, tree4_hook);
	if (!root_bib)
		goto success;

	node = rb_prev(&root_bib->tree4_hook);
	while (node) {
		bib = rb_entry(node, struct bib_entry, tree4_hook);
		node = rb_prev(&bib->tree4_hook);

		if (compare_addr4(bib, addr) != 0)
			break;
		b += remove_fake_usr(bib);
	}

	node = rb_next(&root_bib->tree4_hook);
	while (node) {
		bib = rb_entry(node, struct bib_entry, tree4_hook);
		node = rb_next(&bib->tree4_hook);

		if (compare_addr4(bib, addr) != 0)
			break;
		b += remove_fake_usr(bib);
	}

	b += remove_fake_usr(root_bib);
	/* Fall through. */

success:
	spin_unlock_bh(&table->lock);
	log_debug("Deleted %d BIB entries.", b);
}

int bibdb_delete_by_ipv4(struct in_addr *addr)
{
	if (WARN(!addr, "IPv4 address is NULL"))
		return -EINVAL;

	delete_bibs_by_ipv4(&bib_tcp, addr);
	delete_bibs_by_ipv4(&bib_icmp, addr);
	delete_bibs_by_ipv4(&bib_udp, addr);

	return 0;
}
