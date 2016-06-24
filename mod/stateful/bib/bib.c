#include "nat64/mod/stateful/bib/bib.h"

#include <net/ipv6.h>
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/wkmalloc.h"

/**
 * A row, intended to be part of one of the BIB tables.
 */
struct table_entry {
	/* The entry data. */
	struct bib_entry bib;
	/** Appends this entry to the table's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the table's IPv4 index. */
	struct rb_node tree4_hook;
};

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
};

struct bib {
	/** The BIB table for TCP connections. */
	struct bib_table tcp;
	/** The BIB table for UDP connections. */
	struct bib_table udp;
	/** The BIB table for ICMP connections. */
	struct bib_table icmp;

	struct kref refs;
};


static struct table_entry *get_table4_entry(struct rb_node *node)
{
	return rb_entry(node, struct table_entry, tree4_hook);
}

static void bibtable_init(struct bib_table *table)
{
	table->tree6 = RB_ROOT;
	table->tree4 = RB_ROOT;
	table->count = 0;
}

/**
 * Returns > 0 if bib->ipv6 > addr.
 * Returns < 0 if bib->ipv6 < addr.
 * Returns 0 if bib->ipv6 == addr.
 */
static int compare6(const struct table_entry *entry,
		const struct ipv6_transport_addr *addr)
{
	int gap;

	gap = ipv6_addr_cmp(&entry->bib.ipv6.l3, &addr->l3);
	if (gap)
		return gap;

	gap = entry->bib.ipv6.l4 - addr->l4;
	return gap;
}

/**
 * Returns > 0 if bib->ipv4 > addr.
 * Returns < 0 if bib->ipv4 < addr.
 * Returns 0 if bib->ipv4 == addr.
 */
static int compare4(const struct table_entry *entry,
		const struct ipv4_transport_addr *addr)
{
	int gap;

	gap = ipv4_addr_cmp(&entry->bib.ipv4.l3, &addr->l3);
	if (gap)
		return gap;

	gap = entry->bib.ipv4.l4 - addr->l4;
	return gap;
}

static struct table_entry *find_by_addr6(const struct bib_table *table,
		const struct ipv6_transport_addr *addr)
{
	return rbtree_find(addr, &table->tree6, compare6, struct table_entry,
			tree6_hook);
}

static struct table_entry *find_by_addr4(const struct bib_table *table,
		const struct ipv4_transport_addr *addr)
{
	return rbtree_find(addr, &table->tree4, compare4, struct table_entry,
			tree4_hook);
}

static struct table_entry *add6(struct bib_table *table,
		struct table_entry *entry)
{
	return rbtree_add(entry, &entry->bib.ipv6, &table->tree6, compare6,
			struct table_entry, tree6_hook);
}

static struct table_entry *add4(struct bib_table *table,
		struct table_entry *entry)
{
	return rbtree_add(entry, &entry->bib.ipv4, &table->tree4, compare4,
			struct table_entry, tree4_hook);
}

static struct rb_node *find_starting_point(struct bib_table *table,
		const struct ipv4_transport_addr *offset, bool include_offset)
{
	struct table_entry *bib;
	struct rb_node **node;
	struct rb_node *parent;

	/* If there's no offset, start from the beginning. */
	if (!offset)
		return rb_first(&table->tree4);

	/* If offset is found, start from offset or offset's next. */
	rbtree_find_node(offset, &table->tree4, compare4, struct table_entry,
			tree4_hook, parent, node);
	if (*node)
		return include_offset ? (*node) : rb_next(*node);

	if (!parent)
		return NULL;

	/*
	 * If offset is not found, start from offset's next anyway.
	 * (If offset was meant to exist, it probably timed out and died while
	 * the caller wasn't holding the spinlock; it's nothing to worry about.)
	 */
	bib = rb_entry(parent, struct table_entry, tree4_hook);
	return (compare4(bib, offset) < 0) ? rb_next(parent) : parent;
}

/**
 * get_table - One-liner to get the table corresponding to the @proto protocol.
 */
static struct bib_table *get_table(struct bib *db, const l4_protocol proto)
{
	switch (proto) {
	case L4PROTO_TCP:
		return &db->tcp;
	case L4PROTO_UDP:
		return &db->udp;
	case L4PROTO_ICMP:
		return &db->icmp;
	case L4PROTO_OTHER:
		break;
	}

	WARN(true, "Unsupported transport protocol: %u.", proto);
	return NULL;
}

struct bib *bibdb_init(void)
{
	struct bib *result;

	result = wkmalloc(struct bib, GFP_KERNEL);
	if (!result)
		return NULL;

	bibtable_init(&result->tcp);
	bibtable_init(&result->udp);
	bibtable_init(&result->icmp);
	kref_init(&result->refs);

	return result;
}

/**
 * bibdb_get - Grab a reference towards @db.
 *
 * Revert using bibdb_put().
 */
void bibdb_get(struct bib *db)
{
	kref_get(&db->refs);
}

static void destroy_fast(struct rb_node *node, void *arg)
{
	kfree(get_table4_entry(node));
}

static void release(struct kref *refcounter)
{
	struct bib *db;
	db = container_of(refcounter, typeof(*db), refs);

	log_debug("Emptying the BIB tables...");

	rbtree_clear(&db->udp.tree4, destroy_fast, NULL);
	rbtree_clear(&db->tcp.tree4, destroy_fast, NULL);
	rbtree_clear(&db->icmp.tree4, destroy_fast, NULL);

	wkfree(struct bib, db);
}

/**
 * bibdb_put - Return your reference towards @db. Will destroy @db if there are
 * no more referencers.
 */
void bibdb_put(struct bib *db)
{
	kref_put(&db->refs, release);
}

/**
 * bibdb_find - Returns the BIB entry corresponding to the @tuple tuple.
 * @db: Database instance where you want to do the lookup.
 * @tuple: Summary of the packet. Describes the BIB entry you want.
 * @result: If not NULL, this will point to the BIB entry that matches @tuple.
 *
 * During an IPv6 to IPv4 translation, the entry that corresponds to @tuple
 * is the one whose IPv6 address matches @tuple's source address.
 * During an IPv4 to IPv6 translation, the entry that corresponds to @tuple
 * is the one whose IPv4 address matches @tuple's destination address.
 *
 * The entry will not be returned if @result is NULL, but you will still get a
 * success code if it was found. Otherwise a reference towards @result is taken.
 * Make sure you call bibentry_put_thread(result) when you're done.
 */
int bibdb_find(struct bib *db, const struct tuple *tuple,
		struct bib_entry *result)
{
	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		return bibdb_find6(db, &tuple->src.addr6, tuple->l4_proto,
				result);
	case L3PROTO_IPV4:
		return bibdb_find4(db, &tuple->dst.addr4, tuple->l4_proto,
				result);
	}

	WARN(true, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

/**
 * bibdb_find4 - Returns the BIB entry whose IPv4 transport address is @addr.
 * @db: Database instance where you want to do the lookup.
 * @addr: Transport address you want the BIB entry for.
 * @proto: Identifier of the table to retrieve the entry from.
 * @result: If not NULL, this will point to the BIB entry that matches @addr.
 *
 * The entry will not be returned if @result is NULL, but you will still get a
 * success code if it was found. Otherwise a reference towards @result is taken.
 * Make sure you call bibentry_put_thread(result) when you're done.
 */
int bibdb_find4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto, struct bib_entry *result)
{
	struct bib_table *table;
	struct table_entry *entry;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	entry = find_by_addr4(table, addr);
	if (!entry)
		return -ESRCH;
	if (result)
		*result = entry->bib;
	return 0;
}

/**
 * bibdb_find6 - Returns the BIB entry whose IPv6 transport address is @addr.
 * @db: Database instance where you want to do the lookup.
 * @addr: Transport address you want the BIB entry for.
 * @proto: Identifier of the table to retrieve the entry from.
 * @result: If not NULL, this will point to the BIB entry that matches @addr.
 *
 * The entry will not be returned if @result is NULL, but you will still get a
 * success code if it was found. Otherwise a reference towards @result is taken.
 * Make sure you call bibentry_put_thread(result) when you're done.
 */
int bibdb_find6(struct bib *db, const struct ipv6_transport_addr *addr,
		const l4_protocol proto, struct bib_entry *result)
{
	struct bib_table *table;
	struct table_entry *entry;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	entry = find_by_addr6(table, addr);
	if (!entry)
		return -ESRCH;
	if (result)
		*result = entry->bib;
	return 0;
}

/**
 * bibdb_add - Append @entry to the table (from @db) it belongs.
 * @db: BIB where the entry should be inserted.
 * @entry: Row to be added to the database.
 *    Make sure you create it via bibentry_create(), please.
 * @old: If @entry collides with an already existing entry, the function will
 *    return -EEXIST and @old will point to the existing entry.
 *    If you're not interested in the existing entry, send NULL.
 *
 * See bib_entry->mem_refs and bib_entry->db_refs for notes regarding reference
 * counters.
 */
int bibdb_add(struct bib *db, struct bib_entry *new, struct bib_entry *old)
{
	struct bib_table *table;
	struct table_entry *entry;
	struct table_entry *collision;

	table = get_table(db, new->l4_proto);
	if (!table)
		return -EINVAL;

	entry = wkmalloc(struct table_entry, GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;
	entry->bib = *new;

	collision = add6(table, entry);
	if (collision) {
		log_debug("IPv6 index failed.");
		goto exists;
	}

	collision = add4(table, entry);
	if (collision) {
		rb_erase(&entry->tree6_hook, &table->tree6);
		log_debug("IPv4 index failed.");
		goto exists;
	}

	table->count++;

//	TODO
//	if (table->log_changes)
//		bibentry_log(bib, "Mapped");
	return 0;

exists:
	wkfree(struct table_entry, entry);
	if (old)
		*old = collision->bib;
	return -EEXIST;
}

/**
 * bibdb_foreach - Iterate over @db's entries.
 *
 * Will run @func (with the @arg parameter) on every BIB entry after @offset.
 * Only entries whose protocol is @proto count.
 */
int bibdb_foreach(struct bib *db, const l4_protocol proto,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset)
{
	struct bib_table *table;
	struct rb_node *node;
	int error;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	node = find_starting_point(table, offset, false);
	for (; node; node = rb_next(node)) {
		error = func(&get_table4_entry(node)->bib, arg);
		if (error)
			return error;
	}

	return 0;
}

/**
 * bibdb_count - Returns (in @result) the number of entries in the database
 * whose protocol is @proto.
 */
int bibdb_count(struct bib *db, const l4_protocol proto, __u64 *result)
{
	struct bib_table *table;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	*result = table->count;
	return 0;
}

static void rm(struct bib_table *table, struct table_entry *entry)
{
	rb_erase(&entry->tree6_hook, &table->tree6);
	rb_erase(&entry->tree4_hook, &table->tree4);
	kfree(entry);
	table->count--;
}

/* TODO if this works, copy the logic to sessiondb_rm_range(). */
static void rm_taddr4s(struct bib_table *table, const struct ipv4_range *range)
{
	struct ipv4_transport_addr offset = {
			.l3 = range->prefix.address,
			.l4 = range->ports.min,
	};
	struct table_entry *entry;
	struct rb_node *node, *next;

	node = find_starting_point(table, &offset, true);
	for (; node; node = next) {
		next = rb_next(node);

		entry = get_table4_entry(node);
		if (!prefix4_contains(&range->prefix, &entry->bib.ipv4.l3))
			return;
		if (port_range_contains(&range->ports, entry->bib.ipv4.l4))
			rm(table, entry);
	}
}

int bibdb_rm(struct bib *db, struct bib_entry *bib)
{
	struct bib_table *table;
	struct table_entry *entry;

	table = get_table(db, bib->l4_proto);
	if (!table)
		return -EINVAL;

	entry = find_by_addr4(table, &bib->ipv4);
	if (!entry || !taddr6_equals(&bib->ipv6, &entry->bib.ipv6))
		return -ESRCH;

	rm(table, entry);
	return 0;
}

/**
 * bibdb_delete_taddr4s - Removes the fake users of all the BIB entries whose
 * IPv4 transport addreses match @range.
 */
void bibdb_rm_range(struct bib *db, const struct ipv4_range *range)
{
	rm_taddr4s(&db->tcp, range);
	rm_taddr4s(&db->udp, range);
	rm_taddr4s(&db->icmp, range);
}

static void flush(struct bib_table *table)
{
	rbtree_clear(&table->tree4, destroy_fast, NULL);
	bibtable_init(table);
}

/**
 * bibdb_flush - Removes the fake users of all the BIB entries in @db.
 */
void bibdb_flush(struct bib *db)
{
	log_debug("Emptying the BIB tables...");

	flush(&db->tcp);
	flush(&db->icmp);
	flush(&db->udp);
}
