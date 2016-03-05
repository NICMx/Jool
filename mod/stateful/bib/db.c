#include "nat64/mod/stateful/bib/db.h"

struct bib {
	/** The BIB table for TCP connections. */
	struct bib_table tcp;
	/** The BIB table for UDP connections. */
	struct bib_table udp;
	/** The BIB table for ICMP connections. */
	struct bib_table icmp;

	struct kref refs;
};

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

/**
 * bibdb_init - Initializes the @db database instance.
 */
int bibdb_init(struct bib **db)
{
	struct bib *result;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	bibtable_init(&result->tcp);
	bibtable_init(&result->udp);
	bibtable_init(&result->icmp);
	kref_init(&result->refs);

	*db = result;
	return 0;
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

static void release(struct kref *refcounter)
{
	struct bib *db;
	db = container_of(refcounter, typeof(*db), refs);

	log_debug("Emptying the BIB tables...");

	bibtable_destroy(&db->udp);
	bibtable_destroy(&db->tcp);
	bibtable_destroy(&db->icmp);

	kfree(db);
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
 * bibdb_config_copy - Initializes @config's fields as a summary of @db's
 * configuration.
 */
void bibdb_config_copy(struct bib *db, struct bib_config *config)
{
	bibtable_config_clone(&db->tcp, config);
}

/**
 * bibdb_config_set - Overrides @db's configuration using @config's fields.
 */
void bibdb_config_set(struct bib *db, struct bib_config *config)
{
	bibtable_config_set(&db->tcp, config);
	bibtable_config_set(&db->udp, config);
	bibtable_config_set(&db->icmp, config);
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
		struct bib_entry **result)
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
		const l4_protocol proto, struct bib_entry **result)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_find4(table, addr, result) : -EINVAL;
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
		const l4_protocol proto, struct bib_entry **result)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_find6(table, addr, result) : -EINVAL;
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
int bibdb_add(struct bib *db, struct bib_entry *entry, struct bib_entry **old)
{
	struct bib_table *table = get_table(db, entry->l4_proto);
	return table ? bibtable_add(table, entry, old) : -EINVAL;
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
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_foreach(table, func, arg, offset) : -EINVAL;
}

/**
 * bibdb_count - Returns (in @result) the number of entries in the database
 * whose protocol is @proto.
 */
int bibdb_count(struct bib *db, const l4_protocol proto, __u64 *result)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_count(table, result) : -EINVAL;
}

/**
 * bibdb_delete_taddr4s - Removes the fake users of all the BIB entries whose
 * IPv4 transport addreses match @prefix4 and @ports.
 */
void bibdb_rm_taddr4s(struct bib *db, const struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	bibtable_rm_taddr4s(&db->tcp, prefix, ports);
	bibtable_rm_taddr4s(&db->udp, prefix, ports);
	bibtable_rm_taddr4s(&db->icmp, prefix, ports);
}

/**
 * bibdb_flush - Removes the fake users of all the BIB entries in @db.
 */
void bibdb_flush(struct bib *db)
{
	log_debug("Emptying the BIB tables...");

	bibtable_flush(&db->tcp);
	bibtable_flush(&db->icmp);
	bibtable_flush(&db->udp);
}
