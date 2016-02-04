#include "nat64/mod/stateful/bib/db.h"

#include "nat64/mod/stateful/bib/table.h"
#include "nat64/mod/stateful/bib/port_allocator.h"

struct bib {
	/** The BIB table for TCP connections. */
	struct bib_table tcp;
	/** The BIB table for UDP connections. */
	struct bib_table udp;
	/** The BIB table for ICMP connections. */
	struct bib_table icmp;

	struct kref refcounter;
};

/**
 * One-liner to get the BIB table corresponding to the "proto" protocol.
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
 * Initializes the three tables (TCP, UDP and ICMP).
 * Call during initialization for the remaining functions to work properly.
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
	kref_init(&result->refcounter);

	*db = result;
	return 0;
}

void bibdb_get(struct bib *db)
{
	kref_get(&db->refcounter);
}

/**
 * Empties the BIB tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
static void release(struct kref *refcounter)
{
	struct bib *db;
	db = container_of(refcounter, typeof(*db), refcounter);

	log_debug("Emptying the BIB tables...");

	bibtable_destroy(&db->udp);
	bibtable_destroy(&db->tcp);
	bibtable_destroy(&db->icmp);

	kfree(db);
}

void bibdb_put(struct bib *db)
{
	kref_put(&db->refcounter, release);
}

void bibdb_config_copy(struct bib *db, struct bib_config *config)
{
	bibtable_config_clone(&db->tcp, config);
}

void bibdb_config_set(struct bib *db, struct bib_config *config)
{
	bibtable_config_set(&db->tcp, config);
	bibtable_config_set(&db->udp, config);
	bibtable_config_set(&db->icmp, config);
}

/**
 * Makes "result" point to the BIB entry you'd expect from the "tuple" tuple.
 *
 * That is, when we're translating from IPv6 to IPv4, "result" will point to the
 * BIB entry whose IPv6 address is "tuple"'s source address.
 * When we're translating from IPv4 to IPv6, "result" will point to the entry
 * whose IPv4 address is "tuple"'s destination address.
 *
 * It increases "result"'s refcount. Make sure you call bibdb_return() on it
 * when you're done.
 *
 * @param[in] tuple summary of the packet. Describes the BIB you need.
 * @param[out] the BIB entry you'd expect from the "tuple" tuple.
 * @return error status.
 */
int bibdb_find(struct bib *db, const struct tuple *tuple,
		struct bib_entry **result)
{
	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		return bibdb_find6(db, &tuple->src.addr6, tuple->l4_proto, result);
	case L3PROTO_IPV4:
		return bibdb_find4(db, &tuple->dst.addr4, tuple->l4_proto, result);
	}

	WARN(true, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

/**
 * Makes "result" point to the BIB entry from the "l4_proto" table whose IPv4
 * side (address and port) is "addr".
 *
 * It increases "result"'s refcount. Make sure you call bibdb_return() on it
 * when you're done.
 *
 * @param[in] address address and port you want the BIB entry for.
 * @param[in] l4_proto identifier of the table to retrieve the entry from.
 * @param[out] the BIB entry from the table will be placed here.
 * @return error status.
 */
int bibdb_find4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto, struct bib_entry **result)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_get4(table, addr, result) : -EINVAL;
}

bool bibdb_contains4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_contains4(table, addr) : false;
}

/**
 * Makes "result" point to the BIB entry from the "l4_proto" table whose IPv6
 * side (address and port) is "addr".
 *
 * It increases "result"'s refcount. Make sure you call bibdb_return() on it
 * when you're done.
 *
 * @param[in] address address and port you want the BIB entry for.
 * @param[in] l4_proto identifier of the table to retrieve the entry from.
 * @param[out] the BIB entry from the table will be placed here.
 * @return error status.
 */
int bibdb_find6(struct bib *db, const struct ipv6_transport_addr *addr,
		const l4_protocol proto, struct bib_entry **result)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_get6(table, addr, result) : -EINVAL;
}

/**
 * Append @entry to the table (from @db) it belongs.
 * @db: BIB where the entry should be inserted.
 * @entry: Row to be added to the database.
 *    Make sure you create it via bibentry_create(), please.
 * @old: If @entry collides with an already existing entry, the function will
 *    return -EEXIST and @old will point to the existing entry.
 *    If you're not interested, send NULL.
 *
 * The table's references are not supposed to count towards the entries'
 * refcounts. Do bibentry_put() your reference if your entry made it into the
 * table; do not assume you're transferring it.
 */
int bibdb_add(struct bib *db, struct bib_entry *entry, struct bib_entry **old)
{
	struct bib_table *table = get_table(db, entry->l4_proto);
	return table ? bibtable_add(table, entry, old) : -EINVAL;
}

/**
 * Runs "func" on every BIB entry after "offset".
 */
int bibdb_foreach(struct bib *db, const l4_protocol proto,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_foreach(table, func, arg, offset) : -EINVAL;
}

/**
 * Sets in the value pointed by "result" the number of entries in the database
 * whose protocol is "proto".
 */
int bibdb_count(struct bib *db, const l4_protocol proto, __u64 *result)
{
	struct bib_table *table = get_table(db, proto);
	return table ? bibtable_count(table, result) : -EINVAL;
}

/**
 * Removes the fake users of all the BIB entries whose local IPv4 address is
 * "addr4".
 */
void bibdb_delete_taddr4s(struct bib *db, const struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	bibtable_delete_taddr4s(&db->tcp, prefix, ports);
	bibtable_delete_taddr4s(&db->udp, prefix, ports);
	bibtable_delete_taddr4s(&db->icmp, prefix, ports);
}

/**
 * Removes all the fake users of all the BIB entries in the DB.
 */
void bibdb_flush(struct bib *db)
{
	log_debug("Emptying the BIB tables...");

	bibtable_flush(&db->tcp);
	bibtable_flush(&db->icmp);
	bibtable_flush(&db->udp);
}
