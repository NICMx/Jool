#ifndef _JOOL_MOD_BIB_TABLE_H
#define _JOOL_MOD_BIB_TABLE_H

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/types.h"

/*
 * Note: If your code is a BIB user, you probably do not want to use most of
 * these functions directly.
 * bib/db.h is the API intended for the rest of Jool. It is also better
 * documented (see bib/db.c).
 */

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
	 * This protects the structure of the trees and certain entry fields.
	 */
	spinlock_t lock;

	bool log_changes;
};

/**
 * A row, intended to be part of one of the BIB tables.
 * It dictates which IPv4 transport address is being used to mask a given IPv6
 * (transport) client.
 *
 * Please note that modifications to this structure may need to cascade to
 * struct bib_entry_usr.
 */
struct bib_entry {
	/** The mask. */
	const struct ipv4_transport_addr ipv4;
	/** The service/client being masked. */
	const struct ipv6_transport_addr ipv6;

	/** Protocol of the channel. */
	const l4_protocol l4_proto;

	/**
	 * Should the entry never expire?
	 *
	 * If the entry belongs to a table, you *MUST* hold the table's lock
	 * while reading or writing on this field.
	 */
	bool is_static;

	/**
	 * Reference counter that dictates when the entry should be released
	 * from memory.
	 *
	 * - Each thread referencing this entry holds +1 reference.
	 * - +1 if the database is referencing this entry. (ie. @db_refs > 0)
	 */
	struct kref mem_refs;
	/**
	 * Reference counter that dictates when the entry should be removed from
	 * its table. (Each entry can only be referenced by one table at a
	 * time.)
	 *
	 * - Each session referencing this entry holds +1 reference.
	 * - There's a +1 fake user if the entry is static.
	 */
	atomic_t db_refs;

	/** The table currently holding this entry. */
	struct bib_table *table;
	/** Appends this entry to the table's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the table's IPv4 index. */
	struct rb_node tree4_hook;

	/**
	 * A reference for the IPv4 borrowed from pool4, this is hold it just
	 * for keeping the host6_node alive in the database.
	 */
	struct host_addr4 *host4_addr;
};

int bibentry_init(void);
void bibentry_destroy(void);

struct bib_entry *bibentry_create(const struct ipv4_transport_addr *addr4,
		const struct ipv6_transport_addr *addr6,
		const bool is_static, const l4_protocol proto);
struct bib_entry *bibentry_create_usr(struct bib_entry_usr *usr);

void bibentry_get_db(struct bib_entry *bib);
int bibentry_put_db(struct bib_entry *bib);
void bibentry_get_thread(struct bib_entry *bib);
void bibentry_put_thread(struct bib_entry *bib, bool must_die);

bool bibentry_equals(const struct bib_entry *b1, const struct bib_entry *b2);
void bibentry_log(const struct bib_entry *bib, const char *action);




void bibtable_init(struct bib_table *table);
void bibtable_destroy(struct bib_table *table);

void bibtable_config_clone(struct bib_table *table, struct bib_config *config);
void bibtable_config_set(struct bib_table *table, struct bib_config *config);

int bibtable_add(struct bib_table *table, struct bib_entry *entry,
		struct bib_entry **old);
void bibtable_flush(struct bib_table *table);
void bibtable_rm_taddr4s(struct bib_table *table,
		const struct ipv4_prefix *prefix, struct port_range *ports);

int bibtable_find6(struct bib_table *table,
		const struct ipv6_transport_addr *addr,
		struct bib_entry **result);
int bibtable_find4(struct bib_table *table,
		const struct ipv4_transport_addr *addr,
		struct bib_entry **result);

int bibtable_count(struct bib_table *table, __u64 *result);
int bibtable_foreach(struct bib_table *table,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset);

#endif /* _JOOL_MOD_BIB_TABLE_H */
