#ifndef _JOOL_MOD_BIB_TABLE_H
#define _JOOL_MOD_BIB_TABLE_H

#include "nat64/mod/stateful/bib/entry.h"

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
	 * The entries are immutable, and when they're part of the database,
	 * they can only be killed by bib_release(), which spinlockly deletes
	 * them from the trees first.
	 */
	spinlock_t lock;
};

void bibtable_init(struct bib_table *table);
void bibtable_destroy(struct bib_table *table);

int bibtable_add(struct bib_table *table, struct bib_entry *entry);
void bibtable_rm(struct bib_table *table, struct bib_entry *entry);
void bibtable_flush(struct bib_table *table);
void bibtable_delete_taddr4s(struct bib_table *table,
		const struct ipv4_prefix *prefix, struct port_range *ports);

int bibtable_get6(struct bib_table *table,
		const struct ipv6_transport_addr *addr,
		struct bib_entry **result);
int bibtable_get4(struct bib_table *table,
		const struct ipv4_transport_addr *addr,
		struct bib_entry **result);
bool bibtable_contains4(struct bib_table *table,
		const struct ipv4_transport_addr *addr);

int bibtable_count(struct bib_table *table, __u64 *result);
int bibtable_foreach(struct bib_table *table,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset);

#endif /* _JOOL_MOD_BIB_TABLE_H */
