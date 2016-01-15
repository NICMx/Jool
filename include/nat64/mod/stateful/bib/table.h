#ifndef _JOOL_MOD_BIB_TABLE_H
#define _JOOL_MOD_BIB_TABLE_H

#include "nat64/mod/common/types.h"

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

	atomic_t log_changes;
};

/**
 * A row, intended to be part of one of the BIB tables.
 * A binding between a transport address from the IPv4 network to one from the
 * IPv6 network.
 *
 * Please note that modifications to this structure may need to cascade to
 * struct bib_entry_usr.
 */
struct bib_entry {
	/** The address from the IPv4 network. */
	const struct ipv4_transport_addr ipv4;
	/** The address from the IPv6 network. */
	const struct ipv6_transport_addr ipv6;

	/** l4 protocol used for pool4 return. */
	const l4_protocol l4_proto;

	/**
	 * Should the entry never expire?
	 *
	 * This field is currently only being used by the userspace app's code.
	 * If you want to do something else with it, keep in mind that you might
	 * face the wrath of concurrence hell, because the configuration mutex
	 * is the only thing protecting it.
	 *
	 * The kernel never needs to know whether the entry is static.
	 * Preventing the death of a static entry when it runs out of sessions
	 * is handled by adding a fake user to refcounter.
	 */
	bool is_static;

	/**
	 * Number of active references to this entry, excluding the ones from
	 * the table it belongs to.
	 * When this reaches zero, the db module removes the entry from the
	 * table and frees it.
	 */
	struct kref refcounter;

	struct bib_table *table;
	/** Appends this entry to the database's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the database's IPv4 index. */
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
void bibentry_get(struct bib_entry *bib);
int bibentry_put(struct bib_entry *bib);

void bibentry_log(const struct bib_entry *bib, const char *action);




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
