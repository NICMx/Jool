#ifndef _JOOL_MOD_BIB_DB_H
#define _JOOL_MOD_BIB_DB_H

/**
 * @file
 * The Binding Information Bases.
 * Formally defined in RFC 6146 section 3.1.
 *
 * @author Alberto Leiva
 * @author Daniel Hernandez
 */

#include "nat64/mod/stateful/bib/table.h"

struct bib {
	/** The BIB table for TCP connections. */
	struct bib_table tcp;
	/** The BIB table for UDP connections. */
	struct bib_table udp;
	/** The BIB table for ICMP connections. */
	struct bib_table icmp;

	struct kref refcounter;
};

int bibdb_init(struct bib **db);
void bibdb_get(struct bib *db);
void bibdb_put(struct bib *db);

int bibdb_find(struct bib *db, const struct tuple *tuple,
		struct bib_entry **result);
int bibdb_find4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto, struct bib_entry **result);
int bibdb_find6(struct bib *db, const struct ipv6_transport_addr *addr,
		const l4_protocol proto, struct bib_entry **result);

int bibdb_add(struct bib *db, struct bib_entry *entry);
int bibdb_count(struct bib *db, const l4_protocol proto, __u64 *result);
void bibdb_flush(struct bib *db);

void bibdb_delete_taddr4s(struct bib *db, const struct ipv4_prefix *prefix,
		struct port_range *ports);

bool bibdb_contains4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto);
int bibdb_foreach(struct bib *db, const l4_protocol proto,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset);

#endif /* _JOOL_MOD_BIB_DB_H */
