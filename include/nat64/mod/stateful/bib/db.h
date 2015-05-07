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

#include "nat64/mod/stateful/bib/entry.h"

int bibdb_init(void);
void bibdb_destroy(void);

int bibdb_get(const struct tuple *tuple, struct bib_entry **result);
int bibdb_get4(const struct ipv4_transport_addr *addr, const l4_protocol proto,
		struct bib_entry **result);
int bibdb_get6(const struct ipv6_transport_addr *addr, const l4_protocol proto,
		struct bib_entry **result);
void bibdb_return(struct bib_entry *bib);

int bibdb_add(struct bib_entry *entry);
int bibdb_count(const l4_protocol proto, __u64 *result);
int bibdb_flush(void);

int bibdb_delete_by_prefix4(const struct ipv4_prefix *prefix);

int bibdb_foreach(const l4_protocol proto,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset);

#endif /* _JOOL_MOD_BIB_DB_H */
