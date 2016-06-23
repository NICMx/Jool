#ifndef _JOOL_MOD_BIB_BIB_H
#define _JOOL_MOD_BIB_BIB_H

/**
 * @file
 * The Binding Information Bases.
 * Formally defined in RFC 6146 section 3.1.
 *
 * TODO rename everything to bib_
 */

#include "nat64/mod/common/types.h"
#include "nat64/mod/stateful/bib/entry.h"

struct bib;

int bibdb_init(struct bib **db);
void bibdb_get(struct bib *db);
void bibdb_put(struct bib *db);

int bibdb_find(struct bib *db, const struct tuple *tuple,
		struct bib_entry *result);
int bibdb_find4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto, struct bib_entry *result);
int bibdb_find6(struct bib *db, const struct ipv6_transport_addr *addr,
		const l4_protocol proto, struct bib_entry *result);
/* If you're looking for bibdb_contains, just do bibdb_find(blah blah, NULL) */

int bibdb_add(struct bib *db, struct bib_entry *new, struct bib_entry *old);
int bibdb_count(struct bib *db, const l4_protocol proto, __u64 *result);
void bibdb_flush(struct bib *db);

void bibdb_rm_taddr4s(struct bib *db, const struct ipv4_range *range);

int bibdb_foreach(struct bib *db, const l4_protocol proto,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset);

#endif /* _JOOL_MOD_BIB_BIB_H */
