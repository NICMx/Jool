#ifndef _JOOL_MOD_SESSION_TABLE6_H
#define _JOOL_MOD_SESSION_TABLE6_H

/**
 * The IPv6 index of the sessions.
 * It's a Red-Black tree, plain and simple.
 */

#include "nat64/mod/common/types.h"
#include "nat64/mod/stateful/session/entry.h"

struct session_table6;

struct session_table6 *st6_create(void);
void st6_destroy(struct session_table6 *table);

struct session_entry *st6_find(struct session_table6 *table,
		struct tuple *tuple6);

struct session_entry *st6_add(struct session_table6 *table,
		struct session_entry *session);
void st6_rm(struct session_table6 *table, struct session_entry *session);
void st6_flush(struct session_table6 *table);

//typedef void (*st6_destructor_cb)(struct session_entry *);
//void st6_prune_src6(struct session_table6 *table,
//		struct ipv6_transport_addr *src6,
//		st6_destructor_cb destructor);

struct session_foreach_offset {
	struct taddr6_tuple offset;
	bool include_offset;
};

struct session_foreach_func {
	int (*cb)(struct session_entry *, void *);
	void *arg;
};

int st6_foreach(struct session_table6 *table,
		struct session_foreach_func *func,
		struct session_foreach_offset *offset);

void st6_prune_range(struct session_table6 *table,
		struct ipv6_prefix *prefix,
		struct destructor_arg *destructor);

void st6_print(struct session_table6 *table);

#endif /* _JOOL_MOD_SESSION_TABLE6_H */
