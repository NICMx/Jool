#ifndef _JOOL_MOD_POOL4_TABLE_H
#define _JOOL_MOD_POOL4_TABLE_H

#include "nat64/mod/stateful/pool4/entry.h"

struct pool4_table {
	__u32 mark;
	struct list_head rows;

	struct hlist_node hlist_hook;
};

/*
 * Write functions (Caller must prevent concurrence)
 */

struct pool4_table *pool4table_create(__u32 mark);
void pool4table_destroy(struct pool4_table *table);

int pool4table_add(struct pool4_table *table, struct ipv4_prefix *prefix,
		struct port_range *ports);
int pool4table_rm(struct pool4_table *table, struct ipv4_prefix *prefix,
		struct port_range *ports);

/*
 * Read functions (Legal to use anywhere - caller must lock RCU, though)
 */

bool pool4table_contains(struct pool4_table *table,
		const struct ipv4_transport_addr *addr);
bool pool4table_is_empty(struct pool4_table *table);
void pool4table_count(struct pool4_table *table, __u64 *samples, __u64 *taddrs);

int pool4table_foreach_sample(struct pool4_table *table,
		int (*func)(struct pool4_sample *, void *), void * args,
		struct pool4_sample *offset);
int pool4table_foreach_taddr4(struct pool4_table *table,
		int (*func)(struct ipv4_transport_addr *, void *), void *args,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_TABLE_H */
