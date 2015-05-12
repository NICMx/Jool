#ifndef _JOOL_MOD_POOL4_TABLE_H
#define _JOOL_MOD_POOL4_TABLE_H

#include "nat64/mod/stateful/pool4/entry.h"

struct pool4_table {
	__u32 mark;
	struct list_head rows;

	struct hlist_node hlist_hook;
};

struct pool4_table *pool4table_create(__u32 mark);
void pool4table_destroy(struct pool4_table *table);

int pool4table_add(struct pool4_table *table, struct pool4_sample *sample);
int pool4table_rm(struct pool4_table *table, const struct pool4_sample *sample);
void pool4table_flush(struct pool4_table *table);

bool pool4table_contains(struct pool4_table *table,
		const struct ipv4_transport_addr *addr);
bool pool4table_is_empty(struct pool4_table *table);
int pool4table_count(struct pool4_table *table, __u64 *result);

int pool4table_foreach_sample(struct pool4_table *table,
		int (*func)(struct pool4_sample *, void *), void * args,
		struct pool4_sample *offset);
int pool4table_foreach_port(struct pool4_table *table,
		int (*func)(struct ipv4_transport_addr *, void *), void *args,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_TABLE_H */
