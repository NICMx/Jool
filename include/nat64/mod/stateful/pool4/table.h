#ifndef _JOOL_MOD_POOL4_TABLE_H
#define _JOOL_MOD_POOL4_TABLE_H

#include "nat64/mod/stateful/pool4/entry.h"

struct pool4_table {
	__u32 mark;
	struct list_head rows;
};

int pool4table_init(char *prefix_strs[], int prefix_count);
void pool4table_destroy(void);

int pool4table_add(struct pool4_table *table, struct pool4_sample *sample);
int pool4table_rm(struct pool4_table *table, struct pool4_sample *sample);
int pool4table_flush(struct pool4_table *table);

bool pool4table_contains(struct pool4_table *table,
		const struct ipv4_transport_addr *addr);
int pool4table_foreach_sample(struct pool4_table *table,
		int (*func)(struct pool4_sample *, void *), void * args,
		struct pool4_sample *offset);
int pool4table_foreach_port(struct pool4_table *table,
		int (*func)(struct ipv4_transport_addr *, void *), void *args,
		unsigned int offset);
int pool4table_count(struct pool4_table *table, __u64 *result);

#endif /* _JOOL_MOD_POOL4_TABLE_H */
