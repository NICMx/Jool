#ifndef _JOOL_MOD_POOL4_EMPTY_H
#define _JOOL_MOD_POOL4_EMPTY_H

#include "nat64/mod/stateful/pool4/entry.h"
#include "nat64/mod/stateful/pool4/table.h"


bool pool4empty_contains(struct pool4_table *table,
		const struct ipv4_transport_addr *addr);
int pool4empty_foreach_taddr4(struct pool4_table *table,
		int (*func)(struct ipv4_transport_addr *, void *), void *args,
		unsigned int offset);


#endif /* _JOOL_MOD_POOL4_EMPTY_H */
