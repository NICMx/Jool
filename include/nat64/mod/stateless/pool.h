#ifndef _JOOL_MOD_POOL_H
#define _JOOL_MOD_POOL_H

/**
 * @file
 * This is a handler for pool of IPv4 addresses.
 *
 *
 * @author Alberto Leiva
 * @author Daniel Hdz Felix
 */

#include "nat64/mod/common/types.h"

struct pool_entry {
	struct ipv4_prefix prefix;
	struct list_head list_hook;
};

struct addr4_pool {
	struct list_head __rcu *list;
};

int pool_init(struct addr4_pool *pool, char *pref_strs[], int pref_count);
void pool_destroy(struct addr4_pool *pool);

int pool_add(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int pool_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int pool_flush(struct addr4_pool *pool);

bool pool_contains(struct addr4_pool *pool, struct in_addr *addr);
int pool_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int pool_count(struct addr4_pool *pool, __u64 *result);
bool pool_is_empty(struct addr4_pool *pool);

#endif /* _JOOL_MOD_POOL4_H */
