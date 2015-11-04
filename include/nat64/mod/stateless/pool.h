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

int pool_init(struct list_head __rcu **pool, char *pref_strs[], int pref_count);
void pool_destroy(struct list_head __rcu *pool);

int pool_add(struct list_head __rcu *pool, struct ipv4_prefix *prefix);
int pool_rm(struct list_head __rcu *pool, struct ipv4_prefix *prefix);
int pool_flush(struct list_head __rcu *pool);

bool pool_contains(struct list_head __rcu *pool, struct in_addr *addr);
int pool_foreach(struct list_head __rcu *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int pool_count(struct list_head __rcu *pool, __u64 *result);
bool pool_is_empty(struct list_head __rcu *pool);

#endif /* _JOOL_MOD_POOL4_H */
