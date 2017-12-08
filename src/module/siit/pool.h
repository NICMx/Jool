#ifndef _JOOL_MOD_POOL_H
#define _JOOL_MOD_POOL_H

/**
 * @file
 * This is a handler for pool of IPv4 addresses.
 */

#include "types.h"

struct addr4_pool;

/* Do-not-use-when-you-can't-sleep-functions */

int pool_init(struct addr4_pool **pool);
void pool_get(struct addr4_pool *pool);
void pool_put(struct addr4_pool *pool);

int pool_add(struct addr4_pool *pool, struct ipv4_prefix *prefix, bool force);
int pool_add_str(struct addr4_pool *pool, char *pref_strs[], int pref_count);
int pool_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int pool_flush(struct addr4_pool *pool);

/* Safe-to-use-during-packet-translation functions */

bool pool_contains(struct addr4_pool *pool, struct in_addr *addr);
int pool_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int pool_count(struct addr4_pool *pool, __u64 *result);
bool pool_is_empty(struct addr4_pool *pool);
void pool_print_refcount(struct addr4_pool *pool);

#endif /* _JOOL_MOD_POOL_H */
