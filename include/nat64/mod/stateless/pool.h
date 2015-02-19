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

int pool_init(char *pref_strs[], int pref_count, struct list_head *pool);

void pool_destroy(struct list_head *pool);

int pool_add(struct list_head *pool, struct ipv4_prefix *prefix);

int pool_remove(struct list_head *pool, struct ipv4_prefix *prefix);

int pool_flush(struct list_head *pool);

unsigned int pool_get_prefix_count(struct list_head *pool);

int pool_for_each(struct list_head *pool, int (*func)(struct ipv4_prefix *, void *), void *arg);

int pool_count(struct list_head *pool, __u64 *result);

bool pool_is_empty(struct list_head *pool);

#endif /* _JOOL_MOD_POOL4_H */
