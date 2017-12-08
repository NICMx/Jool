#ifndef _JOOL_MOD_BLACKLIST4_H
#define _JOOL_MOD_BLACKLIST4_H

/**
 * @file
 * Pool of banned IPv4 addresses; Jool will refuse to translate these addresses.
 */

#include <net/net_namespace.h>
#include "siit/pool.h"

int blacklist_init(struct addr4_pool **pool);
void blacklist_get(struct addr4_pool *pool);
void blacklist_put(struct addr4_pool *pool);

int blacklist_add(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int blacklist_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int blacklist_flush(struct addr4_pool *pool);

bool interface_contains(struct net *ns, struct in_addr *addr);
bool blacklist_contains(struct addr4_pool *pool, struct in_addr *addr);

int blacklist_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int blacklist_count(struct addr4_pool *pool, __u64 *result);
bool blacklist_is_empty(struct addr4_pool *pool);

#endif /* _JOOL_MOD_BLACKLIST4_H */
