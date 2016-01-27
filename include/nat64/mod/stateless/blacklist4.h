#ifndef _JOOL_MOD_BLACKLIST4_H
#define _JOOL_MOD_BLACKLIST4_H

/**
 * @file
 * Pool of banned IPv4 addresses; Jool will refuse to translate these addresses.
 *
 * @author Alberto Leiva
 * @author Daniel Hdz Felix
 */

#include <net/net_namespace.h>
#include "nat64/mod/stateless/pool.h"

/* TODO remove lots of these functions; they are just clutter. */

int blacklist_init(struct addr4_pool **pool, char *pref_strs[], int pref_count);
void blacklist_get(struct addr4_pool *pool);
void blacklist_put(struct addr4_pool *pool);

int blacklist_add(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int blacklist_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int blacklist_flush(struct addr4_pool *pool);
bool blacklist_contains(struct addr4_pool *pool, struct net *ns, __be32 addr);

int blacklist_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int blacklist_count(struct addr4_pool *pool, __u64 *result);
bool blacklist_is_empty(struct addr4_pool *pool);

#endif /* _JOOL_MOD_BLACKLIST4_H */
