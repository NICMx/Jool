#ifndef _JOOL_MOD_BLACKLIST4_H
#define _JOOL_MOD_BLACKLIST4_H

/**
 * @file
 * Pool of banned IPv4 addresses; Jool will refuse to translate these addresses.
 */

#include <net/net_namespace.h>
#include "mod/siit/pool.h"

struct addr4_pool *blacklist4_alloc(void);
void blacklist4_get(struct addr4_pool *pool);
void blacklist4_put(struct addr4_pool *pool);

int blacklist4_add(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int blacklist4_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int blacklist4_flush(struct addr4_pool *pool);

bool interface_contains(struct net *ns, struct in_addr *addr);
bool blacklist4_contains(struct addr4_pool *pool, struct in_addr *addr);

int blacklist4_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
bool blacklist4_is_empty(struct addr4_pool *pool);

#endif /* _JOOL_MOD_BLACKLIST4_H */
