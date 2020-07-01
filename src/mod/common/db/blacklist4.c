#include "blacklist4.h"

#include "mod/common/dev.h"
#include "mod/common/address.h"
#include "mod/common/xlator.h"
#include "mod/common/rcu.h"

/* TODO (fine) fuse this module and pool.c */

struct addr4_pool *blacklist4_alloc(void)
{
	return pool_alloc();
}

void blacklist4_get(struct addr4_pool *pool)
{
	pool_get(pool);
}

void blacklist4_put(struct addr4_pool *pool)
{
	pool_put(pool);
}

int blacklist4_add(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_add(pool, prefix, false);
}

int blacklist4_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_rm(pool, prefix);
}

int blacklist4_flush(struct addr4_pool *pool)
{
	return pool_flush(pool);
}

#define NOT_BLACKLISTED false
#define BLACKLISTED true

/* "Check interface address" */
static int check_ifa(struct in_ifaddr *ifa, void const *arg)
{
	struct in_addr const *query = arg;
	struct in_addr ifaddr;

	/* Broadcast */
	/* (RFC3021: /31 and /32 networks lack broadcast) */
	if (ifa->ifa_prefixlen < 31) {
		ifaddr.s_addr = ifa->ifa_local | ~ifa->ifa_mask;
		if (ipv4_addr_cmp(&ifaddr, query) == 0)
			return BLACKLISTED;
	}

	/* Secondary addresses */
	/* https://github.com/NICMx/Jool/issues/223 */
	if (ifa->ifa_flags & IFA_F_SECONDARY)
		return NOT_BLACKLISTED;

	/* Primary addresses */
	ifaddr.s_addr = ifa->ifa_local;
	if (ipv4_addr_cmp(&ifaddr, query) == 0)
		return BLACKLISTED;

	return NOT_BLACKLISTED;
}

/**
 * Is @addr *NOT* translatable, according to the interfaces?
 *
 * The name comes from the fact that interface addresses are usually
 * non-translatable (ie. the traffic is meant for the translator box).
 *
 * Recognizable directed broadcast is also not translatable.
 */
bool interface_contains(struct net *ns, struct in_addr *addr)
{
	return foreach_ifa(ns, check_ifa, addr);
}

bool blacklist4_contains(struct addr4_pool *pool, struct in_addr *addr)
{
	return pool_contains(pool, addr);
}

int blacklist4_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_foreach(pool, func, arg, offset);
}

bool blacklist4_is_empty(struct addr4_pool *pool)
{
	return pool_is_empty(pool);
}
