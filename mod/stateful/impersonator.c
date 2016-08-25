#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateless/blacklist4.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/rfc6791.h"
#include "nat64/mod/stateless/rfc6791v6.h"

/**
 * @file
 * SIIT-specific functions, as linked by NAT64 code.
 *
 * These are all supposed to be unreachable code, so they're very noisy on the
 * kernel log.
 */

static int fail(const char *function_name)
{
	WARN(true, "%s() was called from NAT64 code.", function_name);
	return -EINVAL;
}

int blacklist_init(struct addr4_pool **pool)
{
	return fail(__func__);
}

void blacklist_get(struct addr4_pool *pool)
{
	fail(__func__);
}

void blacklist_put(struct addr4_pool *pool)
{
	fail(__func__);
}

bool interface_contains(struct net *ns, struct in_addr *addr)
{
	fail(__func__);
	return false;
}

bool blacklist_contains(struct addr4_pool *pool, struct in_addr *addr)
{
	fail(__func__);
	return false;
}

int rfc6791_init(struct addr4_pool **pool)
{
	return fail(__func__);
}

void rfc6791_get(struct addr4_pool *pool)
{
	fail(__func__);
}

void rfc6791_put(struct addr4_pool *pool)
{
	fail(__func__);
}

int rfc6791_find(struct xlation *state, __be32 *result)
{
	return fail(__func__);
}

int rfc6791_find_v6(struct xlation *state, struct in6_addr *result)
{
	return fail(__func__);
}

int eamt_init(struct eam_table **eamt)
{
	return fail(__func__);
}

void eamt_get(struct eam_table *eamt)
{
	fail(__func__);
}

void eamt_put(struct eam_table *eamt)
{
	fail(__func__);
}

int eamt_add(struct eam_table *eamt, struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4, bool force)
{
	return fail(__func__);
}

int eamt_rm(struct eam_table *eamt, struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	return fail(__func__);
}

void eamt_flush(struct eam_table *eamt)
{
	fail(__func__);
}

bool eamt_contains4(struct eam_table *eamt, __be32 addr)
{
	fail(__func__);
	return false;
}

int eamt_xlat_4to6(struct eam_table *eamt, struct in_addr *addr4,
		struct in6_addr *result)
{
	return fail(__func__);
}

int eamt_xlat_6to4(struct eam_table *eamt, struct in6_addr *addr6,
		struct in_addr *result)
{
	return fail(__func__);
}

int eamt_foreach(struct eam_table *eamt,
		int (*cb)(struct eamt_entry *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return fail(__func__);
}

int eamt_count(struct eam_table *eamt, __u64 *count)
{
	return fail(__func__);
}

bool eamt_is_empty(struct eam_table *eamt)
{
	fail(__func__);
	return true;
}

int pool_init(struct addr4_pool **pool)
{
	return fail(__func__);
}

void pool_put(struct addr4_pool *pool)
{
	fail(__func__);
}

int pool_add(struct addr4_pool *pool, struct ipv4_prefix *prefix, bool force)
{
	return fail(__func__);
}

int pool_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return fail(__func__);
}

int pool_flush(struct addr4_pool *pool)
{
	return fail(__func__);
}

int pool_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return fail(__func__);
}

int pool_count(struct addr4_pool *pool, __u64 *result)
{
	return fail(__func__);
}
