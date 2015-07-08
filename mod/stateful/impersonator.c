#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateless/eam.h"

/**
 * @file
 * SIIT-specific functions, as linked by NAT64 code.
 *
 * These are all supposed to be unreachable code, so they're very noisy on the
 * kernel log.
 */

static int fail(const char *function_name)
{
	WARN(true, "%s() was called from SIIT code.", function_name);
	return -EINVAL;
}

int blacklist_add(struct ipv4_prefix *prefix)
{
	return fail(__func__);
}

int blacklist_remove(struct ipv4_prefix *prefix)
{
	return fail(__func__);
}

int blacklist_flush(void)
{
	return fail(__func__);
}

bool blacklist_contains(__be32 addr)
{
	fail(__func__);
	return false;
}

int blacklist_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return fail(__func__);
}

int blacklist_count(__u64 *result)
{
	return fail(__func__);
}

int rfc6791_add(struct ipv4_prefix *prefix)
{
	return fail(__func__);
}

int rfc6791_remove(struct ipv4_prefix *prefix)
{
	return fail(__func__);
}

int rfc6791_flush(void)
{
	return fail(__func__);
}

int rfc6791_get(struct packet *in, struct packet *out, __be32 *result)
{
	return fail(__func__);
}

int rfc6791_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return fail(__func__);
}

int rfc6791_count(__u64 *result)
{
	return fail(__func__);
}


int eamt_add(struct ipv6_prefix *ip6_pref, struct ipv4_prefix *ip4_pref)
{
	return fail(__func__);
}

int eamt_remove(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	return fail(__func__);
}

int eamt_flush(void)
{
	return fail(__func__);
}

bool eamt_contains_ipv4(__be32 addr)
{
	fail(__func__);
	return false;
}

int eamt_get_ipv6_by_ipv4(struct in_addr *addr, struct in6_addr *result)
{
	return fail(__func__);
}

int eamt_get_ipv4_by_ipv6(struct in6_addr *addr6, struct in_addr *result)
{
	return fail(__func__);
}

int eamt_for_each(int (*func)(struct eam_entry *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return fail(__func__);
}

int eamt_count(__u64 *count)
{
	return fail(__func__);
}

bool eamt_is_empty(void)
{
	fail(__func__);
	return true;
}
