#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateless/blacklist4.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/rfc6791.h"

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

int blacklist_rm(struct ipv4_prefix *prefix)
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

int rfc6791_add(struct ipv4_prefix *prefix, bool force)
{
	return fail(__func__);
}

int rfc6791_rm(struct ipv4_prefix *prefix)
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


int eamt_add(struct ipv6_prefix *ip6_pref, struct ipv4_prefix *ip4_pref,
		bool force)
{
	return fail(__func__);
}

int eamt_rm(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	return fail(__func__);
}

void eamt_flush(void)
{
	fail(__func__);
}

bool eamt_contains4(__be32 addr)
{
	fail(__func__);
	return false;
}

int eamt_xlat_4to6(struct in_addr *addr, struct in6_addr *result)
{
	return fail(__func__);
}

int eamt_xlat_6to4(struct in6_addr *addr6, struct in_addr *result)
{
	return fail(__func__);
}

int eamt_foreach(int (*cb)(struct eamt_entry *, void *), void *arg,
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
