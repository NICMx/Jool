#include "common/types.h"
#include "mod/common/address_xlat.h"
#include "mod/common/packet.h"
#include "mod/common/db/blacklist4.h"
#include "mod/common/db/eam.h"
#include "mod/common/db/rfc6791v4.h"
#include "mod/common/db/rfc6791v6.h"

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

struct addr4_pool *blacklist4_alloc(void)
{
	fail(__func__);
	return NULL;
}

void blacklist4_get(struct addr4_pool *pool)
{
	fail(__func__);
}

void blacklist4_put(struct addr4_pool *pool)
{
	fail(__func__);
}

bool interface_contains(struct net *ns, struct in_addr *addr)
{
	fail(__func__);
	return false;
}

bool blacklist4_contains(struct addr4_pool *pool, struct in_addr *addr)
{
	fail(__func__);
	return false;
}

int rfc6791v4_find(struct xlation *state, struct in_addr *result)
{
	return fail(__func__);
}

int rfc6791v6_find(struct xlation *state, struct in6_addr *result)
{
	return fail(__func__);
}

struct eam_table *eamt_alloc(void)
{
	fail(__func__);
	return NULL;
}

void eamt_get(struct eam_table *eamt)
{
	fail(__func__);
}

void eamt_put(struct eam_table *eamt)
{
	fail(__func__);
}

int eamt_add(struct eam_table *eamt, struct eamt_entry *new, bool force)
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
		struct result_addrxlat46 *result)
{
	return fail(__func__);
}

int eamt_xlat_6to4(struct eam_table *eamt, struct in6_addr *addr6,
		struct result_addrxlat64 *result)
{
	return fail(__func__);
}

int eamt_foreach(struct eam_table *eamt,
		eamt_foreach_cb cb, void *arg,
		struct ipv4_prefix *offset)
{
	return fail(__func__);
}

bool eamt_is_empty(struct eam_table *eamt)
{
	fail(__func__);
	return true;
}

struct addr4_pool *pool_alloc(void)
{
	fail(__func__);
	return NULL;
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

static struct addrxlat_result fail_addr(void)
{
	static const struct addrxlat_result result = {
		.verdict = ADDRXLAT_DROP,
		.reason = "Stateful NAT64 doesn't do stateless address translation.",
	};

	fail(__func__);
	return result;
}

struct addrxlat_result addrxlat_siit64(struct xlator *instance,
		struct in6_addr *in, struct result_addrxlat64 *out)
{
	return fail_addr();
}

struct addrxlat_result addrxlat_siit46(struct xlator *instance,
		__be32 in, struct result_addrxlat46 *out,
		bool enable_eam, bool enable_blacklists)
{
	return fail_addr();
}

bool is_hairpin_siit(struct xlation *state)
{
	fail(__func__);
	return false;
}

verdict handling_hairpinning_siit(struct xlation *old)
{
	fail(__func__);
	return VERDICT_DROP;
}
