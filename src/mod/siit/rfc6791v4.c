#include "mod/siit/rfc6791v4.h"

#include <linux/inetdevice.h>
#include "mod/common/log.h"
#include "mod/common/route.h"

/**
 * Returns in @result the IPv4 address the ICMP error should be sourced with.
 */
static int get_pool_address(struct xlation *state, struct in_addr *result)
{
	struct ipv4_prefix *pool;
	__u32 n; /* We are going to return the "n"th address. */

	if (state->jool.global->cfg.siit.randomize_error_addresses)
		get_random_bytes(&n, sizeof(n));
	else
		n = pkt_ip6_hdr(&state->in)->hop_limit;

	pool = &state->jool.global->cfg.siit.rfc6791_prefix4.prefix;
	n &= ~get_prefix4_mask(pool);
	result->s_addr = cpu_to_be32(be32_to_cpu(pool->addr.s_addr) | n);

	return 0;
}

/**
 * Returns in @result the IPv4 address the ICMP error should be sourced with,
 * assuming the RFC6791 pool is empty.
 */
static int get_host_address(struct xlation *state, struct in_addr *result)
{
	struct dst_entry *dst;
	__be32 saddr;
	__be32 daddr;

	/*
	 * TODO (warning) if the ICMP error hairpins, this route4 fails so
	 * translation is not done.
	 *
	 * I'm a little stuck on how to fix it. If I assign any address, will
	 * that enhance an attacker's ability to ICMP spoof a connection?
	 * Read RFC 5927 and figure it out.
	 */

	dst = route4(state->jool.ns, &state->out);
	if (!dst)
		return -EINVAL;

	daddr = pkt_ip4_hdr(&state->out)->daddr;
	saddr = inet_select_addr(dst->dev, daddr, RT_SCOPE_LINK);

	if (!saddr) {
		log_warn_once("Can't find a proper src address to reach %pI4.",
				&daddr);
		return -EINVAL;
	}

	result->s_addr = saddr;
	return 0;
}

int rfc6791v4_find(struct xlation *state, struct in_addr *result)
{
	return state->jool.global->cfg.siit.rfc6791_prefix4.set
			? get_pool_address(state, result)
			: get_host_address(state, result);
}
