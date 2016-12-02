#include "nat64/mod/stateless/rfc6791.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/in_route.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip_fib.h>

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/tags.h"

int rfc6791_init(struct addr4_pool **pool)
{
	return pool_init(pool);
}

void rfc6791_get(struct addr4_pool *pool)
{
	return pool_get(pool);
}

void rfc6791_put(struct addr4_pool *pool)
{
	return pool_put(pool);
}

int rfc6791_add(struct addr4_pool *pool, struct ipv4_prefix *prefix, bool force)
{
	return pool_add(pool, prefix, force);
}

int rfc6791_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_rm(pool, prefix);
}

int rfc6791_flush(struct addr4_pool *pool)
{
	return pool_flush(pool);
}

struct foreach_args {
	unsigned int n;
	__be32 *result;
	bool flushed;
};

static int find_nth_addr(struct ipv4_prefix *prefix, void *void_args)
{
	struct foreach_args *args = void_args;
	unsigned int count;

	args->flushed = false;

	count = prefix4_get_addr_count(prefix);
	if (count < args->n) {
		args->n -= count;
		return 0; /* Keep iterating. */
	}

	*args->result = htonl(ntohl(prefix->address.s_addr) | args->n);
	return 1; /* Success. */
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s
 * destination should be sourced with.
 */
static int get_rfc6791_address(struct xlation *state, unsigned int count,
		__be32 *result)
{
	struct foreach_args args;
	int done;

	if (state->jool.global->cfg.siit.randomize_error_addresses)
		get_random_bytes(&args.n, sizeof(args.n));
	else
		args.n = pkt_ip6_hdr(&state->in)->hop_limit;
	args.n %= count;
	args.result = result;

	/*
	 * The list can change between the last loop (the pool_count()) and the
	 * following one. So use @count and @addr_index only as a hint. That's
	 * the rationale for the do while true.
	 * Just ensure @args.n keeps decreasing.
	 */
	do {
		args.flushed = true;

		done = pool_foreach(state->jool.siit.pool6791, find_nth_addr,
				&args, NULL);
		if (done)
			return 0;

		if (args.flushed)
			return -ESRCH;
	} while (true);
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s
 * destination should be sourced with, assuming the RFC6791 pool is empty.
 */
static int get_host_address(struct xlation *state, __be32 *result)
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

	*result = saddr;
	return 0;
}

int rfc6791_find(struct xlation *state, __be32 *result)
{
	__u64 count;
	int error;

	/*
	 * I'm counting the list elements instead of using an algorithm like
	 * reservoir sampling (http://stackoverflow.com/questions/54059) because
	 * the random function can be really expensive. Reservoir sampling
	 * requires one random per iteration, this way requires one random
	 * period.
	 */
	error = pool_count(state->jool.siit.pool6791, &count);
	if (error) {
		log_debug("pool_count failed with errcode %d.", error);
		return error;
	}

	if (count != 0) {
		error = get_rfc6791_address(state, count, result);
		if (!error)
			return 0;
	}

	return get_host_address(state, result);
}

int rfc6791_for_each(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_foreach(pool, func, arg, offset);
}

int rfc6791_count(struct addr4_pool *pool, __u64 *result)
{
	return pool_count(pool, result);
}

bool rfc6791_is_empty(struct addr4_pool *pool)
{
	return pool_is_empty(pool);
}
