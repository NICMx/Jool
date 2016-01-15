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

int rfc6791_init(struct addr4_pool **pool, char *pref_strs[], int pref_count)
{
	return pool_init(pool, pref_strs, pref_count);
}

void rfc6791_get(struct addr4_pool *pool)
{
	return pool_get(pool);
}

void rfc6791_put(struct addr4_pool *pool)
{
	return pool_put(pool);
}

int rfc6791_add(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_add(pool, prefix);
}

int rfc6791_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_rm(pool, prefix);
}

int rfc6791_flush(struct addr4_pool *pool)
{
	return pool_flush(pool);
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s
 * destination should be sourced with.
 *
 * TODO validate count never surpasses uint max.
 */
static int get_rfc6791_address(struct xlation *state, unsigned int count,
		__be32 *result)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;
	unsigned int addr_index;
	int error = 0;

	if (state->jool.global->cfg.siit.randomize_error_addresses)
		get_random_bytes(&addr_index, sizeof(addr_index));
	else
		addr_index = pkt_ip6_hdr(&state->in)->hop_limit;
	addr_index %= count;

	/*
	 * The list can change between the last loop (the pool_count()) and the
	 * following one. So use @cound and @addr_index only as a hint. That's
	 * the rationale for the do while true.
	 * Just ensure @addr_index keeps decreasing.
	 */

	rcu_read_lock_bh();
	list = rcu_dereference_bh(state->jool.siit.pool6791->list);
	do {
		list_for_each_rcu_bh(node, list) {
			entry = list_entry(node, struct pool_entry, list_hook);
			count = prefix4_get_addr_count(&entry->prefix);
			if (count >= addr_index)
				goto success;
			addr_index -= count;
		}

		if (list_empty(list)) {
			error = -ESRCH;
			goto end;
		}
	} while (true);

success:
	*result = htonl(ntohl(entry->prefix.address.s_addr) | addr_index);
end:
	rcu_read_unlock_bh();
	return error;
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

	/* TODO what happens if the packet hairpins? */

	dst = route4(state->jool.ns, &state->out);
	if (!dst)
		return -EINVAL;

	daddr = pkt_ip4_hdr(&state->out)->daddr;
	saddr = inet_select_addr(dst->dev, daddr, RT_SCOPE_LINK);

	if (!saddr) {
		log_warn_once("Can't find a sufficiently scoped primary source "
				"address to reach %pI4.", &daddr);
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
