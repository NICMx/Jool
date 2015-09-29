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
#include "nat64/mod/stateless/pool.h"

static struct list_head __rcu *pool;

int rfc6791_init(char *pref_strs[], int pref_count)
{
	return pool_init(&pool, pref_strs, pref_count);
}

void rfc6791_destroy(void)
{
	return pool_destroy(pool);
}

int rfc6791_add(struct ipv4_prefix *prefix)
{
	return pool_add(pool, prefix);
}

int rfc6791_rm(struct ipv4_prefix *prefix)
{
	return pool_rm(pool, prefix);
}

int rfc6791_flush(void)
{
	return pool_flush(pool);
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s
 * destination should be sourced with.
 */
static int get_rfc6791_address(struct packet *in, __u64 count, __be32 *result)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry = NULL;
	unsigned int addr_index;

	if (config_randomize_rfc6791_pool())
		get_random_bytes(&addr_index, sizeof(addr_index));
	else
		addr_index = pkt_ip6_hdr(in)->hop_limit;

	/* unsigned int % __u64 does something weird, hence the trouble. */
	if (count <= 0xFFFFFFFFU)
		addr_index %= (unsigned int) count;

	list = rcu_dereference_bh(pool);
	list_for_each_rcu_bh(node, list) {
		entry = list_entry(node, struct pool_entry, list_hook);
		count = prefix4_get_addr_count(&entry->prefix);
		if (count >= addr_index)
			break;
		addr_index -= count;
	}

	if (!entry) {
		/* Because count is not supposed to be zero. */
		WARN(true, "The pool contents changed while locked!");
		return -ESRCH;
	}

	*result = htonl(ntohl(entry->prefix.address.s_addr) | addr_index);
	return 0;
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s
 * destination should be sourced with, assuming the RFC6791 pool is empty.
 */
static int get_host_address(struct packet *in, struct packet *out,
		__be32 *result)
{
	struct dst_entry *dst;
	__be32 saddr;
	__be32 daddr;

	/* TODO what happens if the packet hairpins? */
	/* TODO you sure secondary addresses do jack? */

	dst = route4(out);
	if (!dst)
		return -EINVAL;

	daddr = pkt_ip4_hdr(out)->daddr;
	saddr = inet_select_addr(dst->dev, daddr, RT_SCOPE_LINK);

	if (!saddr) {
		log_warn_once("Can't find a sufficiently scoped primary source "
				"address to reach %pI4.", &daddr);
		return -EINVAL;
	}

	*result = saddr;
	return 0;
}

int rfc6791_get(struct packet *in, struct packet *out, __be32 *result)
{
	__u64 count;
	int error;

	rcu_read_lock_bh();

	/*
	 * I'm counting the list elements instead of using an algorithm like
	 * reservoir sampling (http://stackoverflow.com/questions/54059) because
	 * the random function can be really expensive. Reservoir sampling
	 * requires one random per iteration, this way requires one random
	 * period.
	 */
	error = pool_count(pool, &count);
	if (error) {
		rcu_read_unlock_bh();
		log_debug("pool_count failed with errcode %d.", error);
		return error;
	}

	if (count != 0) {
		error = get_rfc6791_address(in, count, result);
		rcu_read_unlock_bh();
		return error;
	}

	rcu_read_unlock_bh();
	return get_host_address(in, out, result);
}

int rfc6791_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_foreach(pool, func, arg, offset);
}

int rfc6791_count(__u64 *result)
{
	return pool_count(pool, result);
}

bool rfc6791_is_empty(void)
{
	return pool_is_empty(pool);
}
