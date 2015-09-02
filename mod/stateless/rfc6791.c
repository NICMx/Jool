#include "nat64/mod/stateless/rfc6791.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/in_route.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip_fib.h>

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateless/pool.h"
#include "nat64/mod/common/route.h"

static struct list_head pool;

int rfc6791_init(char *pref_strs[], int pref_count)
{
	return pool_init(pref_strs, pref_count, &pool);
}

void rfc6791_destroy(void)
{
	return pool_destroy(&pool);
}

int rfc6791_add(struct ipv4_prefix *prefix)
{
	return pool_add(&pool, prefix);
}

int rfc6791_remove(struct ipv4_prefix *prefix)
{
	return pool_remove(&pool, prefix);
}

int rfc6791_flush(void)
{
	return pool_flush(&pool);
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s destination should be sourced
 * with.
 */
static int get_rfc6791_address(struct packet *in, __u64 count, __be32 *result)
{
	struct pool_entry *entry;
	unsigned int addr_index;

	if (config_randomize_rfc6791_pool())
		get_random_bytes(&addr_index, sizeof(addr_index));
	else
		addr_index = pkt_ip6_hdr(in)->hop_limit;

	/* unsigned int % __u64 does something weird, hence the trouble. */
	if (count <= 0xFFFFFFFFU)
		addr_index %= (unsigned int) count;

	rcu_read_lock_bh();
	list_for_each_entry_rcu_bh(entry, &pool, list_hook) {
		count = prefix4_get_addr_count(&entry->prefix);
		if (count >= addr_index)
			break;
		addr_index -= count;
	}
	rcu_read_unlock_bh();

	*result = htonl(ntohl(entry->prefix.address.s_addr) | addr_index);
	return 0;
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s destination should be sourced
 * with, assuming the RFC6791 pool is empty.
 */
static int get_host_address(struct packet *in, struct packet *out, __be32 *result)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifaddr;
	int error;

	error = __route4(in, out);
	if (error)
		return error;

	dev = out->skb->dev;

	rcu_read_lock();
	in_dev = rcu_dereference(dev->ip_ptr);
	ifaddr = in_dev->ifa_list;
	while (ifaddr) {
		if (IN_LOOPBACK(ntohl(ifaddr->ifa_address))) {
			ifaddr = ifaddr->ifa_next;
			continue;
		}
		*result = ifaddr->ifa_address;
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	log_warn_once("The kernel routed an IPv4 packet via device %s, which doesn't have any "
			"(non-loopback) IPv4 addresses.", dev->name);
	return -EINVAL;
}

int rfc6791_get(struct packet *in, struct packet *out, __be32 *result)
{
	__u64 count;
	int error;

	/*
	 * I'm counting the list elements instead of using an algorithm like reservoir sampling
	 * (http://stackoverflow.com/questions/54059) because the random function can be really
	 * expensive. Reservoir sampling requires one random per iteration, this way requires one
	 * random period.
	 */
	error = pool_count(&pool, &count);
	if (error) {
		log_debug("pool_count failed with errcode %d.", error);
		return error;
	}

	return (count != 0)
			? get_rfc6791_address(in, count, result)
			: get_host_address(in, out, result);
}

int rfc6791_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_for_each(&pool, func, arg, offset);
}

int rfc6791_count(__u64 *result)
{
	return pool_count(&pool, result);
}

bool rfc6791_is_empty(void)
{
	return pool_is_empty(&pool);
}
