#include "nat64/mod/stateless/blacklist4.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/rcu.h"

int blacklist_init(struct addr4_pool **pool)
{
	return pool_init(pool);
}

void blacklist_get(struct addr4_pool *pool)
{
	pool_get(pool);
}

void blacklist_put(struct addr4_pool *pool)
{
	pool_put(pool);
}

int blacklist_add(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_add(pool, prefix, false);
}

int blacklist_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_rm(pool, prefix);
}

int blacklist_flush(struct addr4_pool *pool)
{
	return pool_flush(pool);
}

/**
 * Is @addr present in one of @ns's interfaces?
 * Will also return true of @addr is the broadcast address of one of @ns's
 * interfaces.
 */
bool interface_contains(struct net *ns, struct in_addr *addr)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	struct in_addr ifaddr;

	rcu_read_lock();
	for_each_netdev_rcu(ns, dev) {
		in_dev = rcu_dereference(dev->ip_ptr);
		ifa = in_dev->ifa_list;
		while (ifa) {
			ifaddr.s_addr = ifa->ifa_local;
			if (ipv4_addr_cmp(&ifaddr, addr) == 0)
				goto found;

			ifaddr.s_addr = ifa->ifa_local | ~ifa->ifa_mask;
			if (ipv4_addr_cmp(&ifaddr, addr) == 0)
				goto found;

			ifa = ifa->ifa_next;
		}
	}
	rcu_read_unlock();

	return false;

found:
	rcu_read_unlock();
	return true;
}

bool blacklist_contains(struct addr4_pool *pool, struct in_addr *addr)
{
	return pool_contains(pool, addr);
}

int blacklist_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_foreach(pool, func, arg, offset);
}

int blacklist_count(struct addr4_pool *pool, __u64 *result)
{
	return pool_count(pool, result);
}

bool blacklist_is_empty(struct addr4_pool *pool)
{
	return pool_is_empty(pool);
}
