#include "nat64/mod/stateless/blacklist4.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/rcu.h"

int blacklist_init(struct addr4_pool **pool, char *pref_strs[], int pref_count)
{
	return pool_init(pool, pref_strs, pref_count);
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
	return pool_add(pool, prefix);
}

int blacklist_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	return pool_rm(pool, prefix);
}

int blacklist_flush(struct addr4_pool *pool)
{
	return pool_flush(pool);
}

static bool interface_contains(struct net *ns, struct in_addr *addr)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifaddr;
	struct in_addr net_addr;

	rcu_read_lock();
	for_each_netdev_rcu(ns, dev) {
		in_dev = rcu_dereference(dev->ip_ptr);
		ifaddr = in_dev->ifa_list;
		while (ifaddr) {
			net_addr.s_addr = ifaddr->ifa_address;
			if (ipv4_addr_cmp(&net_addr, addr) == 0) {
				rcu_read_unlock();
				return true;
			}
			ifaddr = ifaddr->ifa_next;
		}
	}
	rcu_read_unlock();

	return false;
}

bool blacklist_contains(struct addr4_pool *pool, struct net *ns, __be32 be_addr)
{
	struct in_addr addr = { .s_addr = be_addr };
	return pool_contains(pool, &addr) ? true : interface_contains(ns, &addr);
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
