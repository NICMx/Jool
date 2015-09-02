#include "nat64/mod/stateless/blacklist4.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/stateless/pool.h"

static struct list_head pool;

int blacklist_init(char *pref_strs[], int pref_count)
{
	return pool_init(pref_strs, pref_count, &pool);
}

void blacklist_destroy(void)
{
	return pool_destroy(&pool);
}

int blacklist_add(struct ipv4_prefix *prefix)
{
	return pool_add(&pool, prefix);
}

int blacklist_remove(struct ipv4_prefix *prefix)
{
	return pool_remove(&pool, prefix);
}

int blacklist_flush(void)
{
	return pool_flush(&pool);
}

bool blacklist_contains(__be32 addr)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifaddr;
	struct pool_entry *entry;
	struct in_addr inaddr = { .s_addr = addr };
	struct in_addr net_addr;

	rcu_read_lock_bh();
	list_for_each_entry_rcu_bh(entry, &pool, list_hook) {
		if (prefix4_contains(&entry->prefix, &inaddr)) {
			rcu_read_unlock_bh();
			return true;
		}
	}
	rcu_read_unlock_bh();

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) {
		in_dev = rcu_dereference(dev->ip_ptr);
		ifaddr = in_dev->ifa_list;
		while (ifaddr) {
			net_addr.s_addr = ifaddr->ifa_address;
			if (ipv4_addr_cmp(&net_addr, &inaddr) == 0) {
				rcu_read_unlock();
				return true;
			}
			ifaddr = ifaddr->ifa_next;
		}
	}
	rcu_read_unlock();

	return false;
}

int blacklist_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_for_each(&pool, func, arg, offset);
}

int blacklist_count(__u64 *result)
{
	return pool_count(&pool, result);
}

bool blacklist_is_empty(void)
{
	return pool_is_empty(&pool);
}
