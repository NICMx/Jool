#include "nat64/mod/stateless/blacklist4.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/stateless/pool.h"

static struct list_head __rcu *pool;

int blacklist_init(char *pref_strs[], int pref_count)
{
	return pool_init(&pool, pref_strs, pref_count);
}

void blacklist_destroy(void)
{
	pool_destroy(pool);
}

int blacklist_add(struct ipv4_prefix *prefix)
{
	return pool_add(pool, prefix);
}

int blacklist_rm(struct ipv4_prefix *prefix)
{
	return pool_rm(pool, prefix);
}

int blacklist_flush(void)
{
	return pool_flush(pool);
}

static bool interface_contains(struct in_addr *addr)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifaddr;
	struct in_addr net_addr;

	rcu_read_lock();
	for_each_netdev_rcu(joolns_get(), dev) {
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

bool blacklist_contains(__be32 be_addr)
{
	struct in_addr addr = { .s_addr = be_addr };
	return pool_contains(pool, &addr) ? true : interface_contains(&addr);
}

int blacklist_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_foreach(pool, func, arg, offset);
}

int blacklist_count(__u64 *result)
{
	return pool_count(pool, result);
}

bool blacklist_is_empty(void)
{
	return pool_is_empty(pool);
}

struct list_head *blacklist_config_init_db(void)
{
	struct list_head *config_db;

	config_db = kmalloc(sizeof(*config_db), GFP_ATOMIC);
	if (!config_db) {
		log_err("Allocation of blacklist configuration database failed.");
		return NULL;
	}

	INIT_LIST_HEAD(config_db);

	return config_db;
}

int blacklist_config_add(struct list_head * db, struct ipv4_prefix * entry)
{
	return pool_add(db,entry);
}

int blacklist_switch_database(struct list_head * db)
{
	if (!db) {
		 log_err("Error while switching blacklist database, null pointer received.");
		 return 1;
	}

	blacklist_destroy();

	pool = db;

	return 0;
}
