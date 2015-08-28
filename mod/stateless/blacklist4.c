#include "nat64/mod/stateless/blacklist4.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/stateless/pool.h"

static struct list_head * pool;

int blacklist_init(char *pref_strs[], int pref_count)
{
	if(pool)
	kfree(pool);

	pool = kmalloc(sizeof(*pool),GFP_ATOMIC);

	if(!pool)
		return -ENOMEM;

	return pool_init(pref_strs, pref_count, pool);
}

void blacklist_destroy(void)
{
	return pool_destroy(pool);
}

int blacklist_add(struct ipv4_prefix *prefix)
{
	return pool_add(pool, prefix);
}

int blacklist_remove(struct ipv4_prefix *prefix)
{
	return pool_remove(pool, prefix);
}

int blacklist_flush(void)
{
	return pool_flush(pool);
}

bool blacklist_contains(__be32 addr)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifaddr;
	struct pool_entry *entry;
	struct in_addr inaddr = { .s_addr = addr };
	struct in_addr net_addr;
	bool result = false;

	rcu_read_lock_bh();
	list_for_each_entry_rcu(entry, pool, list_hook) {
		if (prefix4_contains(&entry->prefix, &inaddr)) {
			result = true;
			goto end;
		}
	}

	for_each_netdev_rcu(&init_net, dev) {
		in_dev = rcu_dereference(dev->ip_ptr);
		ifaddr = in_dev->ifa_list;
		while (ifaddr) {
			net_addr.s_addr = ifaddr->ifa_address;
			if (ipv4_addr_cmp(&net_addr, &inaddr) == 0) {
				result = true;
				goto end;
			}
			ifaddr = ifaddr->ifa_next;
		}
	}

end:
	rcu_read_unlock_bh();
	return result;
}

int blacklist_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	return pool_for_each(pool, func, arg, offset);
}

int blacklist_count(__u64 *result)
{
	return pool_count(pool, result);
}

bool blacklist_is_empty(void)
{
	return pool_is_empty(pool);
}

struct list_head * blacklist_config_init_db(void)
{
	struct list_head * config_db;
	config_db = kmalloc(sizeof(*config_db), GFP_ATOMIC);
	INIT_LIST_HEAD(config_db);

	return config_db;
}

int blacklist_config_add(struct list_head * db, struct ipv4_prefix * entry)
{
	return pool_add(db,entry);
}

int blacklist_switch_database(struct list_head * db)
{
	if(!db)
	{
		 log_err("Error while switching blacklist database, null pointer received.");
		 return 1;
	}

	blacklist_destroy();

	pool = db;

	return 0;
}
