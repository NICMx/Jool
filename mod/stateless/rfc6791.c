#include "nat64/mod/stateless/rfc6791.h"

#include <linux/rculist.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/random.h"
#include "nat64/mod/stateless/pool.h"

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

static int pool_count_wrapper(unsigned int *result)
{
	__u64 tmp;
	int error;

	error = pool_count(&pool, &tmp);
	if (error)
		return error;

	*result = (unsigned int) tmp;
	return 0;
}

static int get_host_address(struct in_addr *result)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifaddr;
	unsigned int address_count, iterator_count;
	unsigned int rand;

	/* First iterate and count all the host IPv4 addresses. */
	address_count = 0;
	for_each_netdev_rcu(&init_net, dev) {
		in_dev = rcu_dereference(dev->ip_ptr);
		ifaddr = in_dev->ifa_list;
		while (ifaddr) {
			if (IN_LOOPBACK(ntohl(ifaddr->ifa_address))) {
				ifaddr = ifaddr->ifa_next;
				continue;
			}
			address_count++;
			ifaddr = ifaddr->ifa_next;
		}
	}

	if (address_count == 0)
		return -EEXIST;

	rand = get_random_u32() % address_count;

	/* Now get a random IPv4 address from the host. */
	iterator_count = 0;
	for_each_netdev_rcu(&init_net, dev) {
		in_dev = rcu_dereference(dev->ip_ptr);
		ifaddr = in_dev->ifa_list;
		while (ifaddr) {
			if (IN_LOOPBACK(ntohl(ifaddr->ifa_address))) {
				ifaddr = ifaddr->ifa_next;
				continue;
			}
			if (rand == iterator_count) {
				result->s_addr = ifaddr->ifa_address;
				return 0;
			}
			iterator_count++;
			ifaddr = ifaddr->ifa_next;
		}
	}

	log_err("Something went wrong; looks like the net_device's IPv4 address was modified.");
	return -EINVAL;
}

int rfc6791_get(struct in_addr *result)
{
	struct pool_entry *entry;
	unsigned int count;
	unsigned int rand;
	int error;

	rcu_read_lock();

	/*
	 * I'm counting the list elements instead of using an algorithm like reservoir sampling
	 * (http://stackoverflow.com/questions/54059) because the random function can be really
	 * expensive. Reservoir sampling requires one random per iteration, this way requires one
	 * random period.
	 */
	error = pool_count_wrapper(&count);
	if (error) {
		rcu_read_unlock();
		log_debug("pool_count failed with errcode %d.", error);
		return error;
	}

	if (count == 0) {
		error = get_host_address(result);
		goto end;
	}

	rand = get_random_u32() % count;

	list_for_each_entry_rcu(entry, &pool, list_hook) {
		count = prefix4_get_addr_count(&entry->prefix);
		if (count >= rand)
			break;
		rand -= count;
	}

	result->s_addr = htonl(ntohl(entry->prefix.address.s_addr) | rand);

end:
	rcu_read_unlock();
	if (error)
		log_warn_once("The IPv4 RFC6791 pool and the Host's IPv4 address are empty.");
	return error;
}

int rfc6791_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg)
{
	return pool_for_each(&pool, func, arg);
}

int rfc6791_count(__u64 *result)
{
	return pool_count(&pool, result);
}

bool rfc6791_is_empty(void)
{
	return pool_is_empty(&pool);
}
