#include "nat64/mod/stateless/rfc6791.h"

#include <linux/rculist.h>
#include <linux/inet.h>

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

static unsigned int get_addr_count(struct ipv4_prefix *prefix)
{
	return 1 << (32 - prefix->len);
}

static unsigned int rfc6791_get_prefix_count(void)
{
	return pool_get_prefix_count(&pool);
}

int rfc6791_get(struct in_addr *result)
{
	struct pool_entry *entry;
	unsigned int count;
	unsigned int rand;

	rcu_read_lock();

	/*
	 * I'm counting the list elements instead of using an algorithm like reservoir sampling
	 * (http://stackoverflow.com/questions/54059) because the random function can be really
	 * expensive. Reservoir sampling requires one random per iteration, this way requires one
	 * random period.
	 */
	count = rfc6791_get_prefix_count();
	if (count == 0) {
		rcu_read_unlock();
		log_warn_once("The IPv4 RFC6791 pool is empty.");
		return -EEXIST;
	}

	rand = get_random_u32() % count;

	list_for_each_entry_rcu(entry, &pool, list_hook) {
		count = get_addr_count(&entry->prefix);
		if (count >= rand)
			break;
		rand -= count;
	}

	result->s_addr = htonl(ntohl(entry->prefix.address.s_addr) | rand);

	rcu_read_unlock();
	return 0;
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
