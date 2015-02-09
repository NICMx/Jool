#include "nat64/mod/stateless/pool4.h"

#include <linux/rculist.h>
#include <linux/inet.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/random.h"

struct pool_entry {
	struct ipv4_prefix prefix;
	struct list_head list_hook;
};

static struct list_head pool;

static int parse_prefix4(const char *str, struct ipv4_prefix *prefix)
{
	const char *slash_pos;
	int error = 0;

	if (strchr(str, '/') != 0) {
		if (in4_pton(str, -1, (u8 *) &prefix->address, '/', &slash_pos) != 1)
			error = -EINVAL;
		if (kstrtou8(slash_pos + 1, 0, &prefix->len) != 0)
			error = -EINVAL;
	} else {
		error = str_to_addr4(str, &prefix->address);
		prefix->len = 32;
	}

	if (error)
		log_err("IPv4 address or prefix is malformed: %s.", str);

	return error;
}

int pool4_init(char *pref_strs[], int pref_count)
{
	struct pool_entry *entry;
	unsigned int i;
	int error;

	INIT_LIST_HEAD(&pool);

	for (i = 0; i < pref_count; i++) {
		log_debug("Inserting address or prefix to the IPv4 pool: %s.", pref_strs[i]);

		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry) {
			error = -ENOMEM;
			goto revert;
		}

		error = parse_prefix4(pref_strs[i], &entry->prefix);
		if (error) {
			kfree(entry);
			goto revert;
		}

		list_add_tail(&entry->list_hook, &pool);
	}

	return 0;

revert:
	pool4_destroy();
	return error;
}

void __pool4_flush(bool sync)
{
	struct pool_entry *entry;

	while (!list_empty(&pool)) {
		entry = list_first_entry(&pool, struct pool_entry, list_hook);
		list_del_rcu(&entry->list_hook);
		if (sync)
			synchronize_rcu_bh();
		kfree(entry);
	}
}

void pool4_destroy(void)
{
	__pool4_flush(false);
}

int pool4_add(struct ipv4_prefix *prefix)
{
	struct pool_entry *entry;

	list_for_each_entry(entry, &pool, list_hook) {
		if (ipv4_prefix_intersects(&entry->prefix, prefix)) {
			log_err("The requested entry intersects with pool entry %pI4/%u.",
					&entry->prefix.address, entry->prefix.len);
			return -EEXIST;
		}
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->prefix = *prefix;

	list_add_tail_rcu(&entry->list_hook, &pool);
	return 0;
}

int pool4_remove(struct ipv4_prefix *prefix)
{
	struct pool_entry *entry;

	list_for_each_entry(entry, &pool, list_hook) {
		if (ipv4_prefix_equals(prefix, &entry->prefix)) {
			list_del_rcu(&entry->list_hook);
			synchronize_rcu_bh();
			kfree(entry);
			return 0;
		}
	}

	log_err("Could not find the requested entry in the IPv4 pool.");
	return -ENOENT;
}

int pool4_flush(void)
{
	__pool4_flush(true);
	return 0;
}

static unsigned int get_addr_count(struct ipv4_prefix *prefix)
{
	return 1 << (32 - prefix->len);
}

static unsigned int get_prefix_count(void)
{
	struct pool_entry *entry;
	unsigned int result = 0;

	list_for_each_entry_rcu(entry, &pool, list_hook) {
		result += get_addr_count(&entry->prefix);
	}

	return result;
}

int pool4_get(struct in_addr *result)
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
	count = get_prefix_count();
	if (count == 0) {
		rcu_read_unlock();
		log_warn_once("The IPv4 pool is empty.");
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

int pool4_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg)
{
	struct pool_entry *entry;
	int error;

	list_for_each_entry(entry, &pool, list_hook) {
		error = func(&entry->prefix, arg);
		if (error)
			return error;
	}

	return 0;
}

int pool4_count(__u64 *result)
{
	rcu_read_lock();
	*result = get_prefix_count();
	rcu_read_unlock();
	return 0;
}

bool pool4_is_empty(void)
{
	__u64 result;
	pool4_count(&result);

	if (result)
		return false;

	return true;
}
