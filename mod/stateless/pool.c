#include "nat64/mod/stateless/pool.h"

#include <linux/rculist.h>
#include <linux/inet.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/random.h"

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

int pool_init(char *pref_strs[], int pref_count, struct list_head *pool)
{
	struct pool_entry *entry;
	unsigned int i;
	int error;

	INIT_LIST_HEAD(pool);

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

		list_add_tail(&entry->list_hook, pool);
	}

	return 0;

revert:
	pool_destroy(pool);
	return error;
}

static void __pool_flush(struct list_head *pool, bool sync)
{
	struct pool_entry *entry;

	while (!list_empty(pool)) {
		entry = list_first_entry(pool, struct pool_entry, list_hook);
		list_del_rcu(&entry->list_hook);
		if (sync)
			synchronize_rcu_bh();
		kfree(entry);
	}
}

void pool_destroy(struct list_head *pool)
{
	__pool_flush(pool, false);
}

int pool_add(struct list_head *pool, struct ipv4_prefix *prefix)
{
	struct pool_entry *entry;
	int error;

	error = prefix4_validate(prefix);
	if (error)
		return error;

	list_for_each_entry(entry, pool, list_hook) {
		if (prefix4_intersects(&entry->prefix, prefix)) {
			log_err("The requested entry intersects with pool entry %pI4/%u.",
					&entry->prefix.address, entry->prefix.len);
			return -EEXIST;
		}
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->prefix = *prefix;

	list_add_tail_rcu(&entry->list_hook, pool);
	return 0;
}

int pool_remove(struct list_head *pool, struct ipv4_prefix *prefix)
{
	struct pool_entry *entry;

	list_for_each_entry(entry, pool, list_hook) {
		if (prefix4_equals(prefix, &entry->prefix)) {
			list_del_rcu(&entry->list_hook);
			synchronize_rcu_bh();
			kfree(entry);
			return 0;
		}
	}

	log_err("Could not find the requested entry in the IPv4 pool.");
	return -ENOENT;
}

int pool_flush(struct list_head *pool)
{
	__pool_flush(pool, true);
	return 0;
}

int pool_for_each(struct list_head *pool, int (*func)(struct ipv4_prefix *, void *), void *arg)
{
	struct pool_entry *entry;
	int error = 0;

	rcu_read_lock_bh();
	list_for_each_entry_rcu(entry, pool, list_hook) {
		error = func(&entry->prefix, arg);
		if (error)
			break;
	}
	rcu_read_unlock_bh();

	return error;
}

int pool_count(struct list_head *pool, __u64 *result)
{
	struct pool_entry *entry;
	unsigned int count = 0;

	rcu_read_lock_bh();
	list_for_each_entry_rcu(entry, pool, list_hook) {
		count += prefix4_get_addr_count(&entry->prefix);
	}
	rcu_read_unlock_bh();

	*result = count;
	return 0;
}

bool pool_is_empty(struct list_head *pool)
{
	bool result;

	rcu_read_lock_bh();
	result = list_empty(pool);
	rcu_read_unlock_bh();

	return result;
}
