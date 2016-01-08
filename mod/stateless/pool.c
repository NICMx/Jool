#include "nat64/mod/stateless/pool.h"

#include <linux/rculist.h>
#include <linux/inet.h>

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/tags.h"

/* I can't have per-pool mutexes because of the replace function. */
static DEFINE_MUTEX(lock);

RCUTAG_FREE
static struct pool_entry *get_entry(struct list_head *node)
{
	return list_entry(node, struct pool_entry, list_hook);
}

RCUTAG_FREE
static int parse_prefix4(const char *str, struct ipv4_prefix *prefix)
{
	const char *slash_pos;
	int error = 0;

	if (strchr(str, '/') != NULL) {
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

/**
 * Assumes it has exclusive access to @list.
 */
RCUTAG_FREE
static void __destroy(struct list_head *list)
{
	struct list_head *node;
	struct list_head *tmp;

	list_for_each_safe(node, tmp, list) {
		list_del(node);
		kfree(get_entry(node));
	}

	kfree(list);
}

RCUTAG_USR /* Only because of GFP_KERNEL. Can be easily upgraded to FREE. */
static struct list_head *alloc_list(void)
{
	struct list_head *list;

	list = kmalloc(sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;
	INIT_LIST_HEAD(list);

	return list;
}

RCUTAG_USR
int pool_init(struct addr4_pool *pool, char *pref_strs[], int pref_count)
{
	struct list_head *list;
	struct pool_entry *entry;
	unsigned int i;
	int error;

	list = alloc_list();
	if (!list)
		return -ENOMEM;

	for (i = 0; i < pref_count; i++) {
		log_debug("Inserting address or prefix to the IPv4 pool: %s.",
				pref_strs[i]);

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

		list_add_tail(&entry->list_hook, list);
	}

	mutex_lock(&lock);
	rcu_assign_pointer(pool->list, list);
	mutex_unlock(&lock);
	return 0;

revert:
	__destroy(list);
	return error;
}

RCUTAG_USR
static void pool_replace(struct addr4_pool *pool, struct list_head *new)
{
	struct list_head *tmp;

	mutex_lock(&lock);
	tmp = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));
	rcu_assign_pointer(pool->list, new);
	mutex_unlock(&lock);

	synchronize_rcu_bh();

	__destroy(tmp);
}

RCUTAG_USR
void pool_destroy(struct addr4_pool *pool)
{
	pool_replace(pool, NULL);
}

RCUTAG_USR
int pool_add(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;
	int error;

	error = prefix4_validate(prefix);
	if (error)
		return error;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));
	list_for_each(node, list) {
		entry = get_entry(node);
		if (prefix4_intersects(&entry->prefix, prefix)) {
			log_err("The requested entry intersects with pool "
					"entry %pI4/%u.",
					&entry->prefix.address,
					entry->prefix.len);
			error = -EEXIST;
			goto end;
		}
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		error = -ENOMEM;
		goto end;
	}
	entry->prefix = *prefix;

	list_add_tail_rcu(&entry->list_hook, list);

end:
	mutex_unlock(&lock);
	return error;
}

RCUTAG_USR
int pool_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));
	list_for_each(node, list) {
		entry = get_entry(node);
		if (prefix4_equals(prefix, &entry->prefix)) {
			list_del_rcu(&entry->list_hook);
			mutex_unlock(&lock);
			synchronize_rcu_bh();
			kfree(entry);
			return 0;
		}
	}

	mutex_unlock(&lock);
	log_err("Could not find the requested entry in the IPv4 pool.");
	return -ESRCH;
}

RCUTAG_USR
int pool_flush(struct addr4_pool *pool)
{
	struct list_head *new;

	new = alloc_list();
	if (!new)
		return -ENOMEM;

	pool_replace(pool, new);
	return 0;
}

RCUTAG_PKT
bool pool_contains(struct addr4_pool *pool, struct in_addr *addr)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool->list);
	list_for_each_rcu_bh(node, list) {
		entry = get_entry(node);
		if (prefix4_contains(&entry->prefix, addr)) {
			rcu_read_unlock_bh();
			return true;
		}
	}

	rcu_read_unlock_bh();
	return false;
}

RCUTAG_PKT
int pool_foreach(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;
	int error = 0;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool->list);
	list_for_each_rcu_bh(node, list) {
		entry = get_entry(node);
		if (!offset) {
			error = func(&entry->prefix, arg);
			if (error)
				break;
		} else if (prefix4_equals(offset, &entry->prefix)) {
			offset = NULL;
		}
	}

	rcu_read_unlock_bh();
	return offset ? -ESRCH : error;
}

RCUTAG_PKT
int pool_count(struct addr4_pool *pool, __u64 *result)
{
	struct list_head *list;
	struct list_head *node;
	__u64 count = 0;

	rcu_read_lock_bh();
	list = rcu_dereference_bh(pool->list);
	list_for_each_rcu_bh(node, list) {
		count += prefix4_get_addr_count(&get_entry(node)->prefix);
	}
	rcu_read_unlock_bh();

	*result = count;
	return 0;
}

RCUTAG_PKT
bool pool_is_empty(struct addr4_pool *pool)
{
	struct list_head *list;
	bool result;

	rcu_read_lock_bh();
	list = rcu_dereference_bh(pool->list);
	result = list_empty(list);
	rcu_read_unlock_bh();

	return result;
}
