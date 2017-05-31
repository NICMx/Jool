#include "nat64/mod/stateless/pool.h"

#include <linux/inet.h>
#include <linux/kref.h>
#include <linux/rculist.h>
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/common/wkmalloc.h"

struct pool_entry {
	struct ipv4_prefix prefix;
	struct list_head list_hook;
};

struct addr4_pool {
	struct list_head __rcu *list;
	struct kref refcounter;
};

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
		wkfree(struct pool_entry, get_entry(node));
	}

	__wkfree("IPv4 address pool list", list);
}

RCUTAG_USR /* Only because of GFP_KERNEL. Can be easily upgraded to FREE. */
static struct list_head *alloc_list(void)
{
	struct list_head *list;

	list = __wkmalloc("IPv4 address pool list", sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;
	INIT_LIST_HEAD(list);

	return list;
}

RCUTAG_USR
int pool_init(struct addr4_pool **pool)
{
	struct addr4_pool *result;
	struct list_head *list;

	result = wkmalloc(struct addr4_pool, GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	list = alloc_list();
	if (!list) {
		wkfree(struct addr4_pool, result);
		return -ENOMEM;
	}

	RCU_INIT_POINTER(result->list, list);
	kref_init(&result->refcounter);

	*pool = result;
	return 0;
}

void pool_get(struct addr4_pool *pool)
{
	kref_get(&pool->refcounter);
}

RCUTAG_USR
static void destroy_pool(struct kref *refcounter)
{
	struct addr4_pool *pool;
	pool = container_of(refcounter, struct addr4_pool, refcounter);
	__destroy(rcu_dereference_raw(pool->list));
	wkfree(struct addr4_pool, pool);
}

void pool_put(struct addr4_pool *pool)
{
	kref_put(&pool->refcounter, destroy_pool);
}

static int validate_scope(struct ipv4_prefix *prefix, bool force)
{
	struct ipv4_prefix subnet;

	if (!force && prefix4_has_subnet_scope(prefix, &subnet)) {
		log_err("Prefix %pI4/%u intersects with subnet scoped network %pI4/%u.",
				&prefix->address, prefix->len,
				&subnet.address, subnet.len);
		log_err("Will cancel the operation. Use --force to ignore this validation.");
		return -EINVAL;
	}

	return 0;
}

RCUTAG_USR
int pool_add(struct addr4_pool *pool, struct ipv4_prefix *prefix, bool force)
{
	struct list_head *list;
	struct pool_entry *entry;
	__u64 count;
	int error;

	error = prefix4_validate(prefix);
	if (error)
		return error;
	error = validate_scope(prefix, force);
	if (error)
		return error;

	mutex_lock(&lock);

	error = pool_count(pool, &count);
	if (error) {
		log_err("Unknown error %d while trying to validate overflow.",
				error);
		goto end;
	}

	if (count + prefix4_get_addr_count(prefix) > UINT_MAX) {
		/* Otherwise get_rfc6791_address() overflows. */
		log_err("The pool must not contain more than %u addresses.\n"
				"(Duplicates do count towards the limit.)",
				UINT_MAX);
		goto end;
	}

	entry = wkmalloc(struct pool_entry, GFP_KERNEL);
	if (!entry) {
		error = -ENOMEM;
		goto end;
	}
	entry->prefix = *prefix;

	list = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));
	list_add_tail_rcu(&entry->list_hook, list);

end:
	mutex_unlock(&lock);
	return error;
}

int pool_add_str(struct addr4_pool *pool, char *pref_strs[], int pref_count)
{
	struct ipv4_prefix prefix;
	unsigned int i;
	int error;

	for (i = 0; i < pref_count; i++) {
		log_debug("Inserting address or prefix to the IPv4 pool: %s.",
				pref_strs[i]);
		error = parse_prefix4(pref_strs[i], &prefix);
		if (error)
			return error;
		error = pool_add(pool, &prefix, false);
		if (error)
			return error;
	}

	return 0;
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
			wkfree(struct pool_entry, entry);
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
	struct list_head *old;
	struct list_head *new;

	new = alloc_list();
	if (!new)
		return -ENOMEM;

	mutex_lock(&lock);
	old = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));
	rcu_assign_pointer(pool->list, new);
	mutex_unlock(&lock);

	synchronize_rcu_bh();

	__destroy(old);
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
