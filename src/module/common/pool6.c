#include "nat64/mod/common/pool6.h"

#include <net/ipv6.h>
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/common/wkmalloc.h"

struct pool6 {
	struct list_head __rcu *list;
	struct kref refcount;
};

/**
 * A prefix within the pool.
 */
struct pool_entry {
	struct ipv6_prefix prefix;
	/** The thing that connects this object to its pool6->list list. */
	struct list_head list_hook;
};

/**
 * This protects all pool6 updates (across all namespaces).
 * Each pool6 cannot hold a different mutex because I'd need to dereference
 * the pool to access its mutex... And I'd need the mutex to dereference the
 * pool.
 * The mutex is only needed during userspace app requests, and that happens
 * rarely anyway.
 */
static DEFINE_MUTEX(lock);

RCUTAG_FREE
static struct pool_entry *get_entry(struct list_head *node)
{
	return list_entry(node, struct pool_entry, list_hook);
}

RCUTAG_FREE
static int verify_prefix(int start, struct ipv6_prefix *prefix)
{
	int i;

	for (i = start; i < ARRAY_SIZE(prefix->address.s6_addr); i++) {
		if (prefix->address.s6_addr[i] & 0xFFU) {
			log_err("%pI6c/%u seems to have a suffix.",
					&prefix->address, prefix->len);
			return -EINVAL;
		}
	}

	return 0;
}

RCUTAG_FREE
static int validate_prefix(struct ipv6_prefix *prefix)
{
	switch (prefix->len) {
	case 32:
		return verify_prefix(4, prefix);
	case 40:
		return verify_prefix(5, prefix);
	case 48:
		return verify_prefix(6, prefix);
	case 56:
		return verify_prefix(7, prefix);
	case 64:
		return verify_prefix(8, prefix);
	case 96:
		return verify_prefix(12, prefix);
	default:
		log_err("%u is not a valid prefix length (32, 40, 48, 56, 64, 96).",
				prefix->len);
		return -EINVAL;
	}
}

static int create_list(struct list_head **list)
{
	struct list_head *result;

	result = __wkmalloc("pool6 list", sizeof(struct list_head), GFP_KERNEL);
	if (!result)
		return -ENOMEM;
	INIT_LIST_HEAD(result);

	*list = result;
	return 0;
}

/**
 * Assumes it has exclusive access to @list.
 */
static void destroy_list(struct list_head *list)
{
	struct list_head *node;
	struct list_head *tmp;

	list_for_each_safe(node, tmp, list) {
		list_del(node);
		wkfree(struct pool_entry, get_entry(node));
	}

	__wkfree("pool6 list", list);
}

/**
 * pool6_init - Readies @pool for future use.
 * @prefix_strings: Array of strings denoting the prefixes the pool should start
 * with.
 * @prefix_count size of the "pref_strs" array.
 */
RCUTAG_USR
int pool6_init(struct pool6 **pool)
{
	struct pool6 *result;
	struct list_head *list;
	int error;

	result = wkmalloc(struct pool6, GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	error = create_list(&list);
	if (error) {
		wkfree(struct pool6, result);
		return error;
	}

	RCU_INIT_POINTER(result->list, list);
	kref_init(&result->refcount);

	*pool = result;
	return 0;
}

void pool6_get(struct pool6 *pool)
{
	kref_get(&pool->refcount);
}

static void destroy_pool6(struct kref *ref)
{
	struct pool6 *pool;
	pool = container_of(ref, struct pool6, refcount);
	destroy_list(rcu_dereference_raw(pool->list));
	wkfree(struct pool6, pool);
}

void pool6_put(struct pool6 *pool)
{
	kref_put(&pool->refcount, destroy_pool6);
}

/**
 * pool6_flush - Removes all prefixes from @pool.
 */
RCUTAG_USR
int pool6_flush(struct pool6 *pool)
{
	struct list_head *old;
	struct list_head *new;
	int error;

	error = create_list(&new);
	if (error)
		return error;

	mutex_lock(&lock);
	old = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));
	rcu_assign_pointer(pool->list, new);
	mutex_unlock(&lock);

	synchronize_rcu_bh();
	destroy_list(old);
	return 0;
}

/**
 * pool6_find - Returns (in @result) @pool's prefix corresponding to @addr.
 *
 * You're not actually borrowing the prefix, so you don't have to return it.
 */
RCUTAG_PKT
int pool6_find(struct pool6 *pool, const struct in6_addr *addr,
		struct ipv6_prefix *result)
{
	struct list_head *list;
	struct list_head *node;
	struct ipv6_prefix *prefix;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool->list);

	/*
	 * This seems redundant, but if you want to remove it mind that you need
	 * to debug on callers.
	 */
	if (list_empty(list)) {
		log_debug("pool6 is empty.");
		goto not_found;
	}

	list_for_each_rcu_bh(node, list) {
		prefix = &get_entry(node)->prefix;
		if (ipv6_prefix_equal(&prefix->address, addr, prefix->len)) {
			*result = *prefix;
			rcu_read_unlock_bh();
			return 0;
		}
	}
	/* Fall through. */

not_found:
	rcu_read_unlock_bh();
	return -ESRCH;
}

/**
 * Returns (in @result) any prefix from @pool.
 */
RCUTAG_PKT
int pool6_peek(struct pool6 *pool, struct ipv6_prefix *result)
{
	struct list_head *list;
	struct pool_entry *entry;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool->list);

	if (list_empty(list)) {
		rcu_read_unlock_bh();
		log_debug("pool6 is empty.");
		return -ESRCH;
	}

	/* Just return the first one. */
	entry = get_entry(rcu_dereference_bh(list_next_rcu(list)));
	*result = entry->prefix;

	rcu_read_unlock_bh();
	return 0;
}

/**
 * pool6_contains - Returns whether @addr's network prefix belongs to @pool.
 */
RCUTAG_PKT
bool pool6_contains(struct pool6 *pool, struct in6_addr *addr)
{
	struct ipv6_prefix throwaway;
	return !pool6_find(pool, addr, &throwaway);
}

int pool6_add(struct pool6 *pool, struct ipv6_prefix *prefix)
{
	struct list_head *list;
	struct pool_entry *entry;
	int error;

	error = validate_prefix(prefix);
	if (error)
		return error; /* Error msg already printed. */

	mutex_lock(&lock);
	list = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));

	if (!list_empty(list)) {
		mutex_unlock(&lock);
		/*
		 * TODO (4.0.0) remember to turn pool6 into a single global
		 * param. This whole module being a linked list is stupid.
		 */
		log_err("Only one pool6 prefix can exist per Jool instance.");
		return -EINVAL;
	}

	list_for_each_entry(entry, list, list_hook) {
		if (prefix6_equals(&entry->prefix, prefix)) {
			mutex_unlock(&lock);
			log_err("The prefix already belongs to the pool.");
			return -EEXIST;
		}
	}

	entry = wkmalloc(struct pool_entry, GFP_KERNEL);
	if (!entry) {
		mutex_unlock(&lock);
		log_err("Allocation of IPv6 pool node failed.");
		return -ENOMEM;
	}
	entry->prefix = *prefix;
	list_add_tail_rcu(&entry->list_hook, list);

	mutex_unlock(&lock);
	return 0;
}

int pool6_add_str(struct pool6 *pool, char *prefix_strings[], int prefix_count)
{
	struct ipv6_prefix prefix;
	int i;
	int error;

	for (i = 0; i < prefix_count; i++) {
		error = prefix6_parse(prefix_strings[i], &prefix);
		if (error)
			return error;
		error = pool6_add(pool, &prefix);
		if (error)
			return error;
	}

	return 0;
}

RCUTAG_USR
int pool6_rm(struct pool6 *pool, struct ipv6_prefix *prefix)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;

	mutex_lock(&lock);
	list = rcu_dereference_protected(pool->list, lockdep_is_held(&lock));

	list_for_each(node, list) {
		entry = get_entry(node);
		if (prefix6_equals(&entry->prefix, prefix)) {
			list_del_rcu(&entry->list_hook);
			mutex_unlock(&lock);
			synchronize_rcu_bh();
			wkfree(struct pool_entry, entry);
			return 0;
		}
	}

	mutex_unlock(&lock);
	log_err("The prefix is not part of the pool.");
	return -ESRCH;
}

/**
 * pool6_for_each - run cb() for every prefix in @pool.
 * @cb: routine you want to run on every node in @pool.
 * @arg: additional argument that will be passed to cb() on every iteration.
 * @offset: node you want to start iteration from. Iteration will start from
 *	the first node if you don't supply this.
 */
RCUTAG_PKT
int pool6_foreach(struct pool6 *pool,
		int (*cb)(struct ipv6_prefix *, void *), void *arg,
		struct ipv6_prefix *offset)
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
			error = cb(&entry->prefix, arg);
			if (error)
				break;
		} else if (prefix6_equals(offset, &entry->prefix)) {
			offset = NULL;
		}
	}

	rcu_read_unlock_bh();
	return offset ? -ESRCH : error;
}

RCUTAG_PKT
int pool6_count(struct pool6 *pool, __u64 *result)
{
	struct list_head *list;
	struct list_head *node;
	__u64 count = 0;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool->list);
	list_for_each_rcu_bh(node, list) {
		count++;
	}

	rcu_read_unlock_bh();

	*result = count;
	return 0;
}

RCUTAG_PKT
bool pool6_is_empty(struct pool6 *pool)
{
	bool result;
	rcu_read_lock_bh();
	result = list_empty(rcu_dereference_bh(pool->list));
	rcu_read_unlock_bh();
	return result;
}
