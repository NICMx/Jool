#include "nat64/mod/common/pool6.h"
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/common/types.h"

#include <linux/rculist.h>
#include <net/ipv6.h>


/**
 * A prefix within the pool.
 */
struct pool_node {
	/** The address itself. */
	struct ipv6_prefix prefix;
	/** The thing that connects this object to the "pool" list. */
	struct list_head list_hook;
};

/**
 * The global container of the entire pool.
 * It can be a linked list because we're assuming we won't be holding too many prefixes.
 * The list contains nodes of type pool_node.
 */
static struct list_head __rcu *pool;

static DEFINE_MUTEX(lock);

RCUTAG_FREE
static struct pool_node *pool_entry(struct list_head *node)
{
	return list_entry(node, struct pool_node, list_hook);
}

RCUTAG_FREE
static int verify_prefix(int start, struct ipv6_prefix *prefix)
{
	int i;

	for (i = start; i < ARRAY_SIZE(prefix->address.s6_addr); i++) {
		if (prefix->address.s6_addr[i] & 0xFFU) {
			log_err("%pI6c/%u seems to have a suffix (RFC6052 doesn't like this).",
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
		log_err("%u is not a valid prefix length (32, 40, 48, 56, 64, 96).", prefix->len);
		return -EINVAL;
	}
}

RCUTAG_USR /* Only because of GFP_KERNEL. Can be easily upgraded to FREE. */
static struct list_head *create_pool(void)
{
	struct list_head *result;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return NULL;
	INIT_LIST_HEAD(result);

	return result;
}

RCUTAG_INIT
int pool6_init(char *pref_strs[], int pref_count)
{
	struct list_head *tmp;
	struct ipv6_prefix prefix;
	int i;
	int error;

	tmp = create_pool();
	if (!tmp)
		return -ENOMEM;
	rcu_assign_pointer(pool, tmp);

	if (!pref_strs || pref_count == 0)
		return 0;

	for (i = 0; i < pref_count; i++) {
		error = prefix6_parse(pref_strs[i], &prefix);
		if (error)
			goto fail;
		error = pool6_add(&prefix);
		if (error)
			goto fail;
	}

	return 0;

fail:
	pool6_destroy();
	return error;
}

RCUTAG_FREE
static void __destroy(struct list_head *list)
{
	struct list_head *node;
	struct list_head *tmp;

	list_for_each_safe(node, tmp, list) {
		list_del(node);
		kfree(pool_entry(node));
	}

	kfree(list);
}

RCUTAG_INIT
void pool6_destroy(void)
{
	mutex_lock(&lock);
	__destroy(rcu_dereference_protected(pool, lockdep_is_held(&lock)));
	mutex_unlock(&lock);
}

RCUTAG_USR
int pool6_flush(void)
{
	struct list_head *old_pool;
	struct list_head *new_pool;

	new_pool = create_pool();
	if (!new_pool)
		return -ENOMEM;

	mutex_lock(&lock);
	old_pool = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	rcu_assign_pointer(pool, new_pool);
	mutex_unlock(&lock);

	synchronize_rcu_bh();

	__destroy(old_pool);
	return 0;
}

RCUTAG_PKT
int pool6_get(struct in6_addr *addr, struct ipv6_prefix *result)
{
	struct list_head *first;
	struct list_head *cursor;
	struct pool_node *node;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	rcu_read_lock_bh();

	first = rcu_dereference_bh(pool);

	if (list_empty(first)) {
		rcu_read_unlock_bh();
		log_warn_once("The IPv6 pool is empty.");
		return -ESRCH;
	}

	list_for_each_rcu_bh(cursor, first) {
		node = pool_entry(cursor);
		if (ipv6_prefix_equal(&node->prefix.address, addr, node->prefix.len)) {
			*result = node->prefix;
			rcu_read_unlock_bh();
			return 0;
		}
	}

	rcu_read_unlock_bh();
	return -ESRCH;
}

RCUTAG_PKT
int pool6_peek(struct ipv6_prefix *result)
{
	struct list_head *first;
	struct pool_node *node;

	rcu_read_lock_bh();

	first = rcu_dereference_bh(pool);

	if (list_empty(first)) {
		rcu_read_unlock_bh();
		log_warn_once("The IPv6 pool is empty.");
		return -ESRCH;
	}

	/* Just return the first one. */
	node = pool_entry(rcu_dereference_bh(list_next_rcu(first)));
	*result = node->prefix;

	rcu_read_unlock_bh();
	return 0;
}

RCUTAG_PKT
bool pool6_contains(struct in6_addr *addr)
{
	struct ipv6_prefix result;
	return !pool6_get(addr, &result); /* 0 -> true, -ESRCH or whatever -> false. */
}

int pool6_add(struct ipv6_prefix *prefix)
{
	struct pool_node *node;
	int error;

	log_debug("Inserting prefix to the IPv6 pool: %pI6c/%u.", &prefix->address, prefix->len);

	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	error = validate_prefix(prefix);
	if (error)
		return error; /* Error msg already printed. */

	if (xlat_is_siit() && !list_empty(&pool)) {
		log_err("SIIT Jool only supports one pool6 prefix at a time.");
		return -EINVAL;
	}

	/*
	 * I'm not using list_for_each_entry_rcu() here because this is a writer (as usual,
	 * protected by module initialization or the configuration mutex).
	 * tomoyo_get_group() is an example of a kernel function that iterates like this
	 * before calling list_add_tail_rcu(), so I'm assuming this is correct.
	 */

	list_for_each_entry(node, &pool, list_hook) {
		if (prefix6_equals(&node->prefix, prefix)) {
			log_err("The prefix already belongs to the pool.");
			return -EEXIST;
		}
	}

	node = kmalloc(sizeof(struct pool_node), GFP_ATOMIC);
	if (!node) {
		log_err("Allocation of IPv6 pool node failed.");
		return -ENOMEM;
	}
	node->prefix = *prefix;

	list_add_tail_rcu(&node->list_hook, &pool);
	return 0;
}

int pool6_remove(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	list_for_each_entry(node, &pool, list_hook) {
		if (prefix6_equals(&node->prefix, prefix)) {
			list_del_rcu(&node->list_hook);
			synchronize_rcu_bh();
			kfree(node);
			return 0;
		}
	}

	log_err("The prefix is not part of the pool.");
	return -ESRCH;
}

/**
 * pool6_for_each - run func() for every prefix in this pool.
 * @func: routine you want to run on every node in the pool.
 * @arg: additional argument that will be passed to func() on every iteration.
 * @offset: node you want to start iteration from. Iteration will start from
 *	the first node if you don't supply this.
 *
 * The nodes will be visited in the order in which they are stored.
 */
int pool6_for_each(int (*func)(struct ipv6_prefix *, void *), void *arg,
		struct ipv6_prefix *offset)
{
	struct pool_node *node;
	int error = 0;
	rcu_read_lock_bh();

	list_for_each_entry_rcu_bh(node, &pool, list_hook) {
		if (!offset) {
			error = func(&node->prefix, arg);
			if (error)
				break;
		} else if (prefix6_equals(offset, &node->prefix)) {
			offset = NULL;
		}
	}

	rcu_read_unlock_bh();
	return offset ? -ESRCH : error;
}

int pool6_count(__u64 *result)
{
	struct pool_node *node;
	unsigned int count = 0;

	rcu_read_lock_bh();
	list_for_each_entry_rcu_bh(node, &pool, list_hook) {
		count++;
	}
	rcu_read_unlock_bh();

	*result = count;
	return 0;
}

bool pool6_is_empty(void)
{
	bool result;
	rcu_read_lock_bh();
	result = list_empty(&pool);
	rcu_read_unlock_bh();
	return result;
}
