#include "nat64/mod/pool6.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"

//#include <linux/slab.h>
#include <net/ipv6.h>


/** Rename for the type of the pool list below. */
#define address_list list_head

/**
 * A prefix within the pool.
 */
struct pool_node {
	/** The address itself. */
	struct ipv6_prefix prefix;
	/** Next prefix within the pool (since they are linked listed; see pools.*). */
	struct list_head next;
};

/**
 * The global container of the entire pool.
 * It can be a linked list because we're assuming we won't be holding too many prefixes.
 * The list contains nodes of type pool_node.
 */
static struct address_list pool;

static DEFINE_SPINLOCK(pool_lock);

static bool is_prefix_len_valid(__u8 prefix_len)
{
	__u8 valid_lengths[] = POOL6_PREFIX_LENGTHS;
	int i;

	for (i = 0; i < ARRAY_SIZE(valid_lengths); i++)
		if (prefix_len == valid_lengths[i])
			return true;

	return false;
}

static bool load_defaults(void)
{
	struct ipv6_prefix pool6_prefix;

	if (str_to_addr6(POOL6_DEF_PREFIX, &pool6_prefix.address) != 0) {
		log_err(ERR_POOL6_INVALID_DEFAULT, "IPv6 prefix in headers is malformed: %s.",
				POOL6_DEF_PREFIX);
		return false;
	}
	pool6_prefix.len = POOL6_DEF_PREFIX_LEN;

	return pool6_register(&pool6_prefix) == 0;
}

bool pool6_init(void)
{
	INIT_LIST_HEAD(&pool);
	return load_defaults();
}

void pool6_destroy(void)
{
	spin_lock_bh(&pool_lock);
	while (!list_empty(&pool)) {
		struct pool_node *node = container_of(pool.next, struct pool_node, next);
		list_del(&node->next);
		kfree(node);
	}
	spin_unlock_bh(&pool_lock);
}

int pool6_register(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	if (!prefix) {
		log_err(ERR_NULL, "NULL is not a valid prefix.");
		return EINVAL;
	}

	if (!is_prefix_len_valid(prefix->len)) {
		log_err(ERR_PREF_LEN_RANGE, "%u is not a valid prefix length (32, 40, 48, 56, 64, 96).",
				prefix->len);
		return EINVAL;
	}

	node = kmalloc(sizeof(struct pool_node), GFP_ATOMIC);
	if (!node) {
		log_err(ERR_ALLOC_FAILED, "Allocation of IPv6 pool node failed.");
		return ENOMEM;
	}

	node->prefix = *prefix;

	spin_lock_bh(&pool_lock);
	list_add(&node->next, pool.prev);
	spin_unlock_bh(&pool_lock);

	return 0;
}

int pool6_remove(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	if (!prefix) {
		log_err(ERR_NULL, "NULL is not a valid prefix.");
		return EINVAL;
	}

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty.");
		return EINVAL;
	}

	list_for_each_entry(node, &pool, next) {
		if (ipv6_prefix_equals(&node->prefix, prefix)) {
			list_del(&node->next);
			kfree(node);
			spin_unlock_bh(&pool_lock);
			return 0;
		}
	}
	spin_unlock_bh(&pool_lock);

	log_err(ERR_POOL6_NOT_FOUND, "The prefix is not part of the pool.");
	return ENOENT;
}

bool pool6_contains(struct in6_addr *address)
{
	struct pool_node *node;

	if (!address) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return false;
	}

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty.");
		return false;
	}

	list_for_each_entry(node, &pool, next) {
		if (ipv6_prefix_equal(&node->prefix.address, address, node->prefix.len)) {
			spin_unlock_bh(&pool_lock);
			return true;
		}
	}
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool6_peek(struct ipv6_prefix *out)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty.");
		return false;
	}

	node = container_of(pool.next, struct pool_node, next);
	*out = node->prefix;

	spin_unlock_bh(&pool_lock);
	return true;
}

int pool6_for_each(int (*func)(struct ipv6_prefix *, void *), void * arg)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);
	list_for_each_entry(node, &pool, next) {
		int error = func(&node->prefix, arg);
		if (error) {
			spin_unlock_bh(&pool_lock);
			return error;
		}
	}
	spin_unlock_bh(&pool_lock);

	return 0;
}
