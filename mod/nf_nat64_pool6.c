#include "nf_nat64_pool6.h"

//#include <linux/slab.h>
#include <net/ipv6.h>
#include "nf_nat64_constants.h"


/** Rename for the type of the pool list below. */
#define address_list list_head

/**
 * A prefix within the pool.
 */
struct pool_node
{
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
struct address_list pool;

static DEFINE_SPINLOCK(pool_lock);

static bool load_defaults(void)
{
	struct ipv6_prefix pool6_prefix;
	if (!str_to_addr6(POOL6_DEF_PREFIX, &pool6_prefix.address)) {
		log_warning("IPv6 prefix in Headers is malformed [%s].", POOL6_DEF_PREFIX);
		return false;
	}
	pool6_prefix.maskbits = POOL6_DEF_PREFIX_LEN;

	pool6_register(&pool6_prefix);
	return true;
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

enum response_code pool6_register(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	node = kmalloc(sizeof(struct pool_node), GFP_ATOMIC);
	if (!node)
		return RESPONSE_ALLOC_FAILED;

	node->prefix = *prefix;

	spin_lock_bh(&pool_lock);
	list_add(&node->next, pool.prev);
	spin_unlock_bh(&pool_lock);

	return RESPONSE_SUCCESS;
}

enum response_code pool6_remove(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);
	list_for_each_entry(node, &pool, next) {
		if (ipv6_prefix_equals(&node->prefix, prefix)) {
			list_del(&node->next);
			kfree(node);
			spin_unlock_bh(&pool_lock);
			return RESPONSE_SUCCESS;
		}
	}
	spin_unlock_bh(&pool_lock);
	return RESPONSE_NOT_FOUND;
}

bool pool6_contains(struct in6_addr *address)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);
	list_for_each_entry(node, &pool, next) {
		if (ipv6_prefix_equal(&node->prefix.address, address, node->prefix.maskbits)) {
			spin_unlock_bh(&pool_lock);
			return true;
		}
	}
	spin_unlock_bh(&pool_lock);
	return false;
}

// TODO revisa valor de retorno.
bool pool6_peek(struct ipv6_prefix *out)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		return false;
	}

	node = container_of(pool.next, struct pool_node, next);
	*out = node->prefix;

	spin_unlock_bh(&pool_lock);
	return true;
}

enum response_code pool6_to_array(struct ipv6_prefix **array_out, __u32 *size_out)
{
	struct list_head *cursor;
	struct pool_node *node;

	struct ipv6_prefix *array;
	__u32 size;

	size = 0;
	spin_lock_bh(&pool_lock);
	list_for_each(cursor, &pool)
		size++;
	spin_unlock_bh(&pool_lock);

	array = kmalloc(size * sizeof(*node), GFP_ATOMIC);
	if (!array)
		return RESPONSE_ALLOC_FAILED;

	size = 0;
	spin_lock_bh(&pool_lock);
	list_for_each_entry(node, &pool, next) {
		memcpy(&array[size], &node->prefix, sizeof(*node));
		size++;
	}
	spin_unlock_bh(&pool_lock);

	*array_out = array;
	*size_out = size;
	return RESPONSE_SUCCESS;
}
