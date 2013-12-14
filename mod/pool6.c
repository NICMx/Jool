#include "nat64/mod/pool6.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"

#include <linux/inet.h>
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
static LIST_HEAD(pool);
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

int pool6_init(char *pref_strs[], int pref_count)
{
	char *defaults[] = POOL6_DEF;
	int i;

	if (!pref_strs || pref_count == 0) {
		pref_strs = defaults;
		pref_count = ARRAY_SIZE(defaults);
	}

	for (i = 0; i < pref_count; i++) {
		struct ipv6_prefix pref;
		const char *slash_pos;

		if (in6_pton(pref_strs[i], -1, (u8 *) &pref.address.in6_u.u6_addr8, '/', &slash_pos) != 1)
			goto parse_failure;
		if (kstrtou8(slash_pos + 1, 0, &pref.len) != 0)
			goto parse_failure;
		log_debug("Inserting prefix to the IPv6 pool: %pI6c/%u.", &pref.address, pref.len);
		if (pool6_register(&pref) != 0)
			goto silent_failure;
	}

	return 0;

parse_failure:
	log_err(ERR_PARSE_PREFIX, "IPv6 prefix is malformed: %s.", pref_strs[i]);
	/* Fall through. */

silent_failure:
	pool6_destroy();
	return -EINVAL;
}

void pool6_destroy(void)
{
	spin_lock_bh(&pool_lock);
	while (!list_empty(&pool)) {
		struct pool_node *node = container_of(pool.next, struct pool_node, list_hook);
		list_del(&node->list_hook);
		kfree(node);
	}
	spin_unlock_bh(&pool_lock);
}

int pool6_register(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	if (!prefix) {
		log_err(ERR_NULL, "NULL is not a valid prefix.");
		return -EINVAL;
	}

	if (!is_prefix_len_valid(prefix->len)) {
		log_err(ERR_PREF_LEN_RANGE, "%u is not a valid prefix length (32, 40, 48, 56, 64, 96).",
				prefix->len);
		return -EINVAL;
	}

	node = kmalloc(sizeof(struct pool_node), GFP_ATOMIC);
	if (!node) {
		log_err(ERR_ALLOC_FAILED, "Allocation of IPv6 pool node failed.");
		return -ENOMEM;
	}

	node->prefix = *prefix;

	spin_lock_bh(&pool_lock);
	list_add(&node->list_hook, pool.prev);
	spin_unlock_bh(&pool_lock);

	return 0;
}

int pool6_remove(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	if (!prefix) {
		log_err(ERR_NULL, "NULL is not a valid prefix.");
		return -EINVAL;
	}

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty.");
		return -EINVAL;
	}

	list_for_each_entry(node, &pool, list_hook) {
		if (ipv6_prefix_equals(&node->prefix, prefix)) {
			list_del(&node->list_hook);
			kfree(node);
			spin_unlock_bh(&pool_lock);
			return 0;
		}
	}
	spin_unlock_bh(&pool_lock);

	log_err(ERR_POOL6_NOT_FOUND, "The prefix is not part of the pool.");
	return -ENOENT;
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

	list_for_each_entry(node, &pool, list_hook) {
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

	node = container_of(pool.next, struct pool_node, list_hook);
	*out = node->prefix;

	spin_unlock_bh(&pool_lock);
	return true;
}

int pool6_for_each(int (*func)(struct ipv6_prefix *, void *), void * arg)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);
	list_for_each_entry(node, &pool, list_hook) {
		int error = func(&node->prefix, arg);
		if (error) {
			spin_unlock_bh(&pool_lock);
			return error;
		}
	}
	spin_unlock_bh(&pool_lock);

	return 0;
}
