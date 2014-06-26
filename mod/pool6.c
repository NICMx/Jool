#include "nat64/mod/pool6.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/types.h"

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
static u64 pool_count;
static DEFINE_SPINLOCK(pool_lock);

static int verify_prefix(int start, struct ipv6_prefix *prefix)
{
	int i;

	for (i = start; i < ARRAY_SIZE(prefix->address.s6_addr); i++) {
		if (prefix->address.s6_addr[i] & 0xFF) {
			log_err("%pI6c/%u seems to have a suffix (RFC6052 doesn't like this).",
					&prefix->address, prefix->len);
			return -EINVAL;
		}
	}

	return 0;
}

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

int pool6_init(char *pref_strs[], int pref_count)
{
	char *defaults[] = POOL6_DEF;
	int i;

	if (!pref_strs || pref_count == 0) {
		pref_strs = defaults;
		pref_count = ARRAY_SIZE(defaults);
	}

	pool_count = 0;

	for (i = 0; i < pref_count; i++) {
		struct ipv6_prefix pref;
		const char *slash_pos;

		if (in6_pton(pref_strs[i], -1, (u8 *) &pref.address.in6_u.u6_addr8, '/', &slash_pos) != 1)
			goto parse_failure;
		if (kstrtou8(slash_pos + 1, 0, &pref.len) != 0)
			goto parse_failure;
		log_debug("Inserting prefix to the IPv6 pool: %pI6c/%u.", &pref.address, pref.len);
		if (pool6_add(&pref) != 0)
			goto silent_failure;
	}
	return 0;

parse_failure:
	log_err("IPv6 prefix is malformed: %s.", pref_strs[i]);
	/* Fall through. */

silent_failure:
	pool6_destroy();
	return -EINVAL;
}

void pool6_destroy(void)
{
	while (!list_empty(&pool)) {
		struct pool_node *node = container_of(pool.next, struct pool_node, list_hook);
		list_del(&node->list_hook);
		kfree(node);
	}
}

int pool6_get(struct in6_addr *addr, struct ipv6_prefix *result)
{
	struct pool_node *node;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		log_warn_once("The IPv6 pool is empty.");
		return -ENOENT;
	}

	list_for_each_entry(node, &pool, list_hook) {
		if (ipv6_prefix_equal(&node->prefix.address, addr, node->prefix.len)) {
			*result = node->prefix;
			spin_unlock_bh(&pool_lock);
			return 0;
		}
	}

	spin_unlock_bh(&pool_lock);
	return -ENOENT;
}

int pool6_peek(struct ipv6_prefix *result)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		log_warn_once("The IPv6 pool is empty.");
		return -ENOENT;
	}

	/* Just return the first one. */
	node = container_of(pool.next, struct pool_node, list_hook);
	*result = node->prefix;

	spin_unlock_bh(&pool_lock);
	return 0;
}

bool pool6_contains(struct in6_addr *addr)
{
	struct ipv6_prefix result;
	return !pool6_get(addr, &result); /* 0 -> true, -ENOENT or whatever -> false. */
}

int pool6_add(struct ipv6_prefix *prefix)
{
	struct pool_node *node;
	int error;

	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	error = validate_prefix(prefix);
	if (error)
		return error; /* Error msg already printed. */

	node = kmalloc(sizeof(struct pool_node), GFP_ATOMIC);
	if (!node) {
		log_err("Allocation of IPv6 pool node failed.");
		return -ENOMEM;
	}

	node->prefix = *prefix;

	spin_lock_bh(&pool_lock);
	list_add_tail(&node->list_hook, &pool);
	pool_count++;
	spin_unlock_bh(&pool_lock);

	return 0;
}

int pool6_remove(struct ipv6_prefix *prefix)
{
	struct pool_node *node;

	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock_bh(&pool_lock);
		log_warn_once("The IPv6 pool is empty.");
		return -ENOENT;
	}

	list_for_each_entry(node, &pool, list_hook) {
		if (ipv6_prefix_equals(&node->prefix, prefix)) {
			list_del(&node->list_hook);
			kfree(node);
			pool_count--;
			spin_unlock_bh(&pool_lock);
			return 0;
		}
	}
	spin_unlock_bh(&pool_lock);

	log_err("The prefix is not part of the pool.");
	return -ENOENT;
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

int pool6_count(__u64 *result)
{
	spin_lock_bh(&pool_lock);
	*result = pool_count;
	spin_unlock_bh(&pool_lock);
	return 0;
}
