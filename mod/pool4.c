#include "nat64/mod/pool4.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/poolnum.h"

#include <linux/slab.h>


/**
 * An address within the pool, along with its ports.
 */
struct pool4_node {
	/** The address itself. */
	struct in_addr addr;

	struct {
		/** The address's even ports from the range 0-1023. */
		struct poolnum low_even;
		/** The address's odd ports from the range 0-1023. */
		struct poolnum low_odd;
		/** The address's even ports from the range 1024-65535. */
		struct poolnum high_even;
		/** The address's odd ports from the range 1024-65535. */
		struct poolnum high_odd;
	} udp_ports;
	struct {
		struct poolnum low;
		struct poolnum high;
	} tcp_ports;
	struct poolnum icmp_ids;

	/** The thing that connects this object to the "pool" list. */
	struct list_head list_hook;
};

static LIST_HEAD(pool);
static DEFINE_SPINLOCK(pool_lock);


/**
 * Assumes that pool has already been locked (pool_lock).
 */
static struct pool4_node *get_pool4_node_from_addr(struct in_addr *addr)
{
	struct pool4_node *node;

	if (list_empty(&pool)) {
		log_err(ERR_POOL4_EMPTY, "The IPv4 pool is empty.");
		return NULL;
	}

	list_for_each_entry(node, &pool, list_hook)
		if (ipv4_addr_equals(&node->addr, addr))
			return node;

	return NULL;
}

/**
 * Assumes that pool has already been locked (pool_lock).
 */
static struct poolnum *get_poolnum_from_pool4_node(struct pool4_node *node, l4_protocol l4_proto,
		__u16 id)
{
	switch (l4_proto) {
	case L4PROTO_UDP:
		if (id < 1024)
			return (id % 2 == 0) ? &node->udp_ports.low_even : &node->udp_ports.low_odd;
		else
			return (id % 2 == 0) ? &node->udp_ports.high_even : &node->udp_ports.high_odd;

	case L4PROTO_TCP:
		return (id < 1024) ? &node->tcp_ports.low : &node->tcp_ports.high;

	case L4PROTO_ICMP:
		return &node->icmp_ids;

	case L4PROTO_NONE:
		log_crit(ERR_L4PROTO, "There's no pool for the 'NONE' protocol.");
		return NULL;
	}

	log_crit(ERR_L4PROTO, "Unsupported transport protocol: %u.", l4_proto);
	return NULL;
}

int pool4_init(char *addr_strs[], int addr_count)
{
	char *defaults[] = POOL4_DEF;
	int i;
	int error;

	if (!addr_strs || addr_count == 0) {
		addr_strs = defaults;
		addr_count = ARRAY_SIZE(defaults);
	}

	for (i = 0; i < addr_count; i++) {
		struct in_addr addr;

		error = str_to_addr4(addr_strs[i], &addr);
		if (error)
			goto parse_failure;

		log_debug("Inserting address to the IPv4 pool: %pI4.", &addr);
		error = pool4_register(&addr);
		if (error)
			goto silent_failure;
	}

	return 0;

parse_failure:
	log_err(ERR_PARSE_ADDR4, "Address is malformed: %s.", addr_strs[i]);
	/* Fall through. */

silent_failure:
	pool4_destroy();
	return error;
}

/**
 * Assumes that pool has already been locked (pool_lock).
 */
static void destroy_pool4_node(struct pool4_node *node, bool remove_from_list)
{
	if (remove_from_list)
		list_del(&node->list_hook);

	poolnum_destroy(&node->udp_ports.low_even);
	poolnum_destroy(&node->udp_ports.low_odd);
	poolnum_destroy(&node->udp_ports.high_even);
	poolnum_destroy(&node->udp_ports.high_odd);
	poolnum_destroy(&node->tcp_ports.low);
	poolnum_destroy(&node->tcp_ports.high);
	poolnum_destroy(&node->icmp_ids);

	kfree(node);
}

void pool4_destroy(void)
{
	struct list_head *head;
	struct pool4_node *node;

	spin_lock_bh(&pool_lock);
	while (!list_empty(&pool)) {
		head = pool.next;
		node = container_of(head, struct pool4_node, list_hook);
		destroy_pool4_node(node, true);
	}
	spin_unlock_bh(&pool_lock);
}

int pool4_register(struct in_addr *addr)
{
	struct pool4_node *old_node, *new_node;
	int error;

	if (!addr) {
		log_err(ERR_NULL, "NULL cannot be inserted to the pool.");
		return -EINVAL;
	}

	new_node = kmalloc(sizeof(struct pool4_node), GFP_ATOMIC);
	if (!new_node) {
		log_err(ERR_ALLOC_FAILED, "Allocation of IPv4 pool node failed.");
		return -ENOMEM;
	}
	memset(new_node, 0, sizeof(*new_node));

	new_node->addr = *addr;
	error = poolnum_init(&new_node->udp_ports.low_even, 0, 1022, 2);
	if (error)
		goto failure;
	error = poolnum_init(&new_node->udp_ports.low_odd, 1, 1023, 2);
	if (error)
		goto failure;
	error = poolnum_init(&new_node->udp_ports.high_even, 1024, 65534, 2);
	if (error)
		goto failure;
	error = poolnum_init(&new_node->udp_ports.high_odd, 1025, 65535, 2);
	if (error)
		goto failure;
	error = poolnum_init(&new_node->tcp_ports.low, 0, 1023, 1);
	if (error)
		goto failure;
	error = poolnum_init(&new_node->tcp_ports.high, 1024, 65535, 1);
	if (error)
		goto failure;
	error = poolnum_init(&new_node->icmp_ids, 0, 65535, 1);
	if (error)
		goto failure;

	spin_lock_bh(&pool_lock);

	list_for_each_entry(old_node, &pool, list_hook) {
		if (ipv4_addr_equals(&old_node->addr, addr)) {
			spin_unlock_bh(&pool_lock);
			destroy_pool4_node(new_node, false);
			log_err(ERR_POOL4_REINSERT, "The %pI4 address already belongs to the pool.", addr);
			return -EINVAL;
		}
	}
	/* "add to head->prev" = "add to the end of the list". */
	list_add(&new_node->list_hook, pool.prev);

	spin_unlock_bh(&pool_lock);
	return 0;

failure:
	destroy_pool4_node(new_node, false);
	return error;
}

int pool4_remove(struct in_addr *addr)
{
	struct pool4_node *node;

	if (!addr) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return -EINVAL;
	}

	spin_lock_bh(&pool_lock);

	node = get_pool4_node_from_addr(addr);
	if (!node) {
		spin_unlock_bh(&pool_lock);
		log_err(ERR_POOL4_NOT_FOUND, "The address is not part of the pool.");
		return -ENOENT;
	}

	destroy_pool4_node(node, true);

	spin_unlock_bh(&pool_lock);
	return 0;
}

bool pool4_get_any(l4_protocol l4_proto, __u16 port, struct ipv4_tuple_address *result)
{
	struct pool4_node *node;

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock(&pool_lock);
		log_err(ERR_POOL4_EMPTY, "The IPv4 pool is empty.");
		return false;
	}

	/* Find an address with a compatible port */
	list_for_each_entry(node, &pool, list_hook) {
		struct poolnum *ids;
		int error;

		ids = get_poolnum_from_pool4_node(node, l4_proto, port);
		if (!ids) {
			spin_unlock_bh(&pool_lock);
			return false;
		}

		error = poolnum_get_any(ids, &result->l4_id);
		if (!error) {
			result->address = node->addr;
			spin_unlock_bh(&pool_lock);
			return true;
		}
	}

	/* All compatible ports are taken. Go to a corner and cry... */
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool4_get_similar(l4_protocol l4_proto, struct ipv4_tuple_address *addr,
		struct ipv4_tuple_address *result)
{
	struct pool4_node *node;
	struct poolnum *ids;
	int error;

	if (!addr) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return false;
	}

	spin_lock_bh(&pool_lock);

	node = get_pool4_node_from_addr(&addr->address);
	if (!node) {
		log_err(ERR_POOL4_NOT_FOUND, "%pI4 does not belong to the pool.", &addr->address);
		goto failure;
	}

	ids = get_poolnum_from_pool4_node(node, l4_proto, addr->l4_id);
	if (!ids)
		goto failure;
	error = poolnum_get_any(ids, &result->l4_id);
	if (error)
		goto failure;

	spin_unlock_bh(&pool_lock);
	result->address = addr->address;
	return true;

failure:
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool4_get(l4_protocol l4_proto, struct ipv4_tuple_address *addr)
{
	struct pool4_node *node;
	struct poolnum *ids;
	bool success;

	if (!addr) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return false;
	}

	spin_lock_bh(&pool_lock);

	node = get_pool4_node_from_addr(&addr->address);
	if (!node) {
		log_err(ERR_POOL4_NOT_FOUND, "%pI4 does not belong to the pool.", &addr->address);
		goto failure;
	}

	ids = get_poolnum_from_pool4_node(node, l4_proto, addr->l4_id);
	if (!ids)
		goto failure;
	success = poolnum_get(ids, addr->l4_id);
	if (!success)
		goto failure;

	spin_unlock_bh(&pool_lock);
	return true;

failure:
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool4_return(l4_protocol l4_proto, struct ipv4_tuple_address *addr)
{
	struct pool4_node *node;
	struct poolnum *ids;
	int error;

	if (!addr) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return false;
	}

	spin_lock_bh(&pool_lock);

	node = get_pool4_node_from_addr(&addr->address);
	if (!node) {
		log_err(ERR_POOL4_NOT_FOUND, "%pI4 does not belong to the pool.", &addr->address);
		goto failure;
	}

	ids = get_poolnum_from_pool4_node(node, l4_proto, addr->l4_id);
	if (!ids)
		goto failure;

	error = poolnum_return(ids, addr->l4_id);
	if (error)
		goto failure;

	spin_unlock_bh(&pool_lock);
	return true;

failure:
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool4_contains(struct in_addr *addr)
{
	bool result;

	spin_lock_bh(&pool_lock);
	result = (get_pool4_node_from_addr(addr) != NULL);
	spin_unlock_bh(&pool_lock);

	return result;
}

int pool4_for_each(int (*func)(struct in_addr *, void *), void * arg)
{
	struct pool4_node *node;

	spin_lock_bh(&pool_lock);
	list_for_each_entry(node, &pool, list_hook) {
		int error = func(&node->addr, arg);
		if (error) {
			spin_unlock_bh(&pool_lock);
			return error;
		}
	}
	spin_unlock_bh(&pool_lock);

	return 0;
}
