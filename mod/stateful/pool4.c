#include "nat64/mod/stateful/pool4.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"

#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>

/**
 * An address within the pool, along with its ports.
 */
struct pool4_node {
	/** The address itself. */
	struct in_addr addr;

	struct {
		/** The address's even UDP ports from the range 0-1023. */
		struct poolnum low_even;
		/** The address's odd UDP ports from the range 0-1023. */
		struct poolnum low_odd;
		/** The address's even UDP ports from the range 1024-65535. */
		struct poolnum high_even;
		/** The address's odd UDP ports from the range 1024-65535. */
		struct poolnum high_odd;
	} udp_ports;
	struct {
		/** The address's TCP ports from the range 0-1023. */
		struct poolnum low;
		/** The address's TCP ports from the range 1024-65535. */
		struct poolnum high;
	} tcp_ports;
	/** The address's ICMP IDs. */
	struct poolnum icmp_ids;

	/** Indicates whether the node is visible to the application. */
	bool active;
};

#define HTABLE_NAME pool4_table
#define KEY_TYPE struct in_addr
#define VALUE_TYPE struct pool4_node
#define HASH_TABLE_SIZE 256
#define GENERATE_FOR_EACH
#include "../common/hash_table.c"


static struct pool4_table pool;
static DEFINE_SPINLOCK(pool_lock);
static struct in_addr *last_used_addr;
static int inactives_pool4_node_counter;

/** Cache for struct pool4_nodes, for efficient allocation. */
static struct kmem_cache *node_cache;

static unsigned int ipv4_addr_hashcode(const struct in_addr *addr)
{
	__u32 addr32;
	unsigned int result;

	if (!addr)
		return 0;

	addr32 = be32_to_cpu(addr->s_addr);

	result = (addr32 >> 24) & 0xFF;
	result = 31 * result + ((addr32 >> 16) & 0xFF);
	result = 31 * result + ((addr32 >> 8) & 0xFF);
	result = 31 * result + (addr32 & 0xFF);

	return result;
}

/**
 * Assumes that pool has already been locked (pool_lock).
 */
static bool pool4_is_full(struct pool4_node *node)
{
	if (!poolnum_is_full(&node->icmp_ids))
		goto is_not_full;
	if (!poolnum_is_full(&node->tcp_ports.high))
		goto is_not_full;
	if (!poolnum_is_full(&node->tcp_ports.low))
		goto is_not_full;
	if (!poolnum_is_full(&node->udp_ports.low_even))
		goto is_not_full;
	if (!poolnum_is_full(&node->udp_ports.low_odd))
		goto is_not_full;
	if (!poolnum_is_full(&node->udp_ports.high_even))
		goto is_not_full;
	if (!poolnum_is_full(&node->udp_ports.high_odd))
		goto is_not_full;

	return true;

is_not_full:
	return false;
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
	}

	WARN(true, "Unsupported transport protocol: %u.", l4_proto);
	return NULL;
}

static void initialize_last_used_addr(void)
{
	struct pool4_table_key_value *keyval;
	keyval = list_entry(pool.list.next, struct pool4_table_key_value, list_hook);
	last_used_addr = &keyval->key;
}

static void increment_last_used_addr(void)
{
	struct pool4_table_key_value *keyval;

	if (!last_used_addr) {
		initialize_last_used_addr();
		return;
	}

	keyval = pool4_table_get_aux(&pool, last_used_addr);
	if (WARN(!keyval, "The last used address is not part of the pool.")) {
		initialize_last_used_addr();
		return;
	}

	if (list_is_last(&keyval->list_hook, &pool.list)) {
		/* Wrap around. */
		initialize_last_used_addr();

	} else {
		/* Increment. */
		keyval = list_entry(keyval->list_hook.next, struct pool4_table_key_value, list_hook);
		last_used_addr = &keyval->key;
	}
}

/**
 * Assumes that pool has already been locked (pool_lock).
 */
static void destroy_pool4_node(struct pool4_node *node)
{
	poolnum_destroy(&node->udp_ports.low_even);
	poolnum_destroy(&node->udp_ports.low_odd);
	poolnum_destroy(&node->udp_ports.high_even);
	poolnum_destroy(&node->udp_ports.high_odd);
	poolnum_destroy(&node->tcp_ports.low);
	poolnum_destroy(&node->tcp_ports.high);
	poolnum_destroy(&node->icmp_ids);

	kmem_cache_free(node_cache, node);
}

int pool4_init(char *addr_strs[], int addr_count)
{
	char *defaults[] = POOL4_DEF;
	struct ipv4_prefix addrs;
	unsigned int i;
	int error;

	error = pool4_table_init(&pool, ipv4_addr_equals, ipv4_addr_hashcode);
	if (error)
		return error;

	node_cache = kmem_cache_create("jool_pool4_nodes", sizeof(struct pool4_node), 0, 0, NULL);
	if (!node_cache) {
		pool4_table_empty(&pool, destroy_pool4_node);
		log_err("Could not allocate the IPv4 node cache.");
		return -ENOMEM;
	}

	if (!addr_strs || addr_count == 0) {
		addr_strs = defaults;
		addr_count = ARRAY_SIZE(defaults);
	}

	for (i = 0; i < addr_count; i++) {
		const char *slash_pos;
		if (strchr(addr_strs[i], '/') != 0){
			if (in4_pton(addr_strs[i], -1, (u8 *) &addrs.address, '/', &slash_pos) != 1)
				error = -EINVAL;
			if (kstrtou8(slash_pos + 1, 0, &addrs.len) != 0)
				error = -EINVAL;
		} else {
			error = str_to_addr4(addr_strs[i], &addrs.address);
			addrs.len = 32;
		}

		if (error) {
			log_err("Address is malformed: %s.", addr_strs[i]);
			goto fail;
		}

		log_debug("Adding %pI4/%u to the IPv4 pool.", &addrs.address, addrs.len);
		error = pool4_add(&addrs);
		if (error)
			goto fail;
	}

	last_used_addr = NULL;
	inactives_pool4_node_counter = 0;

	return 0;

fail:
	pool4_destroy();
	return error;
}

void pool4_destroy(void)
{
	pool4_table_empty(&pool, destroy_pool4_node);
	kmem_cache_destroy(node_cache);
}

/**
 * Assumes that pool has already been locked (pool_lock).
 */
static int deactivate_or_destroy_pool4_node(struct pool4_node *node, void * arg)
{
	int error = 0;

	if (!node) {
		error = -EINVAL;
		goto end;
	}
	if (!pool4_is_full(node)) {
		if (node->active) {
			node->active = false;
			inactives_pool4_node_counter++;
		}
		error =  0;
		goto end;
	}
	if (!pool4_table_remove(&pool, &node->addr, destroy_pool4_node))
		error = -EINVAL;

end:
	return error;
}

int pool4_flush(void)
{
	int error;

	spin_lock_bh(&pool_lock);
	error = pool4_table_for_each(&pool, deactivate_or_destroy_pool4_node, NULL);
	spin_unlock_bh(&pool_lock);

	return (error > 0) ? 0 : error;
}

static int __pool4_add(struct in_addr *addr)
{
	struct pool4_node *new_node, *node;
	int error;

	if (WARN(!addr, "NULL cannot be inserted to the pool."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);
	node = pool4_table_get(&pool, addr);
	if (node) {
		if (node->active) {
			spin_unlock_bh(&pool_lock);
			log_err("Address %pI4 already belongs to the pool.", addr);
			return -EEXIST;
		} else {
			node->active = true;
			inactives_pool4_node_counter--;
			spin_unlock_bh(&pool_lock);
			return 0;
		}
	}
	spin_unlock_bh(&pool_lock);

	new_node = kmem_cache_alloc(node_cache, GFP_ATOMIC);
	if (!new_node) {
		log_err("Allocation of IPv4 pool node failed.");
		return -ENOMEM;
	}
	memset(new_node, 0, sizeof(*new_node));

	new_node->addr = *addr;
	new_node->active = true;
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

	error = pool4_table_put(&pool, addr, new_node);

	spin_unlock_bh(&pool_lock);

	if (error)
		goto failure;
	return 0;

failure:
	destroy_pool4_node(new_node);
	return error;
}

static int __pool4_remove(struct in_addr *addr)
{
	struct pool4_node *node;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);

	node = pool4_table_get(&pool, addr);
	if (!node || !node->active)
		goto not_found;
	if (deactivate_or_destroy_pool4_node(node, NULL))
		goto not_found;

	spin_unlock_bh(&pool_lock);

	return 0;

not_found:
	spin_unlock_bh(&pool_lock);
	log_err("The address is not part of the pool.");
	return -ENOENT;
}

int pool4_get(l4_protocol l4_proto, struct ipv4_transport_addr *addr)
{
	struct pool4_node *node;
	struct poolnum *ids;
	int error;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);

	node = pool4_table_get(&pool, &addr->l3);
	if (!node || !node->active) {
		log_debug("%pI4 does not belong to the pool.", &addr->l3);
		spin_unlock_bh(&pool_lock);
		return -EINVAL;
	}

	ids = get_poolnum_from_pool4_node(node, l4_proto, addr->l4);
	if (!ids) {
		spin_unlock_bh(&pool_lock);
		return -EINVAL;
	}

	error = poolnum_get(ids, addr->l4);
	spin_unlock_bh(&pool_lock);
	return error;
}

int pool4_get_match(l4_protocol proto, struct ipv4_transport_addr *addr, __u16 *result)
{
	struct pool4_node *node;
	struct poolnum *ids;
	int error;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);

	node = pool4_table_get(&pool, &addr->l3);
	if (!node || !node->active) {
		log_debug("%pI4 does not belong to the pool.", &addr->l3);
		error = -EINVAL;
		goto end;
	}

	ids = get_poolnum_from_pool4_node(node, proto, addr->l4);
	if (!ids) {
		error = -EINVAL;
		goto end;
	}
	error = poolnum_get_any(ids, result);
	if (error)
		goto end;

end:
	spin_unlock_bh(&pool_lock);
	return error;
}

static int get_any_port(struct pool4_node *node, l4_protocol proto, __u16 *result)
{
	int error = -EINVAL;

	switch (proto) {
	case L4PROTO_UDP:
		error = poolnum_get_any(&node->udp_ports.high_even, result);
		if (!error)
			return 0;
		error = poolnum_get_any(&node->udp_ports.high_odd, result);
		if (!error)
			return 0;
		error = poolnum_get_any(&node->udp_ports.low_even, result);
		if (!error)
			return 0;
		error = poolnum_get_any(&node->udp_ports.low_odd, result);
		break;
	case L4PROTO_TCP:
		error = poolnum_get_any(&node->tcp_ports.high, result);
		if (!error)
			return 0;
		error = poolnum_get_any(&node->tcp_ports.low, result);
		break;
	case L4PROTO_ICMP:
		error = poolnum_get_any(&node->icmp_ids, result);
		break;
	}

	return error;
}

int pool4_get_any_port(l4_protocol proto, const struct in_addr *addr, __u16 *result)
{
	struct pool4_node *node;
	int error = -EINVAL;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);

	node = pool4_table_get(&pool, addr);
	if (!node || !node->active) {
		log_debug("%pI4 does not belong to the pool.", addr);
		goto end;
	}

	error = get_any_port(node, proto, result);
	/* Fall through. */

end:
	spin_unlock_bh(&pool_lock);
	return error;
}

int pool4_get_any_addr(l4_protocol proto, __u16 l4_id, struct ipv4_transport_addr *result)
{
	struct pool4_node *node;
	struct in_addr *original_addr;
	struct poolnum *ids;
	int error = -EINVAL;

	spin_lock_bh(&pool_lock);

	if (pool.node_count == 0) {
		log_warn_once("The IPv4 pool is empty.");
		goto failure;
	}

	/* Iterate through all of the addresses until we find one that has a compatible port. */
	original_addr = last_used_addr;
	do {
		increment_last_used_addr();

		node = pool4_table_get(&pool, last_used_addr);
		if (!node || !node->active)
			continue;

		ids = get_poolnum_from_pool4_node(node, proto, l4_id);
		if (!ids)
			goto failure;

		error = poolnum_get_any(ids, &result->l4);
		if (!error)
			goto success;
	} while (original_addr != last_used_addr);

	/* We have NO addresses with compatible ports. Fall back to using any address. */
	original_addr = last_used_addr;
	do {
		increment_last_used_addr();

		node = pool4_table_get(&pool, last_used_addr);
		if (!node || !node->active)
			continue;

		error = get_any_port(node, proto, &result->l4);
		if (!error)
			goto success;
	} while (original_addr != last_used_addr);

	log_warn_once("I completely ran out of IPv4 addresses and ports.");
	error = -ESRCH;

failure:
	spin_unlock_bh(&pool_lock);
	return error;

success:
	result->l3 = *last_used_addr;
	spin_unlock_bh(&pool_lock);
	return 0;
}

int pool4_return(const l4_protocol l4_proto, const struct ipv4_transport_addr *addr)
{
	struct pool4_node *node;
	struct poolnum *ids;
	int error;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	spin_lock_bh(&pool_lock);

	node = pool4_table_get(&pool, &addr->l3);
	if (!node) {
		log_debug("%pI4 does not belong to the pool.", &addr->l3);
		error = -EINVAL;
		goto failure;
	}

	ids = get_poolnum_from_pool4_node(node, l4_proto, addr->l4);
	if (!ids) {
		error = -EINVAL;
		goto failure;
	}

	error = poolnum_return(ids, addr->l4);
	if (error)
		goto failure;

	if (!node->active) {
		error = deactivate_or_destroy_pool4_node(node, NULL);
		if (error) {
			log_err("Failure when tried to remove an inactive pool4 node.");
			goto failure;
		}
	}

	spin_unlock_bh(&pool_lock);
	return 0;

failure:
	spin_unlock_bh(&pool_lock);
	return error;
}

bool pool4_contains(__be32 addr)
{
	struct pool4_node *node;
	struct in_addr inaddr = { .s_addr = addr };
	bool result = false;

	spin_lock_bh(&pool_lock);
	node = pool4_table_get(&pool, &inaddr);
	if (node)
		result = node->active;
	spin_unlock_bh(&pool_lock);

	return result;
}

struct foreach_wrap {
	int (*func)(struct ipv4_prefix *, void *);
	void *arg;
};

static int pool4_for_each_wrapper(struct pool4_node * node, void *arg)
{
	struct foreach_wrap *wrapper = arg;
	struct ipv4_prefix prefix = { .address = node->addr, .len = 32 };
	return wrapper->func(&prefix, wrapper->arg);
}

int pool4_for_each(int (*func)(struct ipv4_prefix *, void *), void * arg)
{
	struct foreach_wrap wrapper = { .func = func, .arg = arg };
	int error;

	spin_lock_bh(&pool_lock);
	error = pool4_table_for_each(&pool, pool4_for_each_wrapper, &wrapper);
	spin_unlock_bh(&pool_lock);

	return error;
}

int pool4_count(__u64 *result)
{
	spin_lock_bh(&pool_lock);
	*result = pool.node_count - inactives_pool4_node_counter;
	spin_unlock_bh(&pool_lock);
	return 0;
}

int pool4_add(struct ipv4_prefix *addrs)
{
	struct in_addr *addr = &addrs->address;
	__u8 maskbits = addrs->len;
	struct in_addr network;
	struct in_addr *temp = addr;
	unsigned int netmask;
	unsigned int i;
	int error;

	int total_addresses = 1 << (32 - maskbits);
	log_info("total addresses: %d",total_addresses);

	netmask = inet_make_mask(maskbits);
	network.s_addr = addr->s_addr & netmask;

	log_info("IP: %pI4", addr);
	log_info("Maskbits: %u",maskbits);
	log_info("Network: %pI4", &network);

	if (maskbits == 32) {
		(*temp).s_addr = htonl(ntohl(network.s_addr));
		log_debug("usable IP: %pI4",temp);
		error = __pool4_add(temp);
		return error;
	} else {
		for (i=0; i<total_addresses; i++) {
			(*temp).s_addr = htonl(ntohl(network.s_addr) + i);
			error = __pool4_add(temp);
			if (error == -EEXIST)
				continue;
			else if (error)
				return error;
			log_debug("usable IP: %pI4",temp);
		}
	}

	return 0;
}

int pool4_remove(struct ipv4_prefix *addrs)
{
	struct in_addr *addr = &addrs->address;
	__u8 maskbits = addrs->len;
	struct in_addr network;
	struct in_addr *temp = addr;
	unsigned int netmask;
	unsigned int i;
	int error;

	int total_addresses = 1 << (32 - maskbits);
	netmask = inet_make_mask(maskbits);
	network.s_addr = addr->s_addr & netmask;

	log_debug("IP: %pI4", addr);
	log_debug("Maskbits: %u",maskbits);
	log_debug("Network: %pI4", &network);

	if (maskbits == 32) {

		(*temp).s_addr = htonl(ntohl(network.s_addr));
		error = __pool4_remove(temp);
		if (error)
			return error;
		log_debug("deleted IP: %pI4",temp);
		return error;

	} else {

		for (i=0; i<total_addresses; i++) {
			(*temp).s_addr = htonl(ntohl(network.s_addr) + i);
			error = __pool4_remove(temp);
			if (error == -ENOENT)
				continue;
			else if (error)
				return error;
			log_debug("deleted IP: %pI4",temp);
		}
	}

	return 0;
}
