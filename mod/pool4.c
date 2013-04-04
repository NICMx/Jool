#include "nat64/mod/pool4.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"

#include <linux/slab.h>


/**
 * A port which is known to be in the pool; available for borrowal.
 */
struct free_port {
	/** The port number. */
	__u16 port;
	/** Next port within the list of free ones (see addr_section.free_ports). */
	struct list_head next;
};

/**
 * A range of ports within an address.
 */
struct addr_section {
	/** Next available (and never before used) port. */
	__u32 next_port;
	/**
	 * Maximum value "next_port" can hold. If this value has been reached and next_port needs to
	 * be incremented, the section has been exhausted.
	 */
	__u32 max_port;
	/**
	 * List of available (and previously used) ports. Contains structs of type free_port.
	 * It's a list because the FIFO behavior is ideal.
	 */
	struct list_head free_ports;
};

struct protocol_ids {
	/** The address's odd ports from the range 0-1023. */
	struct addr_section odd_low;
	/** The address's even ports from the range 0-1023. */
	struct addr_section even_low;
	/** The address's odd ports from the range 1024-65535. */
	struct addr_section odd_high;
	/** The address's even ports from the range 1024-65535. */
	struct addr_section even_high;
};

/**
 * An address within the pool, along with its ports.
 */
struct pool_node {
	/** The address itself. */
	struct in_addr address;

	struct protocol_ids udp;
	struct protocol_ids tcp;
	struct protocol_ids icmp;

	/** Next address within the pool (since they are linked listed; see pool). */
	struct list_head next;
};

static LIST_HEAD(pool);
static DEFINE_SPINLOCK(pool_lock);


/**
 * Assumes that pool has already been locked (pool->lock).
 */
static struct pool_node *get_pool_node(struct in_addr *address)
{
	struct pool_node *node;

	if (list_empty(&pool)) {
		log_err(ERR_POOL4_EMPTY, "The IPv4 pool is empty.");
		return NULL;
	}

	list_for_each_entry(node, &pool, next)
		if (ipv4_addr_equals(&node->address, address))
			return node;

	return NULL;
}

static struct protocol_ids *get_ids(struct pool_node *node, u_int8_t l4protocol)
{
	switch (l4protocol) {
	case IPPROTO_UDP:
		return &node->udp;
	case IPPROTO_TCP:
		return &node->tcp;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return &node->icmp;
	}

	log_crit(ERR_L4PROTO, "Unsupported transport protocol: %u.", l4protocol);
	return NULL;
}

/**
 * Assumes that node's pool has already been locked (pool->lock).
 */
static struct addr_section *get_section(struct protocol_ids *ids, __u16 l4_id)
{
	if (!ids)
		return NULL;

	if (l4_id < 1024)
		return (l4_id % 2 == 0) ? &ids->even_low : &ids->odd_low;
	else
		return (l4_id % 2 == 0) ? &ids->even_high : &ids->odd_high;
}

/**
 * Assumes that section's pool has already been locked (pool->lock). TODO (doc)
 */
static bool extract_any_port(struct addr_section *section, __u16 *port)
{
	if (!section)
		return NULL;

	if (!list_empty(&section->free_ports)) {
		// Reuse it.
		struct free_port *node = list_entry(section->free_ports.next, struct free_port, next);
		*port = node->port;

		list_del(&node->next);
		kfree(node);

		return true;
	}

	if (section->next_port > section->max_port)
		return false;

	*port = section->next_port;
	section->next_port += 2;
	return true;
}

int pool4_init(char *addr_strs[], int addr_count)
{
	char *defaults[] = POOL4_DEF;
	int i;

	if (!addr_strs || addr_count == 0) {
		addr_strs = defaults;
		addr_count = ARRAY_SIZE(defaults);
	}

	for (i = 0; i < addr_count; i++) {
		struct in_addr addr;

		if (str_to_addr4(addr_strs[i], &addr) != 0)
			goto parse_failure;
		log_debug("Inserting address to the IPv4 pool: %pI4.", &addr);
		if (pool4_register(&addr) != 0)
			goto silent_failure;
	}

	return 0;

parse_failure:
	log_err(ERR_PARSE_ADDR4, "Address is malformed: %s.", addr_strs[i]);
	/* Fall through. */

silent_failure:
	pool4_destroy();
	return -EINVAL;
}

/**
 * Assumes that "pool_lock" has already been locked.
 */
static void destroy_section(struct addr_section *section)
{
	struct list_head *node;
	struct free_port *port;

	while (!list_empty(&section->free_ports)) {
		node = section->free_ports.next;
		port = container_of(node, struct free_port, next);
		list_del(node);
		kfree(port);
	}
}

/**
 * Assumes that "pool_lock" has already been locked.
 */
static void destroy_pool_node(struct pool_node *node)
{
	struct protocol_ids *protos[] = { &node->udp, &node->tcp, &node->icmp };
	int i;

	list_del(&node->next);
	for (i = 0; i < ARRAY_SIZE(protos); i++) {
		destroy_section(&protos[i]->odd_low);
		destroy_section(&protos[i]->even_low);
		destroy_section(&protos[i]->odd_high);
		destroy_section(&protos[i]->even_high);
	}
	kfree(node);
}

void pool4_destroy(void)
{
	struct list_head *head;
	struct pool_node *node;

	spin_lock_bh(&pool_lock);
	while (!list_empty(&pool)) {
		head = pool.next;
		node = container_of(head, struct pool_node, next);
		destroy_pool_node(node);
	}
	spin_unlock_bh(&pool_lock);
}

static void init_section(struct addr_section *section, __u32 next_port, __u32 max_port)
{
	section->next_port = next_port;
	section->max_port = max_port;
	INIT_LIST_HEAD(&section->free_ports);
}

static void init_protocol_ids(struct protocol_ids *ids)
{
	init_section(&ids->odd_low, 1, 1023);
	init_section(&ids->even_low, 0, 1022);
	init_section(&ids->odd_high, 1025, 65535);
	init_section(&ids->even_high, 1024, 65534);
}

int pool4_register(struct in_addr *address)
{
	struct pool_node *old_node, *new_node;

	if (!address) {
		log_err(ERR_NULL, "NULL cannot be inserted to the pool.");
		return -EINVAL;
	}

	new_node = kmalloc(sizeof(struct pool_node), GFP_ATOMIC);
	if (!new_node) {
		log_err(ERR_ALLOC_FAILED, "Allocation of IPv4 pool node failed.");
		return -ENOMEM;
	}

	new_node->address = *address;
	init_protocol_ids(&new_node->udp);
	init_protocol_ids(&new_node->tcp);
	init_protocol_ids(&new_node->icmp);

	spin_lock_bh(&pool_lock);

	list_for_each_entry(old_node, &pool, next) {
		if (ipv4_addr_equals(&old_node->address, address)) {
			spin_unlock_bh(&pool_lock);
			kfree(new_node);
			log_err(ERR_POOL4_REINSERT, "The %pI4 address already belongs to the pool.", address);
			return -EINVAL;
		}
	}

	// "add to head->prev" = "add to the end of the list".
	list_add(&new_node->next, pool.prev);

	spin_unlock_bh(&pool_lock);
	return 0;
}

int pool4_remove(struct in_addr *address)
{
	struct pool_node *node;

	if (!address) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return -EINVAL;
	}

	spin_lock_bh(&pool_lock);

	node = get_pool_node(address);
	if (!node) {
		spin_unlock_bh(&pool_lock);
		log_err(ERR_POOL4_NOT_FOUND, "The address is not part of the pool.");
		return -ENOENT;
	}

	destroy_pool_node(node);

	spin_unlock_bh(&pool_lock);
	return 0;
}

bool pool4_get_any(u_int8_t l4protocol, __u16 port, struct ipv4_tuple_address *result)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);

	if (list_empty(&pool)) {
		spin_unlock(&pool_lock);
		log_err(ERR_POOL4_EMPTY, "The IPv4 pool is empty.");
		return false;
	}

	// Find an address with a compatible port
	list_for_each_entry(node, &pool, next) {
		if (extract_any_port(get_section(get_ids(node, l4protocol), port), &result->l4_id)) {
			result->address = node->address;
			spin_unlock_bh(&pool_lock);
			return true;
		}
	}

	// All compatible ports are taken. Go to a corner and cry...
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool4_get_similar(u_int8_t l4protocol, struct ipv4_tuple_address *address,
		struct ipv4_tuple_address *result)
{
	struct pool_node *node;

	if (!address) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return false;
	}

	spin_lock_bh(&pool_lock);

	node = get_pool_node(&address->address);
	if (!node) {
		log_err(ERR_POOL4_NOT_FOUND, "%pI4 does not belong to the pool.", &address->address);
		goto failure;
	}

	// TODO (later) el RFC permite usar puerto de diferente paridad/rango si aquí no se encuentra.
	result->address = address->address;
	if (extract_any_port(get_section(get_ids(node, l4protocol), address->l4_id), &result->l4_id)) {
		spin_unlock_bh(&pool_lock);
		return true;
	}

	// Fall through.

failure:
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool4_return(u_int8_t l4protocol, struct ipv4_tuple_address *address)
{
	struct pool_node *node;
	struct addr_section *section;
	struct free_port *new_port;

	if (!address) {
		log_err(ERR_NULL, "NULL is not a valid address.");
		return false;
	}

	spin_lock_bh(&pool_lock);

	node = get_pool_node(&address->address);
	if (!node) {
		log_err(ERR_POOL4_NOT_FOUND, "%pI4 does not belong to the pool.", &address->address);
		goto failure;
	}
	section = get_section(get_ids(node, l4protocol), address->l4_id);
	if (!section)
		goto failure;

	new_port = kmalloc(sizeof(*new_port), GFP_ATOMIC);
	if (!new_port) {
		// Well, crap. I guess we won't be seeing this address/port anymore :/.
		log_err(ERR_ALLOC_FAILED, "Cannot instantiate! I won't be able to remember that %pI4#%u "
				"can be reused.", &address->address, address->l4_id);
		goto failure;
	}

	new_port->port = address->l4_id;
	list_add(&new_port->next, section->free_ports.prev);

	spin_unlock_bh(&pool_lock);
	return true;

failure:
	spin_unlock_bh(&pool_lock);
	return false;
}

bool pool4_contains(struct in_addr *address)
{
	bool result;

	spin_lock_bh(&pool_lock);
	result = (get_pool_node(address) != NULL);
	spin_unlock_bh(&pool_lock);

	return result;
}

int pool4_for_each(int (*func)(struct in_addr *, void *), void * arg)
{
	struct pool_node *node;

	spin_lock_bh(&pool_lock);
	list_for_each_entry(node, &pool, next) {
		int error = func(&node->address, arg);
		if (error) {
			spin_unlock_bh(&pool_lock);
			return error;
		}
	}
	spin_unlock_bh(&pool_lock);

	return 0;
}
