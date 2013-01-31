#include "nf_nat64_ipv4_pool.h"

#include <linux/slab.h>
#include "nf_nat64_constants.h"


// TODO (info) revisa nulos en valores de retorno.

/**
 * A port which is known to be in the pool; available for borrowal.
 */
struct free_port {
	/** The port number. */
	__u16 port;
	/** Next port within the list of free ones (see addr_section.free_ports).  */
	struct list_head next;
};

/** Rename for the type of the port list below. */
#define port_list list_head

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
	struct port_list free_ports;
};

/**
 * An address within the pool, along with its ports.
 */
struct pool_node
{
	/** The address itself. */
	struct in_addr address;

	/** The address's odd ports from the range 0-1023. */
	struct addr_section odd_low;
	/** The address's even ports from the range 0-1023. */
	struct addr_section even_low;
	/** The address's odd ports from the range 1024-65535. */
	struct addr_section odd_high;
	/** The address's even ports from the range 1024-65535. */
	struct addr_section even_high;

	/** Next address within the pool (since they are linked listed; see pools.*). */
	struct list_head next;
};

struct address_list {
	struct list_head list;
	spinlock_t lock;
};

/**
 * The global container of the entire pools.
 * Each pool can be a linked list because we're assuming we won't be holding too many addresses, and
 * the first ones will be the ones seeing the most activity.
 */
static struct {
	/** Linked list of addresses for the UDP protocol. Contains structs of type pool_node. */
	struct address_list udp;
	/** Linked list of addresses for the TCP protocol. Contains structs of type pool_node. */
	struct address_list tcp;
	/** Linked list of addresses for the ICMP protocol. Contains structs of type pool_node. */
	struct address_list icmp;
} pools;


static struct address_list *get_pool(u_int8_t l4protocol)
{
	switch (l4protocol) {
		case IPPROTO_UDP:
			return &pools.udp;
			break;
		case IPPROTO_TCP:
			return &pools.tcp;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			return &pools.icmp;
	}

	log_crit("Error: Unknown l4 protocol (%d); no pool mapped to it.", l4protocol);
	return NULL;
}

/**
 * Assumes that pool has already been locked (pool->lock).
 */
static struct pool_node *get_pool_node(struct address_list *pool, struct in_addr *address)
{
	struct pool_node *node;

	list_for_each_entry(node, &pool->list, next)
		if (ipv4_addr_equals(&node->address, address))
			return node;

	return NULL;
}

/**
 * Assumes that node's pool has already been locked (pool->lock).
 */
static struct addr_section *get_section(struct pool_node *node, struct ipv4_tuple_address *address)
{
	__u16 port = be16_to_cpu(address->pi.port);
	if (port < 1024)
		return (port % 2 == 0) ? &node->even_low : &node->odd_low;
	else
		return (port % 2 == 0) ? &node->even_high : &node->odd_high;
}

/**
 * Assumes that section's pool has already been locked (pool->lock).
 */
static bool extract_any_port(struct addr_section *section, __be16 *port)
{
	if (!list_empty(&section->free_ports)) {
		// Reuse it.
		struct free_port *node = list_entry(section->free_ports.next, struct free_port, next);
		*port = cpu_to_be16(node->port);

		list_del(&node->next);
		kfree(node);

		return true;
	}

	if (section->next_port > section->max_port)
		return false;

	*port = cpu_to_be16(section->next_port);
	section->next_port += 2;
	return true;
}

static bool load_defaults(void)
{
	unsigned char *pool4_addresses_str[] = POOL4_DEF;
	struct in_addr current_addr;
	int i;

	for (i = 0; i < ARRAY_SIZE(pool4_addresses_str); i++) {
		if (!str_to_addr4(pool4_addresses_str[i], &current_addr)) {
			log_warning("Address in headers is malformed: '%s'.", pool4_addresses_str[i]);
			pool4_destroy();
			return false;
		}
		pool4_register(&current_addr);
	}

	return true;
}

bool pool4_init(void)
{
	INIT_LIST_HEAD(&pools.udp.list);
	spin_lock_init(&pools.udp.lock);

	INIT_LIST_HEAD(&pools.tcp.list);
	spin_lock_init(&pools.tcp.lock);

	INIT_LIST_HEAD(&pools.icmp.list);
	spin_lock_init(&pools.icmp.lock);

	return load_defaults();
}

/**
 * Assumes that section's pool has already been locked (pool->lock).
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
 * Assumes that node's pool has already been locked (pool->lock).
 */
static void destroy_pool_node(struct pool_node *node)
{
	list_del(&node->next);
	destroy_section(&node->odd_low);
	destroy_section(&node->even_low);
	destroy_section(&node->odd_high);
	destroy_section(&node->even_high);
	kfree(node);
}

void pool4_destroy(void)
{
	struct address_list *pool_lists[] = { &pools.udp, &pools.tcp, &pools.icmp };
	int i;

	for (i = 0; i < ARRAY_SIZE(pool_lists); i++) {
		struct list_head *head;
		struct pool_node *node;

		spin_lock_bh(&pool_lists[i]->lock);
		while (!list_empty(&pool_lists[i]->list)) {
			head = pool_lists[i]->list.next;
			node = container_of(head, struct pool_node, next);
			destroy_pool_node(node);
		}
		spin_unlock_bh(&pool_lists[i]->lock);
	}
}

static void init_section(struct addr_section *section, __u32 next_port, __u32 max_port)
{
	section->next_port = next_port;
	section->max_port = max_port;
	INIT_LIST_HEAD(&section->free_ports);
}

enum response_code pool4_register(struct in_addr *address)
{
	struct address_list *pool[] = { &pools.tcp, &pools.udp, &pools.icmp };
	struct pool_node *node[3]; // TODO (info) array_size()...
	int i;

	for (i = 0; i < 3; i++) {
		node[i] = kmalloc(sizeof(struct pool_node), GFP_ATOMIC);
		if (!node[i]) {
			for (; i >= 0; i--)
				kfree(node[i]);
			return RESPONSE_ALLOC_FAILED;
		}
	}

	for (i = 0; i < 3; i++) {
		node[i]->address = *address;
		init_section(&node[i]->odd_low, 1, 1023);
		init_section(&node[i]->even_low, 0, 1022);
		init_section(&node[i]->odd_high, 1025, 65535);
		init_section(&node[i]->even_high, 1024, 65534);

		spin_lock_bh(&pool[i]->lock);
		// "add to head->prev" = "add to the end of the list".
		list_add(&node[i]->next, pool[i]->list.prev);
		spin_unlock_bh(&pool[i]->lock);
	}

	return RESPONSE_SUCCESS;
}

enum response_code pool4_remove(struct in_addr *address)
{
	struct address_list *pool[] = { &pools.tcp, &pools.udp, &pools.icmp };
	struct pool_node *node;
	int proto;
	int deleted = 0;

	for (proto = 0; proto < 3; proto++) { // TODO ARRAY_SIZE
		spin_lock_bh(&pool[proto]->lock);

		node = get_pool_node(pool[proto], address);
		if (!node) {
			spin_unlock_bh(&pool[proto]->lock);
			continue;
		}
		destroy_pool_node(node);

		spin_unlock_bh(&pool[proto]->lock);
		deleted++;
	}

	if (deleted != 0 && deleted != 3) { // TODO ARRAY_SIZE
		log_crit("Programming error: Address was in %u table(s).", deleted);
		return RESPONSE_NOT_FOUND;
	}

	return RESPONSE_SUCCESS;
}

bool pool4_get_any(u_int8_t l4protocol, __be16 port, struct ipv4_tuple_address *result)
{
	struct address_list *pool;
	struct pool_node *node;

	// Init
	pool = get_pool(l4protocol);
	if (!pool)
		return NULL;
	if (list_empty(&pool->list)) {
		log_warning("The IPv4 pool is empty! Won't be able to lend an address.");
		return NULL;
	}

	// Find an address with a compatible port
	spin_lock_bh(&pool->lock);
	list_for_each_entry(node, &pool->list, next) {
		struct ipv4_tuple_address tuple_addr;
		struct addr_section *section;

		tuple_addr.address = node->address;
		tuple_addr.pi.port = port;
		section = get_section(node, &tuple_addr);

		if (section != NULL && extract_any_port(section, &result->pi.port)) {
			result->address = node->address;
			spin_unlock_bh(&pool->lock);
			return true;
		}
	}
	spin_unlock_bh(&pool->lock);

	// All compatible ports are taken. Go to a corner and cry...
	return false;
}

bool pool4_get_similar(u_int8_t l4protocol, struct ipv4_tuple_address *address,
		struct ipv4_tuple_address *result)
{
	struct address_list *pool;
	struct pool_node *node;
	struct addr_section *section;

	pool = get_pool(l4protocol);
	if (!pool)
		return false;

	spin_lock_bh(&pool->lock);

	node = get_pool_node(pool, &address->address);
	if (!node)
		goto failure;
	// TODO (later) el RFC permite usar puerto de diferente paridad/rango si aquí no se encuentra.
	section = get_section(node, address);
	if (!section)
		goto failure;

	result->address = address->address;
	if (extract_any_port(section, &result->pi.port)) {
		spin_unlock_bh(&pool->lock);
		return true;
	}

	// Fall through.

failure:
	spin_unlock_bh(&pool->lock);
	return false;
}

bool pool4_return(u_int8_t l4protocol, struct ipv4_tuple_address *address)
{
	struct address_list *pool;
	struct pool_node *node;
	struct addr_section *section;
	struct free_port *new_port;

	pool = get_pool(l4protocol);
	if (!pool)
		return false;

	spin_lock_bh(&pool->lock);

	node = get_pool_node(pool, &address->address);
	if (!node)
		goto failure;
	section = get_section(node, address);
	if (!section)
		goto failure;

	new_port = kmalloc(sizeof(*new_port), GFP_ATOMIC);
	if (!new_port) {
		// Well, crap. I guess we won't be seeing this address/port anymore :/.
		log_err("Cannot instantiate! I won't be able to remember that %pI4#%u can be reused.",
				&address->address, address->pi.port);
		goto failure;
	}

	new_port->port = be16_to_cpu(address->pi.port);
	list_add(&new_port->next, section->free_ports.prev);

	spin_unlock_bh(&pool->lock);
	return true;

failure:
	spin_unlock_bh(&pool->lock);
	return false;
}

bool pool4_contains(struct in_addr *address)
{
	bool result;

	spin_lock_bh(&pools.udp.lock);
	result = (get_pool_node(&pools.udp, address) != NULL);
	spin_unlock_bh(&pools.udp.lock);

	return result;
}

enum response_code pool4_to_array(struct in_addr **array_out, __u32 *size_out)
{
	struct list_head *cursor;
	struct pool_node *node;

	struct in_addr *array;
	__u32 size;

	size = 0;
	spin_lock_bh(&pools.udp.lock);
	list_for_each(cursor, &pools.udp.list)
		size++;
	spin_unlock_bh(&pools.udp.lock);

	array = kmalloc(size * sizeof(*node), GFP_ATOMIC);
	if (!array)
		return RESPONSE_ALLOC_FAILED;

	size = 0;
	spin_lock_bh(&pools.udp.lock);
	list_for_each_entry(node, &pools.udp.list, next) {
		memcpy(&array[size], &node->address, sizeof(struct in_addr));
		size++;
	}
	spin_unlock_bh(&pools.udp.lock);

	*array_out = array;
	*size_out = size;
	return RESPONSE_SUCCESS;
}
