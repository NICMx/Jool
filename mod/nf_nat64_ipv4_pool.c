#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/list.h>

#include "nf_nat64_ipv4_pool.h"


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
struct pool_addr
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

	/** Next address within the pool (since they are linked listed; see pool.*). */
	struct list_head next;
};

/** Rename for the type of the pool lists below. */
#define address_list list_head

/**
 * The global container of the entire pools.
 * Each pool can be a linked list because we're assuming we won't be holding too many addresses, and
 * the first ones will be the ones seeing the most activity.
 */
struct {
	/** Linked list of addresses for the UDP protocol. Contains structs of type pool_addr. */
	struct address_list udp;
	/** Linked list of addresses for the TCP protocol. Contains structs of type pool_addr. */
	struct address_list tcp;
	/** Linked list of addresses for the ICMP protocol. Contains structs of type pool_addr. */
	struct address_list icmp;
} pools;


static struct address_list* get_pool(u_int8_t l4protocol)
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

static struct pool_addr *get_pool_addr(u_int8_t l4protocol, struct in_addr *address)
{
	struct address_list *pool;
	struct list_head *cursor;

	pool = get_pool(l4protocol);
	if (!pool)
		return NULL;
	if (list_empty(pool)) {
		log_warning("The IPv4 pool is empty!");
		return NULL;
	}

	list_for_each(cursor, pool) {
		struct pool_addr *pool_address = list_entry(cursor, struct pool_addr, next);
		if (ipv4_addr_equals(&pool_address->address, address))
			return pool_address;
	}

	return NULL;
}

static struct addr_section *get_section(u_int8_t l4protocol, struct ipv4_tuple_address *address)
{
	struct pool_addr *pool_address;
	__u16 port;

	pool_address = get_pool_addr(l4protocol, &address->address);
	if (!pool_address)
		return NULL;

	port = be16_to_cpu(address->pi.port);
	if (port < 1024)
		return (port % 2 == 0) ? &pool_address->even_low : &pool_address->odd_low;
	else
		return (port % 2 == 0) ? &pool_address->even_high : &pool_address->odd_high;
}

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

bool pool4_init(void)
{
	INIT_LIST_HEAD(&pools.udp);
	INIT_LIST_HEAD(&pools.tcp);
	INIT_LIST_HEAD(&pools.icmp);
	return true;
}

static void destroy_section(struct addr_section *section)
{
	struct list_head *current_node;
	struct free_port *current_port;

	while (!list_empty(&section->free_ports)) {
		current_node = section->free_ports.next;
		current_port = container_of(current_node, struct free_port, next);
		list_del(current_node);
		kfree(current_port);
	}
}

static void destroy_pool_addr(struct pool_addr *pool_address)
{
	list_del(&pool_address->next);
	destroy_section(&pool_address->odd_low);
	destroy_section(&pool_address->even_low);
	destroy_section(&pool_address->odd_high);
	destroy_section(&pool_address->even_high);
	kfree(pool_address);
}

void pool4_destroy(void)
{
	struct address_list *pool_lists[] = { &pools.udp, &pools.tcp, &pools.icmp };
	int i;

	for (i = 0; i < ARRAY_SIZE(pool_lists); i++) {
		struct list_head *current_node;
		struct pool_addr *current_address;

		while (!list_empty(pool_lists[i])) {
			current_node = pool_lists[i]->next;
			current_address = container_of(current_node, struct pool_addr, next);
			destroy_pool_addr(current_address);
		}
	}
}

static void init_section(struct addr_section *section, __u32 next_port, __u32 max_port)
{
	section->next_port = next_port;
	section->max_port = max_port;
	INIT_LIST_HEAD(&section->free_ports);
}

bool pool4_register(u_int8_t l4protocol, struct in_addr *address)
{
	struct address_list *pool;
	struct pool_addr *pool_address;

	pool = get_pool(l4protocol);
	if (!pool)
		return false;

	pool_address = kmalloc(sizeof(*pool_address), GFP_ATOMIC);
	if (!pool_address) {
		log_warning("Could not allocate address %pI4 for the pool. Won't be able to include it...",
				address);
		return false;
	}

	pool_address->address = *address;
	init_section(&pool_address->odd_low, 1, 1023);
	init_section(&pool_address->even_low, 0, 1022);
	init_section(&pool_address->odd_high, 1025, 65535);
	init_section(&pool_address->even_high, 1024, 65534);
	// "add to head->prev" = "add to the end of the list".
	list_add(&pool_address->next, pool->prev);

	return true;
}

bool pool4_remove(u_int8_t l4protocol, struct in_addr *address)
{
	struct pool_addr *pool_address = get_pool_addr(l4protocol, address);
	if (!pool_address)
		return false;

	destroy_pool_addr(pool_address);
	return true;
}

struct ipv4_tuple_address *pool4_get_any(u_int8_t l4protocol, __be16 port)
{
	struct address_list *pool;
	struct ipv4_tuple_address *result;
	struct list_head *cursor;

	// Init
	pool = get_pool(l4protocol);
	if (!pool)
		return NULL;
	if (list_empty(pool)) {
		log_warning("The IPv4 pool is empty! Won't be able to lend an address.");
		return NULL;
	}

	result = kmalloc(sizeof(*result), GFP_ATOMIC);
	if (!result) {
		log_warning("Could not allocate a result. Won't be able to lend an address for port %u.",
				be16_to_cpu(port));
		return NULL;
	}

	// Find an address with a compatible port
	list_for_each(cursor, pool) {
		struct pool_addr *current_address;
		struct ipv4_tuple_address tuple_addr;
		struct addr_section *section;

		current_address = list_entry(cursor, struct pool_addr, next);
		tuple_addr.address = current_address->address;
		tuple_addr.pi.port = port;
		section = get_section(l4protocol, &tuple_addr);

		if (extract_any_port(section, &result->pi.port)) {
			result->address = current_address->address;
			return result;
		}
	}

	// All compatible ports are taken. Go to a corner and cry...
	kfree(result);
	return NULL;
}

struct ipv4_tuple_address *pool4_get_similar(u_int8_t l4protocol, struct ipv4_tuple_address *address)
{
	struct addr_section *section;
	struct ipv4_tuple_address *result;

	// Init
	section = get_section(l4protocol, address);
	if (!section)
		return NULL;

	result = kmalloc(sizeof(*result), GFP_ATOMIC);
	if (!result) {
		log_warning("Could not allocate a result. Won't be able to lend an address for %pI4#%u.",
						&address->address, be16_to_cpu(address->pi.port));
		return NULL;
	}
	result->address = address->address;

	// Find a compatible port
	if (extract_any_port(section, &result->pi.port))
		return result;

	// None available; die
	kfree(result);
	return NULL;
}

bool pool4_return(u_int8_t l4protocol, struct ipv4_tuple_address *address)
{
	struct addr_section *section;
	struct free_port *new_port;

	section = get_section(l4protocol, address);
	if (!section)
		return false;

	new_port = kmalloc(sizeof(*new_port), GFP_ATOMIC);
	if (!new_port) {
		// Well, crap. I guess we won't be seeing this address/port anymore :/.
		log_err("Cannot instantiate! I won't be able to remember that %pI4#%u can be reused.",
				&address->address, address->pi.port);
		return false;
	}
	new_port->port = be16_to_cpu(address->pi.port);
	list_add(&new_port->next, section->free_ports.prev);

	kfree(address);
	return true;
}
