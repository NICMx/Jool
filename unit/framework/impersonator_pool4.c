#include "nat64/mod/pool4.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/str_utils.h"

#include <linux/kernel.h>


static struct in_addr pool_address;
static u32 pool_current_udp_port;
static u32 pool_current_tcp_port;
static u32 pool_current_icmp_id;

int pool4_init(char *addr_strs[], int addr_count)
{
	char *defaults[] = POOL4_DEF;

	if (!addr_strs)
		addr_strs = defaults;

	if (str_to_addr4(addr_strs[0], &pool_address) != 0) {
		log_warning("Cannot parse '%s' as a IPv4 address.", addr_strs[0]);
		return -EINVAL;
	}

	pool_current_udp_port = 1024;
	pool_current_tcp_port = 1024;
	pool_current_icmp_id = 1024;

	return 0;
}

void pool4_destroy(void)
{
	/* No code. */
}

int pool4_register(struct in_addr *address)
{
	return 0;
}

int pool4_remove(struct in_addr *address)
{
	return 0;
}

bool pool4_get_any(enum l4_protocol l4_proto, __be16 port, struct ipv4_tuple_address *result)
{
	u32 *port_counter;

	result->address = pool_address;
	switch (l4_proto) {
	case L4PROTO_UDP:
		port_counter = &pool_current_udp_port;
		break;
	case L4PROTO_TCP:
		port_counter = &pool_current_tcp_port;
		break;
	case L4PROTO_ICMP:
		port_counter = &pool_current_icmp_id;
		break;
	default:
		log_warning("Unknown l4 protocol: %d.", l4_proto);
		return false;
	}

	if (*port_counter > 65535) {
		log_warning("I ran out of ports/icmp ids.");
		return false;
	}

	result->l4_id = *port_counter;
	*port_counter += 2;

	return true;
}

bool pool4_get_similar(l4_protocol l4_proto, struct ipv4_tuple_address *address,
		struct ipv4_tuple_address *result)
{
	if (!address) {
		log_warning("Somebody send me NULL as an IPv4 address.");
		return false;
	}

	if (pool_address.s_addr != address->address.s_addr) {
		log_warning("Address %pI4 does not belong to the pool.", &address->address);
		return false;
	}

	return pool4_get_any(l4_proto, address->l4_id, result);
}

bool pool4_get(l4_protocol l4_proto, struct ipv4_tuple_address *address)
{
	log_warning("pool_get() is not implemented for testing.");
	return false;
}

bool pool4_return(l4_protocol l4_proto, struct ipv4_tuple_address *address)
{
	/* Meh, whatever. */
	log_debug("Somebody returned %pI4#%u to the pool.", &address->address, address->l4_id);
	return true;
}

bool pool4_contains(struct in_addr *address)
{
	if (!address) {
		log_warning("Somebody sent me NULL as an IPv4 address.");
		return false;
	}

	return pool_address.s_addr == address->s_addr;
}

int pool4_for_each(int (*func)(struct in_addr *, void *), void * arg)
{
	/* Meh, whatever. */
	log_debug("Somebody asked me to iterate through the pool.");
	return -EINVAL;
}
