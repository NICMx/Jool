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

static int get_next_port(l4_protocol proto, __u16 *result)
{
	u32 *port_counter;

	switch (proto) {
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
		log_warning("Unknown l4 protocol: %d.", proto);
		return -EINVAL;
	}

	if (*port_counter > 65535) {
		log_warning("I ran out of ports/icmp ids.");
		return -ESRCH;
	}

	*result = *port_counter;
	*port_counter += 2;

	return 0;
}

int pool4_get_match(l4_protocol proto, struct ipv4_tuple_address *addr, __u16 *result)
{
	return pool4_get_any_port(proto, &addr->address, result);
}

int pool4_get_any_port(l4_protocol proto, struct in_addr *addr, __u16 *result)
{
	return ipv4_addr_equals(addr, &pool_address)
			? get_next_port(proto, result)
			: -EINVAL;
}

int pool4_get_any_addr(l4_protocol proto, __u16 l4_id, struct ipv4_tuple_address *result)
{
	result->address = pool_address;
	return get_next_port(proto, &result->l4_id);
}

int pool4_return(l4_protocol l4_proto, struct ipv4_tuple_address *address)
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

int pool4_for_each(int (*func)(struct pool4_node *, void *), void * arg)
{
	/* Meh, whatever. */
	log_debug("Somebody asked me to iterate through the pool.");
	return -EINVAL;
}
