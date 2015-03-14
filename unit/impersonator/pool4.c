#include "nat64/mod/stateful/pool4.h"
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/types.h"


static struct in_addr pool_address;
static u32 pool_current_udp_port;
static u32 pool_current_tcp_port;
static u32 pool_current_icmp_id;

int pool4_init(char *addr_strs[], int addr_count)
{
	char *defaults[] = { "192.0.2.128" };

	if (!addr_strs)
		addr_strs = defaults;

	if (str_to_addr4(addr_strs[0], &pool_address) != 0) {
		log_err("Cannot parse '%s' as a IPv4 address.", addr_strs[0]);
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

int pool4_add(struct ipv4_prefix *prefix)
{
	return 0;
}

int pool4_remove(struct ipv4_prefix *prefix)
{
	return 0;
}

int pool4_get(l4_protocol l4_proto, struct ipv4_transport_addr *addr)
{
	return addr4_equals(&addr->l3, &pool_address) ? 0 : -EINVAL;
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
		log_err("Unknown l4 protocol: %d.", proto);
		return -EINVAL;
	}

	if (*port_counter > 65535) {
		log_err("I ran out of ports/icmp ids.");
		return -ESRCH;
	}

	*result = *port_counter;
	*port_counter += 2;

	return 0;
}

int pool4_get_match(l4_protocol proto, struct ipv4_transport_addr *addr, __u16 *result)
{
	return pool4_get_any_port(proto, &addr->l3, result);
}

int pool4_get_any_port(l4_protocol proto, const struct in_addr *addr, __u16 *result)
{
	return addr4_equals(addr, &pool_address)
			? get_next_port(proto, result)
			: -EINVAL;
}

int pool4_get_any_addr(l4_protocol proto, __u16 l4_id, struct ipv4_transport_addr *result)
{
	result->l3 = pool_address;
	return get_next_port(proto, &result->l4);
}

int pool4_return(l4_protocol l4_proto, const struct ipv4_transport_addr *address)
{
	/* Meh, whatever. */
	log_debug("Somebody returned %pI4#%u to the pool.", &address->l3, address->l4);
	return 0;
}

bool pool4_contains(__be32 address)
{
	if (!address) {
		log_err("Somebody sent me NULL as an IPv4 address.");
		return false;
	}

	return pool_address.s_addr == address;
}

int pool4_for_each(int (*func)(struct ipv4_prefix *, void *), void * arg)
{
	/* Meh, whatever. */
	log_debug("Somebody asked me to iterate through the pool.");
	return -EINVAL;
}

int pool4_flush(void)
{
	log_debug("Flushing the IPv4 pool.");
	return 0;
}

int pool4_count(__u64 *result)
{
	*result = 1;
	return 0;
}

bool pool4_is_empty(void)
{
	return false;
}
