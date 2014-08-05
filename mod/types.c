#include "nat64/mod/types.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ipv6.h>


char *l3proto_to_string(l3_protocol l3_proto)
{
	switch (l3_proto) {
	case L3PROTO_IPV6:
		return "IPv6";
	case L3PROTO_IPV4:
		return "IPv4";
	}

	return NULL;
}

char *l4proto_to_string(l4_protocol l4_proto)
{
	switch (l4_proto) {
	case L4PROTO_TCP:
		return "TCP";
	case L4PROTO_UDP:
		return "UDP";
	case L4PROTO_ICMP:
		return "ICMP";
	}

	return NULL;
}

bool ipv4_addr_equals(const struct in_addr *expected, const struct in_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->s_addr != actual->s_addr)
		return false;

	return true;
}

bool ipv6_addr_equals(const struct in6_addr *expected, const struct in6_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(expected, actual))
		return false;

	return true;
}

bool ipv4_tuple_addr_equals(const struct ipv4_tuple_address *expected,
		const struct ipv4_tuple_address *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->address.s_addr != actual->address.s_addr)
		return false;
	if (expected->l4_id != actual->l4_id)
		return false;

	return true;
}

bool ipv6_tuple_addr_equals(const struct ipv6_tuple_address *expected,
		const struct ipv6_tuple_address *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(&expected->address, &actual->address))
		return false;
	if (expected->l4_id != actual->l4_id)
		return false;

	return true;
}

bool ipv6_prefix_equals(const struct ipv6_prefix *expected, const struct ipv6_prefix *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(&expected->address, &actual->address))
		return false;
	if (expected->len != actual->len)
		return false;

	return true;
}

bool is_icmp6_info(__u8 type)
{
	return (type == ICMPV6_ECHO_REQUEST) || (type == ICMPV6_ECHO_REPLY);
}

bool is_icmp6_error(__u8 type)
{
	return (type == ICMPV6_DEST_UNREACH)
			|| (type == ICMPV6_PKT_TOOBIG)
			|| (type == ICMPV6_TIME_EXCEED)
			|| (type == ICMPV6_PARAMPROB);
}

bool is_icmp4_info(__u8 type)
{
	return (type == ICMP_ECHO) || (type == ICMP_ECHOREPLY);
}

bool is_icmp4_error(__u8 type)
{
	return (type == ICMP_DEST_UNREACH)
			|| (type == ICMP_SOURCE_QUENCH)
			|| (type == ICMP_REDIRECT)
			|| (type == ICMP_TIME_EXCEEDED)
			|| (type == ICMP_PARAMETERPROB);
}

/**
* log_tuple() - Prints the "tuple" tuple in the kernel ring buffer.
* @tuple: Structure to be dumped on logging.
*
* It's a ripoff of nf_ct_dump_tuple(), adjusted to comply to this project's logging requirements.
*/
void log_tuple(struct tuple *tuple)
{
	switch (tuple->l3_proto) {
	case L3PROTO_IPV4:
		log_debug("tuple %s-%s %pI4#%u -> %pI4#%u",
				l3proto_to_string(tuple->l3_proto), l4proto_to_string(tuple->l4_proto),
				&tuple->src.addr.ipv4, tuple->src.l4_id,
				&tuple->dst.addr.ipv4, tuple->dst.l4_id);
		break;
	case L3PROTO_IPV6:
		log_debug("tuple %s-%s %pI6c#%u -> %pI6c#%u",
				l3proto_to_string(tuple->l3_proto), l4proto_to_string(tuple->l4_proto),
				&tuple->src.addr.ipv6, tuple->src.l4_id,
				&tuple->dst.addr.ipv6, tuple->dst.l4_id);
		break;
	}
}
