#include "nat64/comm/types.h"
#include "nat64/comm/str_utils.h"

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
	case L4PROTO_NONE:
		return "None";
	case L4PROTO_TCP:
		return "TCP";
	case L4PROTO_UDP:
		return "UDP";
	case L4PROTO_ICMP:
		return "ICMP";
	}

	return NULL;
}

l4_protocol nexthdr_to_l4proto(__u8 nexthdr)
{
	switch (nexthdr) {
	case NEXTHDR_TCP:
		return L4PROTO_TCP;
	case NEXTHDR_UDP:
		return L4PROTO_UDP;
	case NEXTHDR_ICMP:
		return L4PROTO_ICMP;
	}

	return -1;
}

l4_protocol protocol_to_l4proto(__u8 protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return L4PROTO_TCP;
	case IPPROTO_UDP:
		return L4PROTO_UDP;
	case IPPROTO_ICMP:
		return L4PROTO_ICMP;
	}

	return -1;
}

bool ipv4_addr_equals(struct in_addr *expected, struct in_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->s_addr != actual->s_addr)
		return false;

	return true;
}

bool ipv6_addr_equals(struct in6_addr *expected, struct in6_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(expected, actual))
		return false;

	return true;
}

bool ipv4_tuple_addr_equals(struct ipv4_tuple_address *expected, struct ipv4_tuple_address *actual)
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

bool ipv6_tuple_addr_equals(struct ipv6_tuple_address *expected, struct ipv6_tuple_address *actual)
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

bool ipv4_pair_equals(struct ipv4_pair *pair_1, struct ipv4_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;
	if (!ipv4_tuple_addr_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv4_tuple_addr_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

bool ipv6_pair_equals(struct ipv6_pair *pair_1, struct ipv6_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;
	if (!ipv6_tuple_addr_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv6_tuple_addr_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

bool ipv6_prefix_equals(struct ipv6_prefix *expected, struct ipv6_prefix *actual)
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
	/**
	 * TODO (error) I think this is wrong...
	 * see is_icmp4_error() too.
	 */
	return !is_icmp6_info(type);
}

bool is_icmp4_info(__u8 type)
{
	return (type == ICMP_ECHO) || (type == ICMP_ECHOREPLY);
}

bool is_icmp4_error(__u8 type)
{
	return !is_icmp4_info(type);
}

/**
* log_tuple() - Prints the "tuple" tuple on the kernel ring buffer.
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
