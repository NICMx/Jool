#include "nat64/mod/common/types.h"
#include "nat64/comm/str_utils.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ipv6.h>


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

bool ipv4_transport_addr_equals(const struct ipv4_transport_addr *expected,
		const struct ipv4_transport_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->l3.s_addr != actual->l3.s_addr)
		return false;
	if (expected->l4 != actual->l4)
		return false;

	return true;
}

bool ipv6_transport_addr_equals(const struct ipv6_transport_addr *expected,
		const struct ipv6_transport_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(&expected->l3, &actual->l3))
		return false;
	if (expected->l4 != actual->l4)
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

bool ipv4_prefix_equals(const struct ipv4_prefix *expected, const struct ipv4_prefix *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->address.s_addr != actual->address.s_addr)
		return false;
	if (expected->len != actual->len)
		return false;

	return true;
}

bool ipv4_prefix_contains(const struct ipv4_prefix *prefix, const struct in_addr *addr)
{
	__u32 maskbits = (~0) << (32 - prefix->len);
	__u32 prefixbits = be32_to_cpu(prefix->address.s_addr) & maskbits;
	__u32 addrbits = be32_to_cpu(addr->s_addr) & maskbits;
	return prefixbits == addrbits;
}

bool ipv4_prefix_intersects(const struct ipv4_prefix *p1, const struct ipv4_prefix *p2)
{
	return ipv4_prefix_contains(p1, &p2->address) || ipv4_prefix_contains(p2, &p1->address);
}

bool ipv6_prefix_contains(const struct ipv6_prefix *prefix, const struct in6_addr *addr)
{
	return ipv6_prefix_equal(&prefix->address, addr, prefix->len);
}

bool is_icmp6_info(__u8 type)
{
	return (type == ICMPV6_ECHO_REQUEST) || (type == ICMPV6_ECHO_REPLY);
}

bool is_icmp6_error(__u8 type)
{
	/*
	 * We do not return !is_icmp6_info(type) because unknown codes should be considered
	 * untranslatable.
	 */
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
				&tuple->src.addr4.l3, tuple->src.addr4.l4,
				&tuple->dst.addr4.l3, tuple->dst.addr4.l4);
		break;
	case L3PROTO_IPV6:
		log_debug("tuple %s-%s %pI6c#%u -> %pI6c#%u",
				l3proto_to_string(tuple->l3_proto), l4proto_to_string(tuple->l4_proto),
				&tuple->src.addr6.l3, tuple->src.addr6.l4,
				&tuple->dst.addr6.l3, tuple->dst.addr6.l4);
		break;
	}
}
