#include "nat64/mod/common/types.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ipv6.h>
#include "nat64/common/str_utils.h"

__u8 l4_proto_to_nexthdr(l4_protocol proto)
{
	switch (proto) {
	case L4PROTO_TCP:
		return NEXTHDR_TCP;
	case L4PROTO_UDP:
		return NEXTHDR_UDP;
	case L4PROTO_ICMP:
		return NEXTHDR_ICMP;
	case L4PROTO_OTHER:
		return 0;
	}

	return 0;
}

bool port_range_equals(const struct port_range *r1,
		const struct port_range *r2)
{
	return (r1->min == r2->min) && (r1->max == r2->max);
}

/**
 * Range [1,3] touches [2,6].
 * Range [1,3] touches [3,6].
 * Range [1,3] touches [4,6].
 * Range [1,3] does not touch [5,6].
 */
bool port_range_touches(const struct port_range *r1,
		const struct port_range *r2)
{
	return r1->max >= (r2->min - 1) && r1->min <= (r2->max + 1);
}

bool port_range_contains(const struct port_range *range, __u16 port)
{
	return range->min <= port && port <= range->max;
}

unsigned int port_range_count(const struct port_range *range)
{
	return range->max - range->min + 1U;
}

void port_range_fuse(struct port_range *r1, const struct port_range *r2)
{
	r1->min = min(r1->min, r2->min);
	r1->max = max(r1->max, r2->max);
}

bool pool4_range_equals(struct pool4_range *r1, struct pool4_range *r2)
{
	return addr4_equals(&r1->addr, &r2->addr)
			&& port_range_equals(&r1->ports, &r2->ports);
}

bool pool4_range_touches(const struct pool4_range *r1,
		const struct pool4_range *r2)
{
	return addr4_equals(&r1->addr, &r2->addr)
			&& port_range_touches(&r1->ports, &r2->ports);
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
		log_debug("Tuple: %pI4#%u -> %pI4#%u (%s)",
				&tuple->src.addr4.l3, tuple->src.addr4.l4,
				&tuple->dst.addr4.l3, tuple->dst.addr4.l4,
				l4proto_to_string(tuple->l4_proto));
		break;
	case L3PROTO_IPV6:
		log_debug("Tuple: %pI6c#%u -> %pI6c#%u (%s)",
				&tuple->src.addr6.l3, tuple->src.addr6.l4,
				&tuple->dst.addr6.l3, tuple->dst.addr6.l4,
				l4proto_to_string(tuple->l4_proto));
		break;
	}
}
