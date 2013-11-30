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

__u16 ipv4_tuple_addr_hashcode(struct ipv4_tuple_address *address)
{
	return (address != NULL) ? address->l4_id : 0;
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

__u16 ipv6_tuple_addr_hashcode(struct ipv6_tuple_address *address)
{
	/*
	 * address->l4_id would perhaps be the logical hash code, since it's usually random,
	 * but during bib_get_by_ipv6_only() we need to ignore it during lookup
	 * so this needs to be a little more creative.
	 */

	__u16 i;
	__u16 result = 1;

	if (address == NULL)
		return 0;

	for (i = 0; i < 8; i++)
		result = 31 * result + ntohs(address->address.s6_addr16[i]);

	return result;
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

__u16 ipv4_pair_hashcode(struct ipv4_pair *pair)
{
	/*
	 * pair->remote.l4_id would perhaps be the logical hash code, since it's usually random,
	 * but during session_allow() we need to ignore it during lookup
	 * so this needs to be a little more creative.
	 */

	union ipv4_addr_union {
		__be32 by32;
		__be16 by16[2];
	} local, remote;
	__u16 result = 1;

	if (pair == NULL)
		return 0;

	local.by32 = pair->local.address.s_addr;
	remote.by32 = pair->remote.address.s_addr;

	result = 31 * result + ntohs(local.by16[0]);
	result = 31 * result + ntohs(remote.by16[0]);
	result = 31 * result + ntohs(local.by16[1]);
	result = 31 * result + ntohs(remote.by16[1]);

	return result;
}

__u16 ipv6_pair_hashcode(struct ipv6_pair *pair)
{
	return (pair != NULL) ? pair->local.l4_id : 0;
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

int init_ipv4_tuple(struct tuple *tuple, unsigned char *src_addr, u16 src_port,
		unsigned char *dst_addr, u16 dst_port, l4_protocol l4_proto)
{
	int error;

	error = str_to_addr4(src_addr, &tuple->src.addr.ipv4);
	if (error)
		return error;
	tuple->src.l4_id = src_port;

	error = str_to_addr4(dst_addr, &tuple->dst.addr.ipv4);
	if (error)
		return error;
	tuple->dst.l4_id = dst_port;

	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = l4_proto;

	return 0;
}

int init_ipv6_tuple(struct tuple *tuple, unsigned char *src_addr, u16 src_port,
		unsigned char *dst_addr, u16 dst_port, l4_protocol l4_proto)
{
	int error;

	error = str_to_addr6(src_addr, &tuple->src.addr.ipv6);
	if (error)
		return error;
	tuple->src.l4_id = src_port;

	error = str_to_addr6(dst_addr, &tuple->dst.addr.ipv6);
	if (error)
		return error;
	tuple->dst.l4_id = dst_port;

	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = l4_proto;

	return 0;
}

int init_ipv4_tuple_from_pair(struct tuple *tuple, struct ipv4_pair *pair4, l4_protocol l4_proto)
{
	tuple->src.addr.ipv4 = pair4->remote.address;
	tuple->src.l4_id = pair4->remote.l4_id;

	tuple->dst.addr.ipv4 = pair4->local.address;
	tuple->dst.l4_id = pair4->local.l4_id;

	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = l4_proto;

	return 0;
}

int init_ipv6_tuple_from_pair(struct tuple *tuple, struct ipv6_pair *pair6, l4_protocol l4_proto)
{
	tuple->src.addr.ipv6 = pair6->remote.address;
	tuple->src.l4_id = pair6->remote.l4_id;

	tuple->dst.addr.ipv6 = pair6->local.address;
	tuple->dst.l4_id = pair6->local.l4_id;

	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = l4_proto;

	return 0;
}
