#include <linux/inet.h>

#include "nf_nat64_types.h"
#include "nf_nat64_ipv6_hdr_iterator.h"

#define CHECK_NULLS(expected, actual) \
	if (expected == actual) return true; \
	if (expected == NULL || actual == NULL) return false;

/** This is a slightly more versatile in_addr. */
union ipv4_addr_union {
	__be32 by32;
	__be16 by16[2];
};

bool ipv4_addr_equals(struct in_addr *expected, struct in_addr *actual)
{
	CHECK_NULLS(expected, actual);

	if (expected->s_addr != actual->s_addr)
		return false;

	return true;
}

bool ipv6_addr_equals(struct in6_addr *expected, struct in6_addr *actual)
{
	int i;

	CHECK_NULLS(expected, actual);

	for (i = 0; i < 4; i++)
		if (expected->in6_u.u6_addr32[i] != expected->in6_u.u6_addr32[i])
			return false;

	return true;
}

__u16 ipv4_addr_hash_code(struct in_addr *addr)
{
	union ipv4_addr_union addr_union;
	__u16 result = 1;

	if (addr == NULL)
			return 0;
	addr_union.by32 = addr->s_addr;

	result = 31 * result + be16_to_cpu(addr_union.by16[0]);
	result = 31 * result + be16_to_cpu(addr_union.by16[1]);

	return result;
}

bool ipv4_tuple_address_equals(struct ipv4_tuple_address *expected, struct ipv4_tuple_address *actual)
{
	CHECK_NULLS(expected, actual);

	if (!ipv4_addr_equals(&expected->address, &actual->address))
		return false;
	if (expected->pi.port != actual->pi.port)
		return false;

	return true;
}

/** Regresa el hash code correspondiente a la direcction "address". */
__u16 ipv4_tuple_address_hash_code(struct ipv4_tuple_address *address)
{
	return (address != NULL) ? be16_to_cpu(address->pi.port) : 0;
}

bool ipv6_tuple_address_equals(struct ipv6_tuple_address *expected, struct ipv6_tuple_address *actual)
{
	CHECK_NULLS(expected, actual);

	if (!ipv6_addr_equals(&expected->address, &actual->address))
		return false;
	if (expected->pi.port != actual->pi.port)
		return false;

	return true;
}

/** Regresa el hash code correspondiente a la direcction "address". */
__u16 ipv6_tuple_address_hash_code(struct ipv6_tuple_address *address)
{
	return (address != NULL) ? be16_to_cpu(address->pi.port) : 0;
}

bool ipv4_pair_equals(struct ipv4_pair *pair_1, struct ipv4_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;

	if (!ipv4_tuple_address_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv4_tuple_address_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

bool ipv6_pair_equals(struct ipv6_pair *pair_1, struct ipv6_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;

	if (!ipv6_tuple_address_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv6_tuple_address_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

__u16 ipv4_pair_hash_code(struct ipv4_pair *pair)
{
	// pair->remote.pi.port would perhaps be the logical hash code, since it's usually random,
	// but during nat64_is_allowed_by_address_filtering() we need to ignore it during lookup
	// so this needs to be a little more creative.

	union ipv4_addr_union local, remote;
	__u16 result = 1;

	if (pair == NULL)
		return 0;

	local.by32 = pair->local.address.s_addr;
	remote.by32 = pair->remote.address.s_addr;

	result = 31 * result + be16_to_cpu(local.by16[0]);
	result = 31 * result + be16_to_cpu(remote.by16[0]);
	result = 31 * result + be16_to_cpu(local.by16[1]);
	result = 31 * result + be16_to_cpu(remote.by16[1]);

	return result;
}

__u16 ipv6_pair_hash_code(struct ipv6_pair *pair)
{
	return (pair != NULL) ? be16_to_cpu(pair->local.pi.port) : 0;
}

void print_packet(struct sk_buff *skb)
{
	struct iphdr *hdr4 = ip_hdr(skb);
	struct ipv6hdr *hdr6 = ipv6_hdr(skb);

	switch (hdr4->version) {
	case 4:
		pr_debug("  Version: %d\n", hdr4->version);
		pr_debug("  Header length: %d\n", hdr4->ihl);
		pr_debug("  Type of service: %d\n", hdr4->tos);
		pr_debug("  Total length: %d\n", be16_to_cpu(hdr4->tot_len));
		pr_debug("  Identification: %d\n", be16_to_cpu(hdr4->id));
		pr_debug("  Fragment Offset: %d\n", be16_to_cpu(hdr4->frag_off));
		pr_debug("  TTL: %d\n", hdr4->ttl);
		pr_debug("  Protocol: %d\n", hdr4->protocol);
		pr_debug("  Checksum: %d\n", be16_to_cpu(hdr4->check));
		pr_debug("  Source addr: %pI4\n", &hdr4->saddr);
		pr_debug("  Dest addr: %pI4\n", &hdr4->daddr);
		break;

	case 6:
		pr_debug("  Version: %d\n", hdr6->version);
		pr_debug("  Traffic class: %d\n", (hdr6->priority << 4) | (hdr6->flow_lbl[0] >> 4));
		pr_debug("  Flow lbl: %d %d %d\n", hdr6->flow_lbl[0] & 0xFF, hdr6->flow_lbl[1],
				hdr6->flow_lbl[2]);
		pr_debug("  Payload length: %d\n", be16_to_cpu(hdr6->payload_len));
		pr_debug("  Next hdr: %d\n", hdr6->nexthdr);
		pr_debug("  Hop limit: %d\n", hdr6->hop_limit);
		pr_debug("  Source addr: %pI6c\n", &hdr6->saddr);
		pr_debug("  Dest addr: %pI6c\n", &hdr6->daddr);
		break;

	default:
		pr_debug("  Unknown protocol.\n");
		break;
	}
}

bool in6_aton(const char *str, struct in6_addr *result)
{
	return in6_pton(str, -1, (u8 *) result, '\0', NULL);
}

