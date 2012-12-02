#include "external_stuff.h"
#include "nf_nat64_types.h"


bool is_address_legal(struct in6_addr *address)
{
	// TODO (severe) nadie está haciendo esto.
	return true;
}

bool nf_nat64_ipv4_pool_contains_addr(__be32 addr)
{
	return true;
}

bool nf_nat64_ipv6_pool_contains_addr(struct in6_addr *addr)
{
	return true;
}

bool nat64_filtering_and_updating(struct nf_conntrack_tuple *tuple_in)
{
	pr_debug("Step 2: Filtering and Updating Binding and Session Information\n");
	pr_debug("Done step 2.\n");
	return true;
}

bool nat64_determine_outgoing_tuple(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out)
{
	struct nf_conntrack_tuple *result = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
	if (!result) {
		pr_warning("Can't allocate a tuple.\n");
		return false;
	}

	pr_debug("Step 3: Computing the Outgoing Tuple\n");

	switch (tuple_in->src.l3num) {
	case IPPROTO_IP:
		result->ipv6_src_addr.s6_addr32[0] = cpu_to_be32(0x12345678);
		result->ipv6_src_addr.s6_addr32[1] = cpu_to_be32(0x9ABCDEF0);
		result->ipv6_src_addr.s6_addr32[2] = cpu_to_be32(0x12345678);
		result->ipv6_src_addr.s6_addr32[3] = cpu_to_be32(0x9ABCDEF0);
		result->ipv6_dst_addr.s6_addr32[0] = cpu_to_be32(0x9ABCDEF0);
		result->ipv6_dst_addr.s6_addr32[1] = cpu_to_be32(0x12345678);
		result->ipv6_dst_addr.s6_addr32[2] = cpu_to_be32(0x9ABCDEF0);
		result->ipv6_dst_addr.s6_addr32[3] = cpu_to_be32(0x12345678);
		break;

	case IPPROTO_IPV6:
		result->ipv4_src_addr.s_addr = cpu_to_be32(0xAAAAAAAA);
		result->ipv4_dst_addr.s_addr = cpu_to_be32(0xDDDDDDDD);
		break;
	}

	*tuple_out = result;
	pr_debug("Done step 3.\n");
	return true;
}

static void print_packet(struct sk_buff *skb)
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

bool nat64_send_packet(struct sk_buff *skb_out)
{
	// TODO (severe) nadie está haciendo esto.
	print_packet(skb_out);
	return true;
}
