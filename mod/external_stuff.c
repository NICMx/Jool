#include "external_stuff.h"
#include "nf_nat64_types.h"


void nat64_send_icmp_error(struct sk_buff *packet, __u8 type, __u8 code)
{
	// Sin código.
}

bool is_address_legal(struct in6_addr *address)
{
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
	pr_debug("Step 2: Filtering and Updating Binding and Session Information");
	pr_debug("Done step 2.");
	return true;
}

bool nat64_determine_outgoing_tuple(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out)
{
	struct nf_conntrack_tuple *result = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
	if (!result)
		return false;

	pr_debug("Step 3: Computing the Outgoing Tuple");

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
	pr_debug("Done step 3.");
	return true;
}

#define print(msg, param) printk(KERN_DEBUG msg, param)
static void print_packet(struct sk_buff *skb)
{
	struct iphdr *hdr4 = ip_hdr(skb);
	struct ipv6hdr *hdr6 = ipv6_hdr(skb);

	switch (hdr4->version) {
	case 4:
		print("Version: %d", hdr4->version);
		print("Header length: %d", hdr4->ihl);
		print("Type of service: %d", hdr4->tos);
		print("Total length: %d", be16_to_cpu(hdr4->tot_len));
		print("Identification: %d", be16_to_cpu(hdr4->id));
		print("Fragment Offset: %d", be16_to_cpu(hdr4->frag_off));
		print("TTL: %d", hdr4->ttl);
		print("Protocol: %d", hdr4->protocol);
		print("Checksum: %d", be16_to_cpu(hdr4->check));
		print("Source addr: %pI4", &hdr4->saddr);
		print("Dest addr: %pI4", &hdr4->daddr);
		break;

	case 6:
		print("Version: %d", hdr6->version);
		print("Traffic class: %d", (hdr6->priority << 4) | (hdr6->flow_lbl[0] >> 4));
		print("Flow lbl 1: %d", hdr6->flow_lbl[0] & 0xFF);
		print("Flow lbl 2: %d", hdr6->flow_lbl[1]);
		print("Flow lbl 3: %d", hdr6->flow_lbl[2]);
		print("Payload length: %d", be16_to_cpu(hdr6->payload_len));
		print("Next hdr: %d", hdr6->nexthdr);
		print("Hop limit: %d", hdr6->hop_limit);
		print("Source addr: %pI6c", &hdr6->saddr);
		print("Dest addr: %pI6c", &hdr6->daddr);
		break;

	default:
		printk(KERN_DEBUG "Unknown protocol.");
		break;
	}
}
#undef print

bool nat64_send_packet(struct sk_buff *skb_out)
{
	print_packet(skb_out);
	return true;
}
