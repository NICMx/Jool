#include "nat64/unit/validator.h"
#include "nat64/unit/unit_test.h"

#include <net/ipv6.h>

bool validate_fragment_count(struct packet *pkt, int expected_count)
{
	struct fragment *frag;
	int i;

	i = 0;
	list_for_each_entry(frag, &pkt->fragments, next) {
		i++;
	}

	return assert_equals_int(expected_count, i, "Fragment count");
}

bool validate_frag_ipv6(struct fragment *frag, int len)
{
	bool success = true;

	success &= assert_equals_int(L3PROTO_IPV6, frag->l3_hdr.proto, "L3-proto");
	success &= assert_equals_int(len, frag->l3_hdr.len, "L3-len");
	success &= assert_equals_ptr(skb_network_header(frag->skb), frag->l3_hdr.ptr, "L3-ptr");
//	success &= assert_equals_int(true, frag->l3_hdr.ptr_needs_kfree, "L3-ptr in skb");

	return success;
}

bool validate_frag_ipv4(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L3PROTO_IPV4, frag->l3_hdr.proto, "L3-proto");
	success &= assert_equals_int(sizeof(struct iphdr), frag->l3_hdr.len, "L3-len");
	success &= assert_equals_ptr(skb_network_header(frag->skb), frag->l3_hdr.ptr, "L3-ptr");
//	success &= assert_equals_int(true, frag->l3_hdr.ptr_needs_kfree, "L3-ptr in skb");

	return success;
}

bool validate_frag_udp(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_UDP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct udphdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(udp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
//	success &= assert_equals_int(true, frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_tcp(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_TCP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct tcphdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(tcp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
//	success &= assert_equals_int(true, frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_icmp6(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_ICMP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct icmp6hdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(icmp6_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
//	success &= assert_equals_int(true, frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_icmp4(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_ICMP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct icmphdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(icmp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
//	success &= assert_equals_int(true, frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_payload(struct fragment *frag, u16 payload_len)
{
	bool success = true;

	success &= assert_equals_int(payload_len, frag->payload.len, "Payload-len");
	if (frag->l4_hdr.len != 0) {
		success &= assert_equals_ptr(skb_transport_header(frag->skb) + frag->l4_hdr.len, frag->payload.ptr, "Payload-pointer");
	} else {
		success &= assert_equals_ptr(skb_network_header(frag->skb) + frag->l3_hdr.len, frag->payload.ptr, "Payload-pointer");
	}
//	success &= assert_equals_int(true, frag->payload.ptr_needs_kfree, "Payload-ptr in skb");

	return success;
}

bool validate_ipv6_hdr(struct ipv6hdr *hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u16(payload_len, be16_to_cpu(hdr->payload_len), "IPv6 header-payload length");
	success &= assert_equals_u8(nexthdr, hdr->nexthdr, "IPv6 header-nexthdr");
	success &= assert_equals_ipv6(&tuple->src.addr.ipv6, &hdr->saddr, "IPv6 header-source address");
	success &= assert_equals_ipv6(&tuple->dst.addr.ipv6, &hdr->daddr, "IPv6 header-destination address");

	return success;
}

bool validate_frag_hdr(struct frag_hdr *hdr, u16 expected_frag_offset, u16 expected_mf)
{
	bool success = true;

	success &= assert_equals_u16(expected_frag_offset, be16_to_cpu(hdr->frag_off) >> 3, "Fragment header - frag offset");
	success &= assert_equals_u16(expected_mf, be16_to_cpu(hdr->frag_off) & 1, "Fragment header - mf");
	success &= assert_equals_u8(NEXTHDR_UDP, hdr->nexthdr, "Fragment header - nexthdr");

	return success;
}

bool validate_ipv4_hdr(struct iphdr *hdr, u16 total_len, u8 protocol, struct tuple *tuple)
{
	struct in_addr addr;
	bool success = true;

	success &= assert_equals_u16(total_len, be16_to_cpu(hdr->tot_len), "IPv4 header-total length");
	success &= assert_equals_u8(protocol, hdr->protocol, "IPv4 header-protocol");

	addr.s_addr = hdr->saddr;
	success &= assert_equals_ipv4(&tuple->src.addr.ipv4, &addr, "IPv4 header-source address");

	addr.s_addr = hdr->daddr;
	success &= assert_equals_ipv4(&tuple->dst.addr.ipv4, &addr, "IPv4 header-destination address");

	return success;
}

bool validate_frag_empty_l4(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_u16(0, frag->l4_hdr.len, "Empty layer 4-len");
	success &= assert_equals_u16(L4PROTO_NONE, frag->l4_hdr.proto, "Empty layer 4-proto");
	success &= assert_null(frag->l4_hdr.ptr, "Empty layer 4-ptr");

	return success;
}

bool validate_udp_hdr(struct udphdr *hdr, u16 payload_len, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u16(tuple->src.l4_id, be16_to_cpu(hdr->source), "UDP header-source");
	success &= assert_equals_u16(tuple->dst.l4_id, be16_to_cpu(hdr->dest), "UDP header-destination");
	success &= assert_equals_u16(sizeof(*hdr) + payload_len, be16_to_cpu(hdr->len), "UDP header-length");

	return success;
}

bool validate_tcp_hdr(struct tcphdr *hdr, u16 len, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u16(tuple->src.l4_id, be16_to_cpu(hdr->source), "TCP header-source");
	success &= assert_equals_u16(tuple->dst.l4_id, be16_to_cpu(hdr->dest), "TCP header-destination");
	success &= assert_equals_u16(len >> 2, hdr->doff, "TCP header-data offset");

	return success;
}

bool validate_icmp6_hdr(struct icmp6hdr *hdr, u16 id, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u8(ICMPV6_ECHO_REQUEST, hdr->icmp6_type, "ICMP header-type");
	success &= assert_equals_u8(0, hdr->icmp6_code, "ICMP header-code");
	success &= assert_equals_u16(tuple->icmp_id, be16_to_cpu(hdr->icmp6_dataun.u_echo.identifier), "ICMP header-id");

	return success;
}

bool validate_icmp4_hdr(struct icmphdr *hdr, u16 id, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u8(ICMP_ECHO, hdr->type, "ICMP header-type");
	success &= assert_equals_u8(0, hdr->code, "ICMP header-code");
	success &= assert_equals_u16(tuple->icmp_id, be16_to_cpu(hdr->un.echo.id), "ICMP header-id");

	return success;
}

bool validate_payload(unsigned char *payload, u16 len, u16 offset)
{
	u16 i;

	for (i = 0; i < len; i++) {
		if (!assert_equals_u8(i + offset, payload[i], "Payload content"))
			return false;
	}

	return true;
}
