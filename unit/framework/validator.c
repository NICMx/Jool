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

bool validate_frag_ipv6(struct fragment *frag)
{
	if (!assert_equals_int(L3PROTO_IPV6, frag->l3_hdr.proto, "L3-proto"))
		return false;
	if (!assert_equals_int(sizeof(struct ipv6hdr), frag->l3_hdr.len, "L3-len"))
		return false;
	if (!assert_equals_ptr(skb_network_header(frag->skb), frag->l3_hdr.ptr, "L3-ptr"))
		return false;
	if (!assert_equals_int(true, frag->l3_hdr.ptr_belongs_to_skb, "L3-ptr in skb"))
		return false;

	return true;
}

bool validate_frag_ipv4(struct fragment *frag)
{
	if (!assert_equals_int(L3PROTO_IPV4, frag->l3_hdr.proto, "L3-proto"))
		return false;
	if (!assert_equals_int(sizeof(struct iphdr), frag->l3_hdr.len, "L3-len"))
		return false;
	if (!assert_equals_ptr(skb_network_header(frag->skb), frag->l3_hdr.ptr, "L3-ptr"))
		return false;
	if (!assert_equals_int(true, frag->l3_hdr.ptr_belongs_to_skb, "L3-ptr in skb"))
		return false;

	return true;
}

bool validate_frag_udp(struct fragment *frag)
{
	if (!assert_equals_int(L4PROTO_UDP, frag->l4_hdr.proto, "L4-proto"))
		return false;
	if (!assert_equals_int(sizeof(struct udphdr), frag->l4_hdr.len, "L4-len"))
		return false;
	if (!assert_equals_ptr(udp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr"))
		return false;
	if (!assert_equals_int(true, frag->l4_hdr.ptr_belongs_to_skb, "L4-ptr in skb"))
		return false;

	return true;
}

bool validate_frag_tcp(struct fragment *frag)
{
	if (!assert_equals_int(L4PROTO_TCP, frag->l4_hdr.proto, "L4-proto"))
		return false;
	if (!assert_equals_int(sizeof(struct tcphdr), frag->l4_hdr.len, "L4-len"))
		return false;
	if (!assert_equals_ptr(tcp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr"))
		return false;
	if (!assert_equals_int(true, frag->l4_hdr.ptr_belongs_to_skb, "L4-ptr in skb"))
		return false;

	return true;
}

bool validate_frag_icmp6(struct fragment *frag)
{
	if (!assert_equals_int(L4PROTO_ICMP, frag->l4_hdr.proto, "L4-proto"))
		return false;
	if (!assert_equals_int(sizeof(struct icmp6hdr), frag->l4_hdr.len, "L4-len"))
		return false;
	if (!assert_equals_ptr(icmp6_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr"))
		return false;
	if (!assert_equals_int(true, frag->l4_hdr.ptr_belongs_to_skb, "L4-ptr in skb"))
		return false;

	return true;
}

bool validate_frag_icmp4(struct fragment *frag)
{
	if (!assert_equals_int(L4PROTO_ICMP, frag->l4_hdr.proto, "L4-proto"))
		return false;
	if (!assert_equals_int(sizeof(struct icmphdr), frag->l4_hdr.len, "L4-len"))
		return false;
	if (!assert_equals_ptr(icmp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr"))
		return false;
	if (!assert_equals_int(true, frag->l4_hdr.ptr_belongs_to_skb, "L4-ptr in skb"))
		return false;

	return true;
}

bool validate_frag_payload(struct fragment *frag, u16 payload_len)
{
	if (!assert_equals_int(payload_len, frag->payload.len, "Payload-len"))
		return false;
	if (!assert_equals_ptr(skb_transport_header(frag->skb) + frag->l4_hdr.len, frag->payload.ptr, "Payload-pointer"))
		return false;
	if (!assert_equals_int(true, frag->payload.ptr_belongs_to_skb, "Payload-ptr in skb"))
		return false;

	return true;
}

bool validate_ipv6_hdr(struct ipv6hdr *hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple)
{
	if (!assert_equals_u16(payload_len, be16_to_cpu(hdr->payload_len), "IPv6 header-payload length"))
		return false;
	if (!assert_equals_u8(nexthdr, hdr->nexthdr, "IPv6 header-nexthdr"))
		return false;
	if (!assert_equals_ipv6(&tuple->src.addr.ipv6, &hdr->saddr, "IPv6 header-source address"))
		return false;
	if (!assert_equals_ipv6(&tuple->dst.addr.ipv6, &hdr->daddr, "IPv6 header-destination address"))
		return false;

	return true;
}

bool validate_frag_hdr(struct frag_hdr *hdr, u16 expected_frag_offset, u16 expected_mf)
{
	if (!assert_equals_u16(expected_frag_offset | expected_mf, be16_to_cpu(hdr->frag_off),
			"Fragment header - frag offset & MF"))
		return false;
	if (!assert_equals_u8(NEXTHDR_UDP, hdr->nexthdr, "Fragment header - nexthdr"))
		return false;

	return false;
}

bool validate_ipv4_hdr(struct iphdr *hdr, u16 total_len, u8 protocol, struct tuple *tuple)
{
	struct in_addr addr;

	if (!assert_equals_u16(total_len, be16_to_cpu(hdr->tot_len), "IPv4 header-total length"))
		return false;
	if (!assert_equals_u8(protocol, hdr->protocol, "IPv4 header-protocol"))
		return false;

	addr.s_addr = hdr->saddr;
	if (!assert_equals_ipv4(&tuple->src.addr.ipv4, &addr, "IPv4 header-source address"))
		return false;

	addr.s_addr = hdr->daddr;
	if (!assert_equals_ipv4(&tuple->dst.addr.ipv4, &addr, "IPv4 header-destination address"))
		return false;

	return true;
}

bool validate_udp_hdr(struct udphdr *hdr, u16 payload_len, struct tuple *tuple)
{
	if (!assert_equals_u16(tuple->src.l4_id, be16_to_cpu(hdr->source), "UDP header-source"))
		return false;
	if (!assert_equals_u16(tuple->dst.l4_id, be16_to_cpu(hdr->dest), "UDP header-destination"))
		return false;
	if (!assert_equals_u16(sizeof(*hdr) + payload_len, be16_to_cpu(hdr->len), "UDP header-length"))
		return false;

	return true;
}

bool validate_tcp_hdr(struct tcphdr *hdr, u16 len, struct tuple *tuple)
{
	if (!assert_equals_u16(tuple->src.l4_id, be16_to_cpu(hdr->source), "TCP header-source"))
		return false;
	if (!assert_equals_u16(tuple->dst.l4_id, be16_to_cpu(hdr->dest), "TCP header-destination"))
		return false;
	if (!assert_equals_u16(len >> 2, hdr->doff, "TCP header-data offset"))
		return false;

	return true;
}

bool validate_icmp6_hdr(struct icmp6hdr *hdr, u16 id, struct tuple *tuple)
{
	if (!assert_equals_u8(ICMPV6_ECHO_REQUEST, hdr->icmp6_type, "ICMP header-type"))
		return false;
	if (!assert_equals_u8(0, hdr->icmp6_code, "ICMP header-code"))
		return false;
	if (!assert_equals_u16(tuple->icmp_id, be16_to_cpu(hdr->icmp6_dataun.u_echo.identifier), "ICMP header-id"))
		return false;

	return true;
}

bool validate_icmp4_hdr(struct icmphdr *hdr, u16 id, struct tuple *tuple)
{
	if (!assert_equals_u8(ICMP_ECHO, hdr->type, "ICMP header-type"))
		return false;
	if (!assert_equals_u8(0, hdr->code, "ICMP header-code"))
		return false;
	if (!assert_equals_u16(tuple->icmp_id, be16_to_cpu(hdr->un.echo.id), "ICMP header-id"))
		return false;

	return true;
}

bool validate_payload(unsigned char *payload, u16 payload_len)
{
	int i;

	for (i = 0; i < payload_len; i++)
		if (!assert_equals_u8(i, payload[i], "Payload"))
			return false;

	return true;
}
