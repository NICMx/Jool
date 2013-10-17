#include "nat64/unit/validator.h"
#include "nat64/unit/unit_test.h"

#include <net/ip.h>
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
	success &= assert_false(frag->l3_hdr.ptr_needs_kfree, "L3-ptr in skb");

	return success;
}

bool validate_frag_ipv4(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L3PROTO_IPV4, frag->l3_hdr.proto, "L3-proto");
	success &= assert_equals_int(sizeof(struct iphdr), frag->l3_hdr.len, "L3-len");
	success &= assert_equals_ptr(skb_network_header(frag->skb), frag->l3_hdr.ptr, "L3-ptr");
	success &= assert_false(frag->l3_hdr.ptr_needs_kfree, "L3-ptr in skb");

	return success;
}

bool validate_frag_empty_l4(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(0, frag->l4_hdr.len, "Empty layer 4-len");
	success &= assert_equals_int(L4PROTO_NONE, frag->l4_hdr.proto, "Empty layer 4-proto");
	success &= assert_null(frag->l4_hdr.ptr, "Empty layer 4-ptr");

	return success;
}

bool validate_frag_udp(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_UDP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct udphdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(udp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
	success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_tcp(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_TCP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct tcphdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(tcp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
	success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_icmp6(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_ICMP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct icmp6hdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(icmp6_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
	success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_icmp4(struct fragment *frag)
{
	bool success = true;

	success &= assert_equals_int(L4PROTO_ICMP, frag->l4_hdr.proto, "L4-proto");
	success &= assert_equals_int(sizeof(struct icmphdr), frag->l4_hdr.len, "L4-len");
	success &= assert_equals_ptr(icmp_hdr(frag->skb), frag->l4_hdr.ptr, "L4-ptr");
	success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "L4-ptr in skb");

	return success;
}

bool validate_frag_payload(struct fragment *frag, u16 payload_len)
{
	bool success = true;
	void *expected_payload;

	success &= assert_equals_int(payload_len, frag->payload.len, "Payload-len");
	expected_payload = (frag->l4_hdr.len != 0)
			? skb_transport_header(frag->skb) + frag->l4_hdr.len
			: skb_network_header(frag->skb) + frag->l3_hdr.len;
	success &= assert_equals_ptr(expected_payload, frag->payload.ptr, "Payload-ptr");
	success &= assert_false(frag->payload.ptr_needs_kfree, "Payload-kfree");

	return success;
}

bool validate_ipv6_hdr(struct ipv6hdr *hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u8(6, hdr->version, "IPv6hdr-version");
	success &= assert_equals_u8(0, hdr->priority, "IPv6hdr-priority");
	success &= assert_equals_u8(0, hdr->flow_lbl[0], "IPv6hdr-flow lbl[0]");
	success &= assert_equals_u8(0, hdr->flow_lbl[1], "IPv6hdr-flow lbl[1]");
	success &= assert_equals_u8(0, hdr->flow_lbl[2], "IPv6hdr-flow lbl[2]");
	success &= assert_equals_u16(payload_len, be16_to_cpu(hdr->payload_len), "IPv6hdr-payload len");
	success &= assert_equals_u8(nexthdr, hdr->nexthdr, "IPv6hdr-nexthdr");
	/* success &= assert_equals_u8(, hdr->hop_limit, "IPv6hdr-hop limit"); */
	success &= assert_equals_ipv6(&tuple->src.addr.ipv6, &hdr->saddr, "IPv6hdr-src address");
	success &= assert_equals_ipv6(&tuple->dst.addr.ipv6, &hdr->daddr, "IPv6hdr-dst address");

	return success;
}

bool validate_frag_hdr(struct frag_hdr *hdr, u16 frag_offset, u16 mf, __u8 nexthdr)
{
	bool success = true;

	success &= assert_equals_u8(nexthdr, hdr->nexthdr, "Fraghdr-nexthdr");
	success &= assert_equals_u8(0, hdr->reserved, "Fraghdr-nexthdr");
	success &= assert_equals_u16(frag_offset, get_fragment_offset_ipv6(hdr), "Fraghdr-frag offset");
	success &= assert_equals_u16(mf, is_more_fragments_set_ipv6(hdr), "Fraghdr-MF");
	success &= assert_equals_u16(1234, be32_to_cpu(hdr->identification), "Fraghdr-ID");

	return success;
}

bool validate_ipv4_hdr(struct iphdr *hdr, u16 total_len, u16 id, u16 df, u16 mf, u16 frag_off,
		u8 protocol, struct tuple *tuple)
{
	struct in_addr addr;
	bool success = true;

	success &= assert_equals_u8(4, hdr->version, "IPv4hdr-Version");
	success &= assert_equals_u8(5, hdr->ihl, "IPv4hdr-IHL");
	success &= assert_equals_u8(0, hdr->tos, "IPv4hdr-TOS");
	success &= assert_equals_u16(total_len, be16_to_cpu(hdr->tot_len), "IPv4hdr-total length");
	success &= assert_equals_u16(id, be16_to_cpu(hdr->id), "IPv4hdr-ID");
	success &= assert_equals_u16(df, be16_to_cpu(hdr->frag_off) & IP_DF, "IPv4hdr-DF");
	success &= assert_equals_u16(mf, be16_to_cpu(hdr->frag_off) & IP_MF, "IPv4hdr-MF");
	success &= assert_equals_u16(frag_off, get_fragment_offset_ipv4(hdr), "IPv4hdr-Frag offset");
	/* success &= assert_equals_u8(, hdr->ttl, "IPv4 header - TTL"); */
	success &= assert_equals_u8(protocol, hdr->protocol, "IPv4hdr-protocol");

	addr.s_addr = hdr->saddr;
	success &= assert_equals_ipv4(&tuple->src.addr.ipv4, &addr, "IPv4hdr-src address");

	addr.s_addr = hdr->daddr;
	success &= assert_equals_ipv4(&tuple->dst.addr.ipv4, &addr, "IPv4hdr-dst address");

	return success;
}

bool validate_udp_hdr(struct udphdr *hdr, u16 payload_len, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u16(tuple->src.l4_id, be16_to_cpu(hdr->source), "UDPhdr-src");
	success &= assert_equals_u16(tuple->dst.l4_id, be16_to_cpu(hdr->dest), "UDPhdr-dst");
	success &= assert_equals_u16(sizeof(*hdr) + payload_len, be16_to_cpu(hdr->len), "UDPhdr-len");

	return success;
}

bool validate_tcp_hdr(struct tcphdr *hdr, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u16(tuple->src.l4_id, be16_to_cpu(hdr->source), "TCPhdr-src");
	success &= assert_equals_u16(tuple->dst.l4_id, be16_to_cpu(hdr->dest), "TCPhdr-dst");
	success &= assert_equals_u32(4669, be32_to_cpu(hdr->seq), "TCPhdr-seq");
	success &= assert_equals_u32(6576, be32_to_cpu(hdr->ack_seq), "TCPhdr-ack seq");
	success &= assert_equals_u16(5, hdr->doff, "TCPhdr-data offset");
	success &= assert_equals_u16(0, hdr->res1, "TCPhdr-reserved");
	success &= assert_equals_u16(0, hdr->cwr, "TCPhdr-cwr");
	success &= assert_equals_u16(0, hdr->ece, "TCPhdr-ece");
	success &= assert_equals_u16(0, hdr->urg, "TCPhdr-urg");
	success &= assert_equals_u16(0, hdr->ack, "TCPhdr-ack");
	success &= assert_equals_u16(0, hdr->psh, "TCPhdr-psh");
	success &= assert_equals_u16(0, hdr->rst, "TCPhdr-rst");
	success &= assert_equals_u16(0, hdr->syn, "TCPhdr-syn");
	success &= assert_equals_u16(0, hdr->fin, "TCPhdr-fin");
	success &= assert_equals_u16(3233, be16_to_cpu(hdr->window), "TCPhdr-window");
	success &= assert_equals_u16(9865, be16_to_cpu(hdr->urg_ptr), "TCPhdr-urgent ptr");

	return success;
}

bool validate_icmp6_hdr(struct icmp6hdr *hdr, u16 id, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u8(ICMPV6_ECHO_REQUEST, hdr->icmp6_type, "ICMP6hdr-type");
	success &= assert_equals_u8(0, hdr->icmp6_code, "ICMP6hdr-code");
	success &= assert_equals_u16(tuple->icmp_id, be16_to_cpu(hdr->icmp6_identifier), "ICMP6hdr-id");

	return success;
}

bool validate_icmp6_hdr_error(struct icmp6hdr *hdr)
{
	bool success = true;

	success &= assert_equals_u8(ICMPV6_PKT_TOOBIG, hdr->icmp6_type, "ICMP6hdr-type");
	success &= assert_equals_u8(0, hdr->icmp6_code, "ICMP6hdr-code");
	/* success &= assert_equals_u32(1300, be32_to_cpu(hdr->icmp6_mtu), "ICMP6hdr-MTU"); */

	return success;
}

bool validate_icmp4_hdr(struct icmphdr *hdr, u16 id, struct tuple *tuple)
{
	bool success = true;

	success &= assert_equals_u8(ICMP_ECHO, hdr->type, "ICMP4hdr-type");
	success &= assert_equals_u8(0, hdr->code, "ICMP4hdr-code");
	success &= assert_equals_u16(tuple->icmp_id, be16_to_cpu(hdr->un.echo.id), "ICMP4hdr-id");

	return success;
}

bool validate_icmp4_hdr_error(struct icmphdr *hdr)
{
	bool success = true;

	success &= assert_equals_u8(ICMP_DEST_UNREACH, hdr->type, "ICMP4hdr-type");
	success &= assert_equals_u8(ICMP_FRAG_NEEDED, hdr->code, "ICMP4hdr-code");
	/* success &= assert_equals_u16(3100, be16_to_cpu(hdr->un.frag.mtu), "ICMP4hdr-MTU"); */

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

bool validate_inner_pkt_ipv6(unsigned char *payload, u16 len)
{
	struct ipv6hdr *hdr_ipv6;
	struct tcphdr *hdr_tcp;
	unsigned char *inner_payload;
	struct tuple tuple;

	if (init_ipv6_tuple(&tuple, "1::1", 1234, "2::2", 4321, IPPROTO_TCP) != 0)
		return false;

	hdr_ipv6 = (struct ipv6hdr *) payload;
	hdr_tcp = (struct tcphdr *) (hdr_ipv6 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	if (!validate_ipv6_hdr(hdr_ipv6, 80, NEXTHDR_TCP, &tuple))
		return false;
	if (!validate_tcp_hdr(hdr_tcp, &tuple))
		return false;
	if (!validate_payload(inner_payload, len - sizeof(*hdr_ipv6) - sizeof(*hdr_tcp), 0))
		return false;

	return true;
}

bool validate_inner_pkt_ipv4(unsigned char *payload, u16 len)
{
	struct iphdr *hdr_ipv4;
	struct tcphdr *hdr_tcp;
	unsigned char *inner_payload;
	struct tuple tuple;

	if (init_ipv4_tuple(&tuple, "1.1.1.1", 1234, "2.2.2.2", 4321, IPPROTO_TCP) != 0)
		return false;

	hdr_ipv4 = (struct iphdr *) payload;
	hdr_tcp = (struct tcphdr *) (hdr_ipv4 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	if (!validate_ipv4_hdr(hdr_ipv4, 80, 0, IP_DF, 0, 0, IPPROTO_TCP, &tuple))
		return false;
	if (!validate_tcp_hdr(hdr_tcp, &tuple))
		return false;
	if (!validate_payload(inner_payload, len - sizeof(*hdr_ipv4) - sizeof(*hdr_tcp), 0))
		return false;

	return true;
}
