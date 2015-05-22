#include "nat64/unit/validator.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/types.h"

#include <net/ip.h>
#include <net/ipv6.h>

bool validate_fragment_count(struct sk_buff *skb, int expected_count)
{
	int i = 0;

	while (skb) {
		i++;
		skb = skb->next;
	}

	return assert_equals_int(expected_count, i, "Fragment count");
}

bool validate_ipv6_hdr(struct ipv6hdr *hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple6)
{
	bool success = true;

	success &= assert_equals_u8(6, hdr->version, "IPv6hdr-version");
	success &= assert_equals_u8(0, hdr->priority, "IPv6hdr-priority");
	success &= assert_equals_u8(0, hdr->flow_lbl[0], "IPv6hdr-flow lbl[0]");
	success &= assert_equals_u8(0, hdr->flow_lbl[1], "IPv6hdr-flow lbl[1]");
	success &= assert_equals_u8(0, hdr->flow_lbl[2], "IPv6hdr-flow lbl[2]");
	success &= ASSERT_UINT(payload_len, be16_to_cpu(hdr->payload_len), "IPv6hdr-payload len");
	success &= assert_equals_u8(nexthdr, hdr->nexthdr, "IPv6hdr-nexthdr");
	/* success &= assert_equals_u8(, hdr->hop_limit, "IPv6hdr-hop limit"); */
	success &= assert_equals_ipv6(&tuple6->src.addr6.l3, &hdr->saddr, "IPv6hdr-src address");
	success &= assert_equals_ipv6(&tuple6->dst.addr6.l3, &hdr->daddr, "IPv6hdr-dst address");

	return success;
}

bool validate_frag_hdr(struct frag_hdr *hdr, u16 frag_offset, u16 mf, __u8 nexthdr)
{
	bool success = true;

	success &= assert_equals_u8(nexthdr, hdr->nexthdr, "Fraghdr-nexthdr");
	success &= assert_equals_u8(0, hdr->reserved, "Fraghdr-nexthdr");
	success &= ASSERT_UINT(frag_offset, get_fragment_offset_ipv6(hdr), "Fraghdr-frag offset");
	success &= ASSERT_UINT(mf, is_more_fragments_set_ipv6(hdr), "Fraghdr-MF");
	success &= ASSERT_UINT(4321, be32_to_cpu(hdr->identification), "Fraghdr-ID");

	return success;
}

bool validate_ipv4_hdr(struct iphdr *hdr, u16 total_len, u16 id, u16 df, u16 mf, u16 frag_off,
		u8 protocol, struct tuple *tuple4)
{
	struct in_addr addr;
	bool success = true;

	success &= assert_equals_u8(4, hdr->version, "IPv4hdr-Version");
	success &= assert_equals_u8(5, hdr->ihl, "IPv4hdr-IHL");
	success &= assert_equals_u8(0, hdr->tos, "IPv4hdr-TOS");
	success &= ASSERT_UINT(total_len, be16_to_cpu(hdr->tot_len), "IPv4hdr-total length");
	success &= ASSERT_UINT(id, be16_to_cpu(hdr->id), "IPv4hdr-ID");
	success &= ASSERT_UINT(df, be16_to_cpu(hdr->frag_off) & IP_DF, "IPv4hdr-DF");
	success &= ASSERT_UINT(mf, be16_to_cpu(hdr->frag_off) & IP_MF, "IPv4hdr-MF");
	success &= ASSERT_UINT(frag_off, get_fragment_offset_ipv4(hdr), "IPv4hdr-Frag offset");
	/* success &= assert_equals_u8(, hdr->ttl, "IPv4 header - TTL"); */
	success &= assert_equals_u8(protocol, hdr->protocol, "IPv4hdr-protocol");

	addr.s_addr = hdr->saddr;
	success &= assert_equals_ipv4(&tuple4->src.addr4.l3, &addr, "IPv4hdr-src address");

	addr.s_addr = hdr->daddr;
	success &= assert_equals_ipv4(&tuple4->dst.addr4.l3, &addr, "IPv4hdr-dst address");

	return success;
}

bool validate_udp_hdr(struct udphdr *hdr, u16 payload_len, struct tuple *tuple)
{
	bool success = true;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		success &= ASSERT_UINT(tuple->src.addr6.l4, be16_to_cpu(hdr->source), "UDP6hdr-src");
		success &= ASSERT_UINT(tuple->dst.addr6.l4, be16_to_cpu(hdr->dest), "UDP6hdr-dst");
		break;
	case L3PROTO_IPV4:
		success &= ASSERT_UINT(tuple->src.addr4.l4, be16_to_cpu(hdr->source), "UDP4hdr-src");
		success &= ASSERT_UINT(tuple->dst.addr4.l4, be16_to_cpu(hdr->dest), "UDP4hdr-dst");
		break;
	default:
		log_err("L3 proto is not IPv6 or IPv4.");
		success = false;
	}
	success &= ASSERT_UINT(sizeof(*hdr) + payload_len, be16_to_cpu(hdr->len), "UDPhdr-len");

	return success;
}

bool validate_tcp_hdr(struct tcphdr *hdr, struct tuple *tuple)
{
	bool success = true;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		success &= ASSERT_UINT(tuple->src.addr6.l4, be16_to_cpu(hdr->source), "TCP6hdr-src");
		success &= ASSERT_UINT(tuple->dst.addr6.l4, be16_to_cpu(hdr->dest), "TCP6hdr-dst");
		break;
	case L3PROTO_IPV4:
		success &= ASSERT_UINT(tuple->src.addr4.l4, be16_to_cpu(hdr->source), "TCP4hdr-src");
		success &= ASSERT_UINT(tuple->dst.addr4.l4, be16_to_cpu(hdr->dest), "TCP4hdr-dst");
		break;
	default:
		log_err("L3 proto is not IPv6 or IPv4.");
		success = false;
	}
	success &= assert_equals_u32(4669, be32_to_cpu(hdr->seq), "TCPhdr-seq");
	success &= assert_equals_u32(6576, be32_to_cpu(hdr->ack_seq), "TCPhdr-ack seq");
	success &= ASSERT_UINT(5, hdr->doff, "TCPhdr-data offset");
	success &= ASSERT_UINT(0, hdr->res1, "TCPhdr-reserved");
	success &= ASSERT_UINT(0, hdr->cwr, "TCPhdr-cwr");
	success &= ASSERT_UINT(0, hdr->ece, "TCPhdr-ece");
	success &= ASSERT_UINT(0, hdr->urg, "TCPhdr-urg");
	success &= ASSERT_UINT(0, hdr->ack, "TCPhdr-ack");
	success &= ASSERT_UINT(0, hdr->psh, "TCPhdr-psh");
	success &= ASSERT_UINT(0, hdr->rst, "TCPhdr-rst");
	success &= ASSERT_UINT(1, hdr->syn, "TCPhdr-syn");
	success &= ASSERT_UINT(0, hdr->fin, "TCPhdr-fin");
	success &= ASSERT_UINT(3233, be16_to_cpu(hdr->window), "TCPhdr-window");
	success &= ASSERT_UINT(9865, be16_to_cpu(hdr->urg_ptr), "TCPhdr-urgent ptr");

	return success;
}

bool validate_icmp6_hdr(struct icmp6hdr *hdr, u16 id, struct tuple *tuple6)
{
	bool success = true;

	success &= assert_equals_u8(ICMPV6_ECHO_REQUEST, hdr->icmp6_type, "ICMP6hdr-type");
	success &= assert_equals_u8(0, hdr->icmp6_code, "ICMP6hdr-code");
	success &= ASSERT_UINT(tuple6->src.addr6.l4, be16_to_cpu(hdr->icmp6_identifier),
			"ICMP6hdr id");

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

bool validate_icmp4_hdr(struct icmphdr *hdr, u16 id, struct tuple *tuple4)
{
	bool success = true;

	success &= assert_equals_u8(ICMP_ECHO, hdr->type, "ICMP4hdr-type");
	success &= assert_equals_u8(0, hdr->code, "ICMP4hdr-code");
	success &= ASSERT_UINT(tuple4->src.addr4.l4, be16_to_cpu(hdr->un.echo.id), "ICMP4id");

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
	struct tuple tuple6;

	if (init_ipv6_tuple(&tuple6, "2::2", 4321, "1::1", 1234, L4PROTO_TCP) != 0)
		return false;

	hdr_ipv6 = (struct ipv6hdr *) payload;
	hdr_tcp = (struct tcphdr *) (hdr_ipv6 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	if (!validate_ipv6_hdr(hdr_ipv6, 1300, NEXTHDR_TCP, &tuple6))
		return false;
	if (!validate_tcp_hdr(hdr_tcp, &tuple6))
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
	struct tuple tuple4;

	if (init_ipv4_tuple(&tuple4, "2.2.2.2", 4321, "1.1.1.1", 1234, L4PROTO_TCP) != 0)
		return false;

	hdr_ipv4 = (struct iphdr *) payload;
	hdr_tcp = (struct tcphdr *) (hdr_ipv4 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	if (!validate_ipv4_hdr(hdr_ipv4, 1320, 0, IP_DF, 0, 0, IPPROTO_TCP, &tuple4))
		return false;
	if (!validate_tcp_hdr(hdr_tcp, &tuple4))
		return false;
	if (!validate_payload(inner_payload, len - sizeof(*hdr_ipv4) - sizeof(*hdr_tcp), 0))
		return false;

	return true;
}
