#include "nat64/determine-incoming-tuple.h"

#include "ipv6-hdr-iterator.h"

/**
 * ipv4_extract_l4_hdr - Assumes that @hdr_ipv4 is part of a packet, and returns
 * a pointer to the chunk of data after it.
 *
 * Skips IPv4 options if any.
 */
static void *ipv4_extract_l4_hdr(struct iphdr *hdr_ipv4)
{
	return ((void *)hdr_ipv4) + (hdr_ipv4->ihl << 2);
}

static void ipv4_udp(struct packet *pkt, struct tuple *tuple4)
{
	pkt->tuple.src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	pkt->tuple.src.addr4.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->source);
	pkt->tuple.dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	pkt->tuple.dst.addr4.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->dest);
	pkt->tuple.l3_proto = L3PROTO_IPV4;
	pkt->tuple.l4_proto = L4PROTO_UDP;
}

static void ipv4_tcp(struct packet *pkt, struct tuple *tuple4)
{
	tuple4->src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	tuple4->src.addr4.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->source);
	tuple4->dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	tuple4->dst.addr4.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->dest);
	tuple4->l3_proto = L3PROTO_IPV4;
	tuple4->l4_proto = L4PROTO_TCP;
}

static int ipv4_icmp_info(struct packet *pkt, struct tuple *tuple4)
{
	tuple4->src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	tuple4->src.addr4.l4 = be16_to_cpu(pkt_icmp4_hdr(pkt)->un.echo.id);
	tuple4->dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	tuple4->dst.addr4.l4 = tuple4->src.addr4.l4;
	tuple4->l3_proto = L3PROTO_IPV4;
	tuple4->l4_proto = L4PROTO_ICMP;
	return 0;
}

static int ipv4_icmp_err(struct packet *pkt, struct tuple *tuple4)
{
	struct iphdr *inner_ipv4 = (struct iphdr *) (pkt_icmp4_hdr(pkt) + 1);
	union {
		struct udphdr *udp;
		struct tcphdr *tcp;
		struct icmphdr *icmp;
	} inner;

	tuple4->src.addr4.l3.s_addr = inner_ipv4->daddr;
	tuple4->dst.addr4.l3.s_addr = inner_ipv4->saddr;
	tuple4->l3_proto = L3PROTO_IPV4;

	switch (inner_ipv4->protocol) {
	case IPPROTO_UDP:
		inner.udp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple4->src.addr4.l4 = be16_to_cpu(inner.udp->dest);
		tuple4->dst.addr4.l4 = be16_to_cpu(inner.udp->source);
		tuple4->l4_proto = L4PROTO_UDP;
		break;

	case IPPROTO_TCP:
		inner.tcp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple4->src.addr4.l4 = be16_to_cpu(inner.tcp->dest);
		tuple4->dst.addr4.l4 = be16_to_cpu(inner.tcp->source);
		tuple4->l4_proto = L4PROTO_TCP;
		break;

	case IPPROTO_ICMP:
		inner.icmp = ipv4_extract_l4_hdr(inner_ipv4);

		if (is_icmp4_error(inner.icmp->type)) {
			log_debug("Bogus pkt: ICMP error inside ICMP error.");
			kfree_skb(pkt->skb);
			return -EINVAL;
		}

		tuple4->src.addr4.l4 = be16_to_cpu(inner.icmp->un.echo.id);
		tuple4->dst.addr4.l4 = tuple4->src.addr4.l4;
		tuple4->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Packet's inner packet is not UDP, TCP or ICMP (%u).",
				inner_ipv4->protocol);
		kfree_skb(pkt->skb);
		return -EUNSUPPORTED;
	}

	return 0;
}

static int ipv4_icmp(struct packet *pkt, struct tuple *tuple4)
{
	__u8 type = pkt_icmp4_hdr(pkt)->type;

	if (is_icmp4_info(type))
		return ipv4_icmp_info(pkt, tuple4);
	if (is_icmp4_error(type))
		return ipv4_icmp_err(pkt, tuple4);

	log_debug("Unknown ICMPv4 type: %u", type);
	kfree_skb(pkt->skb);
	return -EINVAL;
}

static void ipv6_udp(struct packet *pkt, struct tuple *tuple6)
{
	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->source);
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->dest);
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_UDP;
}

static void ipv6_tcp(struct packet *pkt, struct tuple *tuple6)
{
	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->source);
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->dest);
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_TCP;
}

static int ipv6_icmp_info(struct packet *pkt, struct tuple *tuple6)
{
	__u16 id = be16_to_cpu(pkt_icmp6_hdr(pkt)->icmp6_identifier);

	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = id;
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = id;
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_ICMP;

	return 0;
}

static int ipv6_icmp_err(struct packet *pkt, struct tuple *tuple6)
{
	struct ipv6hdr *inner_ip6 = (struct ipv6hdr *) (pkt_icmp6_hdr(pkt) + 1);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(inner_ip6);
	union {
		struct udphdr *udp;
		struct tcphdr *tcp;
		struct icmp6hdr *icmp;
	} inner;
	__u16 id;

	tuple6->src.addr6.l3 = inner_ip6->daddr;
	tuple6->dst.addr6.l3 = inner_ip6->saddr;
	tuple6->l3_proto = L3PROTO_IPV6;

	hdr_iterator_last(&iterator);
	switch (iterator.hdr_type) {
	case NEXTHDR_UDP:
		inner.udp = iterator.data;
		tuple6->src.addr6.l4 = be16_to_cpu(inner.udp->dest);
		tuple6->dst.addr6.l4 = be16_to_cpu(inner.udp->source);
		tuple6->l4_proto = L4PROTO_UDP;
		break;

	case NEXTHDR_TCP:
		inner.tcp = iterator.data;
		tuple6->src.addr6.l4 = be16_to_cpu(inner.tcp->dest);
		tuple6->dst.addr6.l4 = be16_to_cpu(inner.tcp->source);
		tuple6->l4_proto = L4PROTO_TCP;
		break;

	case NEXTHDR_ICMP:
		inner.icmp = iterator.data;

		if (is_icmp6_error(inner.icmp->icmp6_type)) {
			log_debug("Bogus pkt: ICMP error inside ICMP error.");
			kfree_skb(pkt->skb);
			return -EINVAL;
		}

		id = be16_to_cpu(inner.icmp->icmp6_identifier);
		tuple6->src.addr6.l4 = id;
		tuple6->dst.addr6.l4 = id;
		tuple6->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Packet's inner packet is not UDP, TCP or ICMP (%u).",
				iterator.hdr_type);
		kfree_skb(pkt->skb);
		return -EUNSUPPORTED;
	}

	return 0;
}

static int ipv6_icmp(struct packet *pkt, struct tuple *tuple6)
{
	__u8 type = pkt_icmp6_hdr(pkt)->icmp6_type;

	if (is_icmp6_info(type))
		return ipv6_icmp_info(pkt, tuple6);
	if (is_icmp6_error(type))
		return ipv6_icmp_err(pkt, tuple6);

	log_debug("Unknown ICMPv6 type: %u.", type);
	kfree_skb(pkt->skb);
	return -EINVAL;
}

/**
 * Extracts relevant data from "skb" and stores it in the "tuple" tuple.
 *
 * @param skb packet the data will be extracted from.
 * @param tuple this function will populate this value using "skb"'s contents.
 * @return whether packet processing should continue.
 */
int determine_in_tuple(struct xlation *state)
{
	struct packet *pkt = &state->in;
	int error = 0;

	log_debug("Step 1: Determining the Incoming Tuple");

	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV4:
		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_UDP:
			ipv4_udp(pkt, &pkt->tuple);
			break;
		case L4PROTO_TCP:
			ipv4_tcp(pkt, &pkt->tuple);
			break;
		case L4PROTO_ICMP:
			error = ipv4_icmp(pkt, &pkt->tuple);
			break;
		case L4PROTO_OTHER:
			log_debug("NAT64 doesn't support unknown transport protocols.");
			kfree_skb(pkt->skb);
			return -EUNSUPPORTED;
		}
		break;

	case L3PROTO_IPV6:
		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_UDP:
			ipv6_udp(pkt, &pkt->tuple);
			break;
		case L4PROTO_TCP:
			ipv6_tcp(pkt, &pkt->tuple);
			break;
		case L4PROTO_ICMP:
			error = ipv6_icmp(pkt, &pkt->tuple);
			break;
		case L4PROTO_OTHER:
			log_debug("NAT64 doesn't support unknown transport protocols.");
			kfree_skb(pkt->skb);
			return -EUNSUPPORTED;
		}
		break;
	}

	if (!error) {
		log_tuple(&pkt->tuple);
		log_debug("Done step 1.");
	}

	return error;
}
