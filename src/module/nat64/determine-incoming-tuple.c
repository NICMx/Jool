#include "nat64/determine-incoming-tuple.h"

#include "ipv6-hdr-iterator.h"

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

static void ipv4_icmp_info(struct packet *pkt, struct tuple *tuple4)
{
	tuple4->src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	tuple4->src.addr4.l4 = be16_to_cpu(pkt_icmp4_hdr(pkt)->un.echo.id);
	tuple4->dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	tuple4->dst.addr4.l4 = tuple4->src.addr4.l4;
	tuple4->l3_proto = L3PROTO_IPV4;
	tuple4->l4_proto = L4PROTO_ICMP;
}

/**
 * ipv4_extract_l4_hdr - Assumes that @hdr_ipv4 is part of a packet, and returns
 * a pointer to the chunk of data after it.
 *
 * Skips IPv4 options if any.
 */
static void *ipv4_extract_l4_hdr(struct iphdr *hdr4)
{
	return ((void *)hdr4) + (hdr4->ihl << 2);
}

static int ipv4_icmp_err(struct xlation *state, struct tuple *tuple4)
{
	struct iphdr *hdr4 = (struct iphdr *)(pkt_icmp4_hdr(&state->in) + 1);
	union {
		struct udphdr *udp;
		struct tcphdr *tcp;
		struct icmphdr *icmp;
	} inner;

	tuple4->src.addr4.l3.s_addr = hdr4->daddr;
	tuple4->dst.addr4.l3.s_addr = hdr4->saddr;
	tuple4->l3_proto = L3PROTO_IPV4;

	switch (hdr4->protocol) {
	case IPPROTO_UDP:
		inner.udp = ipv4_extract_l4_hdr(hdr4);
		tuple4->src.addr4.l4 = be16_to_cpu(inner.udp->dest);
		tuple4->dst.addr4.l4 = be16_to_cpu(inner.udp->source);
		tuple4->l4_proto = L4PROTO_UDP;
		break;

	case IPPROTO_TCP:
		inner.tcp = ipv4_extract_l4_hdr(hdr4);
		tuple4->src.addr4.l4 = be16_to_cpu(inner.tcp->dest);
		tuple4->dst.addr4.l4 = be16_to_cpu(inner.tcp->source);
		tuple4->l4_proto = L4PROTO_TCP;
		break;

	case IPPROTO_ICMP:
		inner.icmp = ipv4_extract_l4_hdr(hdr4);

		if (is_icmp4_error(inner.icmp->type)) {
			log_debug("Bogus pkt: ICMP error inside ICMP error.");
			return einval(state, JOOL_MIB_2X_INNER4);
		}

		tuple4->src.addr4.l4 = be16_to_cpu(inner.icmp->un.echo.id);
		tuple4->dst.addr4.l4 = tuple4->src.addr4.l4;
		tuple4->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Inner packet is not UDP, TCP nor ICMP (%u).",
				hdr4->protocol);
		return eunsupported(state, JOOL_MIB_V4_UNKNOWN_INNER_L4);
	}

	return 0;
}

static int ipv4_icmp(struct xlation *state, struct tuple *tuple4)
{
	__u8 type = pkt_icmp4_hdr(&state->in)->type;

	if (is_icmp4_info(type)) {
		ipv4_icmp_info(&state->in, tuple4);
		return 0;
	}

	if (is_icmp4_error(type))
		return ipv4_icmp_err(state, tuple4);

	log_debug("Unknown ICMPv4 type: %u", type);
	/* I don't think there is an ICMP error for unknown ICMP messages. */
	return einval(state, JOOL_MIB_V4_UNKNOWN_ICMP);
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

static void ipv6_icmp_info(struct packet *pkt, struct tuple *tuple6)
{
	__u16 id = be16_to_cpu(pkt_icmp6_hdr(pkt)->icmp6_identifier);

	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = id;
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = id;
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_ICMP;
}

static int ipv6_icmp_err(struct xlation *state, struct tuple *tuple6)
{
	struct ipv6hdr *hdr6 = (struct ipv6hdr *)(pkt_icmp6_hdr(&state->in) + 1);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr6);
	union {
		struct udphdr *udp;
		struct tcphdr *tcp;
		struct icmp6hdr *icmp;
	} inner;
	__u16 id;

	tuple6->src.addr6.l3 = hdr6->daddr;
	tuple6->dst.addr6.l3 = hdr6->saddr;
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
			return einval(state, JOOL_MIB_2X_INNER6);
		}

		id = be16_to_cpu(inner.icmp->icmp6_identifier);
		tuple6->src.addr6.l4 = id;
		tuple6->dst.addr6.l4 = id;
		tuple6->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Inner packet is not UDP, TCP or ICMP (%u).",
				iterator.hdr_type);
		return eunsupported(state, JOOL_MIB_V6_UNKNOWN_INNER_L4);
	}

	return 0;
}

static int ipv6_icmp(struct xlation *state, struct tuple *tuple6)
{
	__u8 type = pkt_icmp6_hdr(&state->in)->icmp6_type;

	if (is_icmp6_info(type)) {
		ipv6_icmp_info(&state->in, tuple6);
		return 0;
	}

	if (is_icmp6_error(type))
		return ipv6_icmp_err(state, tuple6);

	log_debug("Unknown ICMPv6 type: %u.", type);
	/* I don't think there is an ICMP error for unknown ICMP messages. */
	return einval(state, JOOL_MIB_V6_UNKNOWN_ICMP);
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
			error = ipv4_icmp(state, &pkt->tuple);
			break;
		case L4PROTO_OTHER:
			log_debug("NAT64 doesn't support unknown transport protocols.");
			icmp64_send(&state->in, ICMPERR_PROTO_UNREACHABLE, 0);
			return eunsupported(state, JOOL_MIB_V4_UNKNOWN_L4);
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
			error = ipv6_icmp(state, &pkt->tuple);
			break;
		case L4PROTO_OTHER:
			log_debug("NAT64 doesn't support unknown transport protocols.");
			icmp64_send(&state->in, ICMPERR_PROTO_UNREACHABLE, 0);
			return eunsupported(state, JOOL_MIB_V6_UNKNOWN_L4);
		}
		break;
	}

	if (!error) {
		log_tuple(&pkt->tuple);
		log_debug("Done step 1.");
	}

	return error;
}
