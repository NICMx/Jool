#include "nat64/mod/stateful/determine_incoming_tuple.h"

#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/stats.h"

/*
 * There are several points in this module where the RFC says "drop the packet",
 * but Jool "accepts" it instead.
 * This is because of Netfilter idiosyncrasies. The RFC probably assumes a NAT64
 * wouldn't be positioned exactly where Netfilter hooks run.
 * Every one of these RFC mismatches should be commented.
 */

/**
 * ipv4_extract_l4_hdr - Assumes that @hdr_ipv4 is part of a packet, and returns
 * a pointer to the chunk of data after it.
 *
 * Skips IPv4 options if any.
 */
static void *ipv4_extract_l4_hdr(struct iphdr *hdr_ipv4)
{
	return ((void *) hdr_ipv4) + (hdr_ipv4->ihl << 2);
}

/**
 * unknown_inner_proto - whenever this function is called, the RFC says the
 * packet should be dropped, but we're accepting it instead.
 *
 * I made it into a function so I wouldn't have to replicate the rationale:
 *
 * If the packet is an ICMP error that contains a packet of unknown transport
 * protocol, we couldn't have possibly translated the packet that caused the
 * error.
 * Therefore, the original packet came from this host... or it's just crafted
 * garbage.
 * Either way, Linux should be the one who decides the fate of the ICMP error.
 */
static verdict unknown_inner_proto(__u8 proto)
{
	log_debug("Packet's inner packet is not UDP, TCP or ICMP (%u).", proto);
	return VERDICT_ACCEPT;
}

/**
 * @{
 * Builds @tuple's fields based on @pkt.
 */

static verdict ipv4_udp(struct packet *pkt, struct tuple *tuple4)
{
	pkt->tuple.src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	pkt->tuple.src.addr4.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->source);
	pkt->tuple.dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	pkt->tuple.dst.addr4.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->dest);
	pkt->tuple.l3_proto = L3PROTO_IPV4;
	pkt->tuple.l4_proto = L4PROTO_UDP;
	return VERDICT_CONTINUE;
}

static verdict ipv4_tcp(struct packet *pkt, struct tuple *tuple4)
{
	tuple4->src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	tuple4->src.addr4.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->source);
	tuple4->dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	tuple4->dst.addr4.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->dest);
	tuple4->l3_proto = L3PROTO_IPV4;
	tuple4->l4_proto = L4PROTO_TCP;
	return VERDICT_CONTINUE;
}

static verdict ipv4_icmp_info(struct packet *pkt, struct tuple *tuple4)
{
	tuple4->src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	tuple4->src.addr4.l4 = be16_to_cpu(pkt_icmp4_hdr(pkt)->un.echo.id);
	tuple4->dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	tuple4->dst.addr4.l4 = tuple4->src.addr4.l4;
	tuple4->l3_proto = L3PROTO_IPV4;
	tuple4->l4_proto = L4PROTO_ICMP;
	return VERDICT_CONTINUE;
}

static verdict ipv4_icmp_err(struct packet *pkt, struct tuple *tuple4)
{
	struct iphdr *inner_ipv4 = (struct iphdr *) (pkt_icmp4_hdr(pkt) + 1);
	struct udphdr *inner_udp;
	struct tcphdr *inner_tcp;
	struct icmphdr *inner_icmp;

	tuple4->src.addr4.l3.s_addr = inner_ipv4->daddr;
	tuple4->dst.addr4.l3.s_addr = inner_ipv4->saddr;

	switch (inner_ipv4->protocol) {
	case IPPROTO_UDP:
		inner_udp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple4->src.addr4.l4 = be16_to_cpu(inner_udp->dest);
		tuple4->dst.addr4.l4 = be16_to_cpu(inner_udp->source);
		tuple4->l4_proto = L4PROTO_UDP;
		break;

	case IPPROTO_TCP:
		inner_tcp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple4->src.addr4.l4 = be16_to_cpu(inner_tcp->dest);
		tuple4->dst.addr4.l4 = be16_to_cpu(inner_tcp->source);
		tuple4->l4_proto = L4PROTO_TCP;
		break;

	case IPPROTO_ICMP:
		inner_icmp = ipv4_extract_l4_hdr(inner_ipv4);

		if (is_icmp4_error(inner_icmp->type)) {
			log_debug("Bogus pkt: ICMP error inside ICMP error.");
			inc_stats(pkt, IPSTATS_MIB_INHDRERRORS);
			return VERDICT_DROP;
		}

		tuple4->src.addr4.l4 = be16_to_cpu(inner_icmp->un.echo.id);
		tuple4->dst.addr4.l4 = tuple4->src.addr4.l4;
		tuple4->l4_proto = L4PROTO_ICMP;
		break;

	default:
		return unknown_inner_proto(inner_ipv4->protocol);
	}

	tuple4->l3_proto = L3PROTO_IPV4;

	return VERDICT_CONTINUE;
}

static verdict ipv4_icmp(struct packet *pkt, struct tuple *tuple4)
{
	__u8 type = pkt_icmp4_hdr(pkt)->type;

	if (is_icmp4_info(type))
		return ipv4_icmp_info(pkt, tuple4);

	if (is_icmp4_error(type))
		return ipv4_icmp_err(pkt, tuple4);

	log_debug("Unknown ICMPv4 type: %u", type);
	/*
	 * Hope the kernel has something to do with the packet.
	 * Neighbor discovery not likely an issue, but see ipv6_icmp() anyway.
	 */
	return VERDICT_ACCEPT;
}

static verdict ipv6_udp(struct packet *pkt, struct tuple *tuple6)
{
	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->source);
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->dest);
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_UDP;
	return VERDICT_CONTINUE;
}

static verdict ipv6_tcp(struct packet *pkt, struct tuple *tuple6)
{
	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->source);
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = be16_to_cpu(pkt_tcp_hdr(pkt)->dest);
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_TCP;
	return VERDICT_CONTINUE;
}

static verdict ipv6_icmp_info(struct packet *pkt, struct tuple *tuple6)
{
	__u16 id = be16_to_cpu(pkt_icmp6_hdr(pkt)->icmp6_identifier);

	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = id;
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = id;
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_ICMP;

	return VERDICT_CONTINUE;
}

static verdict ipv6_icmp_err(struct packet *pkt, struct tuple *tuple6)
{
	struct ipv6hdr *inner_ip6 = (struct ipv6hdr *) (pkt_icmp6_hdr(pkt) + 1);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(inner_ip6);
	struct udphdr *inner_udp;
	struct tcphdr *inner_tcp;
	struct icmp6hdr *inner_icmp;
	__u16 id;

	tuple6->src.addr6.l3 = inner_ip6->daddr;
	tuple6->dst.addr6.l3 = inner_ip6->saddr;

	hdr_iterator_last(&iterator);
	switch (iterator.hdr_type) {
	case NEXTHDR_UDP:
		inner_udp = iterator.data;
		tuple6->src.addr6.l4 = be16_to_cpu(inner_udp->dest);
		tuple6->dst.addr6.l4 = be16_to_cpu(inner_udp->source);
		tuple6->l4_proto = L4PROTO_UDP;
		break;

	case NEXTHDR_TCP:
		inner_tcp = iterator.data;
		tuple6->src.addr6.l4 = be16_to_cpu(inner_tcp->dest);
		tuple6->dst.addr6.l4 = be16_to_cpu(inner_tcp->source);
		tuple6->l4_proto = L4PROTO_TCP;
		break;

	case NEXTHDR_ICMP:
		inner_icmp = iterator.data;

		if (is_icmp6_error(inner_icmp->icmp6_type)) {
			log_debug("Bogus pkt: ICMP error inside ICMP error.");
			inc_stats(pkt, IPSTATS_MIB_INHDRERRORS);
			return VERDICT_DROP;
		}

		id = be16_to_cpu(inner_icmp->icmp6_identifier);
		tuple6->src.addr6.l4 = id;
		tuple6->dst.addr6.l4 = id;
		tuple6->l4_proto = L4PROTO_ICMP;
		break;

	default:
		return unknown_inner_proto(iterator.hdr_type);
	}

	tuple6->l3_proto = L3PROTO_IPV6;

	return VERDICT_CONTINUE;
}
/**
 * @}
 */

static verdict ipv6_icmp(struct packet *pkt, struct tuple *tuple6)
{
	__u8 type = pkt_icmp6_hdr(pkt)->icmp6_type;

	if (is_icmp6_info(type))
		return ipv6_icmp_info(pkt, tuple6);

	if (is_icmp6_error(type))
		return ipv6_icmp_err(pkt, tuple6);

	log_debug("Unknown ICMPv6 type: %u.", type);
	/*
	 * We return VERDICT_ACCEPT instead of _DROP because the neighbor
	 * discovery code happens after Jool, apparently (even though it's
	 * layer 2 man, wtf).
	 * This message, which is likely single-hop, might actually be intended
	 * for the kernel.
	 */
	return VERDICT_ACCEPT;
}

/**
 * Extracts relevant data from "skb" and stores it in the "tuple" tuple.
 *
 * @param skb packet the data will be extracted from.
 * @param tuple this function will populate this value using "skb"'s contents.
 * @return whether packet processing should continue.
 */
verdict determine_in_tuple(struct xlation *state)
{
	struct packet *pkt = &state->in;
	verdict result = VERDICT_CONTINUE;

	log_debug("Step 1: Determining the Incoming Tuple");

	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV4:
		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_UDP:
			result = ipv4_udp(pkt, &pkt->tuple);
			break;
		case L4PROTO_TCP:
			result = ipv4_tcp(pkt, &pkt->tuple);
			break;
		case L4PROTO_ICMP:
			result = ipv4_icmp(pkt, &pkt->tuple);
			break;
		case L4PROTO_OTHER:
			goto unknown_proto_ipv4;
		}
		break;

	case L3PROTO_IPV6:
		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_UDP:
			result = ipv6_udp(pkt, &pkt->tuple);
			break;
		case L4PROTO_TCP:
			result = ipv6_tcp(pkt, &pkt->tuple);
			break;
		case L4PROTO_ICMP:
			result = ipv6_icmp(pkt, &pkt->tuple);
			break;
		case L4PROTO_OTHER:
			goto unknown_proto_ipv6;
		}
		break;
	}

	if (result == VERDICT_CONTINUE)
		log_tuple(&pkt->tuple);
	log_debug("Done step 1.");
	return result;

unknown_proto_ipv4:
	/*
	 * pool4db_contains() dictates whether an IPv4 packet is supposed to be
	 * NAT64'd.
	 * It requires a transport address as input (set up by this module,
	 * which is the reason the pool4db_contains() validation happens so
	 * late, during filtering).
	 * If the packet has an unknown protocol, then it doesn't have a
	 * pool4db-compatible transport address.
	 * Therefore, it wasn't supposed to be translated in the first place.
	 * Therefore, it's intended for this host; it shouldn't be dropped.
	 */
	log_debug("NAT64 doesn't support unknown transport protocols.");
	return VERDICT_ACCEPT;

unknown_proto_ipv6:
	/**
	 * pool6_contains() doesn't need a transport address, so in IPv6's case
	 * whether an unknown protocol packet was meant to be translated or not
	 * is slightly more involved.
	 */
	log_debug("NAT64 doesn't support unknown transport protocols.");

	if (!pool6_contains(state->jool.pool6, &pkt_ip6_hdr(pkt)->daddr))
		/* Not meant to be translated. unknown_proto_ipv4 logic. */
		return VERDICT_ACCEPT;

	/* RFC6146 logic. */
	icmp64_send(pkt, ICMPERR_PROTO_UNREACHABLE, 0);
	inc_stats(pkt, IPSTATS_MIB_INUNKNOWNPROTOS);
	return VERDICT_DROP;
}
