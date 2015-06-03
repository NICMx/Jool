#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/stats.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ipv6.h>


/**
 * Assumes that hdr_ipv4 is part of a packet, and returns a pointer to the chunk of data after it.
 * Skips IPv4 options if any.
 */
static void *ipv4_extract_l4_hdr(struct iphdr *hdr_ipv4)
{
	return ((void *) hdr_ipv4) + (hdr_ipv4->ihl << 2);
}

/**
 * @{
 * Builds the tuple's fields based on "skb".
 */

static verdict ipv4_udp(struct packet *pkt, struct tuple *tuple4)
{
	tuple4->src.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->saddr;
	tuple4->src.addr4.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->source);
	tuple4->dst.addr4.l3.s_addr = pkt_ip4_hdr(pkt)->daddr;
	tuple4->dst.addr4.l4 = be16_to_cpu(pkt_udp_hdr(pkt)->dest);
	tuple4->l3_proto = L3PROTO_IPV4;
	tuple4->l4_proto = L4PROTO_UDP;
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
			log_debug("Packet is a ICMP error containing a ICMP error.");
			inc_stats(pkt, IPSTATS_MIB_INHDRERRORS);
			return VERDICT_DROP;
		}

		tuple4->src.addr4.l4 = be16_to_cpu(inner_icmp->un.echo.id);
		tuple4->dst.addr4.l4 = tuple4->src.addr4.l4;
		tuple4->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Packet's inner packet is not UDP, TCP or ICMP (%d)", inner_ipv4->protocol);
		inc_stats(pkt, IPSTATS_MIB_INUNKNOWNPROTOS);
		return VERDICT_DROP;
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
	tuple6->src.addr6.l3 = pkt_ip6_hdr(pkt)->saddr;
	tuple6->src.addr6.l4 = be16_to_cpu(pkt_icmp6_hdr(pkt)->icmp6_dataun.u_echo.identifier);
	tuple6->dst.addr6.l3 = pkt_ip6_hdr(pkt)->daddr;
	tuple6->dst.addr6.l4 = tuple6->src.addr6.l4;
	tuple6->l3_proto = L3PROTO_IPV6;
	tuple6->l4_proto = L4PROTO_ICMP;
	return VERDICT_CONTINUE;
}

static verdict ipv6_icmp_err(struct packet *pkt, struct tuple *tuple6)
{
	struct ipv6hdr *inner_ipv6 = (struct ipv6hdr *) (pkt_icmp6_hdr(pkt) + 1);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(inner_ipv6);
	struct udphdr *inner_udp;
	struct tcphdr *inner_tcp;
	struct icmp6hdr *inner_icmp;

	tuple6->src.addr6.l3 = inner_ipv6->daddr;
	tuple6->dst.addr6.l3 = inner_ipv6->saddr;

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
			log_debug("Packet is a ICMP error containing a ICMP error.");
			inc_stats(pkt, IPSTATS_MIB_INHDRERRORS);
			return VERDICT_DROP;
		}

		tuple6->src.addr6.l4 = be16_to_cpu(inner_icmp->icmp6_dataun.u_echo.identifier);
		tuple6->dst.addr6.l4 = tuple6->src.addr6.l4;
		tuple6->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Packet's inner packet is not UDP, TCP or ICMPv6 (%d).", iterator.hdr_type);
		inc_stats(pkt, IPSTATS_MIB_INUNKNOWNPROTOS);
		return VERDICT_DROP;
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
verdict determine_in_tuple(struct packet *pkt, struct tuple *in_tuple)
{
	verdict result = VERDICT_CONTINUE;

	log_debug("Step 1: Determining the Incoming Tuple");

	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV4:
		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_UDP:
			result = ipv4_udp(pkt, in_tuple);
			break;
		case L4PROTO_TCP:
			result = ipv4_tcp(pkt, in_tuple);
			break;
		case L4PROTO_ICMP:
			result = ipv4_icmp(pkt, in_tuple);
			break;
		case L4PROTO_OTHER:
			goto unknown_proto;
		}
		break;

	case L3PROTO_IPV6:
		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_UDP:
			result = ipv6_udp(pkt, in_tuple);
			break;
		case L4PROTO_TCP:
			result = ipv6_tcp(pkt, in_tuple);
			break;
		case L4PROTO_ICMP:
			result = ipv6_icmp(pkt, in_tuple);
			break;
		case L4PROTO_OTHER:
			goto unknown_proto;
		}
		break;
	}

	log_tuple(in_tuple);
	log_debug("Done step 1.");
	return result;

unknown_proto:
	log_debug("Stateful NAT64 doesn't support unknown transport protocols.");
	icmp64_send(pkt, ICMPERR_PROTO_UNREACHABLE, 0);
	inc_stats(pkt, IPSTATS_MIB_INUNKNOWNPROTOS);
	return VERDICT_DROP;
}
