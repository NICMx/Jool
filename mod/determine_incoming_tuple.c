#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

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
 * Builds "tuple"'s fields based on the rest of the arguments.
 */

static verdict ipv4_udp(struct iphdr *hdr_ipv4, struct udphdr *hdr_udp, struct tuple *tuple)
{
	tuple->src.addr.ipv4.s_addr = hdr_ipv4->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_udp->source);
	tuple->dst.addr.ipv4.s_addr = hdr_ipv4->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_udp->dest);
	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = L4PROTO_UDP;
	return VER_CONTINUE;
}

static verdict ipv4_tcp(struct iphdr *hdr_ipv4, struct tcphdr *hdr_tcp, struct tuple *tuple)
{
	tuple->src.addr.ipv4.s_addr = hdr_ipv4->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_tcp->source);
	tuple->dst.addr.ipv4.s_addr = hdr_ipv4->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_tcp->dest);
	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = L4PROTO_TCP;
	return VER_CONTINUE;
}

static verdict ipv4_icmp_info(struct iphdr *hdr_ipv4, struct icmphdr *hdr_icmp,
		struct tuple *tuple)
{
	tuple->src.addr.ipv4.s_addr = hdr_ipv4->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_icmp->un.echo.id);
	tuple->dst.addr.ipv4.s_addr = hdr_ipv4->daddr;
	tuple->dst.l4_id = tuple->src.l4_id;
	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = L4PROTO_ICMP;
	return VER_CONTINUE;
}

static verdict ipv4_icmp_err(struct iphdr *hdr_ipv4, struct icmphdr *hdr_icmp, struct tuple *tuple)
{
	struct iphdr *inner_ipv4 = (struct iphdr *) (hdr_icmp + 1);
	struct udphdr *inner_udp;
	struct tcphdr *inner_tcp;
	struct icmphdr *inner_icmp;

	tuple->src.addr.ipv4.s_addr = inner_ipv4->daddr;
	tuple->dst.addr.ipv4.s_addr = inner_ipv4->saddr;

	switch (inner_ipv4->protocol) {
	case IPPROTO_UDP:
		inner_udp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple->src.l4_id = be16_to_cpu(inner_udp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_udp->source);
		tuple->l4_proto = L4PROTO_UDP;
		break;

	case IPPROTO_TCP:
		inner_tcp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple->src.l4_id = be16_to_cpu(inner_tcp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_tcp->source);
		tuple->l4_proto = L4PROTO_TCP;
		break;

	case IPPROTO_ICMP:
		inner_icmp = ipv4_extract_l4_hdr(inner_ipv4);

		if (is_icmp4_error(inner_icmp->type)) {
			log_debug("Packet is a ICMP error containing a ICMP error.");
			return VER_DROP;
		}

		tuple->src.l4_id = be16_to_cpu(inner_icmp->un.echo.id);
		tuple->dst.l4_id = tuple->src.l4_id;
		tuple->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Packet's inner packet is not UDP, TCP or ICMP (%d)", inner_ipv4->protocol);
		return VER_DROP;
	}

	tuple->l3_proto = L3PROTO_IPV4;

	return VER_CONTINUE;
}

static verdict ipv6_udp(struct ipv6hdr *hdr_ipv6, struct udphdr *hdr_udp, struct tuple *tuple)
{
	tuple->src.addr.ipv6 = hdr_ipv6->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_udp->source);
	tuple->dst.addr.ipv6 = hdr_ipv6->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_udp->dest);
	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = L4PROTO_UDP;
	return VER_CONTINUE;
}

static verdict ipv6_tcp(struct ipv6hdr *hdr_ipv6, struct tcphdr *hdr_tcp, struct tuple *tuple)
{
	tuple->src.addr.ipv6 = hdr_ipv6->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_tcp->source);
	tuple->dst.addr.ipv6 = hdr_ipv6->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_tcp->dest);
	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = L4PROTO_TCP;
	return VER_CONTINUE;
}

static verdict ipv6_icmp_info(struct ipv6hdr *hdr_ipv6, struct icmp6hdr *hdr_icmp,
		struct tuple *tuple)
{
	tuple->src.addr.ipv6 = hdr_ipv6->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_icmp->icmp6_dataun.u_echo.identifier);
	tuple->dst.addr.ipv6 = hdr_ipv6->daddr;
	tuple->dst.l4_id = tuple->src.l4_id;
	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = L4PROTO_ICMP;
	return VER_CONTINUE;
}

static verdict ipv6_icmp_err(struct ipv6hdr *hdr_ipv6, struct icmp6hdr *hdr_icmp,
		struct tuple *tuple)
{
	struct ipv6hdr *inner_ipv6 = (struct ipv6hdr *) (hdr_icmp + 1);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(inner_ipv6);
	struct udphdr *inner_udp;
	struct tcphdr *inner_tcp;
	struct icmp6hdr *inner_icmp;

	tuple->src.addr.ipv6 = inner_ipv6->daddr;
	tuple->dst.addr.ipv6 = inner_ipv6->saddr;

	hdr_iterator_last(&iterator);
	switch (iterator.hdr_type) {
	case NEXTHDR_UDP:
		inner_udp = iterator.data;
		tuple->src.l4_id = be16_to_cpu(inner_udp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_udp->source);
		tuple->l4_proto = L4PROTO_UDP;
		break;

	case NEXTHDR_TCP:
		inner_tcp = iterator.data;
		tuple->src.l4_id = be16_to_cpu(inner_tcp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_tcp->source);
		tuple->l4_proto = L4PROTO_TCP;
		break;

	case NEXTHDR_ICMP:
		inner_icmp = iterator.data;

		if (is_icmp6_error(inner_icmp->icmp6_type)) {
			log_debug("Packet is a ICMP error containing a ICMP error.");
			return VER_DROP;
		}

		tuple->src.l4_id = be16_to_cpu(inner_icmp->icmp6_dataun.u_echo.identifier);
		tuple->dst.l4_id = tuple->src.l4_id;
		tuple->l4_proto = L4PROTO_ICMP;
		break;

	default:
		log_debug("Packet's inner packet is not UDP, TCP or ICMPv6 (%d).", iterator.hdr_type);
		return VER_DROP;
	}

	tuple->l3_proto = L3PROTO_IPV6;

	return VER_CONTINUE;
}
/**
 * @}
 */

/**
 * Extracts relevant data from "skb" and stores it in the "tuple" tuple.
 *
 * @param skb packet the data will be extracted from.
 * @param tuple this function will populate this value using "skb"'s contents.
 * @return whether packet processing should continue.
 */
verdict determine_in_tuple(struct sk_buff *skb, struct tuple *tuple)
{
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct icmphdr *icmp4;
	struct icmp6hdr *icmp6;
	verdict result = VER_CONTINUE;

	log_debug("Step 1: Determining the Incoming Tuple");

	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV4:
		hdr4 = ip_hdr(skb);
		switch (skb_l4_proto(skb)) {
		case L4PROTO_UDP:
			result = ipv4_udp(hdr4, udp_hdr(skb), tuple);
			break;
		case L4PROTO_TCP:
			result = ipv4_tcp(hdr4, tcp_hdr(skb), tuple);
			break;
		case L4PROTO_ICMP:
			icmp4 = icmp_hdr(skb);
			if (is_icmp4_info(icmp4->type)) {
				result = ipv4_icmp_info(hdr4, icmp4, tuple);
			} else if (is_icmp4_error(icmp4->type)) {
				result = ipv4_icmp_err(hdr4, icmp4, tuple);
			} else {
				log_debug("Unknown ICMPv4 type: %u. Dropping packet...", icmp4->type);
				result = VER_DROP;
			}
			break;
		case L4PROTO_NONE:
			WARN(true, "IPv4 - Packet has no transport header.");
			result = VER_DROP;
		}
		break;

	case L3PROTO_IPV6:
		hdr6 = ipv6_hdr(skb);
		switch (skb_l4_proto(skb)) {
		case L4PROTO_UDP:
			result = ipv6_udp(hdr6, udp_hdr(skb), tuple);
			break;
		case L4PROTO_TCP:
			result = ipv6_tcp(hdr6, tcp_hdr(skb), tuple);
			break;
		case L4PROTO_ICMP:
			icmp6 = icmp6_hdr(skb);
			if (is_icmp6_info(icmp6->icmp6_type)) {
				result = ipv6_icmp_info(hdr6, icmp6, tuple);
			} else if (is_icmp6_error(icmp6->icmp6_type)) {
				result = ipv6_icmp_err(hdr6, icmp6, tuple);
			} else {
				log_debug("Unknown ICMPv6 type: %u. Dropping packet...", icmp6->icmp6_type);
				result = VER_DROP;
			}
			break;
		case L4PROTO_NONE:
			WARN(true, "IPv6 - Packet has no transport header.");
			result = VER_DROP;
		}
		break;
	}

	/*
	 * We moved the transport-protocol-not-recognized ICMP errors to packet.c because they're
	 * covered in validations.
	 */

	log_tuple(tuple);
	log_debug("Done step 1.");
	return result;
}
