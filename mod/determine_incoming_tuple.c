#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>


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

static verdict ipv4_icmp_info(struct iphdr *hdr_ipv4, struct icmphdr *hdr_icmp, struct tuple *tuple)
{
	tuple->src.addr.ipv4.s_addr = hdr_ipv4->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_icmp->un.echo.id);
	tuple->dst.addr.ipv4.s_addr = hdr_ipv4->daddr;
	tuple->dst.l4_id = tuple->src.l4_id;
	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = L4PROTO_ICMP;
	return VER_CONTINUE;
}

static void *ipv4_extract_l4_hdr(struct iphdr *hdr_ipv4)
{
	return ((void *) hdr_ipv4) + (hdr_ipv4->ihl << 2);
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
		log_warning("Packet's inner packet is not UDP, TCP or ICMP (%d)", inner_ipv4->protocol);
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

static verdict ipv6_icmp_info(struct ipv6hdr *hdr_ipv6, struct icmp6hdr *hdr_icmp, struct tuple *tuple)
{
	tuple->src.addr.ipv6 = hdr_ipv6->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_icmp->icmp6_dataun.u_echo.identifier);
	tuple->dst.addr.ipv6 = hdr_ipv6->daddr;
	tuple->dst.l4_id = tuple->src.l4_id;
	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = L4PROTO_ICMP;
	return VER_CONTINUE;
}

static verdict ipv6_icmp_err(struct ipv6hdr *hdr_ipv6, struct icmp6hdr *hdr_icmp, struct tuple *tuple)
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
		log_warning("Packet's inner packet is not UDP, TCP or ICMPv6 (%d).", iterator.hdr_type);
		return VER_DROP;
	}

	tuple->l3_proto = L3PROTO_IPV6;

	return VER_CONTINUE;
}

/**
 * Extracts relevant data from "frag" and stores it in the "tuple" tuple.
 *
 * @param frag fragment the data will be extracted from. Whether the packet is fragmented or not,
 *		this has to be the chunk whose fragment offset is zero.
 * @param tuple this function will populate this value using "frag"'s contents.
 * @return whether packet processing should continue.
 */
verdict determine_in_tuple(struct fragment *frag, struct tuple *tuple)
{
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct icmphdr *icmp4;
	struct icmp6hdr *icmp6;
	verdict result = VER_CONTINUE;

	log_debug("Step 1: Determining the Incoming Tuple");

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV4:
		hdr4 = frag_get_ipv4_hdr(frag);
		switch (frag->l4_hdr.proto) {
		case L4PROTO_UDP:
			result = ipv4_udp(hdr4, frag_get_udp_hdr(frag), tuple);
			break;
		case L4PROTO_TCP:
			result = ipv4_tcp(hdr4, frag_get_tcp_hdr(frag), tuple);
			break;
		case L4PROTO_ICMP:
			icmp4 = frag_get_icmp4_hdr(frag);
			result = (is_icmp4_info(icmp4->type))
					? ipv4_icmp_info(hdr4, icmp4, tuple)
					: ipv4_icmp_err(hdr4, icmp4, tuple);
			break;
		case L4PROTO_NONE:
			log_crit(ERR_ILLEGAL_NONE, "IPv4 - First fragment has no transport header.");
			result = VER_DROP;
		}
		break;

	case L3PROTO_IPV6:
		hdr6 = frag_get_ipv6_hdr(frag);
		switch (frag->l4_hdr.proto) {
		case L4PROTO_UDP:
			result = ipv6_udp(hdr6, frag_get_udp_hdr(frag), tuple);
			break;
		case L4PROTO_TCP:
			result = ipv6_tcp(hdr6, frag_get_tcp_hdr(frag), tuple);
			break;
		case L4PROTO_ICMP:
			icmp6 = frag_get_icmp6_hdr(frag);
			result = (is_icmp6_info(icmp6->icmp6_type))
					? ipv6_icmp_info(hdr6, icmp6, tuple)
					: ipv6_icmp_err(hdr6, icmp6, tuple);
			break;
		case L4PROTO_NONE:
			log_crit(ERR_ILLEGAL_NONE, "IPv6 - First fragment has no transport header.");
			result = VER_DROP;
		}
		break;
	}

	/*
	 * We moved the transport-protocol-not-recognized ICMP errors to fragment_db because they're
	 * covered in validations.
	 */

	log_tuple(tuple);
	log_debug("Done step 1.");
	return result;
}
