#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/icmp.h>


static void *ipv4_extract_l4_hdr(struct iphdr *hdr_ipv4)
{
	return ((void *) hdr_ipv4) + (hdr_ipv4->ihl << 2);
}

static bool ipv4_udp(struct iphdr *hdr_ipv4, struct udphdr *hdr_udp, struct tuple *tuple)
{
	tuple->src.addr.ipv4.s_addr = hdr_ipv4->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_udp->source);
	tuple->dst.addr.ipv4.s_addr = hdr_ipv4->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_udp->dest);
	tuple->l3_proto = PF_INET;
	tuple->l4_proto = IPPROTO_UDP;
	return true;
}

static bool ipv4_tcp(struct iphdr *hdr_ipv4, struct tcphdr *hdr_tcp, struct tuple *tuple)
{
	tuple->src.addr.ipv4.s_addr = hdr_ipv4->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_tcp->source);
	tuple->dst.addr.ipv4.s_addr = hdr_ipv4->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_tcp->dest);
	tuple->l3_proto = PF_INET;
	tuple->l4_proto = IPPROTO_TCP;
	return true;
}

static bool ipv4_icmp_info(struct iphdr *hdr_ipv4, struct icmphdr *hdr_icmp, struct tuple *tuple)
{
	tuple->src.addr.ipv4.s_addr = hdr_ipv4->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_icmp->un.echo.id);
	tuple->dst.addr.ipv4.s_addr = hdr_ipv4->daddr;
	tuple->dst.l4_id = tuple->src.l4_id;
	tuple->l3_proto = PF_INET;
	tuple->l4_proto = IPPROTO_ICMP;
	return true;
}

static bool ipv4_icmp_err(struct iphdr *hdr_ipv4, struct icmphdr *hdr_icmp, struct tuple *tuple)
{
	struct iphdr *inner_ipv4 = (struct iphdr *) (hdr_icmp + 1);
	struct udphdr *inner_udp;
	struct tcphdr *inner_tcp;

	tuple->src.addr.ipv4.s_addr = inner_ipv4->daddr;
	tuple->dst.addr.ipv4.s_addr = inner_ipv4->saddr;

	switch (inner_ipv4->protocol) {
	case IPPROTO_UDP:
		inner_udp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple->src.l4_id = be16_to_cpu(inner_udp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_udp->source);
		break;

	case IPPROTO_TCP:
		inner_tcp = ipv4_extract_l4_hdr(inner_ipv4);
		tuple->src.l4_id = be16_to_cpu(inner_tcp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_tcp->source);
		break;

	default:
		log_warning("Packet's inner packet is not UDP or TCP (%d).", inner_ipv4->protocol);
		return false;
	}

	tuple->l3_proto = PF_INET;
	tuple->l4_proto = inner_ipv4->protocol;

	return true;
}

static bool ipv6_udp(struct ipv6hdr *hdr_ipv6, struct udphdr *hdr_udp, struct tuple *tuple)
{
	tuple->src.addr.ipv6 = hdr_ipv6->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_udp->source);
	tuple->dst.addr.ipv6 = hdr_ipv6->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_udp->dest);
	tuple->l3_proto = PF_INET6;
	tuple->l4_proto = IPPROTO_UDP;
	return true;
}

static bool ipv6_tcp(struct ipv6hdr *hdr_ipv6, struct tcphdr *hdr_tcp, struct tuple *tuple)
{
	tuple->src.addr.ipv6 = hdr_ipv6->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_tcp->source);
	tuple->dst.addr.ipv6 = hdr_ipv6->daddr;
	tuple->dst.l4_id = be16_to_cpu(hdr_tcp->dest);
	tuple->l3_proto = PF_INET6;
	tuple->l4_proto = IPPROTO_TCP;
	return true;
}

static bool ipv6_icmp_info(struct ipv6hdr *hdr_ipv6, struct icmp6hdr *hdr_icmp, struct tuple *tuple)
{
	tuple->src.addr.ipv6 = hdr_ipv6->saddr;
	tuple->src.l4_id = be16_to_cpu(hdr_icmp->icmp6_dataun.u_echo.identifier);
	tuple->dst.addr.ipv6 = hdr_ipv6->daddr;
	tuple->dst.l4_id = tuple->src.l4_id;
	tuple->l3_proto = PF_INET6;
	tuple->l4_proto = IPPROTO_ICMPV6;
	return true;
}

static bool ipv6_icmp_err(struct ipv6hdr *hdr_ipv6, struct icmp6hdr *hdr_icmp, struct tuple *tuple)
{
	struct ipv6hdr *inner_ipv6 = (struct ipv6hdr *) (hdr_icmp + 1);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(inner_ipv6);
	struct udphdr *inner_udp;
	struct tcphdr *inner_tcp;

	tuple->src.addr.ipv6 = inner_ipv6->daddr;
	tuple->dst.addr.ipv6 = inner_ipv6->saddr;

	hdr_iterator_last(&iterator);
	switch (iterator.hdr_type) {
	case IPPROTO_UDP:
		inner_udp = iterator.data;
		tuple->src.l4_id = be16_to_cpu(inner_udp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_udp->source);
		break;

	case IPPROTO_TCP:
		inner_tcp = iterator.data;
		tuple->src.l4_id = be16_to_cpu(inner_tcp->dest);
		tuple->dst.l4_id = be16_to_cpu(inner_tcp->source);
		break;

	default:
		log_warning("Packet's inner packet is not UDP or TCP (%d).", iterator.hdr_type);
		return false;
	}

	tuple->l3_proto = PF_INET6;
	tuple->l4_proto = iterator.hdr_type;

	return true;
}

bool determine_in_tuple(struct sk_buff *skb, struct tuple *tuple)
{
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct icmphdr *icmp4;
	struct icmp6hdr *icmp6;
	struct hdr_iterator iterator;

	log_debug("Step 1: Determining the Incoming Tuple");

	switch (be16_to_cpu(skb->protocol)) {
	case ETH_P_IP:
		hdr4 = ip_hdr(skb);
		switch (hdr4->protocol) {
		case IPPROTO_UDP:
			if (!ipv4_udp(hdr4, ipv4_extract_l4_hdr(hdr4), tuple))
				return false;
			break;
		case IPPROTO_TCP:
			if (!ipv4_tcp(hdr4, ipv4_extract_l4_hdr(hdr4), tuple))
				return false;
			break;
		case IPPROTO_ICMP:
			icmp4 = ipv4_extract_l4_hdr(hdr4);
			if (is_icmp_info(icmp4->type)) {
				if (!ipv4_icmp_info(hdr4, icmp4, tuple))
					return false;
			} else {
				if (!ipv4_icmp_err(hdr4, icmp4, tuple))
					return false;
			}
			break;
		default:
			log_info("Unsupported transport protocol for IPv4: %d.", hdr4->protocol);
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, 0);
			return false;
		}
		break;

	case ETH_P_IPV6:
		hdr6 = ipv6_hdr(skb);
		hdr_iterator_init(&iterator, hdr6);
		hdr_iterator_last(&iterator);
		switch (iterator.hdr_type) {
		case IPPROTO_UDP:
			if (!ipv6_udp(hdr6, iterator.data, tuple))
				return false;
			break;
		case IPPROTO_TCP:
			if (!ipv6_tcp(hdr6, iterator.data, tuple))
				return false;
			break;
		case IPPROTO_ICMPV6:
			icmp6 = iterator.data;
			if (is_icmp6_info(icmp6->icmp6_type)) {
				if (!ipv6_icmp_info(hdr6, icmp6, tuple))
					return false;
			} else {
				if (!ipv6_icmp_err(hdr6, icmp6, tuple))
					return false;
			}
			break;
		default:
			log_info("Unsupported transport protocol for IPv6: %d.", iterator.hdr_type);
			icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0);
			return false;
		}
		break;

	default:
		log_info("Packet's protocol (%d) is not IPv4 or IPv6.", be16_to_cpu(skb->protocol));
		return false;
	}

	log_tuple(tuple);
	log_debug("Done step 1.");
	return true;
}
