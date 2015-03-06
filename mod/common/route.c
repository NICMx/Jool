#include "nat64/mod/common/route.h"

#include <linux/icmp.h>
#include <net/ip6_route.h>
#include <net/route.h>

#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/types.h"

int route4(struct packet *pkt)
{
	struct iphdr *hdr_ip = pkt_ip4_hdr(pkt);
	struct flowi4 flow;

	/* Sometimes Jool needs to route prematurely, so don't sweat this on the normal pipelines. */
	if (skb_dst(pkt->skb))
		return 0;

	memset(&flow, 0, sizeof(flow));
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	flow.flowi4_mark = pkt->skb->mark;
	flow.flowi4_tos = RT_TOS(hdr_ip->tos);
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = hdr_ip->protocol;
	/*
	 * TODO (help) Don't know if we should set FLOWI_FLAG_PRECOW_METRICS. Does the kernel ever
	 * create routes on Jool's behalf?
	 * TODO (help) We should probably set FLOWI_FLAG_ANYSRC (for virtual-interfaceless support).
	 * If you change it, the corresponding attribute in route_ipv6() should probably follow.
	 */
	flow.flowi4_flags = 0;
	/* Only used by XFRM ATM (kernel/Documentation/networking/secid.txt). */
	/* flow.flowi4_secid; */
	/* It appears this one only introduces noise. */
	/* flow.saddr = hdr_ip->saddr; */
	flow.daddr = hdr_ip->daddr;

	{
		union {
			struct tcphdr *tcp;
			struct udphdr *udp;
			struct icmphdr *icmp4;
		} hdr;

		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_TCP:
			hdr.tcp = pkt_tcp_hdr(pkt);
			flow.fl4_sport = hdr.tcp->source;
			flow.fl4_dport = hdr.tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr.udp = pkt_udp_hdr(pkt);
			flow.fl4_sport = hdr.udp->source;
			flow.fl4_dport = hdr.udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr.icmp4 = pkt_icmp4_hdr(pkt);
			flow.fl4_icmp_type = hdr.icmp4->type;
			flow.fl4_icmp_code = hdr.icmp4->code;
			break;
		case L4PROTO_OTHER:
			break;
		}
	}


	return __route4(pkt, &flow);
}

int __route4(struct packet *pkt_out, struct flowi4 *flow)
{
	struct rtable *table;
	int error;

	if (!pkt_out || !flow) {
		log_err("pkt_out or flow cannot be NULL");
		return -EINVAL;
	}

	/*
	 * I'm using neither ip_route_output_key() nor ip_route_output_flow() because those seem to
	 * mind about XFRM (= IPsec), which is probably just troublesome overhead given that "any
	 * protocols that protect IP header information are essentially incompatible with NAT64"
	 * (RFC 6146).
	 */
	table = __ip_route_output_key(&init_net, flow);
	if (!table || IS_ERR(table)) {
		error = abs(PTR_ERR(table));
		log_debug("__ip_route_output_key() returned %d. Cannot route packet.", error);
		inc_stats(pkt_out, IPSTATS_MIB_OUTNOROUTES);
		return -error;
	}
	if (table->dst.error) {
		error = abs(table->dst.error);
		log_debug("__ip_route_output_key() returned error %d. Cannot route packet.", error);
		inc_stats(pkt_out, IPSTATS_MIB_OUTNOROUTES);
		return -error;
	}
	if (!table->dst.dev) {
		dst_release(&table->dst);
		log_debug("I found a dst entry with no dev. I don't know what to do; failing...");
		inc_stats(pkt_out, IPSTATS_MIB_OUTNOROUTES);
		return -EINVAL;
	}

	skb_dst_set(pkt_out->skb, &table->dst);
	pkt_out->skb->dev = table->dst.dev;

	return 0;
}

int route6(struct packet *pkt)
{
	struct ipv6hdr *hdr_ip = pkt_ip6_hdr(pkt);
	struct flowi6 flow;
	struct dst_entry *dst;
	struct hdr_iterator iterator;

	if (skb_dst(pkt->skb))
		return 0;

	hdr_iterator_init(&iterator, hdr_ip);
	hdr_iterator_last(&iterator);

	memset(&flow, 0, sizeof(flow));
	/* flow->flowi6_oif; */
	/* flow->flowi6_iif; */
	flow.flowi6_mark = pkt->skb->mark;
	flow.flowi6_tos = get_traffic_class(hdr_ip);
	flow.flowi6_scope = RT_SCOPE_UNIVERSE;
	flow.flowi6_proto = iterator.hdr_type;
	flow.flowi6_flags = 0;
	/* flow->flowi6_secid; */
	flow.saddr = hdr_ip->saddr;
	flow.daddr = hdr_ip->daddr;
	flow.flowlabel = get_flow_label(hdr_ip);
	{
		union {
			struct tcphdr *tcp;
			struct udphdr *udp;
			struct icmp6hdr *icmp6;
		} hdr;

		switch (pkt_l4_proto(pkt)) {
		case L4PROTO_TCP:
			hdr.tcp = pkt_tcp_hdr(pkt);
			flow.fl6_sport = hdr.tcp->source;
			flow.fl6_dport = hdr.tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr.udp = pkt_udp_hdr(pkt);
			flow.fl6_sport = hdr.udp->source;
			flow.fl6_dport = hdr.udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr.icmp6 = pkt_icmp6_hdr(pkt);
			flow.fl6_icmp_type = hdr.icmp6->icmp6_type;
			flow.fl6_icmp_code = hdr.icmp6->icmp6_code;
			break;
		case L4PROTO_OTHER:
			break;
		}
	}

	dst = ip6_route_output(&init_net, NULL, &flow);
	if (!dst) {
		log_debug("ip6_route_output() returned NULL. Cannot route packet.");
		inc_stats(pkt, IPSTATS_MIB_OUTNOROUTES);
		return -EINVAL;
	}
	if (dst->error) {
		int error = abs(dst->error);
		log_debug("ip6_route_output() returned error %d. Cannot route packet.", error);
		inc_stats(pkt, IPSTATS_MIB_OUTNOROUTES);
		return -error;
	}

	skb_dst_set(pkt->skb, dst);
	pkt->skb->dev = dst->dev;

	return 0;
}

int route(struct packet *pkt)
{
	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV6:
		return route6(pkt);
	case L3PROTO_IPV4:
		return route4(pkt);
	}

	WARN(true, "Unsupported network protocol: %u.", pkt_l3_proto(pkt));
	return -EINVAL;
}

int route4_input(struct packet *pkt)
{
	struct iphdr *hdr4;
	struct sk_buff *skb;
	int error;

	if (unlikely(!pkt)) {
		log_err("pkt can't be empty");
		return -EINVAL;
	}

	skb = pkt->skb;
	if (unlikely(!skb) || !skb->dev) {
		log_err("pkt->skb can't be empty");
		return -EINVAL;
	}

	hdr4 = ip_hdr(skb);

	/*
	 * Some kernel functions assume that the incoming packet is already routed.
	 * Because they seem to pop up where we least expect them, we'll just route every incoming
	 * packet, regardless of whether we end up calling one of those functions.
	 */
	error = ip_route_input(skb, hdr4->daddr, hdr4->saddr, hdr4->tos, skb->dev);
	if (error) {
		log_debug("ip_route_input failed: %d", error);
		inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
	}

	return error;
}
