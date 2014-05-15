#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"

#include <linux/version.h>
#include <linux/list.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/route.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

struct dst_entry *route_ipv4(struct iphdr *hdr_ip4, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	struct flowi flow;
	struct rtable *table;
	int error;

	memset(&flow, 0, sizeof(flow));
	/* flow.oif; */
	/* flow.iif; */
	flow.mark = mark;
	flow.fl4_dst = hdr_ip4->daddr;
	/* flow.fl4_src = hdr_ip4->saddr; */
	flow.fl4_tos = RT_TOS(hdr_ip4->tos);
	flow.fl4_scope = RT_SCOPE_UNIVERSE;
	flow.proto = hdr_ip4->protocol;
	flow.flags = 0;
	{
		struct udphdr *hdr_udp;
		struct tcphdr *hdr_tcp;
		struct icmphdr *hdr_icmp4;

		switch (l4_proto) {
		case L4PROTO_NONE:
			break;
		case L4PROTO_TCP:
			hdr_tcp = l4_hdr;
			flow.fl_ip_sport = hdr_tcp->source;
			flow.fl_ip_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = l4_hdr;
			flow.fl_ip_sport = hdr_udp->source;
			flow.fl_ip_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp4 = l4_hdr;
			flow.fl_icmp_type = hdr_icmp4->type;
			flow.fl_icmp_code = hdr_icmp4->code;
			break;
		}
	}
	/* flow.secid; */

	error = ip_route_output_key(&init_net, &table, &flow);
	if (error) {
		log_debug("ip_route_output_key() failed. Code: %d. Cannot route packet.", -error);
		return NULL;
	}
	if (!table) {
		log_debug("The routing table is NULL. Cannot route packet.");
		return NULL;
	}

	return &table->dst;
}

struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip6, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	struct flowi flow;
	struct dst_entry *dst;

	memset(&flow, 0, sizeof(flow));
	/* flow.oif; */
	/* flow.iif; */
	flow.mark = mark;
	flow.fl6_dst = hdr_ip6->daddr;
	flow.fl6_src = hdr_ip6->saddr;
	flow.fl6_flowlabel = get_flow_label(hdr_ip6);
	flow.proto = hdr_ip6->nexthdr;
	flow.flags = 0;
	{
		struct udphdr *hdr_udp;
		struct tcphdr *hdr_tcp;
		struct icmp6hdr *hdr_icmp6;

		switch (l4_proto) {
		case L4PROTO_NONE:
			break;
		case L4PROTO_TCP:
			hdr_tcp = l4_hdr;
			flow.fl_ip_sport = hdr_tcp->source;
			flow.fl_ip_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = l4_hdr;
			flow.fl_ip_sport = hdr_udp->source;
			flow.fl_ip_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp6 = l4_hdr;
			flow.fl_icmp_type = hdr_icmp6->icmp6_type;
			flow.fl_icmp_code = hdr_icmp6->icmp6_code;
			break;
		}
	}
	/* flow.secid; */

	dst = ip6_route_output(&init_net, NULL, &flow);
	if (!dst) {
		log_debug("ip6_route_output() returned NULL. Cannot route packet.");
		return NULL;
	}
	if (dst->error) {
		log_debug("ip6_route_output() returned error %d. Cannot route packet.", -dst->error);
		return NULL;
	}

	return dst;
}

#else

struct dst_entry *route_ipv4(struct iphdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	struct flowi4 flow;
	struct rtable *table;

	memset(&flow, 0, sizeof(flow));
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	flow.flowi4_mark = mark;
	flow.flowi4_tos = RT_TOS(hdr_ip->tos);
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = hdr_ip->protocol;
	/*
	 * TODO (help) Don't know if we should set FLOWI_FLAG_PRECOW_METRICS. Does the kernel ever
	 * create routes on Jool's behalf?
	 * TODO (help) We should probably set FLOWI_FLAG_ANYSRC (for virtual-interfaceless support).
	 * If you change it, the corresponding attribute in route_skb_ipv6() should probably follow.
	 */
	flow.flowi4_flags = 0;
	/* Only used by XFRM ATM (kernel/Documentation/networking/secid.txt). */
	/* flow.flowi4_secid; */
	/* It appears this one only introduces noise. */
	/* flow.saddr = hdr_ip->saddr; */
	flow.daddr = hdr_ip->daddr;

	{
		struct udphdr *hdr_udp;
		struct tcphdr *hdr_tcp;
		struct icmphdr *hdr_icmp4;

		switch (l4_proto) {
		case L4PROTO_NONE:
			break;
		case L4PROTO_TCP:
			hdr_tcp = l4_hdr;
			flow.fl4_sport = hdr_tcp->source;
			flow.fl4_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = l4_hdr;
			flow.fl4_sport = hdr_udp->source;
			flow.fl4_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp4 = l4_hdr;
			flow.fl4_icmp_type = hdr_icmp4->type;
			flow.fl4_icmp_code = hdr_icmp4->code;
			break;
		}
	}

	/*
	 * I'm using neither ip_route_output_key() nor ip_route_output_flow() because those seem to
	 * mind about XFRM (= IPsec), which is probably just troublesome overhead given that "any
	 * protocols that protect IP header information are essentially incompatible with NAT64"
	 * (RFC 6146).
	 */
	table = __ip_route_output_key(&init_net, &flow);
	if (!table || IS_ERR(table)) {
		log_debug("__ip_route_output_key() returned %ld. Cannot route packet.", (long) table);
		return NULL;
	}

	return &table->dst;
}

struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	struct flowi6 flow;
	struct dst_entry *dst;
	struct hdr_iterator iterator;

	hdr_iterator_init(&iterator, hdr_ip);
	hdr_iterator_last(&iterator);

	memset(&flow, 0, sizeof(flow));
	/* flow->flowi6_oif; */
	/* flow->flowi6_iif; */
	flow.flowi6_mark = mark;
	flow.flowi6_tos = get_traffic_class(hdr_ip);
	flow.flowi6_scope = RT_SCOPE_UNIVERSE;
	flow.flowi6_proto = iterator.hdr_type;
	flow.flowi6_flags = 0;
	/* flow->flowi6_secid; */
	flow.saddr = hdr_ip->saddr;
	flow.daddr = hdr_ip->daddr;
	flow.flowlabel = get_flow_label(hdr_ip);
	{
		struct udphdr *hdr_udp;
		struct tcphdr *hdr_tcp;
		struct icmp6hdr *hdr_icmp6;

		switch (l4_proto) {
		case L4PROTO_NONE:
			break;
		case L4PROTO_TCP:
			hdr_tcp = l4_hdr;
			flow.fl6_sport = hdr_tcp->source;
			flow.fl6_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = l4_hdr;
			flow.fl6_sport = hdr_udp->source;
			flow.fl6_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp6 = l4_hdr;
			flow.fl6_icmp_type = hdr_icmp6->icmp6_type;
			flow.fl6_icmp_code = hdr_icmp6->icmp6_code;
			break;
		}
	}

	dst = ip6_route_output(&init_net, NULL, &flow);
	if (!dst) {
		log_debug("ip6_route_output() returned NULL. Cannot route packet.");
		return NULL;
	}
	if (dst->error) {
		log_debug("ip6_route_output() returned error %d. Cannot route packet.", -dst->error);
		return NULL;
	}

	return dst;
}

#endif


verdict send_pkt(struct packet *pkt)
{
	struct fragment *frag;
	int error = 0;

	list_for_each_entry(frag, &pkt->fragments, list_hook) {
		log_debug("Sending skb via device '%s'...", frag->skb->dev->name);
		switch (frag->l3_hdr.proto) {
		case L3PROTO_IPV6:
			error = ip6_local_out(frag->skb);
			break;
		case L3PROTO_IPV4:
			error = ip_local_out(frag->skb);
			break;
		}

		/* the ip*_local_out() functions free the skb, so prevent crashing during frag_kfree(). */
		frag->skb = NULL;

		if (error) {
			log_debug("The kernel's packet dispatch function returned errcode %d. "
					"Cannot send packet.", error);
			return VER_DROP; /* The rest will also probably fail methinks, so meh. */
		}
	}

	return VER_CONTINUE;
}
