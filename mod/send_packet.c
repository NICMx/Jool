#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"

#include <linux/version.h>
#include <linux/list.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/route.h>


int route_ipv4(struct sk_buff *skb)
{
	struct iphdr *hdr_ip = ip_hdr(skb);
	struct flowi4 flow;
	struct rtable *table;
	int error;

	memset(&flow, 0, sizeof(flow));
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	flow.flowi4_mark = skb->mark;
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

		switch (skb_l4_proto(skb)) {
		case L4PROTO_TCP:
			hdr_tcp = tcp_hdr(skb);
			flow.fl4_sport = hdr_tcp->source;
			flow.fl4_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = udp_hdr(skb);
			flow.fl4_sport = hdr_udp->source;
			flow.fl4_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp4 = icmp_hdr(skb);
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
		error = abs(PTR_ERR(table));
		log_debug("__ip_route_output_key() returned %d. Cannot route packet.", error);
		return -error;
	}
	if (table->dst.error) {
		error = abs(table->dst.error);
		log_debug("__ip_route_output_key() returned error %d. Cannot route packet.", error);
		return -error;
	}
	if (!table->dst.dev) {
		dst_release(&table->dst);
		log_debug("I found a dst entry with no dev. I don't know what to do; failing...");
		return -EINVAL;
	}

	skb_dst_set(skb, &table->dst);
	/* TODO (fine) ip_output() already does this, so we have probably never needed it. */
	skb->dev = table->dst.dev;

	return 0;
}

int route_ipv6(struct sk_buff *skb)
{
	struct ipv6hdr *hdr_ip = ipv6_hdr(skb);
	struct flowi6 flow;
	struct dst_entry *dst;
	struct hdr_iterator iterator;
	hdr_iterator_result iterator_result;

	hdr_iterator_init(&iterator, hdr_ip);
	iterator_result = hdr_iterator_last(&iterator);

	memset(&flow, 0, sizeof(flow));
	/* flow->flowi6_oif; */
	/* flow->flowi6_iif; */
	flow.flowi6_mark = skb->mark;
	flow.flowi6_tos = get_traffic_class(hdr_ip);
	flow.flowi6_scope = RT_SCOPE_UNIVERSE;
	flow.flowi6_proto = (iterator_result == HDR_ITERATOR_END) ? iterator.hdr_type : 0;
	flow.flowi6_flags = 0;
	/* flow->flowi6_secid; */
	flow.saddr = hdr_ip->saddr;
	flow.daddr = hdr_ip->daddr;
	flow.flowlabel = get_flow_label(hdr_ip);
	{
		struct udphdr *hdr_udp;
		struct tcphdr *hdr_tcp;
		struct icmp6hdr *hdr_icmp6;

		switch (skb_l4_proto(skb)) {
		case L4PROTO_TCP:
			hdr_tcp = tcp_hdr(skb);
			flow.fl6_sport = hdr_tcp->source;
			flow.fl6_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = udp_hdr(skb);
			flow.fl6_sport = hdr_udp->source;
			flow.fl6_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp6 = icmp6_hdr(skb);
			flow.fl6_icmp_type = hdr_icmp6->icmp6_type;
			flow.fl6_icmp_code = hdr_icmp6->icmp6_code;
			break;
		}
	}

	dst = ip6_route_output(&init_net, NULL, &flow);
	if (!dst) {
		log_debug("ip6_route_output() returned NULL. Cannot route packet.");
		return -EINVAL;
	}
	if (dst->error) {
		int error = abs(dst->error);
		log_debug("ip6_route_output() returned error %d. Cannot route packet.", error);
		return -error;
	}

	skb_dst_set(skb, dst);
	/* TODO (fine) ip6_finish_output2() already does this, so we have probably never needed it. */
	skb->dev = dst->dev;

	return 0;
}

verdict send_pkt(struct sk_buff *skb)
{
	struct sk_buff *next_skb = skb;
	int error = 0;

	while (next_skb) {
		skb = next_skb;
		next_skb = skb->next;
		skb->next = skb->prev = NULL;

		if (!skb->dev) {
			WARN(true, "I'm trying to send a packet that isn't routed.");
			kfree_skb(skb);
			continue;
		}
		log_debug("Sending skb via device '%s'...", skb->dev->name);

		switch (skb_l3_proto(skb)) {
		case L3PROTO_IPV6:
			skb_clear_cb(skb);
			error = ip6_local_out(skb);
			break;
		case L3PROTO_IPV4:
			skb_clear_cb(skb);
			error = ip_local_out(skb);
			break;
		}

		if (error) {
			log_debug("The kernel's packet dispatch function returned errcode %d. "
					"Could not send packet.", error);
			/*
			 * The rest will also probably fail, so don't waste time trying to send them.
			 * If there were more skbs, they were fragments anyway, so the receiving node will
			 * fail to reassemble them.
			 */
			kfree_skb_queued(next_skb);
			return VER_DROP;
		}
	}

	return VER_CONTINUE;
}
