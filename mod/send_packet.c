#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

#include <linux/version.h>
#include <linux/list.h>
#include <net/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
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
		log_err(ERR_ROUTE_FAILED, "ip_route_output_key() failed. Code: %d. Cannot route packet.",
				-error);
		return NULL;
	}
	if (!table) {
		log_err(ERR_ROUTE_FAILED, "The routing table is NULL. Cannot route packet.");
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
		log_err(ERR_ROUTE_FAILED, "ip6_route_output() returned NULL. Cannot route packet.");
		return NULL;
	}
	if (dst->error) {
		log_err(ERR_ROUTE_FAILED, "ip6_route_output() returned error %d. Cannot route packet.",
				-dst->error);
		return NULL;
	}

	return dst;
}

#else

int route_ipv4(struct sk_buff *skb)
{
	struct iphdr *hdr_ip = ip_hdr(skb);
	struct flowi4 flow;
	struct rtable *table;

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
		case L4PROTO_NONE:
			break;
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
		log_err(ERR_ROUTE_FAILED, "__ip_route_output_key() returned %ld. "
				"Cannot route packet.", (long) table);
		return -EINVAL;
	}
	if (table->dst.error) {
		log_err(ERR_ROUTE_FAILED, "__ip_route_output_key() returned error %d. "
				"Cannot route packet.", -table->dst.error);
	}
	if (!table->dst.dev) {
		dst_release(&table->dst);
		log_err(ERR_NULL, "I found a dst entry with no dev. I don't know what to do; failing...");
		return -EINVAL;
	}

	skb_dst_set(skb, &table->dst);
	/* TODO we have probably never needed this, since ip6_finish_output2() does it already. */
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
		case L4PROTO_NONE:
			break;
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
		log_err(ERR_ROUTE_FAILED, "ip6_route_output() returned NULL. Cannot route packet.");
		return -EINVAL;
	}
	if (dst->error) {
		log_err(ERR_ROUTE_FAILED, "ip6_route_output() returned error %d. Cannot route packet.",
				-dst->error);
		return -EINVAL;
	}

	skb_dst_set(skb, dst);
	/* TODO we have probably never needed this, since ip6_finish_output2() does it already. */
	skb->dev = dst->dev;

	return 0;
}

#endif

verdict send_pkt(struct sk_buff *skb)
{
	struct sk_buff *next_skb = skb;
	int error = 0;

	while (next_skb) {
		skb = next_skb;
		next_skb = skb->next;
		skb->next = skb->prev = NULL;

		if (!skb->dev) {
			log_crit(ERR_UNKNOWN_ERROR, "I'm trying to send a packet that isn't routed.");
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
			log_err(ERR_SEND_FAILED, "The kernel's packet dispatch function returned errcode %d. "
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
