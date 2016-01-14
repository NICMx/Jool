#include "nat64/mod/common/route.h"

#include <linux/icmp.h>
#include <net/ip6_route.h>
#include <net/route.h>

#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/types.h"

/**
 * Callers of this function need to mind hairpinning. What happens if @daddr
 * belongs to the translator?
 *
 * The @pkt can be NULL. If this happens, make sure the resulting dst is
 * dst_release()d.
 */
struct dst_entry *__route4(struct net *ns, __be32 daddr, __u8 tos, __u8 proto,
		__u32 mark, struct packet *pkt)
{
	struct flowi4 flow;
	struct rtable *table;
	struct dst_entry *dst;

	/*
	 * Sometimes Jool needs to route prematurely,
	 * so don't sweat this on the normal pipelines.
	 */
	if (pkt) {
		dst = skb_dst(pkt->skb);
		if (dst)
			return dst;
	}

	/**
	 * The flowi's XFRM fields don't matter because "any protocols that
	 * protect IP header information are essentially incompatible with
	 * NAT64" (RFC 6146).
	 */

	memset(&flow, 0, sizeof(flow));
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	flow.flowi4_mark = mark;
	flow.flowi4_tos = tos;
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = proto;
	/*
	 * TODO (help) Don't know if we should set FLOWI_FLAG_PRECOW_METRICS.
	 * Does the kernel ever create routes on Jool's behalf?
	 * TODO (help) We should probably set FLOWI_FLAG_ANYSRC (for
	 * virtual-interfaceless support). If you change it, the corresponding
	 * attribute in route6() should probably follow.
	 */
	flow.flowi4_flags = 0;
	/* Only used by XFRM ATM (kernel/Documentation/networking/secid.txt). */
	/* flow.flowi4_secid; */
	/* It appears this one only introduces harmful noise. */
	/* flow.saddr = saddr; */
	flow.daddr = daddr;

	/*
	 * I'm no longer setting fl4_sport, fl4_dport, fl4_icmp_type nor
	 * fl4_icmp_code because 1) not all callers of this function have set
	 * the respective fields yet, and 2) I can't find any users of them
	 * aside from XFRM code.
	 */

	/*
	 * I'm using neither ip_route_output_key() nor ip_route_output_flow()
	 * because they only add XFRM overhead.
	 */
	table = __ip_route_output_key(ns, &flow);
	if (!table || IS_ERR(table)) {
		log_debug("__ip_route_output_key() returned %ld. Cannot route packet.",
				PTR_ERR(table));
		return NULL;
	}
	dst = &table->dst;
	if (dst->error) {
		log_debug("__ip_route_output_key() returned error %d. Cannot route packet.",
				dst->error);
		dst_release(dst);
		return NULL;
	}
	if (!dst->dev) {
		log_debug("I found a dst entry with no dev; I don't know what to do.");
		dst_release(dst);
		return NULL;
	}

	log_debug("Packet routed via device '%s'.", dst->dev->name);

	if (pkt) {
		skb_dst_set(pkt->skb, dst);
		/* TODO maybe used due to route_input + hairpinning? */
		/* pkt->skb->dev = dst->dev; */
	}

	return dst;
}

struct dst_entry *route4(struct net *ns, struct packet *out)
{
	struct iphdr *hdr = pkt_ip4_hdr(out);
	return __route4(ns, hdr->daddr, hdr->tos, hdr->protocol, out->skb->mark,
			out);
}

/**
 * Unlike route4(), this function doesn't currently have any weird callers.
 * Therefore, @pkt is the outgoing IPv6 packet.
 */
struct dst_entry *route6(struct net *ns, struct packet *pkt)
{
	struct ipv6hdr *hdr_ip = pkt_ip6_hdr(pkt);
	struct flowi6 flow;
	struct dst_entry *dst;
	struct hdr_iterator iterator;

	dst = skb_dst(pkt->skb);
	if (dst)
		return dst;

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

	dst = ip6_route_output(ns, NULL, &flow);
	if (!dst) {
		log_debug("ip6_route_output() returned NULL. Cannot route packet.");
		return NULL;
	}
	if (dst->error) {
		log_debug("ip6_route_output() returned error %d. Cannot route packet.",
				dst->error);
		dst_release(dst);
		return NULL;
	}

	log_debug("Packet routed via device '%s'.", dst->dev->name);
	skb_dst_set(pkt->skb, dst);
	return dst;
}

struct dst_entry *route(struct net *ns, struct packet *pkt)
{
	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV6:
		return route6(ns, pkt);
	case L3PROTO_IPV4:
		return route4(ns, pkt);
	}

	WARN(true, "Unsupported network protocol: %u.", pkt_l3_proto(pkt));
	return NULL;
}

int route4_input(struct packet *pkt)
{
	struct iphdr *hdr;
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

	hdr = ip_hdr(skb);
	error = ip_route_input(skb, hdr->daddr, hdr->saddr, hdr->tos, skb->dev);
	if (error) {
		log_debug("ip_route_input failed: %d", error);
		inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
	}

	return error;
}
