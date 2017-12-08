#include "nat64/mod/common/route.h"

#include <linux/version.h>
#include <net/flow.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include "nat64/mod/common/ipv6_hdr_iterator.h"

/**
 * Callers of this function need to mind hairpinning. What happens if @daddr
 * belongs to the translator?
 *
 * The @pkt can be NULL. If this happens, make sure the resulting dst is
 * dst_release()d.
 */
struct dst_entry *__route4(struct route4_args *args, struct sk_buff *skb)
{
	struct flowi4 flow;
	struct rtable *table;
	struct dst_entry *dst;

	/*
	 * Sometimes Jool needs to route prematurely,
	 * so don't sweat this on the normal pipelines.
	 */
	if (skb) {
		dst = skb_dst(skb);
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
	flow.flowi4_mark = args->mark;
	flow.flowi4_tos = args->tos;
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = args->proto;
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
	flow.daddr = args->daddr.s_addr;

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
	table = __ip_route_output_key(args->ns, &flow);
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

	if (skb) {
		skb_dst_set(skb, dst);
		/* TODO (final) maybe used due to route_input + hairpinning? */
		/* pkt->skb->dev = dst->dev; */
	}

	return dst;
}

struct dst_entry *route4(struct net *ns, struct packet *out)
{
	struct iphdr *hdr = pkt_ip4_hdr(out);
	struct route4_args args = {
			.ns = ns,
			.daddr.s_addr = hdr->daddr,
			.tos = hdr->tos,
			.proto = hdr->protocol,
			.mark = out->skb->mark,
	};
	return __route4(&args, out->skb);
}

struct dst_entry *__route6(struct net *ns, struct sk_buff *skb,
		l4_protocol proto)
{
	struct ipv6hdr *hdr_ip = ipv6_hdr(skb);
	struct flowi6 flow;
	struct dst_entry *dst;
	struct hdr_iterator iterator;

	dst = skb_dst(skb);
	if (dst)
		return dst;

	hdr_iterator_init(&iterator, hdr_ip);
	hdr_iterator_last(&iterator);

	memset(&flow, 0, sizeof(flow));
	/* flow->flowi6_oif; */
	/* flow->flowi6_iif; */
	flow.flowi6_mark = skb->mark;
	/*
	 * BTW: They removed this because nobody was using it.
	 * https://github.com/torvalds/linux/commit/69716a2b51aeb68fe295c0d09e26c8781eacebde
	 * Perhaps we don't gain anything from it either.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
	flow.flowi6_tos = get_traffic_class(hdr_ip);
#endif
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

		switch (proto) {
		case L4PROTO_TCP:
			hdr.tcp = tcp_hdr(skb);
			flow.fl6_sport = hdr.tcp->source;
			flow.fl6_dport = hdr.tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr.udp = udp_hdr(skb);
			flow.fl6_sport = hdr.udp->source;
			flow.fl6_dport = hdr.udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr.icmp6 = icmp6_hdr(skb);
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
	skb_dst_set(skb, dst);
	return dst;
}

struct dst_entry *route6(struct net *ns, struct packet *out)
{
	return __route6(ns, out->skb, pkt_l4_proto(out));
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
