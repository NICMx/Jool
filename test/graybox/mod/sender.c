#include "sender.h"

#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/route.h>

#include "common/types.h"
#include "mod/common/ipv6_hdr_iterator.h"
#include "mod/common/steps/send_packet.h"
#include "log.h"
#include "util.h"

/*
 * Returns the length of the layer 3 headers.
 * This includes IPv4 header, IPv4 options, IPv6 header and IPv6 extension
 * headers.
 */
static int net_hdr_size(void *pkt)
{
	struct hdr_iterator iterator;
	struct iphdr *hdr4;

	switch (get_l3_proto(pkt)) {
	case 6:
		hdr_iterator_init(&iterator, pkt);
		hdr_iterator_last(&iterator);
		return iterator.data - pkt;
	case 4:
		hdr4 = pkt;
		return hdr4->ihl << 2;
	}

	log_err("Invalid protocol: %u", get_l3_proto(pkt));
	return -EINVAL;
}

static struct net *find_current_namespace(void)
{
	struct net *ns;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace. Errcode is %ld.", PTR_ERR(ns));
		return NULL;
	}

	return ns;
}

static struct dst_entry *route(struct net *ns, struct flowi *flow, int family)
{
	struct dst_entry *dst;
	int error;

	dst = NULL;
	error = nf_route(ns, &dst, flow, false, family);
	if (error) {
		log_err("nf_route() returned %d. Cannot route packet.", error);
		return NULL;
	}

	log_debug("Packet routed via device '%s'.", dst->dev->name);
	return dst;
}

static struct dst_entry *route_ipv4(struct net *ns, struct sk_buff *skb)
{
	struct iphdr *hdr;
	struct flowi flow;
	struct dst_entry *dst;

	hdr = ip_hdr(skb);

	memset(&flow, 0, sizeof(flow));
	flow.u.ip4.flowi4_mark = skb->mark;
	flow.u.ip4.flowi4_tos = hdr->tos;
	flow.u.ip4.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.u.ip4.flowi4_proto = hdr->protocol;
	flow.u.ip4.flowi4_flags = FLOWI_FLAG_ANYSRC;
	flow.u.ip4.saddr = 0;
	flow.u.ip4.daddr = hdr->daddr;

	dst = route(ns, &flow, AF_INET);
	if (!dst)
		return NULL;

	skb_dst_set(skb, dst);
	return dst;
}

static l4_protocol nexthdr_to_l4proto(__u8 nexthdr)
{
	switch (nexthdr) {
	case NEXTHDR_TCP:
		return L4PROTO_TCP;
	case NEXTHDR_UDP:
		return L4PROTO_UDP;
	case NEXTHDR_ICMP:
		return L4PROTO_ICMP;
	}
	return L4PROTO_OTHER;
}

static struct dst_entry *route_ipv6(struct net *ns, struct sk_buff *skb)
{
	struct ipv6hdr *hdr;
	struct hdr_iterator iterator;
	struct flowi flow;
	struct dst_entry *dst;

	hdr = ipv6_hdr(skb);

	hdr_iterator_init(&iterator, hdr);
	hdr_iterator_last(&iterator);

	flow.u.ip6.flowi6_mark = skb->mark;
	flow.u.ip6.flowi6_scope = RT_SCOPE_UNIVERSE;
	flow.u.ip6.flowi6_proto = nexthdr_to_l4proto(iterator.hdr_type);
	flow.u.ip6.flowi6_flags = FLOWI_FLAG_ANYSRC;
	flow.u.ip6.saddr = hdr->saddr;
	flow.u.ip6.daddr = hdr->daddr;

	dst = route(ns, &flow, AF_INET6);
	if (!dst)
		return NULL;

	skb_dst_set(skb, dst);
	return dst;
}

int sender_send(char *pkt_name, void *pkt, size_t pkt_len)
{
	struct net *ns;
	struct sk_buff *skb;
	struct dst_entry *dst;
	int error;

	log_info("Sending packet %s (length %zu)...", pkt_name, pkt_len);

	if (pkt_len == 0) {
		log_err("The packet is zero bytes long.");
		return -EINVAL;
	}

	skb = alloc_skb(LL_MAX_HEADER + pkt_len, GFP_KERNEL);
	if (!skb) {
		log_err("Could not allocate a skb.");
		return -ENOMEM;
	}

	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, pkt_len);

	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, 0);
	skb_set_transport_header(skb, net_hdr_size(pkt));

	memcpy(skb_network_header(skb), pkt, pkt_len);

	ns = find_current_namespace();
	if (!ns) {
		kfree_skb(skb);
		return -EINVAL;
	}

	skb->ip_summed = CHECKSUM_NONE;
	switch (get_l3_proto(pkt)) {
	case 6:
		skb->protocol = htons(ETH_P_IPV6);
		dst = route_ipv6(ns, skb);
		break;
	case 4:
		skb->protocol = htons(ETH_P_IP);
		dst = route_ipv4(ns, skb);
		break;
	default:
		log_err("Invalid mode: %u.", get_l3_proto(pkt));
		dst = NULL;
		break;
	}

	if (dst) {
		error = dst_output(ns, NULL, skb);
		if (error)
			log_err("dst_output() returned %d.", error);
	} else {
		log_err("The packet could not be routed.");
		error = -ENETUNREACH;
		kfree_skb(skb);
	}

	put_net(ns);
	return error;
}
