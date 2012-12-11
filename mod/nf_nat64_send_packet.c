#include <linux/ip.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#	include <linux/netfilter_bridge.h>
#endif
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <linux/kallsyms.h>

//#include "compat_xtables.h"

#include "nf_nat64_types.h"
#include "nf_nat64_send_packet.h"


// /home/aleiva/Desktop/Nat64/xtables-addons-1.47.1/extensions/xt_ECHO.c

// TODO (send) estamos linearizando el paquete de entrada?
// TODO (monday) hay que probar la nueva cara de esto.

//static bool tuple_to_flowi6(struct nf_conntrack_tuple *tuple, struct flowi6 *fl)
//{
//	memset(&fl->__fl_common, 0, sizeof(struct flowi_common));
//	fl->flowi6_proto = tuple->l4_protocol;
//
//	memcpy(&fl->saddr, &tuple->ipv6_src_addr, sizeof(fl->saddr));
//	memcpy(&fl->daddr, &tuple->ipv6_dst_addr, sizeof(fl->daddr));
//
//	fl->flowlabel = 0; // TODO (send) ?
//
//	switch (tuple->l4_protocol) {
//	case IPPROTO_TCP: // TODO (send) revisa que estas constantes sean las buenas.
//	case IPPROTO_UDP:
//		fl->fl6_sport = tuple->src_port;
//		fl->fl6_dport = tuple->dst_port;
//		break;
//	case IPPROTO_ICMPV6:
//		fl->fl6_icmp_type = tuple->dst.u.icmp.type;
//		fl->fl6_icmp_code = tuple->dst.u.icmp.code;
//		break;
//	default:
//		log_warning("tuple_to_flowi6: Unknown l4 protocol: %d.", tuple->l4_protocol);
//		return false;
//	}
//
//	return true;
//}
//
//bool send_packet_ipv4(struct sk_buff *skb, struct nf_conntrack_tuple *tuple, struct xt_action_param *par)
//{
//	struct flowi fl;
//	struct dst_entry *dst = NULL;
//	struct net *net = dev_net((par->in != NULL) ? par->in : par->out);
//
//	spin_lock_bh(&send_packet_lock);
//
//	skb->ip_summed = CHECKSUM_COMPLETE;
//	skb->protocol = htons(ETH_P_IP);
//
//	rt = ip_route_output_key(&init_net, &fl.u.ip4);
//
//	skb_dst_set(skb, dst);
//
//	// newip->ttl = ip4_dst_hoplimit(skb_dst(newskb));
//
//	// nf_ct_attach(newskb, *poldskb);
//	ip_local_out(skb);
//
//	spin_unlock_bh(&send_packet_lock);
//	return true;
//}
//
//bool send_packet_ipv6(struct sk_buff *skb, struct nf_conntrack_tuple *tuple, struct xt_action_param *par)
//{
//	struct flowi6 fl;
//	struct dst_entry *dst = NULL;
//	struct net *net = dev_net((par->in != NULL) ? par->in : par->out);
//
//	spin_lock_bh(&send_packet_lock);
//
//	skb->protocol = htons(ETH_P_IPV6);
//
//	if (!tuple_to_flowi6(tuple, &fl))
//		return false;
//	// security_skb_classify_flow((struct sk_buff *) poldskb, flowi6_to_flowi(&fl));
//	dst = ip6_route_output(net, NULL, &fl);
//	if (!dst) {
//		log_err("The kernel returned a null route for the packet.");
//		return false;
//	}
//	if (dst->error != 0) {
//		log_err("The kernel could not route the outgoing packet. Result code: %d.", dst->error);
//		dst_release(dst);
//		return false;
//	}
//
//	skb_dst_set(skb, dst);
//	// ip6_header->hop_limit = ip6_dst_hoplimit(skb_dst(skb));
//	skb->ip_summed = CHECKSUM_COMPLETE;
//
//	// nf_ct_attach(newskb, *poldskb);
//	ip6_local_out(skb);
//
//	spin_unlock_bh(&send_packet_lock);
//	return true;
//}


static DEFINE_SPINLOCK(send_packet_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

static struct rtable *route_packet_ipv4(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct flowi fl;
	struct rtable *table;
	int error;

	memset(&fl, 0, sizeof(fl));
	fl.fl4_dst = iph->daddr;
	fl.fl4_tos = RT_TOS(iph->tos);
	fl.proto = skb->protocol;

	error = ip_route_output_key(&init_net, &table, &fl);
	if (error) {
		log_warning("  Packet could not be routed; ip_route_output_key() failed. Code: %d.", error);
		return NULL;
	}
	if (!table) {
		log_warning("  Packet could not be routed - the routing table is NULL.");
		return NULL;
	}

	return table;
}

static struct dst_entry *route_packet_ipv6(struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct flowi fl;
	struct dst_entry *dst;

	memset(&fl, 0, sizeof(fl));
	fl.fl6_src = iph->saddr;
	fl.fl6_dst = iph->daddr;
	fl.fl6_flowlabel = 0;
	fl.proto = skb->protocol;

	dst = ip6_route_output(&init_net, NULL, &fl);
	if (!dst) {
		log_warning("  Packet could not be routed - ip6_route_output() returned NULL.");
		return NULL;
	}

	return dst;
}

#else

static struct rtable *route_packet_ipv4(struct sk_buff *skb)
{
	struct iphdr *ip_header = ip_hdr(skb);
	struct flowi fl;
	struct rtable *table;

	memset(&fl, 0, sizeof(fl));
	fl.u.ip4.daddr = ip_header->daddr;
	fl.flowi_tos = RT_TOS(ip_header->tos);
	fl.flowi_proto = skb->protocol;

	table = ip_route_output_key(&init_net, &fl.u.ip4);
	if (!table) {
		log_warning("  Packet could not be routed - ip_route_output_key() returned NULL.");
		return NULL;
	}
	if (IS_ERR(table)) {
		log_warning("  Packet could not be routed - ip_route_output_key() returned %p.", table);
		return NULL;
	}

	return table;
}

static struct dst_entry *route_packet_ipv6(struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct flowi fl;
	struct dst_entry *dst;

	memset(&fl, 0, sizeof(fl));
	fl.u.ip6.saddr = iph->saddr;
	fl.u.ip6.daddr = iph->daddr;
	fl.u.ip6.flowlabel = 0;
	fl.flowi_proto= skb->protocol;

	dst = ip6_route_output(&init_net, NULL, &fl.u.ip6);
	if (!dst) {
		log_warning("  Packet could not be routed - ip6_route_output() returned NULL.");
		return NULL;
	}

	return dst;
}

#endif

bool nat64_send_packet_ipv4(struct sk_buff *skb)
{
	struct rtable *routing_table;
	int error;

	spin_lock_bh(&send_packet_lock);

	skb->protocol = htons(ETH_P_IP);

	routing_table = route_packet_ipv4(skb);
	if (!routing_table)
		goto failure;

	skb->dev = routing_table->dst.dev;
	skb_dst_set(skb, (struct dst_entry *) routing_table);

	log_debug("  Sending packet via device '%s'...", skb->dev->name);
	error = ip_local_out(skb);
	if (error) {
		log_warning("  Packet could not be sent - ip_local_out() failed. Code: %d.", error);
		goto failure;
	}

	spin_unlock_bh(&send_packet_lock);
	return true;

failure:
	spin_unlock_bh(&send_packet_lock);
	return false;
}

bool nat64_send_packet_ipv6(struct sk_buff *skb)
{
	struct dst_entry *dst;
	int error;

	spin_lock_bh(&send_packet_lock);

	skb->protocol = htons(ETH_P_IPV6);

	dst = route_packet_ipv6(skb);
	if (!dst)
		goto failure;

	skb->dev = dst->dev;
	skb_dst_set(skb, dst);

	log_debug("  Sending packet via device '%s'...", skb->dev->name);
	// TODO (luis) este #if realmente sirve de algo?
	// TODO (luis) netif_start_queue realmente sirve de algo?
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	netif_start_queue(skb->dev); // Makes sure the net_device can actually send packets.
#endif
	error = ip6_local_out(skb); // Send.
	if (error) {
		log_warning("  Packet could not be sent - ip6_local_out() failed. Code: %d.", error);
		goto failure;
	}

	spin_unlock_bh(&send_packet_lock);
	return true;

failure:
	spin_unlock_bh(&send_packet_lock);
	return false;
}
