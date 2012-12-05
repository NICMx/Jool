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
// TODO (send) este wey define skb->protocol...
// TODO (send) nota que si es exitoso no hay que liberar el skb.

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
//		pr_warning("tuple_to_flowi6: Unknown l4 protocol: %d.\n", tuple->l4_protocol);
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
//	if (skb->len > dst_mtu(skb_dst(skb))) { // "Never happens" (?)
//		// TODO so I guess I should remove this if, since the packet should be fragmented.
//		pr_warning("Packet length (%d) is higher than the MTU (%u).\n", skb->len,
//				dst_mtu(skb_dst(skb)));
//		return false;
//	}
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
//	if (!tuple_to_flowi6(tuple, &fl))
//		return false;
//	// security_skb_classify_flow((struct sk_buff *) poldskb, flowi6_to_flowi(&fl));
//	dst = ip6_route_output(net, NULL, &fl);
//	if (!dst) {
//		pr_err("The kernel returned a null route for the packet.\n");
//		return false;
//	}
//	if (dst->error != 0) {
//		pr_err("The kernel could not route the outgoing packet. Result code: %d.\n", dst->error);
//		dst_release(dst);
//		return false;
//	}
//
//	skb_dst_set(skb, dst);
//	// ip6_header->hop_limit = ip6_dst_hoplimit(skb_dst(skb));
//	skb->ip_summed = CHECKSUM_COMPLETE;
//	skb->protocol = htons(ETH_P_IPV6);
//
//	if (skb->len > dst_mtu(skb_dst(skb))) { // "Never happens" (?)
//		// TODO so I guess I should remove this if, since the packet should be fragmented.
//		pr_warning("Packet length (%d) is higher than the MTU (%u).\n", skb->len,
//				dst_mtu(skb_dst(skb)));
//		return false;
//	}
//
//	// nf_ct_attach(newskb, *poldskb);
//	ip6_local_out(skb);
//
//	spin_unlock_bh(&send_packet_lock);
//	return true;
//}


DEFINE_SPINLOCK(send_packet_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

// Begin Ecdysis (nat64_output_ipv4)
// TODO refactoriza esos mensajes de error.
bool nat64_send_packet_ipv4(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct flowi fl;
	struct rtable *rt;

	spin_lock_bh(&send_packet_lock);

	skb->protocol = htons(ETH_P_IP);
	memset(&fl, 0, sizeof(fl));
	fl.fl4_dst = iph->daddr;
	fl.fl4_tos = RT_TOS(iph->tos);
	fl.proto = skb->protocol;
	if (ip_route_output_key(&init_net, &rt, &fl)) {
		pr_warning("  nf_NAT64: ip_route_output_key failed\n");
		goto failure;
	}
	if (!rt) {
		pr_warning("  nf_NAT64: rt null\n");
		goto failure;
	}
	skb->dev = rt->dst.dev;
	skb_dst_set(skb, (struct dst_entry *)rt);

	if (ip_local_out(skb)) {
		pr_warning("  nf_NAT64: ip_local_out failed\n");
		goto failure;
	}

	spin_unlock_bh(&send_packet_lock);
	return true;
	// End Ecdysis (nat64_output_ipv4)

failure:
	spin_unlock_bh(&send_packet_lock);
	return false;
}

// Function based on Ecdysis's nat64_output_ipv4
int nat64_send_packet_ipv6(struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct flowi fl;
	struct dst_entry *dst;

	spin_lock_bh(&send_packet_lock);

	skb->protocol = htons(ETH_P_IPV6);

	memset(&fl, 0, sizeof(fl));

	if (!&(fl.fl6_src)) {
		goto failure;
	}
	fl.fl6_src = iph->saddr;
	fl.fl6_dst = iph->daddr;
	fl.fl6_flowlabel = 0;
	fl.proto = skb->protocol;

	dst = ip6_route_output(&init_net, NULL, &fl);
	if (!dst) {
		pr_warning("  error: ip6_route_output failed\n");
		goto failure;
	}

	skb->dev = dst->dev;

	skb_dst_set(skb, dst);

	if (ip6_local_out(skb)) {
		pr_warning("  nf_NAT64: ip6_local_out failed.\n");
		goto failure;
	}

	spin_unlock_bh(&send_packet_lock);
	return true;

failure:
	spin_unlock_bh(&send_packet_lock);
	return false;
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)

bool nat64_send_packet_ipv4(struct sk_buff *skb)
{
	print_packet(skb);
	return true;

//	struct iphdr *iph = ip_hdr(skb);
//	struct flowi fl;
//	struct rtable *rt;
//	int out_result;
//
//	spin_lock_bh(&send_packet_lock);
//
//	skb->protocol = htons(ETH_P_IP);
//
//	memset(&fl, 0, sizeof(fl));
//
//	fl.u.ip4.daddr = iph->daddr;
//	fl.flowi_tos = RT_TOS(iph->tos);
//	fl.flowi_proto = skb->protocol;
//
//	rt = ip_route_output_key(&init_net, &fl.u.ip4);
//	if (!rt) {
//		pr_warning("  Packet could not be routed - ip_route_output_key() returned NULL.\n");
//		goto failure;
//	}
//	if (IS_ERR(rt)) {
//		pr_warning("  Packet could not be routed - ip_route_output_key() returned %p.\n", rt);
//		goto failure;
//	}
//
//	skb->dev = rt->dst.dev;
//	skb_dst_set(skb, (struct dst_entry *) rt);
//
//	out_result = ip_local_out(skb);
//	if (out_result) {
//		pr_warning("  Packet could not be sent - ip_local_out() failed. Code: %d.\n", out_result);
//		goto failure;
//	}
//
//	spin_unlock_bh(&send_packet_lock);
//	return true;
//
//failure:
//	spin_unlock_bh(&send_packet_lock);
//	return false;
}

// Function based on Ecdysis's nat64_output_ipv4
bool nat64_send_packet_ipv6(struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct flowi fl;
	struct dst_entry *dst;
	int out_result;

	spin_lock_bh(&send_packet_lock);

	skb->protocol = htons(ETH_P_IPV6);

	memset(&fl, 0, sizeof(fl));

	fl.u.ip6.saddr = iph->saddr;
	fl.u.ip6.daddr = iph->daddr;
	fl.u.ip6.flowlabel = 0;
	fl.flowi_proto= skb->protocol;

	dst = ip6_route_output(&init_net, NULL, &fl.u.ip6);
	if (!dst) {
		pr_warning("  Packet could not be routed - ip6_route_output() returned NULL.\n");
		goto failure;
	}

	skb->dev = dst->dev;
	skb_dst_set(skb, dst);

	pr_debug("  Sending packet via device '%s'...\n", skb->dev->name);

	netif_start_queue(skb->dev); // Makes sure the net_device can actually send packets.

	pr_debug("  Apuntador: %p\n", dst->output);
	print_symbol("  Funcion es %s.\n", (long) dst->output);

//	out_result = ip6_local_out(skb); // Send.
//	if (out_result) {
//		pr_warning("  Packet could not be sent - ip6_local_out() failed. Code: %d.\n", out_result);
//		goto failure;
//	}

	print_packet(skb);

	spin_unlock_bh(&send_packet_lock);
	return true;

failure:
	spin_unlock_bh(&send_packet_lock);
	return false;
}

#endif
