#include "nf_nat64_send_packet.h"

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

#include "nf_nat64_types.h"


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
		log_warning("Packet could not be routed; ip_route_output_key() failed. Code: %d.", error);
		return NULL;
	}
	if (!table) {
		log_warning("Packet could not be routed - the routing table is NULL.");
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
		log_warning("Packet could not be routed - ip6_route_output() returned NULL.");
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
		log_warning("Packet could not be routed - ip_route_output_key() returned NULL.");
		return NULL;
	}
	if (IS_ERR(table)) {
		log_warning("Packet could not be routed - ip_route_output_key() returned %p.", table);
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
		log_warning("Packet could not be routed - ip6_route_output() returned NULL.");
		return NULL;
	}

	return dst;
}

#endif

bool nat64_send_packet_ipv4(struct sk_buff *skb)
{
	struct rtable *routing_table;
	int error;

	skb->protocol = htons(ETH_P_IP);

	routing_table = route_packet_ipv4(skb);
	if (!routing_table)
		return false;

	skb->dev = routing_table->dst.dev;
	skb_dst_set(skb, (struct dst_entry *) routing_table);

	log_debug("Sending packet via device '%s'...", skb->dev->name);
	error = ip_local_out(skb); // Send.
	if (error) {
		log_warning("Packet could not be sent - ip_local_out() failed. Code: %d.", error);
		return false;
	}

	return true;
}

bool nat64_send_packet_ipv6(struct sk_buff *skb)
{
	struct dst_entry *dst;
	int error;

	skb->protocol = htons(ETH_P_IPV6);

	dst = route_packet_ipv6(skb);
	if (!dst)
		return false;

	skb->dev = dst->dev;
	skb_dst_set(skb, dst);

	log_debug("Sending packet via device '%s'...", skb->dev->name);
	error = ip6_local_out(skb); // Send.
	if (error) {
		log_warning("Packet could not be sent - ip6_local_out() failed. Code: %d.", error);
		return false;
	}

	return true;
}
