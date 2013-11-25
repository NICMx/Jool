#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"
#include "nat64/mod/ipv6_hdr_iterator.h"
#include "nat64/mod/translate_packet.h"

#include <linux/ip.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#	include <linux/netfilter_bridge.h>
#endif
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <linux/kallsyms.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/icmp.h>


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
		log_err(ERR_ROUTE_FAILED, "ip_route_output_key() failed. Code: %d. Cannot route packet.",
				error);
		return NULL;
	}
	if (!table) {
		log_err(ERR_ROUTE_FAILED, "The routing table is NULL. Cannot route packet.");
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
		log_err(ERR_ROUTE_FAILED, "ip6_route_output() returned NULL. Cannot route packet.");
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
		log_err(ERR_ROUTE_FAILED, "ip_route_output_key() returned NULL. Cannot route packet.");
		return NULL;
	}
	if (IS_ERR(table)) {
		log_err(ERR_ROUTE_FAILED, "ip_route_output_key() returned %p. Cannot route packet.", table);
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
		log_err(ERR_ROUTE_FAILED, "ip6_route_output() returned NULL. Cannot route packet.");
		return NULL;
	}

	return dst;
}

#endif

static unsigned int min_uint(unsigned int val1, unsigned int val2)
{
	return (val1 < val2) ? val1 : val2;
}

static void ipv4_mtu_hack(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct icmp6hdr *hdr6 = icmp6_hdr(skb_in);
	struct icmphdr *hdr4 = icmp_hdr(skb_out);

	unsigned int ipv6_mtu = skb_in->dev->mtu;
	unsigned int ipv4_mtu = skb_out->dev->mtu;

	if (!skb_in)
		return;

	if (ip_hdr(skb_out)->protocol != IPPROTO_ICMP)
		return;

	if (hdr4->type != ICMP_DEST_UNREACH || hdr4->code != ICMP_FRAG_NEEDED)
		return;

	hdr4->un.frag.mtu = icmp4_minimum_mtu(be32_to_cpu(hdr6->icmp6_mtu) - 20,
			ipv4_mtu,
			ipv6_mtu - 20);
}

static bool ipv4_validate_packet_len(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct iphdr *ip4_hdr = ip_hdr(skb_out);

	if (skb_out->len <= skb_out->dev->mtu)
		return true;

	if (ip4_hdr->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp4_hdr = icmp_hdr(skb_out);
		if (is_icmp4_error(icmp4_hdr->type)) {
			int new_packet_len = skb_out->dev->mtu;

			skb_trim(skb_out, new_packet_len);

			ip4_hdr->tot_len = cpu_to_be16(new_packet_len);
			ip4_hdr->check = 0;
			ip4_hdr->check = ip_fast_csum(ip4_hdr, ip4_hdr->ihl);

			icmp4_hdr->checksum = 0;
			icmp4_hdr->checksum = ip_compute_csum(icmp4_hdr, new_packet_len - 4 * ip4_hdr->ihl);

			return true;
		}
	}

	if (is_dont_fragment_set(ip4_hdr)) {
		unsigned int ipv6_mtu = skb_in->dev->mtu;
		unsigned int ipv4_mtu = skb_out->dev->mtu;

		log_debug("Packet is too large for the outgoing MTU and the DF flag is set. Dropping...");
		icmpv6_send(skb_in, ICMPV6_PKT_TOOBIG, 0, cpu_to_be32(min_uint(ipv4_mtu + 20, ipv6_mtu)));
		return false;
	}

	/* The kernel will fragment it. */
	return true;
}

bool send_packet_ipv4(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct rtable *routing_table;
	int error;

	skb_out->protocol = htons(ETH_P_IP);

	routing_table = route_packet_ipv4(skb_out);
	if (!routing_table) {
		kfree_skb(skb_out);
		return false;
	}

	skb_out->dev = routing_table->dst.dev;
	skb_dst_set(skb_out, (struct dst_entry *) routing_table);

	if (skb_in) {
		ipv4_mtu_hack(skb_in, skb_out);
		if (!ipv4_validate_packet_len(skb_in, skb_out)) {
			kfree_skb(skb_out);
			return false;
		}
	}

	log_debug("Sending packet via device '%s'...", skb_out->dev->name);
	error = ip_local_out(skb_out); /* Send. */
	if (error) {
		log_err(ERR_SEND_FAILED, "ip_local_out() failed. Code: %d. Cannot send packet.", error);
		return false;
	}

	return true;
}

static void ipv6_mtu_hack(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct icmphdr *hdr4 = icmp_hdr(skb_in);
	struct icmp6hdr *hdr6 = icmp6_hdr(skb_out);
	unsigned int ipv6_mtu = skb_out->dev->mtu;
	unsigned int ipv4_mtu = skb_in->dev->mtu;

	if (!skb_in)
		return;

	if (ip_hdr(skb_in)->protocol != IPPROTO_ICMP)
		return;

	if (hdr6->icmp6_type != ICMPV6_PKT_TOOBIG || hdr6->icmp6_type != 0)
		return;

	hdr6->icmp6_mtu = icmp6_minimum_mtu(be16_to_cpu(hdr4->un.frag.mtu) + 20,
			ipv6_mtu,
			ipv4_mtu + 20,
			be16_to_cpu(ip_hdr(skb_in)->tot_len));
}

static bool ipv6_validate_packet_len(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb_out);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);
	unsigned int ipv6_mtu;
	unsigned int ipv4_mtu;

	if (skb_out->len <= skb_out->dev->mtu)
		return true;

	hdr_iterator_last(&iterator);
	if (iterator.hdr_type == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmpv6_hdr = icmp6_hdr(skb_out);
		if (is_icmp6_error(icmpv6_hdr->icmp6_type)) {
			int new_packet_len = skb_out->dev->mtu;
			int l3_payload_len = new_packet_len - (iterator.data - (void *) ip6_hdr);

			skb_trim(skb_out, new_packet_len);

			ip6_hdr->payload_len = cpu_to_be16(new_packet_len - sizeof(struct ipv6hdr));

			icmpv6_hdr->icmp6_cksum = 0;
			icmpv6_hdr->icmp6_cksum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr,
					l3_payload_len, IPPROTO_ICMPV6, csum_partial(icmpv6_hdr, l3_payload_len, 0));

			return true;
		}
	}

	ipv6_mtu = skb_out->dev->mtu;
	ipv4_mtu = skb_in->dev->mtu;

	log_debug("Packet is too large for the outgoing MTU and IPv6 routers don't do fragmentation. "
			"Dropping...");
	icmp_send(skb_in, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			cpu_to_be32(min_uint(ipv6_mtu - 20, ipv4_mtu)));
	return false;
}

bool send_packet_ipv6(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct dst_entry *dst;
	int error;

	skb_out->protocol = htons(ETH_P_IPV6);

	dst = route_packet_ipv6(skb_out);
	if (!dst) {
		kfree_skb(skb_out);
		return false;
	}

	skb_out->dev = dst->dev;
	skb_dst_set(skb_out, dst);

	if (skb_in) {
		ipv6_mtu_hack(skb_in, skb_out);
		if (!ipv6_validate_packet_len(skb_in, skb_out)) {
			kfree_skb(skb_out);
			return false;
		}
	}

	log_debug("Sending packet via device '%s'...", skb_out->dev->name);
	error = ip6_local_out(skb_out); /* Send. */
	if (error) {
		log_err(ERR_SEND_FAILED, "ip6_local_out() failed. Code: %d. Cannot send packet.", error);
		return false;
	}

	return true;
}
