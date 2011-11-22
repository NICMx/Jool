/*
 * NAT64 - Network Address Translator IPv6 to IPv4
 *
 * Copyright (C) 2010 Viagenie Inc. http://www.viagenie.ca
 *
 * Authors:
 *    Juan Antonio Osorio <jaosorior@gmail.com>
 *    Luis Fernando Hinojosa <lf.hinojosa@gmail.com>
 *    David Valenzuela <david.valenzuela.88@gmail.com>
 *    Jose Vicente Ramirez <pepermz@gmail.com>
 *    Mario Gerardo Trevinho <mario_tc88@hotmail.com>
 *
 * Authors of the ip_data, checksum_adjust, checksum_remove, checksum_add
 * checksum_change, adjust_checksum_ipv6_to_ipv4 and 
 * adjust_checksum_ipv5_to_ipv6 functions:
 *    Jean-Philippe Dionne <jean-philippe.dionne@viagenie.ca>
 *    Simon Perreault <simon.perreault@viagenie.ca>
 *    Marc Blanchet <marc.blanchet@viagenie.ca>
 *
 * NAT64 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NAT64 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with NAT64.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>

#include <linux/netdevice.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#include <linux/timer.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_protocol.h>

#include <linux/version.h>

#include "nf_nat64_bib.h"
#include "xt_nat64.h"
#include "nf_nat64_generic_functions.h"
#include "nf_nat64_auxiliary_functions.h"
#include "nf_nat64_filtering_and_updating.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan Antonio Osorio <jaosorior@gmail.com>");
MODULE_DESCRIPTION("Xtables: RFC 6146 \"NAT64\" implementation");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

#define IPV6_HDRLEN 40
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

/*
 * FIXME: Ensure all variables are 32 and 64-bits complaint. 
 * That is, no generic data types akin to integer.
 * FIXED: All the output messages of the stages are in the opposite
 * order of execution
 * in the logs.
 */

static struct nf_conntrack_l3proto * l3proto_ip __read_mostly;
static struct nf_conntrack_l3proto * l3proto_ipv6 __read_mostly;

struct kmem_cache *st_cache;
struct kmem_cache *bib_cache;
struct hlist_head *hash6;
struct hlist_head *hash4;
unsigned int		hash_size;
struct expiry_q	expiry_base[NUM_EXPIRY_QUEUES] =
{
	{{NULL, NULL}, 5*60},
	{{NULL, NULL}, 4*60},
	{{NULL, NULL}, 2*60*60},
	{{NULL, NULL}, 6},
	{{NULL, NULL}, 60}
};
struct list_head expiry_queue = LIST_HEAD_INIT(expiry_queue);

__be32 ipv4_addr;
int ipv4_prefixlen;
__be32 ipv4_netmask;
static char *ipv4_address;
struct in6_addr	prefix_base = {.s6_addr32[0] = 0, .s6_addr32[1] = 0, .s6_addr32[2] = 0, .s6_addr32[3] = 0};
static char *prefix_address;
int prefix_len;

/*module_param(ipv4_address, charp, 0);
MODULE_PARM_DESC(ipv4_address, "NAT64: An IPv4 address or a subnet used by translator. Can be specified as a.b.c.d for single address or as a.b.c.d/p for a subnet.");
module_param(prefix_address, charp, 0);
MODULE_PARM_DESC(prefix_len, "NAT64: Prefix address (default fec0::)");
module_param(prefix_len, int, 0);
MODULE_PARM_DESC(prefix_len, "NAT64: Prefix length (default /64)");
*/

static DEFINE_SPINLOCK(nf_nat64_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static int nat64_send_packet_ipv4(struct sk_buff *skb) 
{
	// Begin Ecdysis (nat64_output_ipv4)
	struct iphdr *iph = ip_hdr(skb);
	struct flowi fl;
	struct rtable *rt;
	skb->protocol = htons(ETH_P_IP);
	memset(&fl, 0, sizeof(fl));
	fl.fl4_dst = iph->daddr;
	fl.fl4_tos = RT_TOS(iph->tos);
	fl.proto = skb->protocol;
	if (ip_route_output_key(&init_net, &rt, &fl)) {
		printk("nf_NAT64: ip_route_output_key failed\n");
		return -EINVAL;
	}
	if (!rt) {
		printk("nf_NAT64: rt null\n");
		return -EINVAL;
	}
	skb->dev = rt->dst.dev;
	skb_dst_set(skb, (struct dst_entry *)rt);
	if(ip_local_out(skb)) {
		printk("nf_NAT64: ip_local_out failed\n");
		return -EINVAL;
	}
	return 0;	
}

// End Ecdysis
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
static int nat64_send_packet_ipv4(struct sk_buff *skb) 
{
	struct iphdr *iph = ip_hdr(skb);
	struct rtable * rt;

	// Set the packet type
	skb->pkt_type = PACKET_OUTGOING;

	/*
	 * Get the routing table in order to get the outgoing device and outgoing
	 * address
	 */
	rt = ip_route_output(&init_net, iph->daddr, iph->saddr, RT_TOS(iph->tos), 0);

	if (!rt || IS_ERR(rt)) {
		pr_info("NAT64: NAT64: nat64_send_packet - rt is null or an error");
		return -1;
	}

	if (rt->dst.dev == NULL) {
		pr_info("NAT64: the route table couldn't get an appropriate device");

	} else {
		/*
		 * Insert the outgoing device in the skb.
		 */
		skb->dev = rt->dst.dev;
	}

	/*
	 * insert the L2 header in the skb... Since we use a function within
	 * the net_device, we don't need to know the type of L2 device... It
	 * could be ethernet, it could be wlan.
	 */
	rt->dst.dev->header_ops->create(skb, rt->dst.dev, skb->protocol,
			NULL, NULL, skb->len);

	/*
	 * Set the destination to the skb.
	 */
	skb_dst_set(skb, &(rt->dst));
	//pr_debug("%ld %ld %d %d %d", skb->head-skb->head, skb->data-skb->head, skb->tail, skb->end, skb->len);

	/*
	 * Makes sure the net_device can actually send packets.
	 */
	netif_start_queue(skb->dev);

	/*
	 * Sends the packet, independent of NAPI or the old API.
	 */
	return dev_queue_xmit(skb);
}

#endif

/*
 * Sends the packet.
 * Right now, the skb->data should be pointing to the L3 layer header.
 */
static int nat64_send_packet(struct sk_buff * old_skb, struct sk_buff *skb)
{
	int ret = -1;

	spin_lock_bh(&nf_nat64_lock);
	pr_debug("NAT64: Sending the new packet...");

	switch (ntohs(old_skb->protocol)) {
		case ETH_P_IPV6:
			pr_debug("NAT64: eth type ipv6 to ipv4");
			skb->protocol = ETH_P_IP;
			ret = nat64_send_packet_ipv4(skb);
			break;
		case ETH_P_IP:
			pr_debug("NAT64: eth type ipv4 to ipv6");
			skb->protocol = ETH_P_IPV6;
			break;
		default:
			kfree_skb(skb);
			pr_debug("NAT64: before unlocking spinlock..."
					" No known eth type.");
			spin_unlock_bh(&nf_nat64_lock);
			return -1;
	}

	if (ret)
		pr_debug("NAT64: an error occured while sending the packet");

	pr_debug("NAT64: dev_queue_xmit return code: %d", ret);

	pr_debug("NAT64: before unlocking spinlock...");
	spin_unlock_bh(&nf_nat64_lock);

	return ret;
}

static __be32 nat64_extract_ipv4(struct in6_addr addr, int prefix)
{
	switch(prefix) {
	case 32:
		return addr.s6_addr32[3];
	case 40:
		return 0;	//FIXME
	case 48:
		return 0;	//FIXME
	case 56:
		return 0;	//FIXME
	case 64:
		return 0;	//FIXME
	case 96:
		return addr.s6_addr32[3];
	default:
		return 0;
	}
}

static int nat64_allocate_hash(unsigned int size)
{
	int			i;
	//struct hlist_head	*hash;

	size = roundup(size, PAGE_SIZE / sizeof(struct hlist_head));
	hash_size = size;
	//nat64_data.vmallocked = 0;

	hash4 = (void *)__get_free_pages(GFP_KERNEL|__GFP_NOWARN,
			get_order(sizeof(struct hlist_head) * size));

	if(!hash4) {
		printk("NAT64: Unable to allocate memory for hash4 via gfp X(.\n");
		return -1;
		//hash = vmalloc(sizeof(struct hlist_head) * size);
		//nat64_data.vmallocked = 1;
	}

	hash6 = (void *)__get_free_pages(GFP_KERNEL|__GFP_NOWARN,
			get_order(sizeof(struct hlist_head) * size));
	if(!hash6) {
		printk("NAT64: Unable to allocate memory for hash6 via gfp X(.\n");
		free_pages((unsigned long)hash4,
				get_order(sizeof(struct hlist_head) * hash_size));
		return -1;
	}

	for (i = 0; i < size; i++)
	{
		INIT_HLIST_HEAD(&hash4[i]);
		INIT_HLIST_HEAD(&hash6[i]);
	}

	for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
		INIT_LIST_HEAD(&expiry_base[i].queue);

	return 0;
}

/*
 * Function that gets the pointer directed to it's 
 * nf_conntrack_l3proto structure.
 */
static int nat64_get_l3struct(u_int8_t l3protocol, 
		struct nf_conntrack_l3proto ** l3proto)
{
	// FIXME We removed the skb as a parameter because it wasn't being used.
	switch (l3protocol) {
		case NFPROTO_IPV4:
			*l3proto = l3proto_ip;
			return true;
		case NFPROTO_IPV6:
			*l3proto = l3proto_ipv6;
			return true;
		default:
			return false;
	}
}

/*
 * IPv6 comparison function. It's used as a call from nat64_tg6 to compare
 * the incoming packet's IP with the rule's IP; therefore, when the module is 
 * in debugging mode it prints the rule's IP.
 */
static bool nat64_tg6_cmp(const struct in6_addr * ip_a, 
		const struct in6_addr * ip_b, const struct in6_addr * ip_mask, 
		__u8 flags)
{

	if (flags & XT_NAT64_IPV6_DST) {
		if (ipv6_masked_addr_cmp(ip_a, ip_mask, ip_b) == 0) {
			pr_debug("NAT64: IPv6 comparison returned true\n");
			return true;
		}
	}

	pr_debug("NAT64: IPv6 comparison returned false: %d\n",
			ipv6_masked_addr_cmp(ip_a, ip_mask, ip_b));
	return false;
}

/*
 * Function to get the tuple out of a given struct_skbuff.
 */
static bool nat64_get_tuple(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	const struct nf_conntrack_l4proto *l4proto;
	struct nf_conntrack_l3proto *l3proto;
	int l3_hdrlen, ret;
	unsigned int protoff = 0;
	u_int8_t protonum = 0;

	pr_debug("NAT64: Getting the protocol and header length");

	/*
	 * Get L3 header length
	 */
	l3_hdrlen = nat64_get_l3hdrlen(skb, l3protocol);

	if (l3_hdrlen == -1) {
		pr_debug("NAT64: Something went wrong getting the"
				" l3 header length");
		return false;
	}

	/*
	 * Get L3 struct to access it's functions.
	 */
	if (!(nat64_get_l3struct(l3protocol, &l3proto)))
		return false;

	if (l3proto == NULL) {
		pr_info("NAT64: nat64_get_tuple - the l3proto pointer is null");
		return false;
	}

	rcu_read_lock();

	pr_debug("NAT64: l3_hdrlen = %d", l3_hdrlen);

	/*
	 * Gets the structure with the respective L4 protocol functions.
	 */
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb), 
			&protoff, &protonum);

	if (ret != NF_ACCEPT) {
		pr_info("NAT64: nat64_get_tuple - error getting the L4 offset");
		pr_debug("NAT64: ret = %d", ret);
		pr_debug("NAT64: protoff = %u", protoff);
		rcu_read_unlock();
		return false;
	} else if (protonum != l4protocol) {
		pr_info("NAT64: nat64_get_tuple - protocols don't match");
		pr_debug("NAT64: protonum = %u", protonum);
		pr_debug("NAT64: l4protocol = %u", l4protocol);
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3protocol, l4protocol);
	pr_debug("l4proto name = %s %d %d", l4proto->name, (u_int32_t)l4proto->l3proto, (u_int32_t)l4proto->l4proto);

	/*
	 * Get the tuple out of the sk_buff.
	 */
	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
				l3_hdrlen,
				(u_int16_t)l3protocol, l4protocol,
				inner, l3proto, l4proto)) {
		pr_debug("NAT64: couldn't get the tuple");
		rcu_read_unlock();
		return false;
	}

	pr_debug("\nPRINTED TUPLE");
	nat64_print_tuple(inner);
	pr_debug("\n");
	rcu_read_unlock();

	return true;
}

/*
 * Function to get the SKB from IPv6 to IPv4.
 * @l4protocol = The incoming L4 protocol
 * @l3len = The outgoing L3 header length
 * @l4len = The outgoing l4 header length
 * @paylen = transport header length + data length
 *
 * FIXME: use IPv4 pool instead of a fixed IP.
 * FIXME: Get available ports instead of using a hardcoded one.
 * IMPORTANT: We don't take into account the optional IPv6 header yet.
 */
static bool nat64_get_skb_from6to4(struct sk_buff * old_skb,
		struct sk_buff * new_skb, u_int8_t l3protocol, 
		u_int8_t l4protocol, u_int8_t l3len, u_int8_t l4len, 
		u_int8_t pay_len, struct nf_conntrack_tuple * outgoing)
{
	/*
	 * Genric Layer 4 header structure.
	 */
	union nat64_l4header_t {
		struct udphdr * uh;
		struct tcphdr * th;
		struct icmphdr * icmph;
	} l4header;

	void * ip6_transp;
	struct in_addr * ip4srcaddr;
	struct iphdr * ip4;
	struct ipv6hdr * ip6;

	/*
	 * FIXME: hardcoded port.
	 */
	uint16_t new_port = htons(60000);

	int ret = 0;

	pr_debug("NAT64: UDP outgoing tuple: %pI4 : %d --> %pI4 : %d", &(outgoing->src.u3.in), outgoing->src.u.udp.port, &(outgoing->dst.u3.in), outgoing->dst.u.udp.port);
	ip4srcaddr = kmalloc(sizeof(struct in_addr *), GFP_KERNEL);

	/*
	 * FIXME: Hardcoded IPv4 Address.
	 */
	ret = in4_pton("192.168.56.26", -1, (__u8*)&(ip4srcaddr->s_addr),
			'\x0', NULL);

	if (!ret) {
		pr_debug("NAT64: getskb_from6to4.. "
				"Something went wrong setting the "
				"IPv4 source address");
		return false;
	}

	ip6 = ipv6_hdr(old_skb);
	ip4 = ip_hdr(new_skb);

	/*
	 * IPv4 construction.
	 */
	ip4->version = 4;
	ip4->ihl = 5;
	ip4->tos = ip6->priority; 
	ip4->tot_len = htons(sizeof(*ip4) + l4len + pay_len);

	/*
	 * According to the RFC6146 the ID should be zero.
	 */
	ip4->id = 0;
	ip4->frag_off = htons(IP_DF);
	ip4->ttl = ip6->hop_limit;
	ip4->protocol = ip6->nexthdr;

	pr_debug("NAT64: l4 proto id = %u", ip6->nexthdr);

	/*
	 * Translation of packet. The RFC6146 states that the embedded IPv4 
	 * address lies within the last 32 bits of the IPv6 address
	 * NAT64 Translation algorithm... bit magic!
	 * IMPORTANT: May need htonl function
	 */
	//	ip4->daddr = (__be32)(ip6->daddr.in6_u.u6_addr32)[3];

	ip4->saddr = (__be32) ip4srcaddr->s_addr;

	ret = in4_pton("192.168.56.3", -1, (__u8*)&(ip4srcaddr->s_addr),
			'\x0', NULL);

	ip4->daddr = (__be32) ip4srcaddr->s_addr;

	/*
	 * Get pointer to Layer 4 header.
	 * FIXME: IPv6 option headers should also be considered.
	 */
	ip6_transp = skb_transport_header(old_skb);

	switch (ip4->protocol) {
		/*
		 * UDP and TCP have the same two first values in the struct. 
		 * So UDP header values are used in order to save code.
		 */
		case IPPROTO_UDP:
		case IPPROTO_TCP:	 
			l4header.uh = ip_data(ip4);
			memcpy(l4header.uh, ip6_transp, l4len + pay_len);

			checksum_change(&(l4header.uh->check), 
					&(l4header.uh->source), new_port,
					(ip4->protocol == IPPROTO_UDP) ? 
					true : false);

			adjust_checksum_ipv6_to_ipv4(&(l4header.uh->check), ip6, 
					ip4, (ip4->protocol == IPPROTO_UDP) ? 
					true : false);
			break;
		case IPPROTO_ICMPV6:
			l4header.icmph = ip_data(ip4);
			memcpy(l4header.icmph, ip6_transp, l4len + pay_len);

			if (l4header.icmph->type & ICMPV6_INFOMSG_MASK) {
				switch (l4header.icmph->type) {
					case ICMPV6_ECHO_REQUEST:
						pr_debug("NAT64: icmp6 type"
								" ECHO_REQUEST");
						l4header.icmph->type = ICMP_ECHO;
						break;
					case ICMPV6_ECHO_REPLY:
						pr_debug("NAT64: icmp6 type"
								" ECHO_REPLY");
						l4header.icmph->type = 
							ICMP_ECHOREPLY;
						break;
					default:
						pr_debug("NAT64: ICMPv6 not "
								"echo or reply");
						return false;
				}
			} else {
				pr_debug("NAT64: no other ICMP Protocols"
						" are supported yet.");
				pr_debug("NAT64: detected protocol %u", 
						l4header.icmph->type);
				pr_debug("NAT64: detected protocol %u", 
						l4header.icmph->code);
				return false;
			}

			l4header.icmph->checksum = 0;
			l4header.icmph->checksum = 
				ip_compute_csum(l4header.icmph, pay_len);
			ip4->protocol = IPPROTO_ICMP;
			break;
		default:
			pr_debug("NAT64: encountered incompatible protocol "
					"while creating the outgoing skb");
			return false;
	}

	ip4->check = 0;
	ip4->check = ip_fast_csum(ip4, ip4->ihl);

	return true;
}
/*
 * Function nat64_get_skb is a generic entry function to get a new skb 
 * that will be sent.
 */
static struct sk_buff * nat64_get_skb(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * outgoing)
{
	struct sk_buff *new_skb;

	u_int8_t pay_len = skb->len - skb->data_len;
	u_int8_t packet_len, l4hdrlen, l3hdrlen, l2hdrlen;

	l4hdrlen = -1;

	/*
	 * Layer 2 header length is assigned the maximum possible header length
	 * possible.
	 */
	l2hdrlen = LL_MAX_HEADER;

	pr_debug("NAT64: get_skb paylen = %u", pay_len);

	/*
	 * This is called in case a paged sk_buff arrives...this should'nt
	 * happen.
	 */ 
	if (skb_linearize(skb) < 0)
		return NULL;

	/*
	 * It's assumed that if the l4 protocol is ICMP or ICMPv6, 
	 * the size of the new header will be the other's.
	 */
	switch (l4protocol) {
		case IPPROTO_ICMP:
			l4hdrlen = sizeof(struct icmp6hdr);
			pay_len = pay_len - sizeof(struct icmphdr);
			break;
		case IPPROTO_ICMPV6:
			l4hdrlen = sizeof(struct icmphdr);
			pay_len = pay_len - sizeof(struct icmp6hdr);
			break;
		default:
			l4hdrlen = nat64_get_l4hdrlength(l4protocol);
			pay_len = pay_len - nat64_get_l4hdrlength(l4protocol);
	}

	/*
	 * We want to get the opposite Layer 3 protocol header length.
	 */
	switch (l3protocol) {
		case NFPROTO_IPV4:
			l3hdrlen = sizeof(struct ipv6hdr);
			pay_len = pay_len - sizeof(struct iphdr);
			break;
		case NFPROTO_IPV6:
			l3hdrlen = sizeof(struct iphdr);
			pay_len = pay_len - sizeof(struct ipv6hdr);
			break;
		default:
			pr_debug("NAT64: nat64_get_skb - unidentified"
					" layer 3 protocol");
			return NULL;
	}
	pr_debug("NAT64: paylen %d", pay_len);
	pr_debug("NAT64: l3hdrlen %d", l3hdrlen);
	pr_debug("NAT64: l4hdrlen %d", l4hdrlen);

	packet_len = l3hdrlen + l4hdrlen + pay_len;

	/*
	 * LL_MAX_HEADER referes to the 'link layer' in the OSI stack.
	 */
	new_skb = alloc_skb(l2hdrlen + packet_len, GFP_ATOMIC);

	if (!new_skb) {
		pr_debug("NAT64: Couldn't allocate space for new skb");
		return NULL;
	}

	/*
	 * At this point skb->data and skb->head are at the same place.
	 * They will be separated by the skb_reserve function.
	 */
	skb_reserve(new_skb, l2hdrlen);
	skb_reset_mac_header(new_skb);

	skb_reset_network_header(new_skb);
	skb_set_transport_header(new_skb, l3hdrlen);

	/*
	 * The skb->data pointer is right on the l2 header.
	 * We move skb->tail to the end of the packet data.
	 */
	skb_put(new_skb, packet_len);

	if (!new_skb) {
		if (printk_ratelimit()) {
			pr_debug("NAT64: failed to alloc a new sk_buff");
		}
		return NULL;
	}

	switch (l3protocol) {
		case NFPROTO_IPV4:
			pr_debug("NAT64: IPv4 to 6 not implemented yet");
			// TODO: Implement IPv4 to IPv6 skb generation.
			return NULL;
		case NFPROTO_IPV6:
			if (nat64_get_skb_from6to4(skb, new_skb, l3protocol,
						l4protocol, l3hdrlen, l4hdrlen, 
						(pay_len), outgoing)) { 
				pr_debug("NAT64: Everything went OK populating the "
						"new sk_buff");
				return new_skb;
			}

			pr_debug("NAT64: something went wrong populating the "
					"new sk_buff");
			return NULL;
	}

	pr_debug("NAT64: Not IPv4 or 6");
	return NULL;
}
/*
 * END: NAT64 shared functions.
 */

static struct sk_buff * nat64_translate_packet(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, 
		struct nf_conntrack_tuple * outgoing)
{
	/*
	 * FIXME: Handle IPv6 options.
	 * The following changes the skb and the L3 and L4 layer protocols to 
	 * the respective new values and calls determine_outgoing_tuple.
	 */
	struct sk_buff * new_skb = nat64_get_skb(l3protocol, l4protocol, skb, outgoing);

	if (!new_skb) {
		pr_debug("NAT64: Skb allocation failed -- returned NULL");
		return NULL;
	}

	/*
	 * Adjust the layer 3 protocol variable to be used in the outgoing tuple
	 * Wether it's IPV4 or IPV6 is already checked in the nat64_tg function
	 */
	l3protocol = (l3protocol == NFPROTO_IPV4) ? NFPROTO_IPV6 : NFPROTO_IPV4;

	/*
	 * Adjust the layer 4 protocol variable to be used 
	 * in the outgoing tuple.
	 */
	if (l4protocol == IPPROTO_ICMP) {
		l4protocol = IPPROTO_ICMPV6;
	} else if (l4protocol == IPPROTO_ICMPV6) {
		l4protocol = IPPROTO_ICMP;
	} else if (!(l4protocol & NAT64_IPV6_ALLWD_PROTOS)){
		pr_debug("NAT64: update n filter -> unkown L4 protocol");
		return NULL;
	}

	if (!(nat64_get_tuple(l3protocol, l4protocol, new_skb, outgoing))) {
		pr_debug("NAT64: Something went wrong getting the tuple");
		return NULL;
	}

	pr_debug("NAT64: Determining the outgoing tuple stage went OK.");
	//pr_debug("%ld %ld %d %d %d", new_skb->head-new_skb->head, new_skb->data-new_skb->head, new_skb->tail, new_skb->end, new_skb->len);

	return new_skb;
}

static struct nf_conntrack_tuple * nat64_determine_outgoing_tuple(u_int8_t l3protocol, 
		u_int8_t l4protocol, struct sk_buff *skb, 
		struct nf_conntrack_tuple * inner,
		struct nf_conntrack_tuple * outgoing)
{
	struct nat64_bib_entry *bib;
	struct nat64_st_entry *session;
	struct in_addr * temp_addr;

	/*
	 * Get the tuple out of the BIB and ST entries.
	 */
	bib = bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.udp.port, IPPROTO_UDP);
	if(bib) {
		session = session_ipv4_lookup(bib, nat64_extract_ipv4(inner->dst.u3.in6, prefix_len), inner->dst.u.udp.port);
		if(session) {
			outgoing = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
			memset(outgoing, 0, sizeof(struct nf_conntrack_tuple));

			temp_addr = kmalloc(sizeof(struct in_addr), GFP_ATOMIC);
			memset(temp_addr, 0, sizeof(struct in_addr));
	
			if(!outgoing) {
				printk(KERN_ERR "NAT64: There's not enough memory for the outgoing tuple.\n");
				return NULL;
			}
			if(!temp_addr) {
				printk(KERN_ERR "NAT64: There's not enough memory to do a procedure to get the outgoing tuple.\n");
				return NULL;
			}
			// Obtain the data of the tuple.
			outgoing->src.l3num = (u_int16_t)l3protocol;
			if (l3protocol == NFPROTO_IPV4) {
				switch (l4protocol) {
					case IPPROTO_TCP:
						pr_debug("NAT64: TCP protocol not currently supported.");
						break;
					case IPPROTO_UDP:
						break;
					case IPPROTO_ICMP:
						pr_debug("NAT64: ICMP protocol not currently supported.");
						break;
					case IPPROTO_ICMPV6:
						pr_debug("NAT64: ICMPv6 protocol not currently supported.");
						break;
					default:
						pr_debug("NAT64: layer 4 protocol not currently supported.");
						break;
				}
			} else if (l3protocol == NFPROTO_IPV6) {
				switch (l4protocol) {
					case IPPROTO_TCP:
						pr_debug("NAT64: TCP protocol not currently supported.");
						break;
					case IPPROTO_UDP:
						// Ports
						outgoing->src.u.udp.port = bib->local4_port;
						outgoing->dst.u.udp.port = session->remote4_port;

						// SRC IP
						outgoing->src.u3.ip = bib->local4_addr;
						temp_addr->s_addr = bib->local4_addr;
						outgoing->src.u3.in = *(temp_addr);

						// DST IP
						outgoing->dst.u3.ip = session->remote4_addr;
						temp_addr->s_addr = session->remote4_addr;
						outgoing->dst.u3.in = *(temp_addr);
						
						pr_debug("NAT64: UDP outgoing tuple: %pI4 : %d --> %pI4 : %d", &(outgoing->src.u3.in), outgoing->src.u.udp.port, &(outgoing->dst.u3.in), outgoing->dst.u.udp.port);
						break;
					case IPPROTO_ICMP:
						pr_debug("NAT64: ICMP protocol not currently supported.");
						break;
					case IPPROTO_ICMPV6:
						pr_debug("NAT64: ICMPv6 protocol not currently supported.");
						break;
					default:
						pr_debug("NAT64: layer 4 protocol not currently supported.");
						break;
				}
			}
						
			return outgoing;
		} else {
			printk(KERN_ERR "The session wasn't found.\n");
			goto error;
		}
	} else {
		printk(KERN_ERR "The BIB wasn't found.\n");
		goto error;
	}
	
	goto error;
error:
	return NULL;
}

/*
 * This procedure performs packet filtering and
 * updates BIBs and STs.
 */
static bool nat64_filtering_and_updating(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	struct nat64_bib_entry *bib;
	struct nat64_st_entry *session;
	bool res;
//	int i;
	res = true;

	if (l3protocol == NFPROTO_IPV4) {
		pr_debug("NAT64: FNU - IPV4");
		/*
		 * Query the STs for any records
		 * If there's no active session for the specified 
		 * connection, the packet should be dropped
		 */
		switch (l4protocol) {
			case IPPROTO_TCP:
				//Query TCP ST
				pr_debug("NAT64: TCP protocol not currently supported.");
				break;
			case IPPROTO_UDP:
				//Query UDP ST
				if (true) {
					//continue processing...
					//FIXME: FIND the session and check if the lifetime is up. If it is, keep processing.
					res = true; 
					goto end;
				} else {
					pr_debug("NAT64: no currently active session found; packet should be dropped.");
					res = false; 
					goto end;
				}
				break;
			case IPPROTO_ICMP:
				//Query ICMP ST
				pr_debug("NAT64: ICMP protocol not currently supported.");
				break;
			case IPPROTO_ICMPV6:
				//Query ICMPV6 ST
				pr_debug("NAT64: ICMPv6 protocol not currently supported.");
				break;
			default:
				//Drop packet
				pr_debug("NAT64: layer 4 protocol not currently supported.");
				break;
		}
		res = false; 
		goto end;
	} else if (l3protocol == NFPROTO_IPV6) {
		pr_debug("NAT64: FNU - IPV6");	
		// FIXME: Return true if it is not H&H. A special return code 
		// will have to be added as a param in the future to handle it.
		res = false;
//		clean_expired_sessions(&expiry_queue);
//		for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
//			clean_expired_sessions(&expiry_base[i].queue);
		switch (l4protocol) {
			case IPPROTO_TCP:
				/*
				 * Verify if there's any binding for the src address by querying
				 * the TCP BIB. If there's a binding, verify if there's a
				 * connection to the specified destination by querying the TCP ST.
				 * 
				 * In case any of these records are missing, they should be created.
				 */
				pr_debug("NAT64: TCP protocol not currently supported.");
				break;
			case IPPROTO_UDP:
				pr_debug("NAT64: FNU - UDP");
				/*
				 * Verify if there's any binding for the src address by querying
				 * the UDP BIB. If there's a binding, verify if there's a
				 * connection to the specified destination by querying the UDP ST.
				 * 
				 * In case these records are missing, they should be created.
				 */
				bib = bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.udp.port, IPPROTO_UDP);
				if(bib) {
					session = session_ipv4_lookup(bib, nat64_extract_ipv4(inner->dst.u3.in6, prefix_len), inner->dst.u.udp.port);
					if(session) {
						session_renew(session, UDP_DEFAULT);
					} else {
						session = session_create(bib, nat64_extract_ipv4(inner->dst.u3.in6, prefix_len), inner->dst.u.udp.port, UDP_DEFAULT);
					}
				} else {
					printk("Create a new BIB and Session entry\n");
					bib = bib_session_create(&(inner->src.u3.in6), nat64_extract_ipv4(inner->dst.u3.in6, prefix_len), inner->src.u.udp.port, inner->dst.u.udp.port, l4protocol, UDP_DEFAULT);
				}
				res = true;
				break;
			case IPPROTO_ICMP:
				//Query ICMP ST
				pr_debug("NAT64: ICMP protocol not currently supported.");
				break;
			case IPPROTO_ICMPV6:
				//Query ICMPV6 ST
				pr_debug("NAT64: ICMPv6 protocol not currently supported.");
				break;
			default:
				//Drop packet
				pr_debug("NAT64: layer 4 protocol not currently supported.");
				break;
		}
		goto end;
	}

	return res;
end: 
	if(res) 
		pr_debug("NAT64: Updating and Filtering stage went OK.");
	else 
		pr_debug("NAT64: Updating and Filtering stage FAILED.");
	return res;
}

/*
 * Function that gets the packet's information and returns a tuple out of it.
 */
static bool nat64_determine_tuple(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	if (!(nat64_get_tuple(l3protocol, l4protocol, skb, inner))) {
		pr_debug("NAT64: Something went wrong getting the tuple");
		return false;
	}

	pr_debug("NAT64: Determining the tuple stage went OK.");

	return true;
}

/*
 * IPv4 entry function
 *
 */
static unsigned int nat64_tg4(struct sk_buff *skb, 
		const struct xt_action_param *par)
{
	int buff_cont;
	unsigned char *buf = skb->data;
	unsigned char cc;

	pr_debug("\n* ICNOMING IPV4 PACKET *\n");
	pr_debug("Drop it\n");

	for (buff_cont = 0; buff_cont < skb->len; buff_cont++) {
		cc = buf[buff_cont];
		printk(KERN_DEBUG "%02x",cc);
	}

	printk(KERN_DEBUG "\n");

	return NF_DROP;
}

/*
 * NAT64 Core Functionality
 *
 */
static unsigned int nat64_core(struct sk_buff *skb, 
		const struct xt_action_param *par, u_int8_t l3protocol,
		u_int8_t l4protocol) {

	struct nf_conntrack_tuple inner;
	struct nf_conntrack_tuple * outgoing;
	struct sk_buff * new_skb;

	if (!nat64_determine_tuple(l3protocol, l4protocol, skb, &inner)) {
		pr_info("NAT64: There was an error determining the Tuple");
		return NF_DROP;
	} 
	
	if (!nat64_filtering_and_updating(l3protocol, l4protocol, skb, &inner)) {
		pr_info("NAT64: There was an error in the updating and"
				" filtering module");
		return NF_DROP;
	}

	outgoing = nat64_determine_outgoing_tuple(l3protocol, l4protocol, 
			skb, &inner, outgoing);

	if (!outgoing) {
		pr_info("NAT64: There was an error in the determining the outgoing"
				" tuple module");
		return NF_DROP;
	}

	new_skb = nat64_translate_packet(l3protocol, l4protocol, skb, outgoing);

	if (!new_skb) {
		pr_info("NAT64: There was an error in the packet translation"
				" module");
		return NF_DROP;
	}

	/*
	 * Returns zero if it works
	 */
	if (nat64_send_packet(skb, new_skb)) {
		pr_info("NAT64: There was an error in the packet transmission"
				" module");
		return NF_DROP;
	}

	/* TODO: Incluir llamada a HAIRPINNING aqui */

	return NF_DROP;
}

/*
 * IPv6 entry function
 *
 */
static unsigned int nat64_tg6(struct sk_buff *skb, 
		const struct xt_action_param *par)
{
	const struct xt_nat64_tginfo *info = par->targinfo;
	struct ipv6hdr *iph = ipv6_hdr(skb);
	__u8 l4_protocol = iph->nexthdr;

	pr_debug("\n* INCOMING IPV6 PACKET *\n");
	pr_debug("PKT SRC=%pI6 \n", &iph->saddr);
	pr_debug("PKT DST=%pI6 \n", &iph->daddr);
	pr_debug("RULE DST=%pI6 \n", &info->ip6dst.in6);
	pr_debug("RULE DST_MSK=%pI6 \n", &info->ip6dst_mask);

	/*
	 * If the packet is not directed towards the NAT64 prefix, 
	 * continue through the Netfilter rules.
	 */
	if (!nat64_tg6_cmp(&info->ip6dst.in6, &info->ip6dst_mask.in6, 
				&iph->daddr, info->flags))
		return NF_ACCEPT;

	if (l4_protocol & NAT64_IPV6_ALLWD_PROTOS) {
		/*
		 * Core functions of the NAT64 implementation.
		 */
		return nat64_core(skb, par, NFPROTO_IPV6, l4_protocol);
	}

	/*
	 * If the packet's protocol is not one of the ones defined for NAT64,
	 * accept it.
	 */
	return NF_ACCEPT;
}

/*
 * General entry point. 
 *
 * Here the NAT64 implementation validates that the
 * incoming packet is IPv4 or IPv6. If it isn't, it silently drops the packet.
 * If it's one of those two, it calls it's respective function, since the IPv6
 * header is handled differently than an IPv4 header.
 */
static unsigned int nat64_tg(struct sk_buff *skb, 
		const struct xt_action_param *par)
{
	if (par->family == NFPROTO_IPV4)
		return nat64_tg4(skb, par);
	else if (par->family == NFPROTO_IPV6)
		return nat64_tg6(skb, par);
	else
		return NF_ACCEPT;
}

static int nat64_tg_check(const struct xt_tgchk_param *par)
{
	int ret;

	ret = nf_ct_l3proto_try_module_get(par->family);
	if (ret < 0)
		pr_info("cannot load support for proto=%u\n",
				par->family);
	return ret;
}

static struct xt_target nat64_tg_reg __read_mostly = {
	.name = "nat64",
	.revision = 0,
	.target = nat64_tg,
	.checkentry = nat64_tg_check,
	.family = NFPROTO_UNSPEC,
	.table = "mangle",
	.hooks = (1 << NF_INET_PRE_ROUTING),
	.targetsize = sizeof(struct xt_nat64_tginfo),
	.me = THIS_MODULE,
};

static int __init nat64_init(void)
{
	int ret = 0;
	ipv4_prefixlen = 24;
	ipv4_addr = 0;
	ipv4_address = "192.168.57.0"; // Default IPv4
	ipv4_netmask = 0xffffff00; // Mask of 24 IPv4
	prefix_address = "fec0::"; // Default IPv6
	prefix_len = 32; // Default IPv6 Prefix

	/*
	 * Include nf_conntrack dependency
	 */
	need_conntrack();
	/*
	 * Include nf_conntrack_ipv4 dependency.
	 * IPv4 conntrack is needed in order to handle complete packets, and not
	 * fragments.
	 */
	need_ipv4_conntrack();

	/*
	 * Disables timestamps in sk_buff.
	 * Timestamps are used in STs.
	 */
	//net_disable_timestamp();

	l3proto_ip = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV4);
	l3proto_ipv6 = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV6);

	if (l3proto_ip == NULL)
		pr_debug("NAT64: couldn't load IPv4 l3proto");
	if (l3proto_ipv6 == NULL)
		pr_debug("NAT64: couldn't load IPv6 l3proto");

	ret = in4_pton(ipv4_address, -1, (u8 *)&ipv4_addr, '\x0', NULL);

	if (!ret)
	{
		printk("NAT64: ipv4 is malformed [%s].\n", ipv4_address);
		ret = -1;
		goto error;
	}
	
	if(ret)
	{
		//ipv4_prefixlen = simple_strtol(++pos, NULL, 10);
		if(ipv4_prefixlen > 32 || ipv4_prefixlen < 1)
		{
			printk("NAT64: ipv4 prefix is malformed [%s].\n", ipv4_address);
			ret = -1;
			goto error;
		}
		ipv4_netmask = inet_make_mask(ipv4_prefixlen);
		ipv4_addr = ipv4_addr & ipv4_netmask;
		printk("NAT64: using IPv4 subnet %pI4/%d (netmask %pI4).\n", &ipv4_addr, ipv4_prefixlen, &ipv4_netmask);
	}

	if(nat64_allocate_hash(65536))
	{
		printk("NAT64: Unable to allocate memmory for hash table.\n");
		goto hash_error;
	}

	st_cache = kmem_cache_create("nat64_st", sizeof(struct nat64_st_entry), 0,0, NULL);
	if(!st_cache) {
		printk(KERN_ERR "NAT64: Unable to create session table slab cache.\n");
		goto st_cache_error;
	} else {
		printk("NAT64: The session table slab cache was succesfully created.\n");
	}

	bib_cache = kmem_cache_create("nat64_bib", sizeof(struct nat64_bib_entry), 0,0, NULL);
	if(!bib_cache) {
		printk(KERN_ERR "NAT64: Unable to create bib table slab cache.\n");
		goto bib_cache_error;
	} else {
		printk("NAT64: The bib table slab cache was succesfully created.\n");
	}

	return xt_register_target(&nat64_tg_reg);

error:
	return -EINVAL;
hash_error:
	return -ENOMEM;
st_cache_error:
	kmem_cache_destroy(st_cache);
	return -ENOMEM;
bib_cache_error:
	kmem_cache_destroy(st_cache);
	kmem_cache_destroy(bib_cache);
	return -ENOMEM;
}

static void __exit nat64_exit(void)
{
	nf_ct_l3proto_put(l3proto_ip);
	nf_ct_l3proto_put(l3proto_ipv6);
	kmem_cache_destroy(st_cache);
	kmem_cache_destroy(bib_cache);
	xt_unregister_target(&nat64_tg_reg);
}

module_init(nat64_init);
module_exit(nat64_exit);
