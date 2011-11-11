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

#include "nf_nat64_bib.h"
#include "xt_nat64.h"
#include "nf_nat64_generic_functions.h"
#include "nf_nat64_auxiliary_functions.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan Antonio Osorio <jaosorior@gmail.com>");
MODULE_DESCRIPTION("Xtables: RFC 6146 \"NAT64\" implementation");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

#define IPV6_HDRLEN 40
//static DEFINE_SPINLOCK(nf_nat64_lock);

/*
 * FIXME: Ensure all variables are 32 and 64-bits complaint. 
 * That is, no generic data types akin to integer.
 * FIXED: All the output messages of the stages are in the opposite
 * order of execution
 * in the logs.
 */

static struct nf_conntrack_l3proto * l3proto_ip __read_mostly;
static struct nf_conntrack_l3proto * l3proto_ipv6 __read_mostly;

/*
 * BEGIN: NAT64 shared functions.
 */

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
		if (ipv6_masked_addr_cmp(ip_a, ip_mask, ip_b) != 0) 
			pr_debug("NAT64: IPv6 comparison returned true\n");
			return true;
	}

	pr_debug("NAT64: IPv6 comparison returned false\n");
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
		pr_debug("NAT64: the l3proto pointer is null");
		return false;
	}

	rcu_read_lock();

	pr_debug("NAT64: l3_hdrlen = %d", l3_hdrlen);

	ret = l3proto->get_l4proto(skb, skb_network_offset(skb), 
					&protoff, &protonum);
	
	if (ret != NF_ACCEPT) {
		pr_debug("NAT64: error getting the L4 offset");
		pr_debug("NAT64: ret = %d", ret);
		pr_debug("NAT64: protoff = %u", protoff);
		rcu_read_unlock();
		return false;
	} else if (protonum != l4protocol) {
		pr_debug("NAT64: protocols don't match");
		pr_debug("NAT64: protonum = %u", protonum);
		pr_debug("NAT64: l4protocol = %u", l4protocol);
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3protocol, l4protocol);

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
static bool nat64_getskb_from6to4(struct sk_buff * old_skb,
		struct sk_buff * new_skb, u_int8_t l3protocol, 
		u_int8_t l4protocol, u_int8_t l3len, u_int8_t l4len, 
		u_int8_t pay_len)
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
	uint16_t new_port = htons(59152);

	int ret = 0;

	ip4srcaddr = kmalloc(sizeof(struct in_addr *), GFP_KERNEL);

	/*
	 * FIXME: Hardcoded IPv4 Address.
	 */
	ret = in4_pton("192.168.1.3", -1, (__u8*)&(ip4srcaddr->s_addr),
			'\x0', NULL);

	if (!ret) {
		pr_debug("NAT64: getskb_from6to4.. "
			 "Something went wrong setting the "
			 "IPv4 source address");
		return false;
	}

	ip6 = ipv6_hdr(old_skb);
	ip4 = ip_hdr(new_skb);

	ip4->version = 4;
	ip4->ihl = 5;
	ip4->tos = ip6->priority; 
	ip4->tot_len = htons(sizeof(*ip4) + pay_len);
	ip4->id = 0;
	ip4->frag_off = htons(IP_DF);
	ip4->ttl = ip6->hop_limit;
	ip4->protocol = ip6->nexthdr;

	/*
	 * Translation of packet. The RFC6146 states that the embedded IPv4 
	 * address lies within the last 32 bits of the IPv6 address
	 * NAT64 Translation algorithm... bit magic!
	 * IMPORTANT: May need htonl function
	 */
	ip4->daddr = (__be32)(ip6->daddr.in6_u.u6_addr32)[3];
	ip4->saddr = (__be32) ip4srcaddr->s_addr;

	/*
	 * Get pointer to Layer 4 header.
	 */
	ip6_transp = (void *)((char *) old_skb->data + 
				(sizeof(struct ipv6hdr)));

	/*
	 * TODO Make this code more elegant.
	 * POINTER MADNESS
	 */
	switch (ip4->protocol) {
		/*
		 * UDP and TCP have the same two first values in the struct. 
		 * So UDP header values are used in order to save code.
		 */
		case IPPROTO_UDP:
		case IPPROTO_TCP:	 
			l4header.uh = ip_data(ip4);
			memcpy(l4header.uh, ip6_transp, pay_len);

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
			memcpy(l4header.icmph, ip6_transp, pay_len);

			if (l4header.icmph->type & ICMPV6_INFOMSG_MASK) {
				switch (l4header.icmph->type) {
					case ICMPV6_ECHO_REQUEST:
						l4header.icmph->type = 
							ICMP_ECHO;
						break;
					case ICMPV6_ECHO_REPLY:
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
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	struct sk_buff *new_skb;

	u_int8_t pay_len = skb->data_len;
	u_int8_t packet_len, l4hdrlen, l3hdrlen;
	unsigned int addr_type;

	addr_type = RTN_LOCAL;
 
	pr_debug("NAT64: get_skb paylen = %u", pay_len);

	if (skb_linearize(skb) < 0)
		return NULL;

	printk(KERN_INFO "dst_out=%p\n", skb_dst(skb)->output);

	/*
	 * It's assumed that if the l4 protocol is ICMP or ICMPv6, 
	 * the size of the new header will be the other's.
	 */
	switch (l4protocol) {
		case IPPROTO_ICMP:
			l4hdrlen = sizeof(struct icmp6hdr);
			break;
		case IPPROTO_ICMPV6:
			l4hdrlen = sizeof(struct icmphdr);
			break;
		default:
			l4hdrlen = nat64_get_l4hdrlength(l4protocol);
	}

	if (l4hdrlen == -1) {
		pr_debug("NAT64: Unknown layer 4 protocol detected"
			 " in nat64_get_skb");
		return NULL;
	}

	/*
	 * We want to get the opposite Layer 3 protocol header length.
	 */
	switch (l3protocol) {
		case NFPROTO_IPV4:
			l3hdrlen = sizeof(struct ipv6hdr); break;
		case NFPROTO_IPV6:
			l3hdrlen = sizeof(struct iphdr); break;
		default:
			return NULL;
	}
	pr_debug("NAT64: l3hdrlen %d", l3hdrlen);

	packet_len = l3hdrlen + l4hdrlen + pay_len;

	// LL_MAX_HEADER referes to the 'link layer' in the OSI stack.
	new_skb = alloc_skb(LL_MAX_HEADER + packet_len, GFP_ATOMIC);

	if (!new_skb) {
		pr_debug("NAT64: Couldn't allocate space for new skb");
		return NULL;
	}

	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_reset_mac_header(new_skb);
	skb_reset_network_header(new_skb);

	skb_set_transport_header(new_skb, l3hdrlen);

	skb_put(new_skb, packet_len);

	if (!new_skb) {
		if (printk_ratelimit()) {
			pr_debug("NAT64: failed to alloc a new sk_buff");
		}
		return NULL;
	}

	if (l3protocol == NFPROTO_IPV4) {
		pr_debug("NAT64: IPv4 to 6 not implemented yet");
		// TODO: Implement IPv4 to IPv6 skb generation.
		return NULL;
	} else if (l3protocol == NFPROTO_IPV6) {
		if (nat64_getskb_from6to4(skb, new_skb, l3protocol, l4protocol,
					 l3hdrlen, l4hdrlen, 
					 (l4hdrlen + pay_len))) { 
			pr_debug("NAT64: Everything went OK populating the "
				 "new sk_buff");
			return new_skb;
		} else {
			pr_debug("NAT64: something went wrong populating the "
				 "new sk_buff");
			return NULL;
		}
	}

	pr_debug("NAT64: Not IPv4 or 6");
	return NULL;
}
/*
 * END: NAT64 shared functions.
 */

static bool nat64_translate_packet_ip4(u_int8_t l3protocol, u_int8_t l4protocol, 
			struct sk_buff *skb, 
			struct nf_conntrack_tuple * outgoing_t) 
{
	pr_debug("NAT64: Translating the packet stage went OK.");
	return true;
}

static bool nat64_translate_packet_ip6(u_int8_t l3protocol, u_int8_t l4protocol, 
			struct sk_buff *skb, 
			struct nf_conntrack_tuple * outgoing_t)
{
	pr_debug("NAT64: Translating the packet stage went OK.");
	return true;
}

static bool nat64_translate_packet(u_int8_t l3protocol, u_int8_t l4protocol, 
			struct sk_buff *skb, 
			struct nf_conntrack_tuple * outgoing_t)
{
	switch(l3protocol) {
		case NFPROTO_IPV4:
			return nat64_translate_packet_ip4(l3protocol, 
					l4protocol, skb, outgoing_t);
			break;
		case NFPROTO_IPV6:
			return nat64_translate_packet_ip6(l3protocol, 
					l4protocol, skb, outgoing_t);
		default:
			return false;
	}
}

static bool nat64_determine_outgoing_tuple(u_int8_t l3protocol, 
		u_int8_t l4protocol, struct sk_buff *skb, 
		struct nf_conntrack_tuple * inner, struct sk_buff *new_skb, 
		struct nf_conntrack_tuple *outgoing)
{
//	struct nf_conntrack_tuple outgoing;
//	struct sk_buff *new_skb;

	/*
	 * The following changes the skb and the L3 and L4 layer protocols to 
	 * the respective new values and calls determine_outgoing_tuple.
	 */
	new_skb = nat64_get_skb(l3protocol, l4protocol, skb, inner);

	if (!new_skb) {
		pr_debug("NAT64: Skb allocation failed -- returned NULL");
		return false;
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
		return false;
	}
	
	if (!(nat64_get_tuple(l3protocol, l4protocol, new_skb, outgoing))) {
		pr_debug("NAT64: Something went wrong getting the tuple");
		return false;
	}
	
	pr_debug("NAT64: Determining the outgoing tuple stage went OK.");
	
	/*
	 * TODO: Implement call to translate_packet to get the new packet
	 * from the tuple.
	 */	
	return true;
}

static bool nat64_update_n_filter(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	/*
	 * TODO: Implement Update_n_Filter
	 */

	pr_debug("NAT64: Updating and Filtering stage went OK.");
	return true;
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
	//union nf_inet_addr;
	//struct iphdr *iph = ip_hdr(skb);
	//__u8 l4_protocol = iph->protocol;

	pr_debug("\n* ICNOMING IPV4 PACKET *\n");
	pr_debug("Drop it\n");

	return NF_DROP;
}

/*
 * NAT64 IPv6 Core Functionality
 *
 */

static unsigned int nat64_ipv6_core(struct sk_buff *skb, 
		const struct xt_action_param *par, u_int8_t l3protocol,
		u_int8_t l4protocol) {
		
	bool nf_ret = true;
	struct nf_conntrack_tuple inner;
	struct nf_conntrack_tuple outgoing;
	struct sk_buff new_skb;
	
	nf_ret = nat64_determine_tuple(l3protocol, l4protocol, skb, &inner);

	if(nf_ret) {
		nf_ret = nat64_update_n_filter(l3protocol, l4protocol, 
			skb, &inner);
	}
	
	if(nf_ret) {
		nf_ret = nat64_determine_outgoing_tuple(l3protocol, l4protocol, 
			skb, &inner, &new_skb, &outgoing);
	}
	
	if(nf_ret) {
		nf_ret = nat64_translate_packet(l3protocol, l4protocol, 
			&new_skb, &outgoing);	
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
		// CORE of NAT64 for TG6
		return nat64_ipv6_core(skb, par, NFPROTO_IPV6, l4_protocol);
	}

	return NF_DROP;
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
		return NF_DROP;
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

	l3proto_ip = nf_ct_l3proto_find_get((u_int16_t)NFPROTO_IPV4);
	l3proto_ipv6 = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV6);

	if (l3proto_ip == NULL)
		pr_debug("NAT64: couldn't load IPv4 l3proto");
	if (l3proto_ipv6 == NULL)
		pr_debug("NAT64: couldn't load IPv6 l3proto");

	return xt_register_target(&nat64_tg_reg);
}

static void __exit nat64_exit(void)
{
	nf_ct_l3proto_put(l3proto_ip);
	nf_ct_l3proto_put(l3proto_ipv6);
	xt_unregister_target(&nat64_tg_reg);
}

module_init(nat64_init);
module_exit(nat64_exit);
