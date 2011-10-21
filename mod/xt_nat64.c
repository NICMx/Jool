/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>

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
#include "nf_nat64_tuple.h"
#include "xt_nat64.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan Antonio Osorio <jaosorior@gmail.com>");
MODULE_DESCRIPTION("Xtables: RFC 6146 \"NAT64\" implementation");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

#define IPV6_HDRLEN 40
//static DEFINE_SPINLOCK(nf_nat64_lock);

static struct nf_conntrack_l3proto * l3proto_ip __read_mostly;
static struct nf_conntrack_l3proto * l3proto_ipv6 __read_mostly;

/*
 * This structure's purpose is getting the L4 layer respective function to get
 * the outgoing tuple.
 */
struct nat64_outtuple_func {
	struct nf_conntrack_tuple * (* get_outtuple)(union nf_inet_addr, u_int16_t,
			union nf_inet_addr, u_int16_t, u_int8_t, u_int8_t);
};

/*
 * BEGIN: Generic Auxiliary Functions
 */

/*
 * Function that receives a tuple and prints it.
 */
static void nat64_print_tuple(const struct nf_conntrack_tuple *t)
{
	pr_debug("NAT64: print_tuple -> l3 proto = %d", t->src.l3num);
	switch(t->src.l3num) {
		case NFPROTO_IPV4:
			pr_debug("NAT64: tuple %p: %u %pI4:%hu -> %pI4:%hu",
				t, t->dst.protonum,
				&t->src.u3.ip, t->src.u.all,
				&t->dst.u3.ip, t->dst.u.all);
		break;
		case NFPROTO_IPV6:
			pr_debug("NAT64: tuple %p: %u %pI6: %hu -> %pI6:%hu",
				t, t->dst.protonum,
				&t->src.u3.all, t->src.u.all,
				&t->dst.u3.all, t->dst.u.all);
		break;
		default:
			pr_debug("NAT64: Not IPv4 or IPv6?");
	}
}


/*
 * END: Generic Auxiliary Functions
 */

/*
 * BEGIN: Packet Auxiliary Functions
 */

/*
 * Function that retrieves a pointer to the Layer 4 header.
 */
inline void * ip_data(struct iphdr *ip4)
{
	return (char *)ip4 + ip4->ihl*4;
}

/*
 * Function that gets the Layer 4 header length.
 */
static int nat64_get_l4hdrlength(u_int8_t l4protocol)
{
	switch(l4protocol) {
		case IPPROTO_TCP:
			return sizeof(struct tcphdr);
		case IPPROTO_UDP:
			return sizeof(struct udphdr);
		case IPPROTO_ICMP:
			return sizeof(struct icmphdr);
		case IPPROTO_ICMPV6:
			return sizeof(struct icmp6hdr);
	}
	return -1;
}


/*
 * Function that gets the pointer directed to it's nf_conntrack_l3proto structure.
 */
static int nat64_get_l3struct(struct sk_buff *skb, u_int8_t l3protocol, 
		struct nf_conntrack_l3proto ** l3proto)
{
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
 * Function to get the Layer 3 header length.
 */
static int nat64_get_l3hdrlen(struct sk_buff *skb, u_int8_t l3protocol)
{
	switch (l3protocol) {
		case NFPROTO_IPV4:
			return ip_hdrlen(skb);
		case NFPROTO_IPV6:
			return (skb_network_offset(skb) + sizeof(struct ipv6hdr));
		default:
			return -1;
	}
}

static void checksum_adjust(uint16_t *sum, uint16_t old, uint16_t new, bool udp)
{
	uint32_t s;

	if (udp && !*sum)
		return;

	s = *sum + old - new;
	*sum = (s & 0xffff) + (s >> 16);

	if (udp && !*sum)
		*sum = 0xffff;
}

static void checksum_remove(uint16_t *sum, uint16_t *begin, uint16_t *end, bool udp)
{
        while (begin < end)
                checksum_adjust(sum, *begin++, 0, udp);
}

static void checksum_add(uint16_t *sum, uint16_t *begin, uint16_t *end, bool udp)
{
        while (begin < end)
                checksum_adjust(sum, 0, *begin++, udp);
}



static void checksum_change(uint16_t *sum, uint16_t *x, uint16_t new, bool udp)
{
	checksum_adjust(sum, *x, new, udp);
	*x = new;
}

static void adjust_checksum_ipv6_to_ipv4(uint16_t *sum, struct ipv6hdr *ip6, 
		struct iphdr *ip4, bool udp)
{
	WARN_ON_ONCE(udp && !*sum);

	checksum_remove(sum, (uint16_t *)&ip6->saddr,
			(uint16_t *)(&ip6->saddr + 2), udp);

	checksum_add(sum, (uint16_t *)&ip4->saddr,
			(uint16_t *)(&ip4->saddr + 2), udp);
}

static void adjust_checksum_ipv4_to_ipv6(uint16_t *sum, struct iphdr *ip4, 
		struct ipv6hdr *ip6, int udp)
{
	WARN_ON_ONCE(udp && !*sum);

	checksum_remove(sum, (uint16_t *)&ip4->saddr,
			(uint16_t *)(&ip4->saddr + 2), udp);

	checksum_add(sum, (uint16_t *)&ip6->saddr,
			(uint16_t *)(&ip6->saddr + 2), udp);
}

/*
 * IPv6 comparison function. It's use as a call from nat64_tg6 is to compare
 * the incoming packet's ip with the rule's ip, and so when the module is in
 * debugging mode it prints the rule's IP.
 */
static bool nat64_tg6_cmp(const struct in6_addr * ip_a, 
		const struct in6_addr * ip_b, const struct in6_addr * ip_mask, __u8 flags)
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
 * END: Packet Auxiliary Functions
 */

/*
 * BEGIN: NAT64 shared functions.
 */

/*
 * Function that assigns the pointer to a function to handle the outgoing tuple
 * from IPv6 to IPv4
 */
static bool nat64_get_outfunc4(u_int8_t l4protocol,
		struct nat64_outtuple_func ** outfunc)
{
	switch (l4protocol) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			return false;
		case IPPROTO_ICMP:
			(*outfunc)->get_outtuple = &nat64_outfunc4_icmpv6;
		default:
			return false;
	}
}

/*
 * Function that assigns the pointer to a function to handle the outgoing tuple
 * from IPv4 to IPv6
 */
static bool nat64_get_outfunc6(u_int8_t l4protocol,
		struct nat64_outtuple_func ** outfunc)
{
	switch (l4protocol) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			return false;
		case IPPROTO_ICMPV6:
			//*outfunc = &nat64_outfunc6_icmp;
		default:
			return false;
	}
}

static bool nat64_get_outfunc(u_int8_t l3protocol, u_int8_t l4protocol,
		struct nat64_outtuple_func * outfunc)
{
	switch (l3protocol) {
		case NFPROTO_IPV4:
			return nat64_get_outfunc4(l4protocol, &outfunc);
		case NFPROTO_IPV6:
			return nat64_get_outfunc6(l4protocol, &outfunc);
		default:
			return false;
	}
		
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
		pr_debug("NAT64: Something went wrong getting the l3 header length");
		return false;
	}

	/*
	 * Get L3 struct to access it's functions.
	 */
	if (!(nat64_get_l3struct(skb, l3protocol, &l3proto)))
		return false;

	if (l3proto == NULL) {
		pr_debug("NAT64: the l3proto pointer is null");
		return false;
	}

	rcu_read_lock();

	pr_debug("NAT64: l3_hdrlen = %d", l3_hdrlen);

	ret = l3proto->get_l4proto(skb, skb_network_offset(skb), &protoff, &protonum);
	
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

	nat64_print_tuple(inner);
	rcu_read_unlock();

	return true;
}

//static bool nat64_getskb_from4to6()
//{
//	struct iphdr *ip4;
//	struct ipv6hdr *ip6;
//}

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
		u_int8_t l4protocol, u_int8_t l3len, u_int8_t l4len, u_int8_t pay_len)
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
	struct in_addr * ip4saddr;
	struct iphdr * ip4;
	struct ipv6hdr * ip6;

	/*
	 * FIXME: hardcoded port.
	 */
	uint16_t new_port = htons(59152);

	int ret = 0;

	ip4saddr = kmalloc(sizeof(struct in_addr *), GFP_KERNEL);

	/*
	 * FIXME: Hardcoded IPv4 Address.
	 */
	ret = in4_pton("192.168.1.3", -1, (__u8*)&(ip4saddr->s_addr),'\x0', NULL);

	if (!ret) {
		pr_debug("NAT64: getskb_from6to4... Something went wrong setting "
				"the IPv4 source address");
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
	 * Translation of packet. The RFC6146 states that the embedded IPv4 address
	 * lies within the last 32 bits of the IPv6 address
	 * NAT64 Translation algorithm... bit magic!
	 * IMPORTANT: May need htonl function
	 */
	ip4->daddr = (__be32)(ip6->daddr.in6_u.u6_addr32)[3];
	ip4->saddr = (__be32) ip4saddr->s_addr;

	/*
	 * Get pointer to Layer 4 header.
	 */
	ip6_transp = (void *)((char *) old_skb->data + (sizeof(struct ipv6hdr)));

	/*
	 * TODO Make this code more elegant.
	 * POINTER MADNESS
	 */
	switch (ip4->protocol) {
		/*
		 * UDP and TCP have the same two first values in the struct. So udp
		 * header values are used in order to save code.
		 */
		case IPPROTO_UDP:
		case IPPROTO_TCP:	 
			l4header.uh = ip_data(ip4);
			memcpy(l4header.uh, ip6_transp, pay_len);
			
			checksum_change(&(l4header.uh->check), &(l4header.uh->source), new_port,
					(ip4->protocol == IPPROTO_UDP) ? true : false);

			adjust_checksum_ipv6_to_ipv4(&(l4header.uh->check), ip6, ip4, 
					(ip4->protocol == IPPROTO_UDP) ? true : false);
			break;
		case IPPROTO_ICMPV6:
			l4header.icmph = ip_data(ip4);
			memcpy(l4header.icmph, ip6_transp, pay_len);

			if (l4header.icmph->type & ICMPV6_INFOMSG_MASK) {
				switch (l4header.icmph->type) {
					case ICMPV6_ECHO_REQUEST:
						l4header.icmph->type = ICMP_ECHO;
						break;
					case ICMPV6_ECHO_REPLY:
						l4header.icmph->type = ICMP_ECHOREPLY;
						break;
					default:
						pr_debug("NAT64: ICMPv6 not echo or reply");
						return false;
				}
			} else {
				pr_debug("NAT64: no other ICMP Protocols are supported yet.");
				pr_debug("NAT64: detected protocol %u", l4header.icmph->type);
				pr_debug("NAT64: detected protocol %u", l4header.icmph->code);
				return false;
			}

			l4header.icmph->checksum = 0;
			l4header.icmph->checksum = ip_compute_csum(l4header.icmph, pay_len);
			ip4->protocol = IPPROTO_ICMP;
			break;
		default:
			pr_debug("NAT64: encountered incompatible protocol while creating"
					" the outgoing skb");
			return false;
	}

	ip4->check = 0;
	ip4->check = ip_fast_csum(ip4, ip4->ihl);

	return true;
}

/*
 * Function nat64_get_skb is a generic entry function to get a new skb that will be sent.
 */
static struct sk_buff * nat64_get_skb(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	struct sk_buff *new_skb;

	u_int8_t pay_len = skb->data_len;
	u_int8_t packet_len, l4hdrlen, l3hdrlen;
	pr_debug("NAT64: get_skb paylen = %u", pay_len);

	/*
	 * It's assumed that if the l4 protocol is ICMP or ICMPv6, the size of the new
	 * header will be the other's.
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
		pr_debug("NAT64: Unknown layer 4 protocol detected in nat64_get_skb");
		return NULL;
	}

	/*
	 * We want to get the opposite Layer 3 protocol header length. We don't
	 * validate here if the l3 protocol is other than IPV4 or IPV6 since we
	 * already did that in the nat64_tg function.
	 */
	l3hdrlen = nat64_get_l3hdrlen(skb, (l3protocol == NFPROTO_IPV4) ? NFPROTO_IPV6 :
			NFPROTO_IPV4);

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
		return NULL;
	} else if (l3protocol == NFPROTO_IPV6) {
		if (nat64_getskb_from6to4(skb, new_skb, l3protocol, l4protocol, l3hdrlen,
					l4hdrlen, (l4hdrlen + pay_len))) {
			pr_debug("NAT64: Everything went OK populating the new sk_buff");
			return new_skb;
		} else {
			pr_debug("NAT64: something went wrong populating the new sk_buff");
			return NULL;
		}
	}

	pr_debug("NAT64: Not IPv4 or 6");
	return NULL;
}

/*
 * END: NAT64 shared functions.
 */


static bool nat64_determine_outgoing_tuple(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb)
{
	struct nf_conntrack_tuple outgoing;

	if (!(nat64_get_tuple(l3protocol, l4protocol, skb, &outgoing))) {
		pr_debug("NAT64: Something went wrong getting the tuple");
		return false;
	}
	
	return true;
}

static bool nat64_update_n_filter(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	struct sk_buff *new_skb;
	new_skb = nat64_get_skb(l3protocol, l4protocol, skb, inner);

	if (!new_skb) {
		pr_debug("NAT64: Skb allocation failed -- returned NULL");
		return false;
	}

	/*
	 * Adjust the layer 3 protocol variable to be used in the outgoing tuple.
	 * Wether it's IPV4 or IPV6 is already checked in the nat64_tg function.
	 */
	l3protocol = (l3protocol == NFPROTO_IPV4) ? NFPROTO_IPV6 : NFPROTO_IPV4;

	/*
	 * Adjust the layer 4 protocol variable to be used in the outgoing tuple.
	 */
	if (l4protocol == IPPROTO_ICMP) {
		l4protocol = IPPROTO_ICMPV6;
	} else if (l4protocol == IPPROTO_ICMPV6) {
		l4protocol = IPPROTO_ICMP;
	} else if (!(l4protocol & NAT64_IPV6_ALLWD_PROTOS)){
		pr_debug("NAT64: update n filter -> unkown L4 protocol");
		return false;
	}

	if (nat64_determine_outgoing_tuple(l3protocol, l4protocol, new_skb)) {
		pr_debug("NAT64: Determining the outgoing tuple stage went OK.");
		return true;
	} else {
		pr_debug("NAT64: Something went wrong in the Determining the outgoing tuple"
				" stage.");
		return false;
	}
}
/*
 * Function that gets the packet's information and returns a tuple out of it.
 */
static bool nat64_determine_tuple(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb)
{
	struct nf_conntrack_tuple inner;

	if (!(nat64_get_tuple(l3protocol, l4protocol, skb, &inner))) {
		pr_debug("NAT64: Something went wrong getting the tuple");
		return false;
	}

	if (nat64_update_n_filter(l3protocol, l4protocol, skb, &inner)) {
		pr_debug("NAT64: Updating and Filtering stage went OK.");
		return true;
	} else {
		pr_debug("NAT64: Something went wrong in the Updating and Filtering "
				"stage.");
		return false;
	}
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
	 * If the packet is not directed towards the NAT64 prefix, continue through
	 * the Netfilter rules.
	 */
	if (!nat64_tg6_cmp(&info->ip6dst.in6, &info->ip6dst_mask.in6, 
				&iph->daddr, info->flags))
		return NF_ACCEPT;

	if (l4_protocol & NAT64_IPV6_ALLWD_PROTOS) {
		if(nat64_determine_tuple(NFPROTO_IPV6, l4_protocol, skb))
			pr_debug("NAT64: Determining the tuple stage went OK.");
		else
			pr_debug("NAT64: Something went wrong in the determining the tuple"
					"stage.");
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
static unsigned int nat64_tg(struct sk_buff *skb, const struct xt_action_param *par)
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
