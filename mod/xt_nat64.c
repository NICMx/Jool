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

static struct nf_conntrack_l3proto *l3proto_ip __read_mostly;
static struct nf_conntrack_l3proto *l3proto_ipv6 __read_mostly;

/*
 * IPv6 comparison function. It's use as a call from nat64_tg6 is to compare
 * the incoming packet's ip with the rule's ip, and so when the module is in
 * debugging mode it prints the rule's IP.
 */
static bool nat64_tg6_cmp(const struct in6_addr * ip_a, const struct in6_addr * ip_b,
		const struct in6_addr * ip_mask, __u8 flags)
{

	if (flags & XT_NAT64_IPV6_DST) {
		if (ipv6_masked_addr_cmp(ip_a, ip_mask, ip_b) != 0) 
			pr_debug("NAT64: IPv6 comparison returned true\n");
			return true;
	}

	pr_debug("NAT64: IPv6 comparison returned false\n");
	return false;
}

static bool nat64_determine_tuple(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb)
{
	const struct nf_conntrack_l4proto *l4proto;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_tuple inner;
	int l3_hdrlen, ret;
	unsigned int protoff;
	u_int8_t protonum;

	if (l3protocol == NFPROTO_IPV4) {
		l3proto = l3proto_ip;
		l3_hdrlen = ip_hdrlen(skb);
	} else {
		l3proto = l3proto_ipv6;
		l3_hdrlen = IPV6_HDRLEN;
	}

	rcu_read_lock();

	if (l4protocol == IPPROTO_TCP) {
		l3_hdrlen +=  skb_network_offset(skb) + sizeof(struct tcphdr);
	} else if (l4protocol == IPPROTO_UDP) {
		l3_hdrlen +=  skb_network_offset(skb) + sizeof(struct udphdr);
	} else if (l4protocol == IPPROTO_ICMP) {
		l3_hdrlen +=  skb_network_offset(skb) + sizeof(struct icmphdr);
	} else if (l4protocol == IPPROTO_ICMPV6) {
		l3_hdrlen +=  skb_network_offset(skb) + sizeof(struct icmp6hdr);
	} else {
		rcu_read_unlock();
		return false;
	}

	if (l3protocol == NFPROTO_IPV4)
		ret = l3proto_ip->get_l4proto(skb, l3_hdrlen, &protoff, &protonum);
	else if (l3protocol == NFPROTO_IPV6)
		ret = l3proto_ipv6->get_l4proto(skb, l3_hdrlen, &protoff, &protonum);
	
	if (ret != NF_ACCEPT) {
		rcu_read_unlock();
		return false;
	} else if (protonum != l4protocol) {
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3protocol, l4protocol);



	if (!nf_ct_get_tuple(skb, l3_hdrlen,
				protoff, (u_int16_t)l3protocol, l4protocol,
				&inner, l3proto, l4proto)) {
		rcu_read_unlock();
		return false;
	}

	pr_debug("NAT64: Determining the tuple OK");

	rcu_read_unlock();
	return true;
}

/*
 * IPv4 entry function
 *
 */
static unsigned int nat64_tg4(struct sk_buff *skb, const struct xt_action_param *par)
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
static unsigned int nat64_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	union nf_inet_addr;
	const struct xt_nat64_tginfo *info = par->targinfo;
	struct ipv6hdr *iph = ipv6_hdr(skb);
	__u8 l4_protocol = iph->nexthdr;

	pr_debug("\n* ICNOMING IPV6 PACKET *\n");
	pr_debug("PKT SRC=%pI6 \n", &iph->saddr);
	pr_debug("PKT DST=%pI6 \n", &iph->daddr);
	pr_debug("RULE DST=%pI6 \n", &info->ip6dst.in6);
	pr_debug("RULE DST_MSK=%pI6 \n", &info->ip6dst_mask);

	if (!nat64_tg6_cmp(&info->ip6dst.in6, &info->ip6dst_mask.in6, &iph->saddr, info->flags))
		return NF_DROP;

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
	 * IPv4 conntrack is needed in order to handle complete packets, and not
	 * fragments.
	 */
	need_ipv4_conntrack();

	l3proto_ip = nf_ct_l3proto_find_get((u_int16_t)NFPROTO_IPV4);
	l3proto_ipv6 = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV6);

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
