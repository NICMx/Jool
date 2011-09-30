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
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>

#include "nf_nat64_bib.h"
#include "nf_nat64_tuple.h"
#include "xt_nat64.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan Antonio Osorio <jaosorior@gmail.com>");
MODULE_DESCRIPTION("Xtables: RFC 6146 \"NAT64\" implementation");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

static bool nat64_tg6_cmp(struct ipv6hdr *iph, const struct xt_nat64_tginfo *info)
{
	pr_debug("\n* ICNOMING IPV6 PACKET COMPARISON *\n");
	pr_debug("PKT SRC=%pI6 \n", &iph->saddr);
	pr_debug("PKT DST=%pI6 \n", &iph->daddr);

	if (info->flags & XT_NAT64_IPV6_DST) {
		pr_debug("RULE DST=%pI6 \n", &info->ip6dst.in6);
		pr_debug("RULE DST_MSK=%pI6 \n", &info->ip6dst_mask.in6);

		if (ipv6_masked_addr_cmp(&info->ip6dst.in6, &info->ip6dst_mask.in6,
					&iph->saddr) != 0) 
			pr_debug("Comparison returned true\n");
			return true;
	}

	pr_debug("Comparison returned false\n");
	return false;
}

static unsigned int nat64_tg_icmp(struct sk_buff *skb, const struct xt_action_param *par)
{
	//const struct xt_nat64_tginfo *info = par->targinfo;
	struct iphdr *iph = ip_hdr(skb);
	//struct nf_nat_range range = {};
	//struct nf_conn *ct;

	/* for debugging */
	//ct = nf_ct_get(skb, &ctinfo);
	/* 
	 * For an IPv4 packet to enter a connection needs to be attached to it
	 * already
	 */
	//NF_CT_ASSERT(ct != NULL && (ctinfo == IP_CT_RELATED));
	//range.flags = IP_NAT_RANGE_MAP_IPS;
	//range.min_ip = ntohl(iph->saddr) & 

	pr_debug("\n* ICNOMING IPV4 PACKET *\n");
	pr_debug("Drop it\n");
	pr_debug("Protocol: ");

	if (iph->protocol == IPPROTO_TCP)
		pr_debug("TCP\n");
	else if (iph->protocol == IPPROTO_UDP)
		pr_debug("UDP\n");
	else if (iph->protocol == IPPROTO_ICMP)
		pr_debug("ICMP\n");

	return NF_DROP;
}

static unsigned int nat64_tg_icmpv6(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_nat64_tginfo *info = par->targinfo;
	struct ipv6hdr *iph = ipv6_hdr(skb);
	//struct nf_conn *ct;
	bool accept = nat64_tg6_cmp(iph, info);

	if (!accept)
		return NF_DROP;

	pr_debug("Protocol: ");

	if (iph->nexthdr == IPPROTO_TCP)
		pr_debug("TCP\n");
	else if (iph->nexthdr == IPPROTO_UDP)
		pr_debug("UDP\n");
	else if (iph->nexthdr == IPPROTO_ICMP)
		pr_debug("ICMP\n");
	else if (iph->nexthdr == IPPROTO_ICMPV6)
		pr_debug("ICMPV6\n");
	else
		return NF_DROP;

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

static struct xt_target nat64_tg_reg[] __read_mostly = {
	{
		.name = "nat64",
		.revision = 0,
		.target = nat64_tg_icmp,
		.checkentry = nat64_tg_check,
		.family = NFPROTO_IPV4,
		.table = "mangle",
		.hooks = (1 << NF_INET_PRE_ROUTING),
		.targetsize = sizeof(struct xt_nat64_tginfo),
		.me = THIS_MODULE,
	},
	{
		.name = "nat64",
		.revision = 0,
		.target = nat64_tg_icmpv6,
		.checkentry = nat64_tg_check,
		.family = NFPROTO_IPV6,
		.table = "mangle",
		.hooks = (1 << NF_INET_PRE_ROUTING),
		.targetsize = sizeof(struct xt_nat64_tginfo),
		.me = THIS_MODULE,
	},
};

static int __init nat64_init(void)
{
	return xt_register_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));
}

static void __exit nat64_exit(void)
{
	xt_unregister_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));
}

module_init(nat64_init);
module_exit(nat64_exit);
