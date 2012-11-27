#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/ip.h>

#include <net/netfilter/nf_conntrack.h>

#include "xt_nat64_core.h"
#include "external_stuff.h"
#include "libxt_NAT64.h"
#include "nf_nat64_ipv6_hdr_iterator.h"

#include "nf_nat64_outgoing.h"
#include "nf_nat64_translate_packet.h"


unsigned int nat64_core(struct sk_buff *skb_in)
{
	struct sk_buff *skb_out = NULL;
	struct nf_conntrack_tuple *tuple_in = NULL, *tuple_out = NULL;

	if (!nat64_determine_incoming_tuple(skb_in, &tuple_in))
		goto failure;
	if (!nat64_filtering_and_updating(tuple_in))
		goto failure;
	if (!nat64_determine_outgoing_tuple(tuple_in, &tuple_out))
		goto failure;
	if (!nat64_translating_the_packet(tuple_out, skb_in, &skb_out))
		goto failure;
	if (!nat64_hairpinning_and_handling(tuple_out, skb_out))
		goto failure;
	if (!nat64_send_packet(skb_out))
		goto failure;

	// TODO (warning) no hay qeu liberar skb_out o in?
	printk(KERN_DEBUG "Success.");

	kfree(tuple_out);
	return NF_DROP;

failure:
	printk(KERN_DEBUG "Failed.");

	kfree_skb(skb_out);
	kfree(tuple_out);
	return NF_DROP;
}

unsigned int nat64_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *ip4_header = ip_hdr(skb);
	__u8 l4protocol = ip4_header->protocol;

	printk(KERN_DEBUG "Incoming IPv4 packet: %pI4->%pI4", &ip4_header->saddr, &ip4_header->daddr);

	// Validate.
	if (skb->len < sizeof(struct iphdr) || ip4_header->version != 4)
		goto failure;

	if (!nf_nat64_ipv4_pool_contains_addr(ip4_header->daddr))
	 	goto failure;

	// TODO (fine) add header validations?

	if (l4protocol != IPPROTO_TCP && l4protocol != IPPROTO_UDP && l4protocol != IPPROTO_ICMP)
		goto failure;

	return nat64_core(skb);

failure:
	return NF_ACCEPT;
}

unsigned int nat64_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ip6_header = ipv6_hdr(skb);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_header);
	__u8 l4protocol;

	hdr_iterator_last(&iterator);
	l4protocol = iterator.hdr_type;

	printk(KERN_DEBUG "Incoming IPv6 packet: %pI6c->%pI6c", &ip6_header->saddr, &ip6_header->daddr);

	if (nf_nat64_ipv6_pool_contains_addr(&ip6_header->daddr))
		goto failure;

	// TODO (fine) add header validations?

	if (l4protocol != NEXTHDR_TCP && l4protocol != NEXTHDR_UDP && l4protocol != NEXTHDR_ICMP)
		goto failure;

	return nat64_core(skb);

failure:
	return NF_ACCEPT;
}

int nat64_tg_check(const struct xt_tgchk_param *par)
{
//	int ret = nf_ct_l3proto_try_module_get(par->family);
//	if (ret < 0)
//		pr_info("cannot load support for proto=%u\n", par->family);
//	return ret;

	printk(KERN_INFO "Check function.");
	return 0;
}

static struct xt_target nat64_tg_reg[] __read_mostly = {
	{
		.name = MODULE_NAME,
		.revision = 0,
		.family = NFPROTO_IPV4,
		.table = "mangle",
		.target = nat64_tg4,
		.checkentry = nat64_tg_check,
		.hooks = (1 << NF_INET_PRE_ROUTING),
		.me = THIS_MODULE,
	},
	{
		.name = MODULE_NAME,
		.revision = 0,
		.family = NFPROTO_IPV6,
		.table = "mangle",
		.target = nat64_tg6,
		.checkentry = nat64_tg_check,
		.hooks = (1 << NF_INET_PRE_ROUTING),
		.me = THIS_MODULE,
	}
};

int __init nat64_init(void)
{
	int result;

	printk(KERN_DEBUG "Inserting NAT64 module...");
	// need_conntrack();
	// need_ipv4_conntrack();

	result = xt_register_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));

	if (result == 0)
		printk(KERN_DEBUG "Ok, success.");
	return result;
}

void __exit nat64_exit(void)
{
	xt_unregister_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));
	printk(KERN_DEBUG "NAT64 module removed.");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM"); // TODO (later) decidir quienes van a ir aquí?
MODULE_DESCRIPTION("\"NAT64\" (RFC 6146)");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

module_init(nat64_init);
module_exit(nat64_exit);
