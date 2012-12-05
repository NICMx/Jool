#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <net/netfilter/nf_conntrack.h>

#include "xt_nat64_core.h"
#include "external_stuff.h"
#include "libxt_NAT64.h"
#include "nf_nat64_ipv6_hdr_iterator.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_session.h"
#include "nf_nat64_config.h"

#include "nf_nat64_determine_incoming_tuple.h"
#include "nf_nat64_outgoing.h"
#include "nf_nat64_translate_packet.h"
#include "nf_nat64_handling_hairpinning.h"
#include "nf_nat64_send_packet.h"


static bool handle_hairpin(struct sk_buff *skb_in, struct nf_conntrack_tuple *tuple_in,
		bool (*determine_outgoing_tuple_fn)(struct nf_conntrack_tuple *, struct nf_conntrack_tuple **),
		bool (*send_packet_fn)(struct sk_buff *))
{
	struct sk_buff *skb_out = NULL;
	struct nf_conntrack_tuple *tuple_out = NULL;

	pr_debug("Step 5: Handling Hairpinning...\n");

	if (!nat64_determine_incoming_tuple(skb_in, &tuple_in))
		goto failure;
	if (!nat64_filtering_and_updating(tuple_in))
		goto failure;
	if (!determine_outgoing_tuple_fn(tuple_in, &tuple_out)) // TODO esto también está mal.
		goto failure;
	if (!nat64_translating_the_packet(tuple_out, skb_in, &skb_out))
		goto failure;
	if (!send_packet_fn(skb_out)) // TODO esto está mal.
		goto failure;

	kfree(tuple_out);
	kfree_skb(skb_out);
	pr_debug("Done step 5.\n");
	return true;

failure:
	kfree(tuple_out);
	kfree_skb(skb_out);
	return false;
}

unsigned int nat64_core(struct sk_buff *skb_in,
		bool (*determine_outgoing_tuple_fn)(struct nf_conntrack_tuple *, struct nf_conntrack_tuple **),
		bool (*send_packet_fn)(struct sk_buff *))
{
	struct sk_buff *skb_out = NULL;
	struct nf_conntrack_tuple *tuple_in = NULL, *tuple_out = NULL;

	if (!nat64_determine_incoming_tuple(skb_in, &tuple_in))
		goto failure;
	if (!nat64_filtering_and_updating(tuple_in))
		goto failure;
	if (!determine_outgoing_tuple_fn(tuple_in, &tuple_out))
		goto failure;
	if (!nat64_translating_the_packet(tuple_out, skb_in, &skb_out))
		goto failure;
	if (nat64_got_hairpin(tuple_out)) {
		if (!handle_hairpin(skb_out, tuple_out, determine_outgoing_tuple_fn, send_packet_fn))
			goto failure;
	} else {
		if (!send_packet_fn(skb_out))
			goto failure;
	}

	pr_debug("Success.\n");
	kfree(tuple_out);
	kfree_skb(skb_out);
	return NF_DROP;

failure:
	pr_debug("Failure.\n");
	kfree(tuple_out);
	kfree_skb(skb_out);
	return NF_DROP;
}

unsigned int nat64_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *ip4_header = ip_hdr(skb);
	__u8 l4protocol = ip4_header->protocol;

	pr_debug("===============================================\n");
	pr_debug("Incoming IPv4 packet: %pI4->%pI4\n", &ip4_header->saddr, &ip4_header->daddr);

	// Validate.
	if (!nf_nat64_ipv4_pool_contains_addr(ip4_header->daddr)) {
		pr_info("Packet is not destined to me.\n");
	 	goto failure;
	}

	// TODO (warning) add header validations?

	if (l4protocol != IPPROTO_TCP && l4protocol != IPPROTO_UDP && l4protocol != IPPROTO_ICMP) {
		pr_info("Packet does not use TCP, UDP or ICMPv4.\n");
		goto failure;
	}

	// Set the skb's transport header pointer.
	// It's yet to be set because the packet hasn't reached the kernel's transport layer.
	// And despite that, we'll need it.
	skb_set_transport_header(skb, 4 * ip_hdr(skb)->ihl);

	return nat64_core(skb,
			&nat64_determine_outgoing_tuple_4to6,
			&nat64_send_packet_ipv6);

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

	pr_debug("===============================================\n");
	pr_debug("Incoming IPv6 packet: %pI6c->%pI6c\n", &ip6_header->saddr, &ip6_header->daddr);

	if (!nf_nat64_ipv6_pool_contains_addr(&ip6_header->daddr)) {
		pr_info("Packet is not destined to me.\n");
		goto failure;
	}

	// TODO (warning) add header validations?

	if (l4protocol != NEXTHDR_TCP && l4protocol != NEXTHDR_UDP && l4protocol != NEXTHDR_ICMP) {
		pr_info("Packet does not use TCP, UDP or ICMPv6.\n");
		goto failure;
	}

	// Set the skb's transport header pointer.
	// It's yet to be set because the packet hasn't reached the kernel's transport layer.
	// And despite that, we'll need it.
	skb_set_transport_header(skb, iterator.data - (void *) ip6_header);

	return nat64_core(skb,
			&nat64_determine_outgoing_tuple_6to4,
			&nat64_send_packet_ipv4);

failure:
	return NF_ACCEPT;
}

int nat64_tg_check(const struct xt_tgchk_param *par)
{
//	int ret = nf_ct_l3proto_try_module_get(par->family);
//	if (ret < 0)
//		pr_info("cannot load support for proto=%u\n\n", par->family);
//	return ret;

	pr_info("Check function.\n");
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

	pr_debug("%sInserting NAT64 module...\n", banner);

	need_conntrack();
	need_ipv4_conntrack();

	nat64_load_default_config();
	nat64_bib_init();
	nat64_session_init();
	nat64_determine_incoming_tuple_init();

	result = xt_register_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));
	if (result == 0)
		pr_debug("Ok, success.\n");
	return result;
}

void __exit nat64_exit(void)
{
	xt_unregister_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));

	nat64_determine_incoming_tuple_destroy();
	nat64_session_destroy();
	nat64_bib_destroy();

	pr_debug("NAT64 module removed.\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM"); // TODO (later) decidir quienes van a ir aquí?
MODULE_DESCRIPTION("\"NAT64\" (RFC 6146)");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

module_init(nat64_init);
module_exit(nat64_exit);
