#include "xt_nat64_core.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_conntrack.h>

#include "libxt_NAT64.h"
#include "nf_nat64_ipv6_hdr_iterator.h"
#include "nf_nat64_ipv4_pool.h"
#include "nf_nat64_pool6.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_session.h"
#include "nf_nat64_config.h"

#include "nf_nat64_determine_incoming_tuple.h"
#include "nf_nat64_filtering_and_updating.h"
#include "nf_nat64_outgoing.h"
#include "nf_nat64_translate_packet.h"
#include "nf_nat64_handling_hairpinning.h"
#include "nf_nat64_send_packet.h"


unsigned int nat64_core(struct sk_buff *skb_in,
		bool (*compute_outgoing_fn)(struct nf_conntrack_tuple *in, struct sk_buff *skb_in,
				struct nf_conntrack_tuple *out),
		bool (*translate_packet_fn)(struct nf_conntrack_tuple *, struct sk_buff *,
				struct sk_buff **),
		bool (*send_packet_fn)(struct sk_buff *))
{
	struct sk_buff *skb_out = NULL;
	struct nf_conntrack_tuple *tuple_in = NULL, tuple_out;

	if (!nat64_determine_incoming_tuple(skb_in, &tuple_in))
		goto free_and_fail;
	if (!filtering_and_updating(skb_in, tuple_in) != NF_ACCEPT)
		goto free_and_fail;
	if (!compute_outgoing_fn(tuple_in, skb_in, &tuple_out))
		goto free_and_fail;
	if (!translate_packet_fn(&tuple_out, skb_in, &skb_out))
		goto free_and_fail;
	if (nat64_got_hairpin(&tuple_out)) {
		if (!nat64_handling_hairpinning(skb_out, &tuple_out))
			goto free_and_fail;
	} else {
		if (!send_packet_fn(skb_out))
			goto fail;
	}

	log_debug("Success.");
	return NF_DROP;

free_and_fail:
	kfree_skb(skb_out);
	// Fall through.

fail:
	log_debug("Failure.");
	return NF_DROP;
}

unsigned int nat64_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *ip4_header = ip_hdr(skb);
	__u8 l4protocol = ip4_header->protocol;
	struct in_addr daddr_aux;

	log_debug("===============================================");
	log_debug("Incoming IPv4 packet: %pI4->%pI4", &ip4_header->saddr, &ip4_header->daddr);

	// Validate.
	daddr_aux.s_addr = ip4_header->daddr;
	if (!pool4_contains(&daddr_aux)) {
		log_info("Packet is not destined to me.");
	 	goto failure;
	}

	// TODO (warning) add header validations?

	if (l4protocol != IPPROTO_TCP && l4protocol != IPPROTO_UDP && l4protocol != IPPROTO_ICMP) {
		log_info("Packet does not use TCP, UDP or ICMPv4.");
		goto failure;
	}

	// Set the skb's transport header pointer.
	// It's yet to be set because the packet hasn't reached the kernel's transport layer.
	// And despite that, its availability will be appreciated.
	skb_set_transport_header(skb, 4 * ip_hdr(skb)->ihl);

	return nat64_core(skb,
			compute_outgoing_tuple_4to6,
			nat64_translating_the_packet_4to6,
			nat64_send_packet_ipv6);

failure:
	return NF_ACCEPT;
}

unsigned int nat64_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ip6_header = ipv6_hdr(skb);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_header);
	enum hdr_iterator_result iterator_result;
	__u8 l4protocol;

	log_debug("===============================================");
	log_debug("Incoming IPv6 packet: %pI6c->%pI6c", &ip6_header->saddr, &ip6_header->daddr);

	// Validate.
	if (!pool6_contains(&ip6_header->daddr)) {
		log_info("Packet is not destined to me.");
		goto failure;
	}

	iterator_result = hdr_iterator_last(&iterator);
	switch (iterator_result) {
	case HDR_ITERATOR_SUCCESS:
		log_crit("Programming error: I was supposed to reach the packet's payload, "
				"but iterator reports there are more headers left. o_o");
		goto failure;
	case HDR_ITERATOR_END:
		l4protocol = iterator.hdr_type;
		break;
	case HDR_ITERATOR_UNSUPPORTED:
		log_info("Packet contains an Authentication or ESP header, which I do not support.");
		goto failure;
	case HDR_ITERATOR_OVERFLOW:
		log_warning("IPv6 extension header analysis ran past the end of the packet. "
				"Packet seems corrupted; ignoring.");
		goto failure;
	default:
		log_crit("Unknown header iterator result code: %d.", iterator_result);
		goto failure;
	}

	switch (l4protocol) {
	case NEXTHDR_TCP:
		if (iterator.data + tcp_hdrlen(skb) > iterator.limit) {
			log_warning("TCP header does not fit in the packet. Packet seems corrupted; ignoring.");
			goto failure;
		}
		break;

	case NEXTHDR_UDP: {
		struct udphdr *hdr = iterator.data;
		if (iterator.data + sizeof(struct udphdr) > iterator.limit) {
			log_warning("UDP header does not fit in the packet. Packet seems corrupted; ignoring.");
			goto failure;
		}
		if (iterator.data + be16_to_cpu(hdr->len) > iterator.limit) {
			log_warning("UDP header + payload do not fit in the packet. Packet seems corrupted; ignoring.");
			goto failure;
		}
		break;
	}

	case NEXTHDR_ICMP: {
		struct icmp6hdr *hdr = iterator.data;
		if (iterator.data + sizeof(*hdr) > iterator.limit) {
			log_warning("ICMP header does not fit in the packet. Packet seems corrupted; ignoring.");
			goto failure;
		}
		break;
	}

	default:
		log_info("Packet does not use TCP, UDP or ICMPv6.");
		goto failure;
	}

	// Set the skb's transport header pointer.
	// It's yet to be set because the packet hasn't reached the kernel's transport layer.
	// And despite that, its availability will be appreciated.
	skb_set_transport_header(skb, iterator.data - (void *) ip6_header);

	return nat64_core(skb,
			compute_outgoing_tuple_6to4,
			nat64_translating_the_packet_6to4,
			nat64_send_packet_ipv4);

failure:
	return NF_ACCEPT;
}

int nat64_tg_check(const struct xt_tgchk_param *par)
{
//	int ret = nf_ct_l3proto_try_module_get(par->family);
//	if (ret < 0)
//		log_info("cannot load support for proto=%u", par->family);
//	return ret;

	log_info("Check function.");
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

	log_debug("%s", banner);
	log_debug("Inserting the module...");

	need_conntrack();
	need_ipv4_conntrack();

	if (!nat64_config_init())
		return false;
	if (!pool6_init())
		return false;
	if (!pool4_init())
		return false;
	nat64_bib_init();
	nat64_session_init();
	if (!nat64_determine_incoming_tuple_init())
		return false;
	if (!translate_packet_init())
		return false;

	result = xt_register_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));
	if (result == 0)
		log_debug("Ok, success.");
	return result;
}

void __exit nat64_exit(void)
{
	xt_unregister_targets(nat64_tg_reg, ARRAY_SIZE(nat64_tg_reg));

	translate_packet_destroy();
	nat64_determine_incoming_tuple_destroy();
	nat64_session_destroy();
	nat64_bib_destroy();
	pool4_destroy();
	pool6_destroy();
	nat64_config_destroy();

	log_debug("NAT64 module removed.");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM"); // TODO (later) decidir quienes van a ir aquí?
MODULE_DESCRIPTION("\"NAT64\" (RFC 6146)");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

module_init(nat64_init);
module_exit(nat64_exit);
