#include "nat64/mod/core.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/send_packet.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <linux/icmp.h>
#include <net/icmp.h>



static unsigned int nat64_core(struct sk_buff *skb_in,
		bool (*compute_out_tuple_fn)(struct tuple *, struct sk_buff *, struct tuple *),
		bool (*translate_packet_fn)(struct tuple *, struct sk_buff *, struct sk_buff **),
		bool (*send_packet_fn)(struct sk_buff *, struct sk_buff *))
{
	struct sk_buff *skb_out = NULL;
	struct tuple tuple_in, tuple_out;
	int nf_result;

	if (!determine_in_tuple(skb_in, &tuple_in))
		goto free_and_fail;

	nf_result = filtering_and_updating(skb_in, &tuple_in);
	switch(nf_result){
	case NF_DROP:
		goto free_and_fail;
	case NF_STOLEN:
		log_debug("The packet was stored.");
		return NF_STOLEN;
	}

	if (!compute_out_tuple_fn(&tuple_in, skb_in, &tuple_out))
		goto free_and_fail;
	if (!translate_packet_fn(&tuple_out, skb_in, &skb_out))
		goto free_and_fail;
	if (is_hairpin(&tuple_out)) {
		if (!handling_hairpinning(skb_out, &tuple_out))
			goto free_and_fail;
	} else {
		if (!send_packet_fn(skb_in, skb_out))
			goto fail;
	}

	log_debug("Success.");
	return NF_DROP; /* Lol, the irony. */

free_and_fail:
	kfree_skb(skb_out);
	/* Fall through. */

fail:
	log_debug("Failure.");
	return NF_DROP;
}

unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *ip4_header;
	struct in_addr daddr;
	enum verdict result;

	skb_linearize(skb);

	ip4_header = ip_hdr(skb);

	daddr.s_addr = ip4_header->daddr;
	if (!pool4_contains(&daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &ip4_header->saddr, &ip4_header->daddr);

	result = validate_skb_ipv4(skb);
	if (result != VER_CONTINUE)
		return result;

	return nat64_core(skb,
			compute_out_tuple_4to6,
			translating_the_packet_4to6,
			send_packet_ipv6);
}

unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *ip6_header;
	enum verdict result;

	skb_linearize(skb);

	ip6_header = ipv6_hdr(skb);

	if (!pool6_contains(&ip6_header->daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &ip6_header->saddr, &ip6_header->daddr);

	result = validate_skb_ipv6(skb);
	if (result != VER_CONTINUE)
		return result;

	return nat64_core(skb,
			compute_out_tuple_6to4,
			translating_the_packet_6to4,
			send_packet_ipv4);
}
