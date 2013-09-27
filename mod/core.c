#include "nat64/mod/core.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/packet_db.h"
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


static unsigned int core_common(struct sk_buff *skb_in)
{
	struct packet *pkt_in = NULL;
	struct packet pkt_out;
	struct tuple tuple_in;
	struct tuple tuple_out;
	enum verdict result;

	result = pkt_from_skb(skb_in, &pkt_in);
	if (result != VER_CONTINUE)
		return result;

	memset(&pkt_out, 0, sizeof(pkt_out));

	/*
	if (!determine_in_tuple(skb_in, &tuple_in))
		goto free_and_fail;
	*/
	/*
	if (filtering_and_updating(skb_in, &tuple_in) != NF_ACCEPT)
		goto free_and_fail;
	*/
	result = compute_out_tuple(&tuple_in, pkt_in, &tuple_out);
	if (result != VER_CONTINUE)
		goto fail;
	result = translating_the_packet(&tuple_out, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;
	if (is_hairpin(&tuple_out)) {
		/*
		if (!handling_hairpinning(skb_out, &tuple_out))
			goto free_and_fail;
		*/
	} else {
		result = send_pkt(&pkt_out);
		if (result != VER_CONTINUE)
			goto fail;
	}

	log_debug("Success.");
	return NF_DROP; /* Lol, the irony. */

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	log_debug("Failure.");
	return result;
}

/**
 * Entry point for IPv4 packet processing.
 */
unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *ip4_header;
	struct in_addr daddr;

	skb_linearize(skb);

	ip4_header = ip_hdr(skb);

	daddr.s_addr = ip4_header->daddr;
	if (!pool4_contains(&daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &ip4_header->saddr, &ip4_header->daddr);

	return core_common(skb);
}

/**
 * Entry point for IPv6 packet processing.
 */
unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *ip6_header;

	skb_linearize(skb);

	ip6_header = ipv6_hdr(skb);

	if (!pool6_contains(&ip6_header->daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &ip6_header->saddr, &ip6_header->daddr);

	return core_common(skb);
}
