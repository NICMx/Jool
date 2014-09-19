#include "nat64/mod/core.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/fragment_db.h"
#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/ttp/core.h"
#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/stats.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


static unsigned int core_common(struct sk_buff *skb_in)
{
	struct sk_buff *skb_out;
	struct tuple tuple_in;
	struct tuple tuple_out;
	verdict result;
	int field = 0;

	result = determine_in_tuple(skb_in, &tuple_in);
	if (result != VER_CONTINUE)
		goto end;
	result = filtering_and_updating(skb_in, &tuple_in);
	if (result != VER_CONTINUE)
		goto end;
	result = compute_out_tuple(&tuple_in, &tuple_out, &field);
	if (result != VER_CONTINUE) {
		inc_stats(skb_in, field);
		goto end;
	}
	result = translating_the_packet(&tuple_out, skb_in, &skb_out);
	if (result != VER_CONTINUE)
		goto end;

	if (is_hairpin(skb_out)) {
		result = handling_hairpinning(skb_out, &tuple_out);
		kfree_skb(skb_out);
	} else {
		result = send_pkt(skb_out);
		/* send_pkt releases skb_out regardless of verdict. */
	}

	if (result != VER_CONTINUE)
		goto end;

	log_debug("Success.");
	/* The new packet was sent, so the original one can die; drop it. */
	result = VER_DROP;
	/* Fall through. */

end:
	if (result == VER_DROP)
		kfree_skb_queued(skb_in);
	return NF_STOLEN;
}

unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *hdr = ip_hdr(skb);
	struct in_addr daddr;
	struct sk_buff *skbs;
	int error;
	verdict result;

	daddr.s_addr = hdr->daddr;
	if (!pool4_contains(&daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	error = skb_linearize(skb);
	if (error) {
		log_debug("Packet linearization failed with error code %u; cannot translate.", error);
		return NF_DROP;
	}

	/* Do not use hdr or daddr from now on. */

	/*
	 * I'm assuming the control buffer is empty, and therefore I can throw my crap at it happily.
	 * Though common sense dictates any Netfilter module should not have to worry about leftover
	 * CB garbage, I do not see any confirmation (formal or otherwise) of this anywhere.
	 * Any objections?
	 */
	error = skb_init_cb_ipv4(skb);
	if (error)
		return NF_DROP;

	result = fragment_arrives(skb, &skbs);
	if (result != VER_CONTINUE)
		return (unsigned int) result;

	error = validate_icmp4_csum(skbs);
	if (error) {
		inc_stats(skbs, IPSTATS_MIB_INHDRERRORS);
		kfree_skb_queued(skbs);
		return NF_STOLEN;
	}

	return core_common(skbs);
}

unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	struct sk_buff *skbs;
	int error;
	verdict result;

	if (!pool6_contains(&hdr->daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &hdr->saddr, &hdr->daddr);

	error = skb_linearize(skb);
	if (error) {
		log_debug("Packet linearization failed with error code %u; cannot translate.", error);
		return NF_DROP;
	}

	/* See respective comments above. */
	error = skb_init_cb_ipv6(skb);
	if (error)
		return NF_DROP;

	result = fragment_arrives(skb, &skbs);
	if (result != VER_CONTINUE)
		return (unsigned int) result;

	error = validate_icmp6_csum(skbs);
	if (error) {
		inc_stats(skbs, IPSTATS_MIB_INHDRERRORS);
		kfree_skb_queued(skbs);
		return NF_STOLEN;
	}

	return core_common(skbs);
}
