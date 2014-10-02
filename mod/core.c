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

	result = determine_in_tuple(skb_in, &tuple_in);
	if (result != VER_CONTINUE)
		goto end;
	result = filtering_and_updating(skb_in, &tuple_in);
	if (result != VER_CONTINUE)
		goto end;
	result = compute_out_tuple(&tuple_in, &tuple_out, skb_in);
	if (result != VER_CONTINUE)
		goto end;
	result = translating_the_packet(&tuple_out, skb_in, &skb_out);
	if (result != VER_CONTINUE)
		goto end;

	if (is_hairpin(skb_out)) {
		result = handling_hairpinning(skb_out, &tuple_out);
		kfree_skb_queued(skb_out);
	} else {
		result = sendpkt_send(skb_in, skb_out);
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

/**
 * Just random paranoia.
 *
 * We can most likely trust the kernel in sending us healthy skb structures, but nobody out there
 * audits every potentially existing kernel module a random user might queue before Jool.
 *
 * If it's going to crash horribly, it better not be Jool's fault.
 */
static int ensure_good_citizens(struct sk_buff *skb)
{
	if (skb->prev || skb->next) {
		/*
		 * Jool uses prev and next heavily (and somewhat unlike the rest of the kernel),
		 * so if the packet is already in a list with some other purpose, crashing is inevitable.
		 */
		log_warn_once("Packet is listed; I'm going to ignore it.");
		return -EINVAL;
	}

	return 0;
}

static int linearize(struct sk_buff *skb)
{
	int error;

	error = skb_linearize(skb);
	if (error) {
		log_debug("Packet linearization failed with error code %u; cannot translate.", error);
		inc_stats(skb, IPSTATS_MIB_INDISCARDS);
		return error;
	}

	return 0;
}

unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *hdr = ip_hdr(skb);
	struct sk_buff *skbs;
	int error;
	verdict result;

	if (!pool4_contains(hdr->daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	if (ensure_good_citizens(skb) != 0)
		return NF_ACCEPT;
	if (linearize(skb) != 0) /* Do not use hdr from now on. */
		return NF_DROP;

	error = skb_init_cb_ipv4(skb);
	if (error)
		return NF_DROP;

	result = fragdb_handle4(skb, &skbs);
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

	if (ensure_good_citizens(skb) != 0)
		return NF_ACCEPT;
	if (linearize(skb) != 0) /* Do not use hdr from now on. */
		return NF_DROP;

	error = skb_init_cb_ipv6(skb);
	if (error)
		return NF_DROP;

	result = fragdb_handle6(skb, &skbs);
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
