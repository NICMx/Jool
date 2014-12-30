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
		kfree_skb(skb_out);
	} else {
		result = sendpkt_send(skb_in, skb_out);
		/* send_pkt releases skb_out regardless of verdict. */
	}

	if (result != VER_CONTINUE)
		goto end;

	log_debug("Success.");
	/*
	 * The new packet was sent, so the original one can die; drop it.
	 *
	 * NF_DROP translates into an error (see nf_hook_slow()).
	 * Sending a replacing & translated version of the packet should not count as an error,
	 * so we free the incoming packet ourselves and return NF_STOLEN on success.
	 */
	kfree_skb(skb_in);
	result = VER_STOLEN;
	/* Fall through. */

end:
	return (unsigned int) result;
}

unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *hdr = ip_hdr(skb);
	int error;

	if (!pool4_contains(hdr->daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	if (WARN(skb_shared(skb), "The packet is shared!")) {
		/*
		 * Apparently, as of 2007, Netfilter modules can assume they are the sole owners of their
		 * skbs.
		 * I can sort of confirm it by noticing that if it's not the case, editing the sk_buff
		 * structs themselves would be impossible (since they'd have to operate on a clone, and
		 * there's no way to bounce back that clone to Netfilter).
		 * Therefore, I think this WARN is fair.
		 */
		return NF_DROP;
	}

	error = skb_init_cb_ipv4(skb);
	if (error)
		return NF_DROP;

	error = validate_icmp4_csum(skb);
	if (error) {
		inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
		skb_clear_cb(skb);
		return NF_DROP;
	}

	return core_common(skb);
}

unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	int error;
	verdict result;

	if (!pool6_contains(&hdr->daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &hdr->saddr, &hdr->daddr);

	if (WARN(skb_shared(skb), "The packet is shared!"))
		return NF_DROP; /* See the corresponding comment in core_4to6(). */

	error = skb_init_cb_ipv6(skb);
	if (error)
		return NF_DROP;

	result = fragdb_handle(&skb);
	if (result != VER_CONTINUE)
		return (unsigned int) result;

	error = validate_icmp6_csum(skb);
	if (error) {
		inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
		skb_clear_cb(skb);
		return NF_DROP;
	}

	return core_common(skb);
}
