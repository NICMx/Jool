#include "nat64/mod/core.h"
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
	result = compute_out_tuple(&tuple_in, &tuple_out);
	if (result != VER_CONTINUE)
		goto end;
	result = translating_the_packet(&tuple_out, skb_in, &skb_out);
	if (result != VER_CONTINUE)
		goto end;

	if (is_hairpin(skb_out)) {
		/*
		 * Note: There's no risk of skb_out being fragmented here,
		 * because only outgoing IPv6 packets get fragmented,
		 * and only outgoing IPv4 packets can hairpin.
		 */
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
	return (unsigned int) result;
}

unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *hdr;
	struct in_addr daddr;

	skb_linearize(skb);

	hdr = ip_hdr(skb);

	daddr.s_addr = hdr->daddr;
	if (!pool4_contains(&daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	/*
	 * I'm assuming the control buffer is empty, and therefore I can throw my crap at it happily.
	 * Though common sense dictates any Netfilter module should not have to worry about leftover
	 * CB garbage, I do not see any confirmation (formal or otherwise) of this anywhere.
	 * Any objections?
	 */
	if (skb_init_cb_ipv4(skb) != 0)
		return NF_DROP;
	if (fix_checksums_ipv4(skb) != 0)
		return NF_DROP;

	return core_common(skb);
}

unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *hdr;

	skb_linearize(skb);

	hdr = ipv6_hdr(skb);

	if (!pool6_contains(&hdr->daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &hdr->saddr, &hdr->daddr);

	/* See respective comment above. */
	if (skb_init_cb_ipv6(skb) != 0)
		return NF_DROP;
	if (fix_checksums_ipv6(skb) != 0)
		return NF_DROP;

	return core_common(skb);
}
