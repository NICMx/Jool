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

	if (determine_in_tuple(skb_in, &tuple_in) != VER_CONTINUE)
		goto end;
	if (filtering_and_updating(skb_in, &tuple_in) != VER_CONTINUE)
		goto end;
	if (compute_out_tuple(&tuple_in, &tuple_out) != VER_CONTINUE)
		goto end;
	if (translating_the_packet(&tuple_out, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	if (is_hairpin(skb_out)) {
		verdict result = handling_hairpinning(skb_out, &tuple_out);
		kfree_skb(skb_out);
		if (result != VER_CONTINUE)
			goto end;
	} else {
		if (send_pkt(skb_out) != VER_CONTINUE)
			goto end;
		/* send_pkt releases skb_out regardless of verdict. */
	}

	log_debug("Success.");
	/* Fall through. */

end:
	kfree_skb(skb_in);
	return (unsigned int) VER_STOLEN;
}

/**
 * Entry point for IPv4 packet processing.
 */
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

	if (skb_init_cb_ipv4(skb) != 0)
		return NF_DROP;
	if (fix_checksums_ipv4(skb) != 0)
		return NF_DROP;

	return core_common(skb);
}

/**
 * Entry point for IPv6 packet processing.
 */
unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *hdr;

	skb_linearize(skb);

	hdr = ipv6_hdr(skb);

	if (!pool6_contains(&hdr->daddr))
		return NF_ACCEPT; /* Not meant for translation; let the kernel handle it. */

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &hdr->saddr, &hdr->daddr);

	if (skb_init_cb_ipv6(skb) != 0)
		return NF_DROP;
	if (fix_checksums_ipv6(skb) != 0)
		return NF_DROP;

	return core_common(skb);
}
