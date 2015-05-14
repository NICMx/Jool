#include "nat64/mod/common/core.h"
#include "nat64/mod/common/blacklist.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/send_packet.h"
#include "nat64/mod/common/config.h"

#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/handling_hairpinning.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


#ifdef STATEFUL

static unsigned int core_common(struct packet *in)
{
	struct packet out;
	struct tuple tuple_in;
	struct tuple tuple_out;
	verdict result;

	result = determine_in_tuple(in, &tuple_in);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = filtering_and_updating(in, &tuple_in);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = compute_out_tuple(&tuple_in, &tuple_out, in);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = translating_the_packet(&tuple_out, in, &out);
	if (result != VERDICT_CONTINUE)
		goto end;

	if (is_hairpin(&out, &tuple_out)) {
		result = handling_hairpinning(&out, &tuple_out);
		kfree_skb(out.skb);
	} else {
		result = sendpkt_send(in, &out);
		/* send_pkt releases skb_out regardless of verdict. */
	}

	if (result != VERDICT_CONTINUE)
		goto end;

	log_debug("Success.");
	/*
	 * The new packet was sent, so the original one can die; drop it.
	 *
	 * NF_DROP translates into an error (see nf_hook_slow()).
	 * Sending a replacing & translated version of the packet should not count as an error,
	 * so we free the incoming packet ourselves and return NF_STOLEN on success.
	 */
	kfree_skb(in->skb);
	result = VERDICT_STOLEN;
	/* Fall through. */

end:
	if (result == VERDICT_ACCEPT)
		log_debug("Returning the packet to the kernel.");

	return (unsigned int) result;
}

#else

static unsigned int core_common(struct packet *in)
{
	struct packet out;
	verdict result;

	result = translating_the_packet(NULL, in, &out);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = sendpkt_send(in, &out);
	if (result != VERDICT_CONTINUE)
		goto end;

	log_debug("Success.");
	/* See the large comment above. */
	kfree_skb(in->skb);
	result = VERDICT_STOLEN;
	/* Fall through. */

end:
	if (result == VERDICT_ACCEPT)
		log_debug("Returning the packet to the kernel.");

	return (unsigned int) result;
}

#endif

unsigned int core_4to6(struct sk_buff *skb)
{
	struct packet pkt;
	struct iphdr *hdr = ip_hdr(skb);
	int error;

	/* TODO (later) this is silly. We should probably unhook Jool from Netfilter instead. */
	if (config_get_is_disable())
		return NF_ACCEPT; /* Translation is disabled; let the packet pass. */

	/* TODO This suffers the hairpinning dilemma. You will have to move this to translate. */
	if (is_blacklisted4(hdr->saddr) || is_blacklisted4(hdr->daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	error = pkt_init_ipv4(&pkt, skb); /* Reminder: This function might change pointers. */
	if (error)
		return NF_DROP;

	return core_common(&pkt);
}

unsigned int core_6to4(struct sk_buff *skb)
{
	struct packet pkt;
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	int error;

	if (config_get_is_disable())
		return NF_ACCEPT; /* Translation is disabled; let the packet pass. */

	if (is_blacklisted6(&hdr->saddr) || is_blacklisted6(&hdr->daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &hdr->saddr, &hdr->daddr);

	error = pkt_init_ipv6(&pkt, skb); /* Reminder: This function might change pointers. */
	if (error)
		return NF_DROP;

	if (nat64_is_stateful()) {
		verdict result = fragdb_handle(&pkt);
		if (result != VERDICT_CONTINUE)
			return (unsigned int) result;
	}

	return core_common(&pkt);
}
