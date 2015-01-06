#include "nat64/mod/stateful/handling_hairpinning.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/stateful/send_packet.h"
#include "nat64/mod/common/stats.h"


/**
 * Checks whether "pkt" is a hairpin packet.
 *
 * @param pkt outgoing packet the NAT64 would send if it's not a hairpin.
 * @return whether pkt is a hairpin packet.
 */
bool is_hairpin(struct sk_buff *skb)
{
	return (skb_l3_proto(skb) == L3PROTO_IPV4) ? pool4_contains(ip_hdr(skb)->daddr) : false;
}

/**
 * Mirrors the core's behavior by processing skb_in as if it was the incoming packet.
 *
 * @param skb_in the outgoing packet. Except because it's a hairpin, here it's treated as if it was
 *		the one received from the network.
 * @param tuple_in skb_in's tuple.
 * @return whether we managed to U-turn the packet successfully.
 */
verdict handling_hairpinning(struct sk_buff *skb_in, struct tuple *tuple_in)
{
	struct sk_buff *skb_out;
	struct tuple tuple_out;
	verdict result;

	log_debug("Step 5: Handling Hairpinning...");

	if (skb_l4_proto(skb_in) == L4PROTO_ICMP) {
		/*
		 * RFC 6146 section 2 (Definition of "Hairpinning").
		 *
		 * Update 2014-11-21:
		 * Actually, since ICMP errors count as UDP or TCP packets tuple-wise, maybe the RFC means
		 * we should only filter out ICMP echoes.
		 * Or maybe not even that, since they're going to be dropped later anyway, once Jool fails
		 * to find the mapping.
		 * Unfortunately, if I remove this if, Jool crashes when I hairpin a ICMP error.
		 * TODO (warning) we need to investigate this crash further.
		 */
		log_debug("ICMP is not supported by hairpinning. Dropping packet...");
		return VER_DROP;
	}

	result = filtering_and_updating(skb_in, tuple_in);
	if (result != VER_CONTINUE)
		return result;
	result = compute_out_tuple(tuple_in, &tuple_out, skb_in);
	if (result != VER_CONTINUE)
		return result;
	result = translating_the_packet(&tuple_out, skb_in, &skb_out);
	if (result != VER_CONTINUE)
		return result;
	result = sendpkt_send(skb_in, skb_out);
	if (result != VER_CONTINUE)
		return result;

	log_debug("Done step 5.");
	return VER_CONTINUE;
}
