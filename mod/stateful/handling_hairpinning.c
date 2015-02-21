#include "nat64/mod/stateful/handling_hairpinning.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/send_packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/pool4.h"


/**
 * Checks whether "pkt" is a hairpin packet.
 *
 * @param pkt outgoing packet the NAT64 would send if it's not a hairpin.
 * @return whether pkt is a hairpin packet.
 */
bool is_hairpin(struct packet *pkt)
{
	return (pkt_l3_proto(pkt) == L3PROTO_IPV4) ? pool4_contains(pkt_ip4_hdr(pkt)->daddr) : false;
}

/**
 * Mirrors the core's behavior by processing skb_in as if it was the incoming packet.
 *
 * @param skb_in the outgoing packet. Except because it's a hairpin, here it's treated as if it was
 *		the one received from the network.
 * @param tuple_in skb_in's tuple.
 * @return whether we managed to U-turn the packet successfully.
 */
verdict handling_hairpinning(struct packet *in, struct tuple *tuple_in)
{
	struct packet out;
	struct tuple tuple_out;
	verdict result;

	log_debug("Step 5: Handling Hairpinning...");

	if (pkt_l4_proto(in) == L4PROTO_ICMP) {
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
		return VERDICT_DROP;
	}

	result = filtering_and_updating(in, tuple_in);
	if (result != VERDICT_CONTINUE)
		return result;
	result = compute_out_tuple(tuple_in, &tuple_out, in);
	if (result != VERDICT_CONTINUE)
		return result;
	result = translating_the_packet(&tuple_out, in, &out);
	if (result != VERDICT_CONTINUE)
		return result;
	result = sendpkt_send(in, &out);
	if (result != VERDICT_CONTINUE)
		return result;

	log_debug("Done step 5.");
	return VERDICT_CONTINUE;
}
