#include "nat64/mod/common/handling_hairpinning.h"

#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/send_packet.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/pool4/db.h"


/**
 * Checks whether "pkt" is a hairpin packet.
 *
 * @param pkt outgoing packet the NAT64 would send if it's not a hairpin.
 * @return whether pkt is a hairpin packet.
 */
bool is_hairpin(struct xlation *state)
{
	if (state->out.tuple.l3_proto == L3PROTO_IPV6)
		return false;

	/*
	 * This collides with RFC 6146.
	 * The RFC says "packet (...) destination address", but I'm using
	 * "tuple destination address".
	 * I mean you can throw tomatoes, but this makes lot more sense to me.
	 * Otherwise Jool would hairpin ICMP errors that were actually intended
	 * for its node. It might take a miracle for these packets to exist,
	 * but hey, why the hell not.
	 */
	return pool4db_contains(state->jool.nat64.pool4, state->jool.ns,
			state->out.tuple.l4_proto, &state->out.tuple.dst.addr4);
}

/**
 * Mirrors the core's behavior by processing skb_in as if it was the incoming packet.
 *
 * @param skb_in the outgoing packet. Except because it's a hairpin, here it's treated as if it was
 *		the one received from the network.
 * @param tuple_in skb_in's tuple.
 * @return whether we managed to U-turn the packet successfully.
 */
verdict handling_hairpinning(struct xlation *old)
{
	struct xlation new;
	verdict result;

	log_debug("Step 5: Handling Hairpinning...");

	xlation_init(&new);
	new.jool = old->jool;
	new.in = old->out;

	result = filtering_and_updating(&new);
	if (result != VERDICT_CONTINUE)
		return result;
	result = compute_out_tuple(&new);
	if (result != VERDICT_CONTINUE)
		return result;
	result = translating_the_packet(&new);
	if (result != VERDICT_CONTINUE)
		return result;
	result = sendpkt_send(&new);
	if (result != VERDICT_CONTINUE)
		return result;

	log_debug("Done step 5.");
	return VERDICT_CONTINUE;
}
